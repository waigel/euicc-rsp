/*
 * rsp_bpp.c -- assembling and recovering a Bound Profile Package (BPP).
 *
 * SGP.22 v2.6 section 2.5.4, "Bound Profile Package", gives the exact
 * ASN.1 -- identical to the BoundProfilePackage definition in rsp-2.5.asn
 * -- and the order of its four TLV groups, in this order:
 *
 *   1. the key-agreement request (initialiseSecureChannelRequest), in clear
 *   2. firstSequenceOf87: ConfigureISDP, under SCP03t tag '87'
 *   3. sequenceOf88: StoreMetadata, under SCP03t tag '88' (MAC-only)
 *   4. secondSequenceOf87: an OPTIONAL second '87' group carrying Profile
 *      Protection Keys -- only used in SGP.22's "random key" mode, which
 *      this library does not implement (see rsp.h: session keys only).
 *      Always absent here.
 *   5. sequenceOf86: the Protected Profile Package, as tag-'86' segments
 *
 * Groups 2 and 3 are now protected exactly as SGP.22 v2.6 Table 4
 * requires: '87' (ConfigureISDP) is encrypted and MAC'd with the same
 * SCP03t construction as '86' (S-ENC, S-CMAC) -- rsp_protect below takes
 * the segment's tag as a parameter for exactly this reason, so the same
 * function serves both '86' and '87'. '88' (StoreMetadata) is MAC'd only,
 * never encrypted -- rsp_protect_mac_only (src/rsp_crypto.c) is the
 * separate, narrower construction Table 4 describes for it. Both '87' and
 * '88' advance the same s->chain the '86' segments do, in wire order
 * (firstSequenceOf87, then sequenceOf88, then sequenceOf86): section
 * 2.5.4's own text, "The encryption counter for ICV calculation is
 * incremented each time a TLV with tag '86', '87' or '88' is received,"
 * describes one shared chaining value across all three tags, not three
 * independent ones -- see src/rsp_crypto.c's own comment for the full
 * account, including what that means for '88', which has no ICV or
 * encryption step of its own to increment a counter for.
 *
 * SGP.22 v2.6 section 2.5.3, "Protected Profile Package", is where the
 * segment size limit comes from: "That block of data is split into
 * segments of a maximum size of 1020 bytes (including the tag, length
 * field and MAC)", and its own NOTE works out the usable payload: "From
 * the 1020 bytes of each data segment, only 1008 bytes are usable for
 * payload (deducted the 1 byte tag, 3 bytes length field and 8 bytes
 * MAC). Considering the necessary padding during encryption ... each
 * data segment can only contain 1007 bytes of the PPP data block."
 * RSP_BPP_MAX_SEGMENT_PLAINTEXT below is exactly that 1007: with
 * rsp_protect's 1-to-16-byte padding, a 1007-byte plaintext chunk always
 * pads to 1008 bytes (the next multiple of 16 above 1007), so ciphertext
 * (1008) + 8-byte MAC (1016 total) takes a 3-byte DER length (0x82 xx xx,
 * since 1016 > 255) for a 1 + 3 + 1016 = 1020-byte segment -- the spec's
 * own maximum, not a byte more.
 *
 * WHY THE OUTER ENVELOPE IS HAND-WRITTEN, PERMANENTLY, NOT asn1c-GENERATED:
 *
 * BoundProfilePackage's firstSequenceOf87/sequenceOf88/secondSequenceOf87/
 * sequenceOf86 fields are each "SEQUENCE OF [N] OCTET STRING" -- an inline
 * tag on the *element* type of a SEQUENCE OF, not on a SEQUENCE member.
 * asn1c-0.9.29's generated code for that shape cannot produce SGP.22's
 * wire bytes at all, in either direction, confirmed by reading
 * dist/constr_SET_OF.c (regenerated fresh from the same asn1c, so this is
 * not a one-off artifact) and by direct experiment. This is not a single
 * bug that a future asn1c release fixes back into usefulness -- it is two
 * independent defects that compound into "no byte sequence the generated
 * encoder can write is one the generated decoder can read back":
 *
 *   1. The member table for e.g. firstSequenceOf87's element sets
 *      tag_mode to +1 ("EXPLICIT tag at current level"), where every
 *      *other* manually-tagged field in this AUTOMATIC TAGS module gets
 *      -1 (IMPLICIT) -- initialiseSecureChannelRequest's own [35] does,
 *      for instance. EXPLICIT tagging adds a wrapping TLV around the
 *      element's own natural tag rather than replacing it, so even a
 *      SET_OF encoder that correctly applied tag_mode would emit a
 *      *nested* `A7 <len> { 04 <len2> <content> }` for tag 7, not
 *      SGP.22's flat `87 <len> <content>`. Whether this is asn1c
 *      mis-choosing EXPLICIT for this shape, or the only tag_mode its
 *      grammar can express for an inline-tagged SEQUENCE OF element, the
 *      observable fact is that the member table itself never encodes the
 *      construction SGP.22 wants, independent of the bug below.
 *   2. SET_OF_encode_der and its helper SET_OF__encode_sorted call the
 *      element's der_encoder with a literal 0 for tag_mode regardless of
 *      what the member table says (`elm->type->op->der_encoder(elm->type,
 *      memb_ptr, 0, elm->tag, ...)`), so in practice neither the (wrong)
 *      +1 nor a hypothetical correct -1 is ever used: the element is
 *      written with OCTET_STRING's bare universal tag ('04'). Verified
 *      with `openssl asn1parse` on the raw output: the element under
 *      firstSequenceOf87 showed as `prim: OCTET STRING`, tag `04`, not
 *      `cont [ 7 ]`.
 *   3. SET_OF_decode_ber's element loop, independently of both of the
 *      above, checks the wire tag against elm->tag *before* invoking the
 *      element's own decoder (`if(BER_TAGS_EQUAL(tlv_tag, elm->tag))
 *      ... else RETURN(RC_FAIL)`), and its own microphase2 then calls
 *      that decoder with tag_mode hardcoded to 0 too -- so the decoder
 *      wants the context tag at the outer check and the bare universal
 *      tag at the position it actually reads from (ber_fetch_tag only
 *      peeks; it does not advance past the tag it checked).
 *
 * Concretely, none of the three candidate wire forms round-trips through
 * asn1c's generated ber_decode(): the as-generated form ('04', what (2)
 * actually writes) fails (3)'s outer elm->tag check; a hypothetically
 * tag_mode-correct EXPLICIT form ('A7' wrapping '04') still fails (3)'s
 * inner universal-tag re-check, because ber_fetch_tag in the outer check
 * never consumed anything; and SGP.22's own flat form ('87' primitive,
 * what this file actually writes) fails that same inner re-check for the
 * identical reason. Verified directly: feeding this file's correct,
 * spec-conformant output to asn1c's own ber_decode(&asn_DEF_
 * BoundProfilePackage, ...) still fails with RC_FAIL at the exact byte
 * offset where the first '87' element begins -- the same offset as
 * feeding it the buggy as-generated output. Patching dist/ is not an
 * option regardless (it is generated fresh by `make` from rsp-2.5.asn
 * and never committed): but even if it were, there is no tag_mode value
 * that makes constr_SET_OF.c's *decoder* accept a flat context-tagged
 * primitive element, so this is not a workaround pending an upstream
 * fix -- it is the only way to get SGP.22's wire bytes out of this exact
 * ASN.1 shape with this asn1c/skeleton pair, and will remain so unless
 * asn1c's SET_OF decode strategy changes for tagged elements, not merely
 * its tag_mode handling.
 *
 * The four SEQUENCE OF fields and their outer [54] SEQUENCE are
 * therefore written and read by hand below, with plain BER TLV
 * primitives (ber_fetch_tag/ber_fetch_length, already used throughout
 * the vendored codec, so this reuses proven low-level code -- only the
 * SEQUENCE OF *of a tagged element* path is affected).
 * InitialiseSecureChannelRequest, ConfigureISDPRequest and
 * StoreMetadataRequest are plain SEQUENCEs, unaffected (their member tags
 * go through constr_SEQUENCE.c, which correctly threads elm->tag_mode
 * and elm->tag both), so those three are still built and DER-encoded
 * with Task 2's generated types, as the brief asks.
 */
#include "rsp.h"
#include "rsp_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/platform_util.h"

#include "ber_tlv_length.h"
#include "ber_tlv_tag.h"
#include "ConfigureISDPRequest.h"
#include "InitialiseSecureChannelRequest.h"
#include "StoreMetadataRequest.h"

#define RSP_BPP_MAX_SEGMENT_PLAINTEXT 1007

/* rsp_protect's worst case for a chunk this size: padding adds up to 16
   bytes, then an 8-byte MAC. */
#define RSP_BPP_SEGMENT_BUF (RSP_BPP_MAX_SEGMENT_PLAINTEXT + 16 + 8)

/* The wire byte for a single low-tag-number (< 31) BER tag: class in the
   top two bits, the constructed bit, the tag number in the bottom five.
   Every tag this file writes by hand is one of these. */
#define TAG_BYTE(class2, constructed, num) \
    (uint8_t)(((class2) << 6) | ((constructed) ? 0x20 : 0) | (num))

/* BoundProfilePackage's own [54], high-tag form: two tag octets, since 54
   does not fit the 5-bit low-tag-number form (< 31). TAG_BPP_FIRST is the
   class/constructed/high-tag-number-marker octet (0xBF: context,
   constructed, 0x1F); TAG_BPP_SECOND is 54's single base-128 byte (54 fits
   with no continuation bit). There is no [2]-wrapper constant: secondSequenceOf87
   is always absent here (see the comment where it is omitted, below), so
   nothing ever writes its tag by hand; decode still checks for it. */
#define TAG_BPP_FIRST    0xBF
#define TAG_BPP_SECOND   0x36
#define TAG_F87_WRAPPER  TAG_BYTE(2, 1, 0)  /* firstSequenceOf87  [0], SEQUENCE OF: constructed */
#define TAG_88_WRAPPER   TAG_BYTE(2, 1, 1)  /* sequenceOf88       [1] */
#define TAG_86_WRAPPER   TAG_BYTE(2, 1, 3)  /* sequenceOf86       [3] */
#define TAG_87_ELEMENT   TAG_BYTE(2, 0, 7)  /* '87' TLV, primitive */
#define TAG_88_ELEMENT   TAG_BYTE(2, 0, 8)  /* '88' TLV, primitive */
#define TAG_86_ELEMENT   TAG_BYTE(2, 0, 6)  /* '86' TLV, primitive */

/* smdpSign's own concatenation (SGP.22 v2.6 section 5.5.1, build_isc_tbs
   below): the exact IMPLICIT tag InitialiseSecureChannelRequest's own
   generated member table (dist/InitialiseSecureChannelRequest.c) assigns
   each field -- not values re-typed independently of that table. remoteOpId
   carries no override in that table (tag_mode 0: RemoteOpId's own natural
   [2] IMPLICIT INTEGER tag, unchanged); transactionId, controlRefTemplate
   are each re-tagged IMPLICIT at [0] and [6]; ControlRefTemplate's own three
   members (dist/ControlRefTemplate.c) are IMPLICIT at [0], [1], [4].
   smdpOtpk/euiccOtpk share one tag, APPLICATION 73 (otPK.*.ECKA is the same
   OCTET STRING type for both DP and eUICC's one-time public key) -- its
   high-tag-number form needs two octets, so it is not a TAG_BYTE constant
   like the others. Checked against a working reference implementation, not
   assumed: pySim's ES8+ helper (pySim/esim/es8p.py,
   gen_init_sec_chan_signed_part) builds this exact concatenation, tag by
   tag, the same way. */
#define TAG_REMOTEOPID    TAG_BYTE(2, 0, 2)  /* remoteOpId: RemoteOpId's own [2] INTEGER tag */
#define TAG_TRANSACTIONID TAG_BYTE(2, 0, 0)  /* transactionId [0] IMPLICIT */
#define TAG_CRT           TAG_BYTE(2, 1, 6)  /* controlRefTemplate [6] IMPLICIT, constructed (SEQUENCE) */
#define TAG_CRT_KEYTYPE   TAG_BYTE(2, 0, 0)  /* ControlRefTemplate.keyType [0] IMPLICIT */
#define TAG_CRT_KEYLEN    TAG_BYTE(2, 0, 1)  /* ControlRefTemplate.keyLen  [1] IMPLICIT */
#define TAG_CRT_HOSTID    TAG_BYTE(2, 0, 4)  /* ControlRefTemplate.hostId  [4] IMPLICIT */
static const uint8_t TAG_OTPK[2] = { 0x5F, 0x49 }; /* smdpOtpk / euiccOtpk: APPLICATION 73 IMPLICIT */

/* The packed (class | tag_number << 2) form ber_fetch_tag hands back --
   see ber_tlv_tag.h. Used only to check the wrapper tags on decode. */
#define PACKED_TAG(class2, num) (ber_tlv_tag_t)((class2) | ((num) << 2))

/* rsp_growbuf_t and its append/free live in rsp_internal.h now, shared
   with euicc-lpa's src/rsp_es10.c and its inward response accumulator,
   which reaches this header through the vendored submodule -- see that
   header's top comment for why a fourth hand-rolled copy is what this
   move prevents. Every growbuf this file frees might be holding recovered
   UPP plaintext (rsp_bpp_recover's rejection path) or, less critically,
   DER destined for the wire anyway; rsp_growbuf_free wipes unconditionally
   rather than asking call sites to know which. */

static int der_collect(const void *buf, size_t n, void *key)
{
    return rsp_growbuf_append((rsp_growbuf_t *)key, buf, n) == 0 ? 0 : -1;
}

/* DER-encode an asn1c type into a freshly malloc'ed buffer. Used only for
   the three plain SEQUENCEs (InitialiseSecureChannelRequest,
   ConfigureISDPRequest, StoreMetadataRequest) -- see the file header for
   why the BoundProfilePackage envelope itself is not encoded this way. */
static int der_encode_alloc(asn_TYPE_descriptor_t *td, const void *sptr,
                             uint8_t **out, size_t *out_len)
{
    rsp_growbuf_t g;
    asn_enc_rval_t r;

    memset(&g, 0, sizeof g);
    r = der_encode(td, sptr, der_collect, &g);
    if (r.encoded < 0) {
        rsp_growbuf_free(&g);
        return -1;
    }
    *out = g.buf;
    *out_len = g.len;
    return 0;
}

/* rsp_der_length_octets (src/rsp_internal.h) is the DER length rule this
   file used to carry its own copy of, extended to a 4-octet form (up to
   0xFFFFFFFF bytes, RSP_DER_LEN_OCTETS_MAX total octets including the
   leading tag-of-length byte): a first review round found the 3-octet
   cap (65535 bytes) this file's own original copy had refused any UPP
   whose sequenceOf86 content -- or the BoundProfilePackage's own outer
   content -- crossed that boundary, measured at a 64527-byte UPP, well
   inside profiles that carry applets. Nothing in SGP.22 imposes 65535 as
   a limit, and ber_fetch_length (dist/ber_tlv_length.c) already decodes
   length forms longer than 3 octets without complaint, so build was
   refusing packages recover could read -- an asymmetry with no basis in
   the spec. The shared implementation carries that same 4-octet form
   (0xFFFFFFFF bytes, 4 GiB, past any UPP this library will plausibly
   see) rather than this file quietly reverting to a narrower one of its
   own; a UPP that size is refused here (see the checks in rsp_bpp_build
   below), not silently truncated. */

/* Append one TLV: tag (tag_len octets, written as given -- the caller is
   responsible for it being a well-formed BER tag), minimal DER length,
   content. Generalizes put_tlv below to tags wider than one octet: every
   tag this file otherwise writes is a single low-tag-number octet, but
   smdpSign's own concatenation (build_isc_tbs) also needs APPLICATION 73's
   two-octet high-tag-number form (TAG_OTPK, above). */
static int put_tlv_tag(rsp_growbuf_t *g, const uint8_t *tag, size_t tag_len,
                        const uint8_t *content, size_t len)
{
    uint8_t lo[RSP_DER_LEN_OCTETS_MAX];
    size_t n;

    if (rsp_der_length_octets(len, lo, &n) != 0) {
        return -1;
    }
    if (rsp_growbuf_append(g, tag, tag_len) != 0) {
        return -1;
    }
    if (rsp_growbuf_append(g, lo, n) != 0) {
        return -1;
    }
    if (len && rsp_growbuf_append(g, content, len) != 0) {
        return -1;
    }
    return 0;
}

/* Append one TLV with a single-byte tag: tag, minimal DER length, content. */
static int put_tlv(rsp_growbuf_t *g, uint8_t tag, const uint8_t *content,
                    size_t len)
{
    return put_tlv_tag(g, &tag, 1, content, len);
}

/* Read one BER/DER TLV header at p (n bytes available). *tag receives the
   packed ber_tlv_tag_t ber_fetch_tag itself produces (class in the low
   bits, tag number shifted -- see ber_tlv_tag.h; this is not the wire
   byte). *value and *value_len describe the content. Returns the total
   bytes the TLV occupies (tag + length + value), or -1 for anything
   malformed, including indefinite length: DER never produces it, and
   everything this function reads was produced by rsp_bpp_build or by
   asn1c. */
static ssize_t read_tlv(const uint8_t *p, size_t n, ber_tlv_tag_t *tag,
                         const uint8_t **value, size_t *value_len)
{
    ber_tlv_tag_t t;
    ssize_t tag_len;
    int constructed;
    ber_tlv_len_t len;
    ssize_t len_len;

    tag_len = ber_fetch_tag(p, n, &t);
    if (tag_len <= 0) {
        return -1;
    }
    constructed = BER_TLV_CONSTRUCTED(p);
    len_len = ber_fetch_length(constructed, p + tag_len,
                                n - (size_t)tag_len, &len);
    if (len_len <= 0 || len < 0) {
        return -1;
    }
    if ((size_t)tag_len + (size_t)len_len + (size_t)len > n) {
        return -1;
    }
    *tag = t;
    *value = p + (size_t)tag_len + (size_t)len_len;
    *value_len = (size_t)len;
    return (ssize_t)((size_t)tag_len + (size_t)len_len + (size_t)len);
}

/* smdpSign's own to-be-signed bytes (SGP.22 v2.6 section 5.5.1): "the
   SM-DP+ private key SK.DPbp.ECDSA across the following concatenated data
   objects: remoteOpId; transactionId; controlRefTemplate; smdpOtpk;
   euiccOtpk." Section 2.6.7.2's general rule for ASN.1-data-object signing
   ("the signature SHALL be computed for the data object after encoding,
   i.e. in its DER representation") applies to each one individually, so
   this is each field's own encoded TLV, concatenated -- not their bare
   values, and not InitialiseSecureChannelRequest's own encoding either
   (which cannot be what is meant: it would have to include smdpSign
   itself, and it does not include euiccOtpk at all, which comes from
   PrepareDownloadResponse, an earlier exchange). See TAG_REMOTEOPID and
   its neighbors, above, for exactly which tag each field carries and how
   that was checked, not assumed. key_type/key_len/host_id/host_id_len are
   the same three values build_isc below fills controlRefTemplate's own
   three members with -- passed in rather than re-read from isc, so this
   function has no ordering dependency on when isc's own fields are
   populated. */
static int build_isc_tbs(rsp_growbuf_t *g,
                          const uint8_t transaction_id[16],
                          uint8_t key_type, uint8_t key_len,
                          const uint8_t *host_id, size_t host_id_len,
                          const uint8_t smdp_otpk[65],
                          const uint8_t euicc_otpk[65])
{
    /* This library only ever requests one remote operation type -- see
       build_isc's own use of RemoteOpId_installBoundProfilePackage --
       so this is the one value this concatenation ever needs, not a
       second, independent copy of that choice. */
    static const uint8_t remote_op_id = RemoteOpId_installBoundProfilePackage;
    rsp_growbuf_t crt;
    int ret = -1;

    memset(&crt, 0, sizeof crt);

    if (put_tlv(&crt, TAG_CRT_KEYTYPE, &key_type, 1) != 0 ||
        put_tlv(&crt, TAG_CRT_KEYLEN, &key_len, 1) != 0 ||
        put_tlv(&crt, TAG_CRT_HOSTID, host_id, host_id_len) != 0) {
        goto out;
    }

    if (put_tlv(g, TAG_REMOTEOPID, &remote_op_id, 1) != 0 ||
        put_tlv(g, TAG_TRANSACTIONID, transaction_id, 16) != 0 ||
        put_tlv(g, TAG_CRT, crt.buf, crt.len) != 0 ||
        put_tlv_tag(g, TAG_OTPK, sizeof TAG_OTPK, smdp_otpk, 65) != 0 ||
        put_tlv_tag(g, TAG_OTPK, sizeof TAG_OTPK, euicc_otpk, 65) != 0) {
        goto out;
    }
    ret = 0;

out:
    rsp_growbuf_free(&crt);
    return ret;
}

/* InitialiseSecureChannelRequest, SGP.22 v2.6 section 5.5.1 / the ASN.1 at
   rsp-2.5.asn line 463. transactionId is in->transaction_id, the same
   value the caller's RSP session generated (not a placeholder).
   controlRefTemplate.hostId is RSP_HOST_ID (src/rsp_internal.h) -- an
   arbitrary, fixed, SM-DP+-chosen identifier for the Host side of the key
   agreement, NOT the eUICC's EID and NOT in->iccid: both were tried in
   this exact function at different points in this project's history and
   are documented, in RSP_HOST_ID's own comment, as wrong for this field.
   smdpSign is now a real signature -- see build_isc_tbs above for the
   concatenation and rsp_sign (rsp.h) for the deterministic-ECDSA primitive
   it is computed with, using the DPpb credential the caller supplies via
   in->dppb (never DPauth: DPauth signs InitiateAuthentication's own
   serverSigned1, a different key for a different purpose -- see
   src/rsp_es9.c's own top comment). */
static int build_isc(InitialiseSecureChannelRequest_t *isc,
                      const rsp_bpp_input_t *in)
{
    /* GlobalPlatform Card Specification v2.3.1 Table 11-16: AES key type
       is '88'; keyLen is fixed to 0x10 (16 bytes) by rsp-2.5.asn's own
       comment on ControlRefTemplate.keyLen. */
    static const uint8_t key_type_aes = 0x88;
    static const uint8_t key_len_16 = 0x10;
    rsp_growbuf_t tbs;
    uint8_t sig[64];
    int ret = -1;

    memset(isc, 0, sizeof *isc);
    memset(&tbs, 0, sizeof tbs);

    isc->remoteOpId = RemoteOpId_installBoundProfilePackage;

    if (OCTET_STRING_fromBuf(&isc->transactionId,
                              (const char *)in->transaction_id, 16) != 0) {
        goto out;
    }
    if (OCTET_STRING_fromBuf(&isc->controlRefTemplate.keyType,
                              (const char *)&key_type_aes, 1) != 0) {
        goto out;
    }
    if (OCTET_STRING_fromBuf(&isc->controlRefTemplate.keyLen,
                              (const char *)&key_len_16, 1) != 0) {
        goto out;
    }
    if (OCTET_STRING_fromBuf(&isc->controlRefTemplate.hostId,
                              (const char *)RSP_HOST_ID, RSP_HOST_ID_LEN) != 0) {
        goto out;
    }
    if (OCTET_STRING_fromBuf(&isc->smdpOtpk,
                              (const char *)in->otpk_dp, 65) != 0) {
        goto out;
    }

    if (build_isc_tbs(&tbs, in->transaction_id, key_type_aes, key_len_16,
                       RSP_HOST_ID, RSP_HOST_ID_LEN,
                       in->otpk_dp, in->euicc_otpk) != 0) {
        goto out;
    }
    if (rsp_sign(in->dppb, tbs.buf, tbs.len, sig) != 0) {
        goto out;
    }
    if (OCTET_STRING_fromBuf(&isc->smdpSign, (const char *)sig,
                              sizeof sig) != 0) {
        goto out;
    }
    ret = 0;

out:
    rsp_growbuf_free(&tbs);
    return ret;
}

/* ConfigureISDPRequest, rsp-2.5.asn line 478. dpProprietaryData is
   OPTIONAL and this library has no SM-DP+ OID to put in it, so it is left
   absent. */
static void build_configure(ConfigureISDPRequest_t *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    cfg->dpProprietaryData = NULL;
}

/* StoreMetadataRequest, rsp-2.5.asn line 204. The sizes checked below are
   the module's own SIZE constraints on serviceProviderName (0..32) and
   profileName (0..64); asn1c's generic der_encode does not enforce SIZE,
   so a caller string that is too long would otherwise be encoded as a
   silently non-conformant TLV instead of being refused here.

   The check is strlen() -- bytes -- against a SIZE that counts UTF8String
   characters, not bytes. That is conservative, never permissive: it can
   refuse a compliant string that uses enough multi-byte characters to
   push its byte length past the character limit while staying within it
   in characters, but it can never accept a string that is actually too
   long. Given this project's plain-ASCII test material, that gap is
   unexercised; a caller passing profile or provider names rich in
   multi-byte UTF-8 should not rely on this check for the exact SGP.22
   boundary. */
static int build_metadata(StoreMetadataRequest_t *md,
                           const rsp_bpp_input_t *in)
{
    size_t name_len = strlen(in->profile_name);
    size_t sp_len = strlen(in->service_provider_name);

    /* Zeroed before the very first failure return, unlike an earlier
       version of this function -- so that a caller can unconditionally
       ASN_STRUCT_RESET md even when this returns -1, the same way
       build_isc already guarantees. */
    memset(md, 0, sizeof *md);

    if (name_len > 64 || sp_len > 32) {
        return -1;
    }

    if (OCTET_STRING_fromBuf(&md->iccid, (const char *)in->iccid, 10) != 0) {
        return -1;
    }
    if (OCTET_STRING_fromBuf(&md->serviceProviderName,
                              in->service_provider_name, (int)sp_len) != 0) {
        return -1;
    }
    if (OCTET_STRING_fromBuf(&md->profileName, in->profile_name,
                              (int)name_len) != 0) {
        return -1;
    }
    return 0;
}

int rsp_bpp_build(rsp_session_t *s, const rsp_bpp_input_t *in,
                   uint8_t **out, size_t *out_len)
{
    uint8_t *isc_der = NULL, *configure_der = NULL, *metadata_der = NULL;
    size_t isc_len = 0, configure_len = 0, metadata_len = 0;
    rsp_growbuf_t content;   /* BoundProfilePackage's own content */
    rsp_growbuf_t seq86;     /* sequenceOf86's content: concatenated '86' TLVs */
    uint8_t seg_buf[RSP_BPP_SEGMENT_BUF];
    size_t off;
    int ret = -1;

    if (!s || !in || !out || !out_len) {
        return -1;
    }
    if (!in->otpk_dp || !in->iccid || !in->profile_name ||
        !in->service_provider_name || !in->transaction_id ||
        !in->euicc_otpk || !in->dppb) {
        return -1;
    }
    if (!in->upp && in->upp_len) {
        return -1;
    }
    /* An empty UPP would still produce a BPP (the do/while below writes
     * exactly one, zero-length, segment for it -- see the comment there),
     * but rsp_bpp_recover cannot tell that BPP apart from one whose
     * sequenceOf86 has no segments at all without either misreporting
     * the empty-UPP case or accepting a wire shape it must otherwise
     * refuse (see rsp_bpp_recover and include/rsp.h's own note on
     * *upp). Refusing the ambiguous input here, rather than trying to
     * make recovery disambiguate it after the fact, is the cleaner fix:
     * there is no real profile this UPP would ever legitimately be. */
    if (in->upp_len == 0) {
        return -1;
    }

    memset(&content, 0, sizeof content);
    memset(&seq86, 0, sizeof seq86);

    {
        InitialiseSecureChannelRequest_t isc;
        int build_rc = build_isc(&isc, in);
        int rc = 0;
        /* build_isc zeroes isc as its first act (see build_isc), so even
           when it fails partway -- some OCTET_STRING_fromBuf calls
           already succeeded and allocated, one then failed -- isc is
           always in a state ASN_STRUCT_RESET can safely walk. Skipping
           the reset on build_rc != 0, as an earlier version of this file
           did, leaked whatever OCTET STRINGs build_isc had already
           allocated before hitting its own failing call. */
        if (build_rc == 0) {
            rc = der_encode_alloc(&asn_DEF_InitialiseSecureChannelRequest,
                                   &isc, &isc_der, &isc_len);
        }
        ASN_STRUCT_RESET(asn_DEF_InitialiseSecureChannelRequest, &isc);
        if (build_rc != 0 || rc != 0) {
            goto out;
        }
    }
    /* isc_der already carries its own correct [35] tag (InitialiseSecure-
       ChannelRequest's own natural encoding), so it is appended as-is --
       no extra wrapper, matching the ASN.1 (it is a direct SEQUENCE
       member, not a SEQUENCE OF element). */
    if (rsp_growbuf_append(&content, isc_der, isc_len) != 0) {
        goto out;
    }

    {
        ConfigureISDPRequest_t cfg;
        int rc;
        build_configure(&cfg);
        rc = der_encode_alloc(&asn_DEF_ConfigureISDPRequest, &cfg,
                               &configure_der, &configure_len);
        ASN_STRUCT_RESET(asn_DEF_ConfigureISDPRequest, &cfg);
        if (rc != 0) {
            goto out;
        }
    }
    /* '87': ConfigureISDP, encrypted-and-MAC'd with rsp_protect -- the same
       construction as '86', a different tag (SGP.22 v2.6 Table 4; see this
       file's own top comment and rsp_protect's in include/rsp.h). Table 4
       describes no remainder form for '87' the way it does for '88', so a
       ConfigureISDPRequest that does not fit one segment is refused rather
       than guessed at -- ConfigureISDPRequest's only field
       (dpProprietaryData) is capped well under this by its own SIZE
       constraint in practice, so this is not expected to ever trigger, but
       refusing beats silently truncating if it somehow did. */
    if (configure_len > RSP_BPP_MAX_SEGMENT_PLAINTEXT) {
        goto out;
    }
    {
        uint8_t prot87[RSP_BPP_SEGMENT_BUF];
        long n = rsp_protect(s, configure_der, configure_len,
                              TAG_87_ELEMENT, prot87, sizeof prot87);
        rsp_growbuf_t wrapped;
        if (n < 0) {
            goto out;
        }
        memset(&wrapped, 0, sizeof wrapped);
        if (put_tlv(&wrapped, TAG_87_ELEMENT, prot87, (size_t)n) != 0 ||
            put_tlv(&content, TAG_F87_WRAPPER, wrapped.buf, wrapped.len) != 0) {
            rsp_growbuf_free(&wrapped);
            goto out;
        }
        rsp_growbuf_free(&wrapped);
    }

    {
        StoreMetadataRequest_t md;
        int build_rc = build_metadata(&md, in);
        int rc = 0;
        if (build_rc == 0) {
            rc = der_encode_alloc(&asn_DEF_StoreMetadataRequest, &md,
                                   &metadata_der, &metadata_len);
        }
        ASN_STRUCT_RESET(asn_DEF_StoreMetadataRequest, &md);
        if (build_rc != 0 || rc != 0) {
            goto out;
        }
    }
    /* '88': StoreMetadata, MAC'd only with rsp_protect_mac_only -- Table 4's
       own words, "MAC protected ... (i.e. not encrypted)". Table 4 does
       allow a second, remainder '88' TLV if the first cannot hold the
       whole StoreMetadataRequest; that is not implemented (see
       include/rsp.h's own note on rsp_bpp_input_t), so a
       StoreMetadataRequest too large for one segment is refused here
       rather than silently truncated or wrongly split. */
    if (metadata_len > RSP_BPP_MAX_SEGMENT_PLAINTEXT) {
        goto out;
    }
    {
        uint8_t prot88[RSP_BPP_SEGMENT_BUF];
        long n = rsp_protect_mac_only(s, metadata_der, metadata_len,
                                       TAG_88_ELEMENT, prot88, sizeof prot88);
        rsp_growbuf_t wrapped;
        if (n < 0) {
            goto out;
        }
        memset(&wrapped, 0, sizeof wrapped);
        if (put_tlv(&wrapped, TAG_88_ELEMENT, prot88, (size_t)n) != 0 ||
            put_tlv(&content, TAG_88_WRAPPER, wrapped.buf, wrapped.len) != 0) {
            rsp_growbuf_free(&wrapped);
            goto out;
        }
        rsp_growbuf_free(&wrapped);
    }

    /* secondSequenceOf87: OPTIONAL, only used for random-key mode. This
       library only supports the session-key mode (rsp.h), so it is
       omitted entirely -- SGP.22's ASN.1 marks it OPTIONAL, and DER
       omits an absent OPTIONAL field rather than encoding it empty. */

    /* Split the UPP into RSP_BPP_MAX_SEGMENT_PLAINTEXT-byte chunks (SGP.22
       v2.6 section 2.5.3) and protect each into a sequenceOf86 element.
       The do/while, rather than a for loop over off < upp_len, guarantees
       at least one segment even for an empty UPP -- section 2.5.3 treats
       the UPP as "a unique block of data" to be segmented, not as
       something that can be absent from the PPP. */
    off = 0;
    do {
        size_t chunk = in->upp_len - off;
        const uint8_t *p;
        long n;

        if (chunk > RSP_BPP_MAX_SEGMENT_PLAINTEXT) {
            chunk = RSP_BPP_MAX_SEGMENT_PLAINTEXT;
        }
        p = (chunk && in->upp) ? in->upp + off : NULL;

        n = rsp_protect(s, p, chunk, TAG_86_ELEMENT, seg_buf, sizeof seg_buf);
        if (n < 0) {
            goto out;
        }
        if (put_tlv(&seq86, TAG_86_ELEMENT, seg_buf, (size_t)n) != 0) {
            goto out;
        }
        off += chunk;
    } while (off < in->upp_len);

    if (put_tlv(&content, TAG_86_WRAPPER, seq86.buf, seq86.len) != 0) {
        goto out;
    }

    /* The outer [54] SEQUENCE (BoundProfilePackage itself, tag 'BF36').
       54 needs the BER high-tag-number form (two tag octets: 0xBF, then
       0x36 -- 54 fits one base-128 continuation byte with no continuation
       bit set), which is why this one wrapper is not put_tlv (that helper
       only handles the single-byte low-tag-number form used everywhere
       else in this file). */
    {
        rsp_growbuf_t g;
        uint8_t lo[RSP_DER_LEN_OCTETS_MAX];
        size_t n;

        memset(&g, 0, sizeof g);
        if (rsp_der_length_octets(content.len, lo, &n) != 0) {
            goto out;
        }
        {
            static const uint8_t outer_tag[2] = { TAG_BPP_FIRST, TAG_BPP_SECOND };
            if (rsp_growbuf_append(&g, outer_tag, 2) != 0 ||
                rsp_growbuf_append(&g, lo, n) != 0 ||
                rsp_growbuf_append(&g, content.buf, content.len) != 0) {
                rsp_growbuf_free(&g);
                goto out;
            }
        }
        *out = g.buf;
        *out_len = g.len;
    }
    ret = 0;

out:
    free(isc_der);
    free(configure_der);
    free(metadata_der);
    rsp_growbuf_free(&content);
    rsp_growbuf_free(&seq86);
    return ret;
}

/* Verifies every element inside a firstSequenceOf87/sequenceOf88 wrapper's
   own content (wrapper_val, wrapper_len), advancing s->chain through each
   one in wire order -- without keeping any of the recovered plaintext,
   which is not part of the UPP. This replays, on the recovering side,
   exactly the chain advancement rsp_bpp_build performed on the building
   side via rsp_protect ('87') / rsp_protect_mac_only ('88'); see this
   file's own top comment and src/rsp_crypto.c's SCP03t comment for why
   skipping either -- as this function did before both were genuinely
   protected -- would desynchronize the chain the first '86' segment is
   then checked against, with a failure that looks like it is about '86'.

   elem_tag is the packed tag read_tlv compares each element against
   (PACKED_TAG(2, 7) or PACKED_TAG(2, 8)); wire_tag is that same tag's raw
   wire byte, threaded through to rsp_unprotect/rsp_unprotect_mac_only
   (TAG_87_ELEMENT or TAG_88_ELEMENT) -- both are needed because read_tlv
   and rsp_unprotect* use two different tag representations (see PACKED_TAG
   and TAG_BYTE's own comments, above). mac_only selects which of the two
   inverse functions applies: '87' is encrypted-and-MAC'd like '86', '88'
   is MAC-only (Table 4).

   Zero or more elements are accepted, not "at least one": firstSequenceOf87
   and sequenceOf88 are each exactly one TLV as far as rsp_bpp_build is
   concerned, but an empty wrapper is not the same kind of ambiguity
   sequenceOf86 has (see rsp_bpp_recover's own comment on why *that* one
   does require at least one) -- a hand-built BPP is free to leave either
   group empty without that meaning anything went missing. Returns 0 on
   success. -1 if some element's MAC did not match (a real no, propagated
   from rsp_unprotect/rsp_unprotect_mac_only unchanged). -2 if malformed
   (a bad element tag, a truncated TLV) or an allocation failure. */
static int verify_and_advance(rsp_session_t *s, const uint8_t *wrapper_val,
                               size_t wrapper_len, ber_tlv_tag_t elem_tag,
                               uint8_t wire_tag, int mac_only)
{
    size_t p = 0;

    while (p < wrapper_len) {
        ber_tlv_tag_t et;
        const uint8_t *ev;
        size_t evlen;
        uint8_t *plain;
        long un;
        ssize_t en = read_tlv(wrapper_val + p, wrapper_len - p, &et, &ev, &evlen);

        if (en < 0 || et != elem_tag) {
            return -2;
        }
        p += (size_t)en;

        /* Sized the same way the sequenceOf86 loop below sizes its own
           scratch buffer: the recovered plaintext is never longer than
           the element's own value bytes, encrypted or not. */
        plain = malloc(evlen ? evlen : 1);
        if (!plain) {
            return -2;
        }
        un = mac_only
            ? rsp_unprotect_mac_only(s, ev, evlen, wire_tag, plain, evlen)
            : rsp_unprotect(s, ev, evlen, wire_tag, plain, evlen);
        mbedtls_platform_zeroize(plain, evlen);
        free(plain);
        if (un < 0) {
            return (un == -1) ? -1 : -2;
        }
    }
    return 0;
}

int rsp_bpp_recover(rsp_session_t *s, const uint8_t *bpp, size_t bpp_len,
                     uint8_t **upp, size_t *upp_len)
{
    ber_tlv_tag_t tag;
    const uint8_t *content;
    size_t content_len;
    size_t pos;
    rsp_growbuf_t g;
    /* -2 by default: everything below other than a segment's MAC actually
     * failing is "the question was never reached" -- a malformed
     * envelope, a bad tag, a truncated TLV, an empty sequenceOf86, an
     * allocation failure -- see include/rsp.h's failure convention. The
     * one place this function asks a real yes/no question is inside the
     * segment loop, and there ret is set from rsp_unprotect's own answer
     * rather than left at this default. */
    int ret = -2;

    if (!s || !bpp || !upp || !upp_len) {
        return -2;
    }
    memset(&g, 0, sizeof g);

    /* The outer [54] SEQUENCE. */
    if (read_tlv(bpp, bpp_len, &tag, &content, &content_len) != (ssize_t)bpp_len) {
        goto out;
    }
    if (tag != PACKED_TAG(2, 54)) {
        goto out;
    }

    pos = 0;

    /* initialiseSecureChannelRequest: not needed to recover the UPP, so
       its content is skipped as a raw TLV rather than decoded -- but its
       tag is still checked, so a BPP missing it entirely is rejected
       rather than accepted with whatever happens to occupy that slot. */
    {
        ber_tlv_tag_t t;
        const uint8_t *v;
        size_t vlen;
        ssize_t n = read_tlv(content + pos, content_len - pos, &t, &v, &vlen);
        if (n < 0 || t != PACKED_TAG(2, 35)) {
            goto out;
        }
        pos += (size_t)n;
    }

    /* firstSequenceOf87: ConfigureISDP is not part of the UPP, and its
       recovered plaintext is discarded -- but it is now genuinely
       protected (see this file's own top comment), so it must be verified
       and its chain advancement replayed, not merely skipped as a raw
       TLV. verify_and_advance, above, does both. */
    {
        ber_tlv_tag_t t;
        const uint8_t *v;
        size_t vlen;
        ssize_t n = read_tlv(content + pos, content_len - pos, &t, &v, &vlen);
        int vrc;
        if (n < 0 || t != PACKED_TAG(2, 0)) {
            goto out;
        }
        pos += (size_t)n;
        vrc = verify_and_advance(s, v, vlen, PACKED_TAG(2, 7),
                                  TAG_87_ELEMENT, 0);
        if (vrc != 0) {
            ret = vrc;
            goto out;
        }
    }

    /* sequenceOf88: same treatment -- StoreMetadata is not part of the
       UPP, but its MAC-only protection must still be verified and its
       chain advancement replayed. */
    {
        ber_tlv_tag_t t;
        const uint8_t *v;
        size_t vlen;
        ssize_t n = read_tlv(content + pos, content_len - pos, &t, &v, &vlen);
        int vrc;
        if (n < 0 || t != PACKED_TAG(2, 1)) {
            goto out;
        }
        pos += (size_t)n;
        vrc = verify_and_advance(s, v, vlen, PACKED_TAG(2, 8),
                                  TAG_88_ELEMENT, 1);
        if (vrc != 0) {
            ret = vrc;
            goto out;
        }
    }

    /* secondSequenceOf87: OPTIONAL. rsp_bpp_build never emits it, but a
       BPP built by something else might -- skip it if present rather
       than assume its absence. */
    {
        ber_tlv_tag_t t;
        const uint8_t *v;
        size_t vlen;
        ssize_t n;

        if (pos < content_len) {
            n = read_tlv(content + pos, content_len - pos, &t, &v, &vlen);
            if (n >= 0 && t == PACKED_TAG(2, 2)) {
                pos += (size_t)n;
            }
        }
    }

    /* sequenceOf86: the Protected Profile Package, as tag-'86' segments.
       Walked in order and unprotected one at a time. rsp_unprotect
       advances s->chain the same way rsp_protect did, so the chaining
       value only stays correct if the segments are consumed in the order
       they were produced -- exactly the order the SEQUENCE OF preserves.
       The moment one segment's MAC fails, this returns -1 immediately:
       no partial concatenation is ever handed back to the caller. */
    {
        ber_tlv_tag_t t;
        const uint8_t *seq86;
        size_t seq86_len;
        size_t p;
        size_t segments_seen = 0;
        ssize_t n = read_tlv(content + pos, content_len - pos, &t,
                              &seq86, &seq86_len);
        if (n < 0 || t != PACKED_TAG(2, 3)) {
            goto out;
        }
        pos += (size_t)n;
        if (pos != content_len) {
            /* Trailing bytes after sequenceOf86 in the outer SEQUENCE:
               not a shape this function produces or expects. */
            goto out;
        }

        p = 0;
        while (p < seq86_len) {
            ber_tlv_tag_t et;
            const uint8_t *ev;
            size_t evlen;
            uint8_t *plain;
            long un;
            ssize_t en = read_tlv(seq86 + p, seq86_len - p, &et, &ev, &evlen);

            if (en < 0 || et != PACKED_TAG(2, 6)) {
                goto out;
            }
            p += (size_t)en;
            segments_seen++;

            /* The recovered plaintext is never longer than the
               ciphertext (it had padding removed), so the element's own
               value length is always a large-enough scratch buffer. */
            plain = malloc(evlen ? evlen : 1);
            if (!plain) {
                goto out;
            }
            un = rsp_unprotect(s, ev, evlen, TAG_86_ELEMENT, plain, evlen);
            if (un < 0) {
                /* Propagate rsp_unprotect's own answer rather than
                 * collapsing it: un == -1 means this segment's MAC did
                 * not match under these session keys, a real "no" this
                 * function's caller needs to see as -1 too; anything
                 * else (un == -2) means rsp_unprotect itself never
                 * reached that question, which stays -2 here as well. */
                ret = (un == -1) ? -1 : -2;
                mbedtls_platform_zeroize(plain, evlen);
                free(plain);
                goto out;
            }
            if (rsp_growbuf_append(&g, plain, (size_t)un) != 0) {
                mbedtls_platform_zeroize(plain, evlen);
                free(plain);
                goto out;
            }
            mbedtls_platform_zeroize(plain, evlen);
            free(plain);
        }

        /* sequenceOf86 with zero elements is not a package this function
           ever produces (rsp_bpp_build's do/while always writes at least
           one segment, even for an empty UPP), and it must not be
           mistaken for one that recovered a genuinely empty UPP: that
           case still goes through the loop above exactly once, with
           un == 0. An empty sequenceOf86 instead means "nothing was
           recovered because there was nothing to recover", which is not
           success -- the header promises *upp is malloc'ed and the
           caller's self-check-before-sending path needs "recovered
           nothing" to never read as "recovered". */
        if (segments_seen == 0) {
            goto out;
        }
    }

    *upp = g.buf;
    *upp_len = g.len;
    ret = 0;
    /* Ownership of g.buf passed to the caller; do not free it below. */
    g.buf = NULL;

out:
    if (ret != 0) {
        rsp_growbuf_free(&g);
    }
    return ret;
}
