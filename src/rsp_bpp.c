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
 * Groups 2 and 3 are placed UNPROTECTED -- their ConfigureISDPRequest and
 * StoreMetadataRequest are DER-encoded and placed straight into the '87'/
 * '88' TLV's value. This is a deliberate, documented scope cut for this
 * half of the project: rsp.h says plainly that rsp_protect and
 * rsp_unprotect hard-code tag '86' and that '87'/'88' protection (a
 * different construction -- '87' is encrypted and MAC'd like '86', '88'
 * is MAC-only, no encryption) is out of scope here. A real card will
 * refuse a BPP built this way; the first task that talks to a card is
 * where '87'/'88' protection belongs.
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
 * WHY THE OUTER ENVELOPE IS HAND-WRITTEN, NOT asn1c-GENERATED:
 *
 * BoundProfilePackage's firstSequenceOf87/sequenceOf88/secondSequenceOf87/
 * sequenceOf86 fields are each "SEQUENCE OF [N] OCTET STRING" -- an inline
 * tag on the *element* type of a SEQUENCE OF, not on a SEQUENCE member.
 * asn1c-0.9.29's generated code for that shape is internally inconsistent
 * between encode and decode, confirmed by reading dist/constr_SET_OF.c
 * (regenerated from the same asn1c, so this is not a one-off artifact):
 *
 *   - SET_OF_encode_der and its helper SET_OF__encode_sorted both call
 *     the element's der_encoder with a literal 0 for tag_mode
 *     (constr_SET_OF.c, the `elm->type->op->der_encoder(elm->type,
 *     memb_ptr, 0, elm->tag, ...)` calls), which makes OCTET_STRING's own
 *     encoder ignore elm->tag entirely and write its universal tag
 *     ('04') instead of the intended context tag ('86'/'87'/'88').
 *   - SET_OF_decode_ber's element loop, by contrast, checks the wire tag
 *     against elm->tag before accepting an element (`if(BER_TAGS_EQUAL
 *     (tlv_tag, elm->tag)) ... else RETURN(RC_FAIL)`), i.e. it demands
 *     the context tag the encoder never wrote.
 *
 * The result: der_encode() and ber_decode() of a BoundProfilePackage_t
 * do not even round-trip against each other, independent of this
 * library's own correctness -- verified directly: encoding a BPP and
 * feeding it back to ber_decode() failed with RC_FAIL at the exact byte
 * offset where the first '87' element begins. Patching the vendored
 * dist/ output is not an option (it is generated fresh by `make` from
 * rsp-2.5.asn and never committed), so the four SEQUENCE OF fields and
 * their outer [54] SEQUENCE are written and read by hand below, with
 * plain BER TLV primitives (ber_fetch_tag/ber_fetch_length, already used
 * throughout the vendored codec, so this reuses proven low-level code --
 * only the SEQUENCE OF *of a tagged element* path is affected).
 * InitialiseSecureChannelRequest, ConfigureISDPRequest and
 * StoreMetadataRequest are plain SEQUENCEs, unaffected (their member tags
 * go through constr_SEQUENCE.c, which correctly threads elm->tag_mode),
 * so those three are still built and DER-encoded with Task 2's generated
 * types, as the brief asks.
 */
#include "rsp.h"

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

#define TAG_ISCR_OUTER   0xBF  /* BoundProfilePackage's own [54], high-tag
                                   form: 0xBF 0x36 (54 needs 2 tag octets) */
#define TAG_BPP_SECOND   0x36
#define TAG_F87_WRAPPER  TAG_BYTE(2, 1, 0)  /* firstSequenceOf87  [0], SEQUENCE OF: constructed */
#define TAG_88_WRAPPER   TAG_BYTE(2, 1, 1)  /* sequenceOf88       [1] */
#define TAG_S87_WRAPPER  TAG_BYTE(2, 1, 2)  /* secondSequenceOf87 [2], OPTIONAL */
#define TAG_86_WRAPPER   TAG_BYTE(2, 1, 3)  /* sequenceOf86       [3] */
#define TAG_87_ELEMENT   TAG_BYTE(2, 0, 7)  /* '87' TLV, primitive */
#define TAG_88_ELEMENT   TAG_BYTE(2, 0, 8)  /* '88' TLV, primitive */
#define TAG_86_ELEMENT   TAG_BYTE(2, 0, 6)  /* '86' TLV, primitive */

/* The packed (class | tag_number << 2) form ber_fetch_tag hands back --
   see ber_tlv_tag.h. Used only to check the wrapper tags on decode. */
#define PACKED_TAG(class2, num) (ber_tlv_tag_t)((class2) | ((num) << 2))

/* A plain growable buffer, for hand-assembling TLVs and for der_encode's
   callback interface and for concatenating recovered segments. */
typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
} rsp_growbuf_t;

static int growbuf_append(rsp_growbuf_t *g, const void *data, size_t n)
{
    if (g->len + n > g->cap) {
        size_t newcap = g->cap ? g->cap * 2 : 512;
        while (newcap < g->len + n) {
            newcap *= 2;
        }
        uint8_t *p = realloc(g->buf, newcap);
        if (!p) {
            return -1;
        }
        g->buf = p;
        g->cap = newcap;
    }
    if (n) {
        memcpy(g->buf + g->len, data, n);
    }
    g->len += n;
    return 0;
}

static void growbuf_free(rsp_growbuf_t *g)
{
    free(g->buf);
    g->buf = NULL;
    g->len = 0;
    g->cap = 0;
}

static int der_collect(const void *buf, size_t n, void *key)
{
    return growbuf_append((rsp_growbuf_t *)key, buf, n) == 0 ? 0 : -1;
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
        growbuf_free(&g);
        return -1;
    }
    *out = g.buf;
    *out_len = g.len;
    return 0;
}

/* Minimal DER length octets (no leading zero byte) -- the same rule
   src/rsp_crypto.c uses for SCP03t's own length field, restated here
   because that copy is private to that file. Supports up to a 3-octet
   length (65535 bytes), comfortably past anything this file assembles. */
static int der_len_octets(size_t len, uint8_t out[3], size_t *n)
{
    if (len < 0x80) {
        out[0] = (uint8_t)len;
        *n = 1;
    } else if (len <= 0xFF) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        *n = 2;
    } else if (len <= 0xFFFF) {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)len;
        *n = 3;
    } else {
        return -1;
    }
    return 0;
}

/* Append one TLV with a single-byte tag: tag, minimal DER length, content. */
static int put_tlv(rsp_growbuf_t *g, uint8_t tag, const uint8_t *content,
                    size_t len)
{
    uint8_t lo[3];
    size_t n;

    if (der_len_octets(len, lo, &n) != 0) {
        return -1;
    }
    if (growbuf_append(g, &tag, 1) != 0) {
        return -1;
    }
    if (growbuf_append(g, lo, n) != 0) {
        return -1;
    }
    if (len && growbuf_append(g, content, len) != 0) {
        return -1;
    }
    return 0;
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

/* InitialiseSecureChannelRequest, SGP.22 v2.6 section 5.5.1 / the ASN.1 at
   rsp-2.5.asn line 463. Only smdpOtpk and the iccid-derived hostId
   placeholder come from the caller; transactionId, the real hostId (the
   eUICC's EID) and smdpSign belong to the ES9+/ES8+ exchange this half of
   the project does not implement (no AuthenticateClient round trip
   supplies a transaction id or an EID, and no ECDSA signing primitive is
   exposed by rsp.h at this stage -- Task 3 only verifies certificates, it
   does not sign). They are filled with clearly-marked placeholders so the
   message still encodes to a structurally valid TLV; the task that wires
   the full ES9+/ES8+ flow supplies the real values. */
static int build_isc(InitialiseSecureChannelRequest_t *isc,
                      const rsp_bpp_input_t *in)
{
    static const uint8_t placeholder_txn[1] = { 0x01 };
    /* GlobalPlatform Card Specification v2.3.1 Table 11-16: AES key type
       is '88'; keyLen is fixed to 0x10 (16 bytes) by rsp-2.5.asn's own
       comment on ControlRefTemplate.keyLen. */
    static const uint8_t key_type_aes = 0x88;
    static const uint8_t key_len_16 = 0x10;

    memset(isc, 0, sizeof *isc);
    isc->remoteOpId = RemoteOpId_installBoundProfilePackage;

    if (OCTET_STRING_fromBuf(&isc->transactionId,
                              (const char *)placeholder_txn, 1) != 0) {
        return -1;
    }
    if (OCTET_STRING_fromBuf(&isc->controlRefTemplate.keyType,
                              (const char *)&key_type_aes, 1) != 0) {
        return -1;
    }
    if (OCTET_STRING_fromBuf(&isc->controlRefTemplate.keyLen,
                              (const char *)&key_len_16, 1) != 0) {
        return -1;
    }
    /* Placeholder hostId: reuses the ICCID only because it is a 10-byte
       value already at hand, not because it is the correct field -- the
       real hostId is the eUICC's EID, which rsp_bpp_input_t does not
       carry. */
    if (OCTET_STRING_fromBuf(&isc->controlRefTemplate.hostId,
                              (const char *)in->iccid, 10) != 0) {
        return -1;
    }
    if (OCTET_STRING_fromBuf(&isc->smdpOtpk,
                              (const char *)in->otpk_dp, 65) != 0) {
        return -1;
    }
    /* Left empty, not filled with filler bytes: an empty signature cannot
       be mistaken for a real one the way a fixed-length placeholder
       could. */
    if (OCTET_STRING_fromBuf(&isc->smdpSign, "", 0) != 0) {
        return -1;
    }
    return 0;
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
   silently non-conformant TLV instead of being refused here. */
static int build_metadata(StoreMetadataRequest_t *md,
                           const rsp_bpp_input_t *in)
{
    size_t name_len = strlen(in->profile_name);
    size_t sp_len = strlen(in->service_provider_name);

    if (name_len > 64 || sp_len > 32) {
        return -1;
    }

    memset(md, 0, sizeof *md);
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
        !in->service_provider_name) {
        return -1;
    }
    if (!in->upp && in->upp_len) {
        return -1;
    }

    memset(&content, 0, sizeof content);
    memset(&seq86, 0, sizeof seq86);

    {
        InitialiseSecureChannelRequest_t isc;
        int rc;
        if (build_isc(&isc, in) != 0) {
            goto out;
        }
        rc = der_encode_alloc(&asn_DEF_InitialiseSecureChannelRequest, &isc,
                               &isc_der, &isc_len);
        ASN_STRUCT_RESET(asn_DEF_InitialiseSecureChannelRequest, &isc);
        if (rc != 0) {
            goto out;
        }
    }
    /* isc_der already carries its own correct [35] tag (InitialiseSecure-
       ChannelRequest's own natural encoding), so it is appended as-is --
       no extra wrapper, matching the ASN.1 (it is a direct SEQUENCE
       member, not a SEQUENCE OF element). */
    if (growbuf_append(&content, isc_der, isc_len) != 0) {
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
    {
        rsp_growbuf_t wrapped;
        memset(&wrapped, 0, sizeof wrapped);
        if (put_tlv(&wrapped, TAG_87_ELEMENT, configure_der, configure_len) != 0 ||
            put_tlv(&content, TAG_F87_WRAPPER, wrapped.buf, wrapped.len) != 0) {
            growbuf_free(&wrapped);
            goto out;
        }
        growbuf_free(&wrapped);
    }

    {
        StoreMetadataRequest_t md;
        int rc;
        if (build_metadata(&md, in) != 0) {
            goto out;
        }
        rc = der_encode_alloc(&asn_DEF_StoreMetadataRequest, &md,
                               &metadata_der, &metadata_len);
        ASN_STRUCT_RESET(asn_DEF_StoreMetadataRequest, &md);
        if (rc != 0) {
            goto out;
        }
    }
    {
        rsp_growbuf_t wrapped;
        memset(&wrapped, 0, sizeof wrapped);
        if (put_tlv(&wrapped, TAG_88_ELEMENT, metadata_der, metadata_len) != 0 ||
            put_tlv(&content, TAG_88_WRAPPER, wrapped.buf, wrapped.len) != 0) {
            growbuf_free(&wrapped);
            goto out;
        }
        growbuf_free(&wrapped);
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

        n = rsp_protect(s, p, chunk, seg_buf, sizeof seg_buf);
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
        uint8_t lo[3];
        size_t n;

        memset(&g, 0, sizeof g);
        if (der_len_octets(content.len, lo, &n) != 0) {
            goto out;
        }
        {
            static const uint8_t outer_tag[2] = { TAG_ISCR_OUTER, TAG_BPP_SECOND };
            if (growbuf_append(&g, outer_tag, 2) != 0 ||
                growbuf_append(&g, lo, n) != 0 ||
                growbuf_append(&g, content.buf, content.len) != 0) {
                growbuf_free(&g);
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
    growbuf_free(&content);
    growbuf_free(&seq86);
    return ret;
}

int rsp_bpp_recover(rsp_session_t *s, const uint8_t *bpp, size_t bpp_len,
                     uint8_t **upp, size_t *upp_len)
{
    ber_tlv_tag_t tag;
    const uint8_t *content;
    size_t content_len;
    size_t pos;
    rsp_growbuf_t g;
    int ret = -1;

    if (!s || !bpp || !upp || !upp_len) {
        return -1;
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
       it is skipped as a raw TLV rather than decoded. */
    {
        ber_tlv_tag_t t;
        const uint8_t *v;
        size_t vlen;
        ssize_t n = read_tlv(content + pos, content_len - pos, &t, &v, &vlen);
        if (n < 0) {
            goto out;
        }
        pos += (size_t)n;
    }

    /* firstSequenceOf87: also skipped -- ConfigureISDP is not part of the
       UPP. */
    {
        ber_tlv_tag_t t;
        const uint8_t *v;
        size_t vlen;
        ssize_t n = read_tlv(content + pos, content_len - pos, &t, &v, &vlen);
        if (n < 0 || t != PACKED_TAG(2, 0)) {
            goto out;
        }
        pos += (size_t)n;
    }

    /* sequenceOf88: skipped -- StoreMetadata is not part of the UPP. */
    {
        ber_tlv_tag_t t;
        const uint8_t *v;
        size_t vlen;
        ssize_t n = read_tlv(content + pos, content_len - pos, &t, &v, &vlen);
        if (n < 0 || t != PACKED_TAG(2, 1)) {
            goto out;
        }
        pos += (size_t)n;
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

            /* The recovered plaintext is never longer than the
               ciphertext (it had padding removed), so the element's own
               value length is always a large-enough scratch buffer. */
            plain = malloc(evlen ? evlen : 1);
            if (!plain) {
                goto out;
            }
            un = rsp_unprotect(s, ev, evlen, plain, evlen);
            if (un < 0) {
                mbedtls_platform_zeroize(plain, evlen);
                free(plain);
                goto out;
            }
            if (growbuf_append(&g, plain, (size_t)un) != 0) {
                mbedtls_platform_zeroize(plain, evlen);
                free(plain);
                goto out;
            }
            mbedtls_platform_zeroize(plain, evlen);
            free(plain);
        }
    }

    *upp = g.buf;
    *upp_len = g.len;
    ret = 0;
    /* Ownership of g.buf passed to the caller; do not free it below. */
    g.buf = NULL;

out:
    if (ret != 0) {
        growbuf_free(&g);
    }
    return ret;
}
