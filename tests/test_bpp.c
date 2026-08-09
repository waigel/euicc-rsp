/* The whole first half in one assertion: a real profile goes in, a BPP comes
   out, and the same session keys give the profile back byte for byte. What
   this does not prove is that a card agrees -- that is the second half, and
   the first BPP a card accepts becomes the golden vector here.

   testdata/profile.der is 736 bytes -- one segment, since the limit is 1007
   (SGP.22 v2.6 section 2.5.3) -- so the block above never exercises the
   segmentation loop or the chaining value's advance across segments. A
   first review round proved three wire-changing mutations (the segment
   limit raised sixtyfold, the chaining value frozen across segments, and
   the DER length encoder forced to a non-minimal form) all left this file
   green, because the only checks were bpp_len > upp_len and a round trip --
   exactly the "round trip alone can hide a symmetric error" trap this
   project's own hard-won lessons warn about. The MULTI_UPP block below adds
   a fixture that actually splits into three segments, a hard-coded expected
   bpp_len (an absolute pin on the wire bytes, not just their round trip),
   and an explicit assertion that the chaining value advanced. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsp.h"
#include "rsp_internal.h"

#include "ber_tlv_length.h"
#include "ber_tlv_tag.h"
#include "InitialiseSecureChannelRequest.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if(!good) fails++;
}

static uint8_t *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if(!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *p = malloc((size_t)n);
    if(p && fread(p, 1, (size_t)n, f) != (size_t)n) { free(p); p = NULL; }
    fclose(f);
    if(p) *len = (size_t)n;
    return p;
}

static void session(rsp_session_t *s) {
    memset(s, 0, sizeof *s);
    for(int i = 0; i < 16; i++) { s->s_enc[i] = i; s->s_mac[i] = 0x40 + i; }
}

static const uint8_t iccid[10] = {
    0x98,0x00,0x10,0x32,0x54,0x76,0x98,0x10,0x32,0x14
};

/* Skip a BER/DER TLV's own tag and length octets, returning a pointer to
   its content and, via *rest_len, how many bytes remain from there to the
   end of the buffer given. Used only to find where
   InitialiseSecureChannelRequest's own bytes begin inside a built BPP,
   past BoundProfilePackage's own outer [54] tag+length -- the same
   BER-header parse src/rsp_bpp.c's own (static, unexported) read_tlv does,
   reimplemented here rather than shared, since this file has no other
   reason to reach into that file's internals. ber_decode is tolerant of
   trailing bytes after the one TLV it actually reads, so nothing past the
   ISC itself needs to be located. Returns NULL if the header does not
   parse. */
static const uint8_t *skip_outer_tlv(const uint8_t *p, size_t n,
                                      size_t *rest_len) {
    ber_tlv_tag_t t;
    ssize_t tag_len = ber_fetch_tag(p, n, &t);
    int constructed;
    ber_tlv_len_t len;
    ssize_t len_len;
    if (tag_len <= 0) return NULL;
    constructed = BER_TLV_CONSTRUCTED(p);
    len_len = ber_fetch_length(constructed, p + tag_len,
                                n - (size_t)tag_len, &len);
    if (len_len <= 0 || len < 0) return NULL;
    *rest_len = n - (size_t)tag_len - (size_t)len_len;
    return p + tag_len + len_len;
}

/* Appends one TLV with a single-byte tag and a short-form (< 128 bytes)
   length -- every field this test's own smdpSign reconstruction below
   handles is well under that. Returns the number of bytes written. */
static size_t put_short_tlv(uint8_t *buf, uint8_t tag, const uint8_t *val,
                             size_t len) {
    buf[0] = tag;
    buf[1] = (uint8_t)len;
    if (len) memcpy(buf + 2, val, len);
    return 2 + len;
}

/* Same, for the two-byte APPLICATION-73 tag smdpOtpk/euiccOtpk share. */
static size_t put_short_tlv2(uint8_t *buf, const uint8_t tag[2],
                              const uint8_t *val, size_t len) {
    buf[0] = tag[0];
    buf[1] = tag[1];
    buf[2] = (uint8_t)len;
    if (len) memcpy(buf + 3, val, len);
    return 3 + len;
}

/* Three segments at the SGP.22 section 2.5.3 limit (1007 + 1007 + 1): the
   reviewer walked exactly this boundary set (1006/1007 one segment, 1008
   two, 2013/2014 two, 2015 three) against the wire bytes, so this fixture
   size is not arbitrary -- it lands on an already-verified boundary. */
#define MULTI_UPP_LEN 2015

int main(void) {
    size_t upp_len = 0;
    uint8_t *upp = slurp("testdata/profile.der", &upp_len);
    ok("the test profile is readable", upp && upp_len > 0);
    if(!upp) return 1;

    uint8_t otpk[65]; memset(otpk, 0, sizeof otpk); otpk[0] = 0x04;

    /* The three inputs InitialiseSecureChannelRequest gained when its
       placeholders came out. Fixed here, not random, for the same reason
       as everything else in this file: a fixture that changes between runs
       cannot be pinned. euicc_otpk differs from otpk_dp in its last byte,
       so a build that confused the two -- signing over its own key instead
       of the card's -- would not produce the bytes the pins below expect. */
    uint8_t euicc_otpk[65];
    memset(euicc_otpk, 0, sizeof euicc_otpk);
    euicc_otpk[0] = 0x04;
    euicc_otpk[64] = 0x01;

    static const uint8_t transaction_id[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    /* smdpSign is signed with SK.DPpb, not DPauth (SGP.22 v2.6 section
       5.5.1). rsp_sign is deterministic since RFC 6979 landed, so the
       signature is the same on every run and the absolute length pins
       below hold. */
    rsp_credential_t dppb;
    ok("DPpb loads, for smdpSign", rsp_pki_dp(1, &dppb) == 0);

    rsp_bpp_input_t in = {
        .upp = upp, .upp_len = upp_len, .otpk_dp = otpk, .iccid = iccid,
        .profile_name = "example", .service_provider_name = "euicc-tools",
        .transaction_id = transaction_id, .euicc_otpk = euicc_otpk,
        .dppb = &dppb
    };

    rsp_session_t s1, s2;
    session(&s1); session(&s2);

    uint8_t *bpp = NULL; size_t bpp_len = 0;
    ok("the BPP is built", rsp_bpp_build(&s1, &in, &bpp, &bpp_len) == 0);
    ok("the BPP is larger than the profile", bpp_len > upp_len);

    /* The two things a card checks that a round trip cannot see: what the
       InitialiseSecureChannelRequest actually carries, and whether its
       signature holds. Both are decoded out of the built BPP rather than
       compared against values this test also supplied, so a build that
       wrote something else into the wire bytes is caught here. */
    {
        size_t rest = 0;
        const uint8_t *isc = skip_outer_tlv(bpp, bpp_len, &rest);
        ok("the BPP's outer TLV header parses", isc != NULL);

        InitialiseSecureChannelRequest_t *r = NULL;
        asn_dec_rval_t dr;
        memset(&dr, 0, sizeof dr);
        if (isc) {
            dr = ber_decode(NULL, &asn_DEF_InitialiseSecureChannelRequest,
                            (void **)&r, isc, rest);
        }
        ok("InitialiseSecureChannelRequest decodes", dr.code == RC_OK && r);

        if (r) {
            /* hostId must be the one RSP_HOST_ID names. The same bytes go
               into the Annex G SharedInfo the session is derived from
               (src/rsp_es9.c), and if a second copy ever appears in
               src/rsp_bpp.c the two sides derive different keys with
               nothing to say why. This reads the value out of the encoded
               CRT, so a hardcoded literal there fails even though it would
               still round-trip. */
            ok("the CRT's hostId is RSP_HOST_ID, not a second copy",
               r->controlRefTemplate.hostId.size == (int)RSP_HOST_ID_LEN
               && memcmp(r->controlRefTemplate.hostId.buf,
                         RSP_HOST_ID, RSP_HOST_ID_LEN) == 0);

            ok("the transactionId is the one that was passed in",
               r->transactionId.size == 16
               && memcmp(r->transactionId.buf, transaction_id, 16) == 0);

            ok("smdpSign is a real 64-byte signature, not the empty "
               "placeholder", r->smdpSign.size == 64);

            /* SGP.22 v2.6 section 5.5.1: smdpSign is computed with
               SK.DPpb over remoteOpId || transactionId ||
               controlRefTemplate || smdpOtpk || euiccOtpk. Rebuilt here
               from the decoded fields, so signing over the wrong
               concatenation -- or over our own one-time key instead of
               the card's -- fails this. */
            static const uint8_t otpk_tag[2] = { 0x5F, 0x49 };
            uint8_t tbs[512];
            size_t n = 0;
            /* remoteOpId is RemoteOpId's own [2] INTEGER tag, 0x82;
               transactionId is [0] IMPLICIT, 0x80. Written out here as
               literals rather than reusing src/rsp_bpp.c's TAG_ macros --
               a test that borrows the implementation's own constants
               agrees with it by construction and would not have caught
               these two being swapped, which is exactly what happened on
               the first attempt at this assertion. */
            uint8_t remote_op = (uint8_t)r->remoteOpId;
            n += put_short_tlv(tbs + n, 0x82, &remote_op, 1);
            n += put_short_tlv(tbs + n, 0x80, r->transactionId.buf,
                               (size_t)r->transactionId.size);
            {
                uint8_t crt[64];
                size_t c = 0;
                c += put_short_tlv(crt + c, 0x80,
                                   r->controlRefTemplate.keyType.buf, 1);
                c += put_short_tlv(crt + c, 0x81,
                                   r->controlRefTemplate.keyLen.buf, 1);
                c += put_short_tlv(crt + c, 0x84,
                                   r->controlRefTemplate.hostId.buf,
                                   (size_t)r->controlRefTemplate.hostId.size);
                tbs[n++] = 0xA6;
                tbs[n++] = (uint8_t)c;
                memcpy(tbs + n, crt, c);
                n += c;
            }
            n += put_short_tlv2(tbs + n, otpk_tag, r->smdpOtpk.buf,
                                (size_t)r->smdpOtpk.size);
            n += put_short_tlv2(tbs + n, otpk_tag, euicc_otpk,
                                sizeof euicc_otpk);

            ok("smdpSign verifies against CERT.DPpb over 5.5.1's own "
               "concatenation",
               rsp_sign_verify(dppb.der, dppb.der_len, tbs, n,
                               r->smdpSign.buf) == 0);
        }
        if (r) ASN_STRUCT_FREE(asn_DEF_InitialiseSecureChannelRequest, r);
    }

    uint8_t *back = NULL; size_t back_len = 0;
    ok("the profile is recovered",
       rsp_bpp_recover(&s2, bpp, bpp_len, &back, &back_len) == 0);
    ok("the recovered profile has the original length", back_len == upp_len);
    ok("the recovered profile is identical",
       back && memcmp(upp, back, upp_len) == 0);
    free(back); back = NULL;

    /* A BPP built with different keys must not decrypt with these. This
       flips s_enc only, as the brief's own test text does -- which means
       rejection actually happens at the padding check inside
       rsp_unprotect, not the MAC: s_mac and the initial chaining value
       are untouched, so the MAC over the (wrongly-decrypted) ciphertext
       still verifies, and it is the '80'-marker search on garbage
       plaintext that fails instead. That is not the property this
       assertion's name claims. The dedicated MAC-failure assertion below,
       against the multi-segment fixture, is where a MAC mismatch is
       actually what fires -- kept here too because it is still a real
       rejection, just for a different reason than the name suggests. */
    rsp_session_t s3; session(&s3); s3.s_enc[0] ^= 0xFF;
    uint8_t *other = NULL; size_t other_len = 0;
    rsp_session_t s4; session(&s4);
    /* -1, not -2: rejected by the padding check, but the padding check
       itself is only reached because the MAC (over the wrongly-decrypted
       ciphertext, still computed with the right s_mac) verified -- a
       real answer about this segment's content, per include/rsp.h's
       failure convention, propagated through unchanged from
       rsp_unprotect's own -1 for the same case. */
    ok("a BPP under different keys is refused (rejected by padding, not"
       " the MAC -- see below) with -1",
       rsp_bpp_build(&s3, &in, &other, &other_len) == 0
       && rsp_bpp_recover(&s4, other, other_len, &back, &back_len) == -1);
    free(other); other = NULL;
    free(back); back = NULL;

    /* rsp_bpp_build itself refuses upp_len == 0 (see src/rsp_bpp.c): an
       empty UPP would otherwise still produce a BPP -- the do/while below
       always writes at least one, zero-length, segment -- but that BPP is
       byte-for-byte indistinguishable, on recovery, from one whose
       sequenceOf86 has no segments at all, which rsp_bpp_recover must
       refuse for the unrelated reason the next block tests. Refusing the
       ambiguous input at build time, rather than trying to make recovery
       disambiguate it afterwards, closes that off entirely. */
    {
        rsp_bpp_input_t empty_in = in;
        empty_in.upp = NULL;
        empty_in.upp_len = 0;
        uint8_t *e_out = NULL; size_t e_out_len = 0;
        rsp_session_t s0; session(&s0);
        ok("rsp_bpp_build refuses an empty UPP outright",
           rsp_bpp_build(&s0, &empty_in, &e_out, &e_out_len) < 0
           && e_out == NULL);
        free(e_out);
    }

    /* A BPP with an empty sequenceOf86 (no '86' elements at all) must be
       refused, not treated as having recovered an empty profile. This is
       no longer reachable through rsp_bpp_build (the check above refuses
       an empty UPP before it ever gets this far), so this is a
       hand-built input standing in for a BPP from anywhere else that
       shares this shape. Hand-built: BF36 09 { BF23 00  A0 00 A1 00
       A3 00 } -- a minimal outer SEQUENCE holding empty placeholder TLVs
       for initialiseSecureChannelRequest, firstSequenceOf87 and
       sequenceOf88, then sequenceOf86 with zero elements. Verified
       against an intentionally-reverted build that this exact input
       returns 0 with *upp == NULL if the "at least one segment" check is
       removed -- so this input is known to exercise that check, not some
       earlier, unrelated rejection. */
    {
        static const uint8_t empty_seq86[] = {
            0xBF, 0x36, 0x09,
            0xBF, 0x23, 0x00,
            0xA0, 0x00,
            0xA1, 0x00,
            0xA3, 0x00
        };
        uint8_t *e_upp = NULL; size_t e_upp_len = 0;
        rsp_session_t s5; session(&s5);
        /* -2, not -1: no segment's MAC was ever checked here -- there are
           no segments -- so this is "the question was never reached",
           per include/rsp.h's failure convention, not a real MAC "no". */
        ok("a BPP with no protected segments at all is refused, not treated"
           " as an empty recovery, with -2",
           rsp_bpp_recover(&s5, empty_seq86, sizeof empty_seq86,
                            &e_upp, &e_upp_len) == -2
           && e_upp == NULL);
        free(e_upp);
    }

    /* The multi-segment fixture: a real 2015-byte UPP split into three
       '86' segments, with an absolute pin on the resulting BPP's exact
       length and an explicit check that the chaining value moved. */
    {
        static uint8_t multi_upp[MULTI_UPP_LEN];
        memset(multi_upp, 0x5A, sizeof multi_upp);

        rsp_bpp_input_t min = {
            .upp = multi_upp, .upp_len = sizeof multi_upp, .otpk_dp = otpk,
            .iccid = iccid, .profile_name = "example",
            .service_provider_name = "euicc-tools",
            .transaction_id = transaction_id, .euicc_otpk = euicc_otpk,
            .dppb = &dppb
        };

        rsp_session_t ms1, ms2;
        session(&ms1); session(&ms2);
        uint8_t chain0[16];
        memcpy(chain0, ms1.chain, sizeof chain0);

        uint8_t *mbpp = NULL; size_t mbpp_len = 0;
        ok("the multi-segment BPP is built",
           rsp_bpp_build(&ms1, &min, &mbpp, &mbpp_len) == 0);
        /* The absolute pin: computed once from this exact input (fixed
           session keys, fixed ICCID/otpk/names/transactionId/euiccOtpk,
           2015 bytes of 0x5A) and recorded here, not derived at test
           time -- a wrong segment size, a wrong TLV order, or a
           non-minimal length encoding changes this number.

           It moved from 2223 to 2331 when the InitialiseSecureChannel
           placeholders came out, and the +108 is accounted for rather
           than accepted: smdpSign +64 (an empty OCTET STRING became a
           real 64-byte signature), transactionId +15 (one byte became
           sixteen), hostId -1 (the 10-byte ICCID became RSP_HOST_ID,
           nine), the 88 group +8 for its C-MAC, and the 87 group its
           padding to a 16-byte multiple plus its own 8-byte C-MAC. */
        ok("the multi-segment BPP has the expected length (an absolute pin, not a round trip)",
           mbpp_len == 2331);
        ok("the chaining value advanced across the multi-segment build",
           memcmp(chain0, ms1.chain, sizeof chain0) != 0);

        uint8_t *mback = NULL; size_t mback_len = 0;
        ok("the multi-segment profile is recovered",
           rsp_bpp_recover(&ms2, mbpp, mbpp_len, &mback, &mback_len) == 0);
        ok("the multi-segment recovered profile has the original length",
           mback_len == sizeof multi_upp);
        ok("the multi-segment recovered profile is identical",
           mback && memcmp(multi_upp, mback, sizeof multi_upp) == 0);
        free(mback); mback = NULL;

        /* Flipping s_mac (not s_enc) makes the MAC itself the thing that
           fails: rsp_unprotect computes and compares the MAC before it
           ever looks at padding (src/rsp_crypto.c), so a wrong s_mac
           cannot be masked by an accidental padding-block hit the way a
           wrong s_enc can. This is deterministic, not a ~1/255 chance. */
        rsp_session_t ms3; session(&ms3); ms3.s_mac[0] ^= 0xFF;
        /* -1, not -2: the question was actually asked (rsp_unprotect ran
           the comparison) and the answer is a real no, per
           include/rsp.h's failure convention -- propagated through from
           rsp_unprotect's own -1 for exactly this case. */
        ok("a BPP recovered with the wrong MAC key is refused by the MAC"
           " itself, with -1",
           rsp_bpp_recover(&ms3, mbpp, mbpp_len, &mback, &mback_len) == -1
           && mback == NULL);

        free(mbpp);
    }

    free(upp);
    free(bpp);
    return fails ? 1 : 0;
}
