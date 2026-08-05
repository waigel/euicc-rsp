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

    rsp_bpp_input_t in = {
        .upp = upp, .upp_len = upp_len, .otpk_dp = otpk, .iccid = iccid,
        .profile_name = "example", .service_provider_name = "euicc-tools"
    };

    rsp_session_t s1, s2;
    session(&s1); session(&s2);

    uint8_t *bpp = NULL; size_t bpp_len = 0;
    ok("the BPP is built", rsp_bpp_build(&s1, &in, &bpp, &bpp_len) == 0);
    ok("the BPP is larger than the profile", bpp_len > upp_len);

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
    ok("a BPP under different keys is refused (rejected by padding, not the MAC -- see below)",
       rsp_bpp_build(&s3, &in, &other, &other_len) == 0
       && rsp_bpp_recover(&s4, other, other_len, &back, &back_len) < 0);
    free(other); other = NULL;
    free(back); back = NULL;

    /* A BPP with an empty sequenceOf86 (no '86' elements at all -- not the
       same as one segment that decrypts to zero bytes, which is the
       legitimate empty-UPP case) must be refused, not treated as having
       recovered an empty profile. Hand-built: BF36 09 { BF23 00  A0 00
       A1 00  A3 00 } -- a minimal outer SEQUENCE holding empty
       placeholder TLVs for initialiseSecureChannelRequest, firstSequenceOf87
       and sequenceOf88, then sequenceOf86 with zero elements. Verified
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
        ok("a BPP with no protected segments at all is refused, not treated as an empty recovery",
           rsp_bpp_recover(&s5, empty_seq86, sizeof empty_seq86,
                            &e_upp, &e_upp_len) < 0
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
            .service_provider_name = "euicc-tools"
        };

        rsp_session_t ms1, ms2;
        session(&ms1); session(&ms2);
        uint8_t chain0[16];
        memcpy(chain0, ms1.chain, sizeof chain0);

        uint8_t *mbpp = NULL; size_t mbpp_len = 0;
        ok("the multi-segment BPP is built",
           rsp_bpp_build(&ms1, &min, &mbpp, &mbpp_len) == 0);
        /* The absolute pin: computed once from this exact input (fixed
           session keys, fixed ICCID/otpk/names, 2015 bytes of 0x5A) and
           recorded here, not derived at test time -- a wrong segment
           size, a wrong TLV order, or a non-minimal length encoding
           changes this number. */
        ok("the multi-segment BPP has the expected length (an absolute pin, not a round trip)",
           mbpp_len == 2223);
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
        ok("a BPP recovered with the wrong MAC key is refused by the MAC itself",
           rsp_bpp_recover(&ms3, mbpp, mbpp_len, &mback, &mback_len) < 0
           && mback == NULL);

        free(mbpp);
    }

    free(upp);
    free(bpp);
    return fails ? 1 : 0;
}
