/* The whole first half in one assertion: a real profile goes in, a BPP comes
   out, and the same session keys give the profile back byte for byte. What
   this does not prove is that a card agrees -- that is the second half, and
   the first BPP a card accepts becomes the golden vector here. */
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

int main(void) {
    size_t upp_len = 0;
    uint8_t *upp = slurp("testdata/profile.der", &upp_len);
    ok("the test profile is readable", upp && upp_len > 0);
    if(!upp) return 1;

    static const uint8_t iccid[10] = {
        0x98,0x00,0x10,0x32,0x54,0x76,0x98,0x10,0x32,0x14
    };
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

    /* A BPP built with different keys must not decrypt with these. */
    rsp_session_t s3; session(&s3); s3.s_enc[0] ^= 0xFF;
    uint8_t *other = NULL; size_t other_len = 0;
    rsp_session_t s4; session(&s4);
    ok("a BPP under different keys is refused",
       rsp_bpp_build(&s3, &in, &other, &other_len) == 0
       && rsp_bpp_recover(&s4, other, other_len, &back, &back_len) < 0);

    free(upp); free(bpp); free(other);
    return fails ? 1 : 0;
}
