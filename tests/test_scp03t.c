/* Two things at once. CMAC is pinned to a published vector, because it has
   one. The framing is proven by inversion: whatever protect() builds,
   unprotect() must give back exactly what went in. That catches padding,
   segmentation and the chaining, which is where these implementations
   actually break. */
#include <stdio.h>
#include <string.h>
#include "rsp.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if(!good) fails++;
}

/* NIST SP 800-38B, AES-128 CMAC, the empty-message case. */
static const uint8_t CMAC_KEY[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
static const uint8_t CMAC_EMPTY[16] = {
    0xbb,0x1d,0x69,0x29,0xe9,0x59,0x37,0x28,0x7f,0xa3,0x7d,0x12,0x9b,0x75,0x67,0x46
};

static void session(rsp_session_t *s) {
    memset(s, 0, sizeof *s);
    for(int i = 0; i < 16; i++) { s->s_enc[i] = i; s->s_mac[i] = 0x40 + i; }
}

int main(void) {
    uint8_t mac[16];
    ok("AES-128 CMAC matches SP 800-38B for the empty message",
       rsp_cmac(CMAC_KEY, NULL, 0, mac) == 0 && memcmp(mac, CMAC_EMPTY, 16) == 0);

    /* Inversion, over lengths that straddle the block size: an off-by-one in
       the padding hides at exactly 16 bytes and nowhere else. */
    static const size_t lens[] = { 1, 15, 16, 17, 255, 256, 1024 };
    for(size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        size_t n = lens[i];
        uint8_t plain[1024], seg[2048], back[2048];
        for(size_t k = 0; k < n; k++) plain[k] = (uint8_t)(k * 7 + 1);

        rsp_session_t s1, s2;
        session(&s1); session(&s2);

        long enc = rsp_protect(&s1, plain, n, seg, sizeof seg);
        long dec = enc > 0 ? rsp_unprotect(&s2, seg, (size_t)enc, back, sizeof back) : -1;

        char what[64];
        snprintf(what, sizeof what, "%zu bytes survive protect and unprotect", n);
        ok(what, dec == (long)n && memcmp(plain, back, n) == 0);

        snprintf(what, sizeof what, "%zu bytes: the chaining value advanced", n);
        ok(what, memcmp(s1.chain, s2.chain, 16) == 0
                 && memcmp(s1.chain, (uint8_t[16]){0}, 16) != 0);
    }

    /* A tampered segment must be refused, not silently decrypted. */
    {
        uint8_t plain[32], seg[256], back[256];
        memset(plain, 0xA5, sizeof plain);
        rsp_session_t s1, s2;
        session(&s1); session(&s2);
        long enc = rsp_protect(&s1, plain, sizeof plain, seg, sizeof seg);
        ok("a segment was produced", enc > 0);
        seg[enc / 2] ^= 0x01;
        ok("a tampered segment is refused",
           rsp_unprotect(&s2, seg, (size_t)enc, back, sizeof back) < 0);
    }
    return fails ? 1 : 0;
}
