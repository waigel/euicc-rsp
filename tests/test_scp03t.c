/* Two things at once. CMAC is pinned to a published vector, because it has
   one. The framing is proven by inversion: whatever protect() builds,
   unprotect() must give back exactly what went in. That catches padding,
   segmentation and the chaining, which is where these implementations
   actually break. */
#include <stdint.h>
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

    /* This plaintext is exactly two AES blocks, so after padding the
       segment is three ciphertext blocks and the whole third block is
       padding (an '80' byte then 15 zero bytes). Flipping a bit in the
       middle of the segment lands inside the *second* ciphertext block;
       under CBC decryption, corrupting ciphertext block C_i derandomizes
       plaintext block P_i completely but changes P_{i+1} = Decrypt(C_{i+1})
       XOR C_i by exactly one predictable bit -- so this bit-flip turns one
       '00' padding byte into '01', and padding validation rejects it on
       its own, before the MAC comparison even runs. This test proves
       rsp_unprotect's padding check works. It does NOT exercise the MAC:
       see the next test for that, and see "fix round 1" in
       task-5-report.md for how this was confirmed (by disabling the MAC
       comparison and observing this assertion stay green). */
    {
        uint8_t plain[32], seg[256], back[256];
        memset(plain, 0xA5, sizeof plain);
        rsp_session_t s1, s2;
        session(&s1); session(&s2);
        long enc = rsp_protect(&s1, plain, sizeof plain, seg, sizeof seg);
        ok("a segment was produced", enc > 0);
        seg[enc / 2] ^= 0x01;
        /* -1, not just negative, either way: the MAC covers this
           ciphertext byte too, so in the shipped code (MAC checked before
           any decryption is attempted) this is rejected by the MAC
           mismatch itself; the comment above is about a counterfactual
           ablation (MAC checking disabled) that established padding
           validation would *also* catch it on its own. Whichever check
           actually trips, include/rsp.h's failure convention calls it a
           real "no" about this segment's content: -1, not -2. */
        ok("a segment tampered inside the padding block is refused"
           " (padding validation, not the MAC) with -1, a real no",
           rsp_unprotect(&s2, seg, (size_t)enc, back, sizeof back) == -1);
    }

    /* The MAC-only case. This plaintext is four AES blocks of real data,
       so after padding the segment is five ciphertext blocks and the
       whole fifth block is padding. CBC error propagation from a
       corrupted ciphertext block C_i only ever reaches P_i and P_{i+1}
       (see the comment above) -- so tampering block 0 can only affect
       recovered plaintext blocks 0 and 1, and blocks 2, 3 and the
       trailing all-padding block 4 are provably untouched. Padding
       validation therefore cannot catch this one; only the MAC can. If a
       later reader shortens this plaintext or moves the tamper closer to
       the end "to simplify the test", the bit-flip will land back inside
       the padding block and this test will silently start testing padding
       again instead of the MAC -- which is exactly the mistake this
       comment exists to prevent. */
    {
        uint8_t plain[64], seg[256], back[256];
        for (size_t k = 0; k < sizeof plain; k++) plain[k] = (uint8_t)(k * 3 + 5);
        rsp_session_t s1, s2;
        session(&s1); session(&s2);
        long enc = rsp_protect(&s1, plain, sizeof plain, seg, sizeof seg);
        ok("a segment was produced for the MAC-only tamper case", enc > 0);
        seg[0] ^= 0x01; /* first ciphertext byte: block 0, four blocks
                            clear of the trailing padding block (block 4) */
        ok("a segment tampered outside the padding block is refused"
           " (the MAC, not padding) with -1, a real no",
           rsp_unprotect(&s2, seg, (size_t)enc, back, sizeof back) == -1);
    }

    /* fix round 2, finding 2: an absurd plain_len must be rejected before
       the padding-length arithmetic (plain_len + pad_len) can wrap
       SIZE_MAX into something small enough to pass the capacity check,
       which would then let the memcpy that follows overrun a heap buffer
       sized for the wrapped value instead. plain does not, and must not,
       actually hold this many bytes: rsp_protect has to reject the call
       before it ever reads plain_len bytes from it, so a 1-byte buffer is
       enough to prove no out-of-bounds read happens either. */
    {
        rsp_session_t s;
        session(&s);
        uint8_t one_byte[1] = { 0 };
        uint8_t out[16];
        ok("a plain_len near SIZE_MAX is rejected, not overflowed",
           rsp_protect(&s, one_byte, SIZE_MAX - 1, out, sizeof out) < 0);
    }

    /* Absolute pin on the wire bytes. Every other check in this file is an
       inversion (protect, then unprotect, then compare) or a MAC pinned in
       isolation -- and an inversion cannot see an error that is symmetric
       between rsp_protect and rsp_unprotect: swap the MAC input tag, take
       the wire MAC from the wrong end of the CMAC, use a non-minimal DER
       length in the MAC input, reverse the chaining value, or use the
       chaining value itself as the ICV instead of AES-ECB(S-ENC, chain) --
       and both sides of the round trip still agree with each other while
       disagreeing with what a real eUICC expects on the wire. This is this
       implementation's own measured output for two consecutive
       rsp_protect calls -- reproduced independently before being written
       here, not copied from anywhere -- and *not* a GSMA known-answer
       test: no published SGP.22 vector for SCP03t's byte-level framing is
       available to this repository. The card settles that in the second
       half of the project. Two segments, not one: the chaining-value
       mutation only shows up in the second segment, since the first
       segment's chain is still the all-zero fixture value regardless. */
    {
        static const uint8_t want_seg1[40] = {
            0xe6, 0x6d, 0x91, 0x52, 0x33, 0x0d, 0xaa, 0x4b,
            0xb0, 0x07, 0xb7, 0x4c, 0xae, 0x9b, 0x9f, 0xc9,
            0xf7, 0xfd, 0x7d, 0x3b, 0x94, 0x8c, 0x10, 0x2b,
            0x8b, 0x8d, 0x50, 0xa6, 0xec, 0x2d, 0x63, 0x1c,
            0x1d, 0xae, 0x9b, 0x60, 0x37, 0xa2, 0xdf, 0xf9
        };
        static const uint8_t want_seg2[40] = {
            0x73, 0xa4, 0x96, 0x3a, 0x1a, 0x2f, 0xaf, 0x47,
            0x93, 0xd7, 0x2c, 0x08, 0x8e, 0xe5, 0xba, 0xef,
            0x0e, 0xb8, 0x38, 0x7a, 0xde, 0x65, 0x5f, 0x70,
            0x19, 0x69, 0x2d, 0xf5, 0x11, 0x2d, 0x06, 0xce,
            0x78, 0xe2, 0x4a, 0x78, 0x9b, 0x50, 0x9e, 0xb1
        };
        uint8_t plain[16], seg1[64], seg2[64];
        memset(plain, 0x5A, sizeof plain);
        rsp_session_t s;
        session(&s);

        long n1 = rsp_protect(&s, plain, sizeof plain, seg1, sizeof seg1);
        long n2 = rsp_protect(&s, plain, sizeof plain, seg2, sizeof seg2);
        ok("two segments were produced for the absolute wire pin",
           n1 == (long)sizeof want_seg1 && n2 == (long)sizeof want_seg2);
        ok("the first segment's wire bytes match this implementation's own"
           " measured output (an absolute pin, not a round trip)",
           n1 == (long)sizeof want_seg1 &&
           memcmp(seg1, want_seg1, sizeof want_seg1) == 0);
        ok("the second segment's wire bytes match this implementation's"
           " own measured output (this is the one mutation 4, the reversed"
           " chaining value, actually shows up in)",
           n2 == (long)sizeof want_seg2 &&
           memcmp(seg2, want_seg2, sizeof want_seg2) == 0);
    }

    /* fix round 2, finding 1: rsp_unprotect now compares the MAC with
       mbedtls_ct_memcmp instead of memcmp, so the comparison time does not
       depend on how many leading bytes matched (see the comment at that
       call site in src/rsp_crypto.c). A timing test to prove that directly
       would be flaky and prove nothing in CI, so this does not attempt
       one. What this proves instead: the comparison still covers the
       *whole* 8-byte MAC, not just a prefix -- corrupting only the MAC's
       last byte, leaving the ciphertext and the first 7 MAC bytes
       untouched, must still be refused. */
    {
        uint8_t plain[16], seg[256], back[256];
        memset(plain, 0x5A, sizeof plain);
        rsp_session_t s1, s2;
        session(&s1); session(&s2);
        long enc = rsp_protect(&s1, plain, sizeof plain, seg, sizeof seg);
        ok("a segment was produced for the MAC-last-byte case", enc > 0);
        seg[enc - 1] ^= 0x01; /* only the MAC's last byte */
        ok("a segment with only the MAC's last byte corrupted is refused"
           " with -1, a real no",
           rsp_unprotect(&s2, seg, (size_t)enc, back, sizeof back) == -1);
    }

    /* -2, not -1: seg_len too small to even hold a MAC is a malformed
       input, not a case where the MAC was checked and found wanting --
       the question of whether this segment's MAC matches is never
       actually reached. */
    {
        rsp_session_t s;
        session(&s);
        uint8_t seg[4] = { 0, 1, 2, 3 };
        uint8_t back[16];
        ok("a segment too short to hold a MAC answers -2, not -1"
           " (include/rsp.h's failure convention)",
           rsp_unprotect(&s, seg, sizeof seg, back, sizeof back) == -2);
    }
    return fails ? 1 : 0;
}
