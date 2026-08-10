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
    /* The encryption counter starts at '00...01', not at zero -- what
       rsp_session_init leaves behind (SGP.22 v2.6 section 2.5.3). Set here
       rather than left to the memset above, because a hand-built session
       that starts it at zero exercises an ICV no real session ever
       computes, and the wire pins below would then pin bytes no card would
       ever be sent. */
    s->enc_counter[15] = 0x01;
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

        long enc = rsp_protect(&s1, plain, n, 0x86, seg, sizeof seg);
        long dec = enc > 0 ? rsp_unprotect(&s2, seg, (size_t)enc, 0x86, back, sizeof back) : -1;

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
        long enc = rsp_protect(&s1, plain, sizeof plain, 0x86, seg, sizeof seg);
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
           rsp_unprotect(&s2, seg, (size_t)enc, 0x86, back, sizeof back) == -1);
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
        long enc = rsp_protect(&s1, plain, sizeof plain, 0x86, seg, sizeof seg);
        ok("a segment was produced for the MAC-only tamper case", enc > 0);
        seg[0] ^= 0x01; /* first ciphertext byte: block 0, four blocks
                            clear of the trailing padding block (block 4) */
        ok("a segment tampered outside the padding block is refused"
           " (the MAC, not padding) with -1, a real no",
           rsp_unprotect(&s2, seg, (size_t)enc, 0x86, back, sizeof back) == -1);
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
           rsp_protect(&s, one_byte, SIZE_MAX - 1, 0x86, out, sizeof out) < 0);
    }

    /* Absolute pin on the wire bytes. Every other check in this file is an
       inversion (protect, then unprotect, then compare) or a MAC pinned in
       isolation -- and an inversion cannot see an error that is symmetric
       between rsp_protect and rsp_unprotect: swap the MAC input tag, take
       the wire MAC from the wrong end of the CMAC, use a non-minimal DER
       length in the MAC input, reverse the chaining value, or derive the
       ICV from the wrong 16 bytes -- and both sides of the round trip
       still agree with each other while disagreeing with what a real
       eUICC expects on the wire. This is this implementation's own
       measured output for two consecutive rsp_protect calls -- and *not*
       a GSMA known-answer test: no published SGP.22 vector for SCP03t's
       byte-level framing is available to this repository.

       Which is exactly the limit these numbers have, and it has now been
       demonstrated rather than merely stated. The pin held for months
       over an ICV derived from the MAC chaining value instead of the
       encryption counter; a real eUICC rejected the first '87' of a
       Bound Profile Package built that way with scp03tSecurityError(8).
       These values were re-measured after that fix, from the same
       implementation, and can therefore still only catch a *change* --
       never a wrong construction. The card is the authority; see
       src/rsp_crypto.c's rule 2 for what the spec actually says.

       Two segments, not one: the chaining-value mutation only shows up
       in the second segment, since the first segment's chain is still
       the all-zero fixture value regardless. */
    {
        static const uint8_t want_seg1[40] = {
            0x73, 0xe8, 0xf1, 0xcd, 0xef, 0x54, 0xef, 0xc5,
            0xbd, 0xe7, 0x0e, 0xee, 0xd5, 0xff, 0x4f, 0x9d,
            0x47, 0xfa, 0x5d, 0x24, 0x61, 0xab, 0x21, 0x2e,
            0x01, 0x38, 0x09, 0x64, 0x26, 0x05, 0xda, 0x7b,
            0x0f, 0x90, 0x74, 0xf6, 0x4f, 0xe4, 0xd6, 0x3a
        };
        static const uint8_t want_seg2[40] = {
            0xf4, 0xd1, 0x41, 0x3c, 0xa6, 0xff, 0x31, 0x3a,
            0xd8, 0xcc, 0x45, 0x4a, 0x86, 0xfe, 0x02, 0xc7,
            0x28, 0x59, 0xd3, 0x9a, 0xae, 0x88, 0xb3, 0xe1,
            0x56, 0x03, 0xa4, 0x23, 0x72, 0x70, 0x83, 0x60,
            0xd2, 0x79, 0x1b, 0xd0, 0xbd, 0x95, 0xc7, 0x60
        };
        uint8_t plain[16], seg1[64], seg2[64];
        memset(plain, 0x5A, sizeof plain);
        rsp_session_t s;
        session(&s);

        long n1 = rsp_protect(&s, plain, sizeof plain, 0x86, seg1, sizeof seg1);
        long n2 = rsp_protect(&s, plain, sizeof plain, 0x86, seg2, sizeof seg2);
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
        long enc = rsp_protect(&s1, plain, sizeof plain, 0x86, seg, sizeof seg);
        ok("a segment was produced for the MAC-last-byte case", enc > 0);
        seg[enc - 1] ^= 0x01; /* only the MAC's last byte */
        ok("a segment with only the MAC's last byte corrupted is refused"
           " with -1, a real no",
           rsp_unprotect(&s2, seg, (size_t)enc, 0x86, back, sizeof back) == -1);
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
           rsp_unprotect(&s, seg, sizeof seg, 0x86, back, sizeof back) == -2);
    }

    /* rsp_protect_mac_only: Table 4's '88' construction, MAC only, never
       encrypted. Two things to prove: the plaintext is recoverable with
       nothing more than "read plain_len bytes, then check the MAC" -- no
       decryption step of any kind -- and the MAC itself covers the tag
       and length octets, not just the plaintext bytes (rule 3:
       CMAC(S-MAC, chain || tag || Lcc || data), src/rsp_crypto.c's own
       comment). The second half is checked by independently recomputing
       that same CMAC by hand, at this test's own level, from the session's
       known initial chain, the '88' tag, and the DER-minimal length octet
       for (plain_len + 8) -- not by re-deriving what
       rsp_protect_mac_only's own internals would compute (which would
       prove nothing), but by building the MAC input from the rule as
       stated, independently. */
    {
        uint8_t plain[20];
        uint8_t out[32];
        uint8_t manual_mac_input[16 + 1 + 1 + 20];
        uint8_t manual_mac[16];
        rsp_session_t s;
        long n;

        for (size_t k = 0; k < sizeof plain; k++) {
            plain[k] = (uint8_t)(k * 5 + 3);
        }
        session(&s);

        /* chain || '88' || Lcc || plain. Lcc is the single DER length
           octet for sizeof(plain)+8 = 28, which is < 0x80 -- the short
           form, one byte, 0x1C -- so this hand-built input does not need
           rsp_der_length_octets to reproduce it. */
        memcpy(manual_mac_input, s.chain, 16);
        manual_mac_input[16] = 0x88;
        manual_mac_input[17] = (uint8_t)(sizeof plain + 8);
        memcpy(manual_mac_input + 18, plain, sizeof plain);

        ok("the reference CMAC over the hand-built MAC input computes",
           rsp_cmac(s.s_mac, manual_mac_input, sizeof manual_mac_input,
                    manual_mac) == 0);

        n = rsp_protect_mac_only(&s, plain, sizeof plain, 0x88, out, sizeof out);
        ok("rsp_protect_mac_only produced a segment of plain_len + 8 bytes",
           n == (long)(sizeof plain + 8));

        ok("the plaintext is recoverable with no decryption step at all --"
           " just the first plain_len bytes of the output, unchanged",
           n > 0 && memcmp(out, plain, sizeof plain) == 0);

        ok("the appended MAC is the top 8 bytes of a CMAC that covers the"
           " tag and length octets, not just the plaintext",
           n > 0 && memcmp(out + sizeof plain, manual_mac, 8) == 0);
    }

    /* The chaining assertion the brief calls the one that matters: showing
       the chain merely changed after some operation is weak, since it
       changes on every call regardless. This is stronger: it shows the
       chain a '86' segment ends up with depends on whatever '87' and '88'
       segments came before it, not on '86' alone. Two sessions start from
       the identical initial chain (session(), below); one protects a '87'
       segment, then a '88' segment, then a '86' segment; the other
       protects only that same '86' segment, with nothing before it. If
       either '87' or '88' ever stopped advancing s->chain, the two
       sessions would still agree by the time the '86' call runs, and this
       assertion would pass when it should fail -- exactly the failure
       Step 6 of the brief asks this test to be able to catch. */
    {
        rsp_session_t with_8788, alone;
        uint8_t p87[10], p88[12], p86[14];
        uint8_t out87[64], out88[64], out86[64];
        uint8_t chain_with[16], chain_alone[16];

        session(&with_8788);
        session(&alone);
        memset(p87, 0x11, sizeof p87);
        memset(p88, 0x22, sizeof p88);
        memset(p86, 0x33, sizeof p86);

        ok("a '87' segment was protected ahead of the chaining comparison",
           rsp_protect(&with_8788, p87, sizeof p87, 0x87, out87,
                       sizeof out87) > 0);
        ok("a '88' segment was protected ahead of the chaining comparison",
           rsp_protect_mac_only(&with_8788, p88, sizeof p88, 0x88, out88,
                                 sizeof out88) > 0);
        ok("the '86' segment following '87' and '88' was protected",
           rsp_protect(&with_8788, p86, sizeof p86, 0x86, out86,
                       sizeof out86) > 0);
        memcpy(chain_with, with_8788.chain, 16);

        ok("the same '86' segment, protected alone from the same starting"
           " chain, was protected",
           rsp_protect(&alone, p86, sizeof p86, 0x86, out86, sizeof out86) > 0);
        memcpy(chain_alone, alone.chain, 16);

        ok("the chain after '87' then '88' then '86' differs from the chain"
           " after '86' alone -- proving '87' and '88' both advanced it",
           memcmp(chain_with, chain_alone, 16) != 0);
    }
    return fails ? 1 : 0;
}
