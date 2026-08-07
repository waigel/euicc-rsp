/* Both sides of the handshake, played locally. A signature that verifies
   against the wrong key, or a tampered message that still verifies, is the
   failure that matters -- and neither shows up if the test only signs and
   checks the happy path.

   The dispatch for this task quotes rsp_pki_mint("test DPauth", 0, &dp) as
   how to get two distinct stand-in credentials. That function does not
   exist: Task 3's own dispatch withdrew it before Task 3 was built --
   SGP.26 publishes complete DPauth/DPpb certificates and secret keys, not
   a CI private key to mint under, so there is nothing to mint, and
   rsp_pki_dp(role, ...) loads the published material instead (see
   task-3-report.md, "Scope change from the brief", and rsp.h's actual
   declarations). Two calls to rsp_pki_dp with different roles give the
   same thing this test actually needs -- two credentials with two
   different, real key pairs -- through the interface that exists. */
#include <stdio.h>
#include <string.h>
#include "rsp.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if(!good) fails++;
}

/* ---- OpenSSL cross-check vectors (fix round 1) ----
 *
 * Everything above this comment is rsp_sign checked against rsp_sign_verify --
 * self-consistency, not correctness. A build that swapped r and s (or any
 * other internally-consistent convention bug, in both functions at once)
 * would pass every one of those assertions while every real eUICC and
 * every real SM-DP+ rejected the result, because both sides of this
 * project would agree with each other on the wrong thing. These two
 * (message, DER signature) pairs cross that boundary: the signature came
 * from an ECDSA implementation this project did not write, checked
 * against the real published SGP.26 DPauth key rsp_pki_dp(0, ...) loads.
 *
 * They are OpenSSL's output, not a GSMA-published known-answer test.
 * Produced once, offline, with OpenSSL 3.5.4, on 2026-08-05, by:
 *
 *     printf '%s' "OpenSSL cross-check vector one -- not produced by this library" \
 *         > vecA_msg.bin
 *     printf '%s' "OpenSSL cross-check vector two -- also not produced by this library" \
 *         > vecB_msg.bin
 *     openssl dgst -sha256 -sign testdata/sgp26/dpauth-key.pem \
 *         -out vecA_sig.der vecA_msg.bin
 *     openssl dgst -sha256 -sign testdata/sgp26/dpauth-key.pem \
 *         -out vecB_sig.der vecB_msg.bin
 *     od -An -tx1 vecA_sig.der    # (and vecB_sig.der) to get the bytes below
 *
 * VEC_A_SIG_DER's r happens to need a leading 0x00 pad byte in OpenSSL's
 * DER (its top bit is set) -- exactly the r||s edge case the review round
 * checked empirically across 5000 signatures. unwrap_der_sig below turns
 * OpenSSL's DER SEQUENCE { INTEGER r, INTEGER s } into the plain 64-byte
 * r||s pair rsp_sign_verify expects (SGP.22 v2.6 section 2.6.7.2 / GlobalPlatform
 * Amendment E section 3.1.3): it handles short-form lengths only, because
 * both committed DER blobs are under 128 bytes -- a fixed unwrapper for
 * these two vectors, not a general ASN.1 parser, and no OpenSSL, no
 * interpreter and no network are needed to run it.
 */
static const uint8_t VEC_A_MSG[] =
    "OpenSSL cross-check vector one -- not produced by this library";
static const uint8_t VEC_A_SIG_DER[] = {
    0x30, 0x45, 0x02, 0x21, 0x00, 0xc1, 0x6d, 0xec, 0x28, 0x5c, 0xf0, 0xf8,
    0x19, 0x1a, 0x3e, 0xb8, 0x40, 0xc2, 0x43, 0x04, 0xd2, 0x59, 0x4e, 0x78,
    0x1c, 0x17, 0x27, 0xe1, 0x45, 0xcd, 0x67, 0xd1, 0x61, 0x0b, 0x32, 0xce,
    0x35, 0x02, 0x20, 0x59, 0x62, 0xb8, 0x56, 0x59, 0x30, 0x67, 0x98, 0xc4,
    0x05, 0x99, 0x3f, 0x9f, 0x54, 0xac, 0x89, 0xa5, 0x97, 0xdf, 0x0f, 0xb5,
    0x51, 0xe2, 0x33, 0x06, 0x9d, 0x5f, 0x7a, 0x84, 0x86, 0x0a, 0x6a
};

static const uint8_t VEC_B_MSG[] =
    "OpenSSL cross-check vector two -- also not produced by this library";
static const uint8_t VEC_B_SIG_DER[] = {
    0x30, 0x44, 0x02, 0x20, 0x65, 0x50, 0xff, 0xaf, 0x0b, 0x32, 0x0a, 0x7b,
    0x6a, 0x44, 0xfd, 0x74, 0xb4, 0x81, 0xc7, 0x1f, 0x9a, 0x10, 0x32, 0x58,
    0x64, 0xc9, 0x95, 0x7e, 0x60, 0xd9, 0x96, 0xd5, 0x28, 0x17, 0xed, 0xb2,
    0x02, 0x20, 0x3c, 0x20, 0x7b, 0xa4, 0xc7, 0x12, 0x0f, 0x34, 0xfa, 0xd0,
    0x5c, 0xf5, 0x28, 0xd3, 0x61, 0x97, 0x59, 0x3c, 0x4f, 0xcf, 0x1f, 0x7b,
    0x2e, 0x56, 0x07, 0x8d, 0x61, 0xcb, 0x17, 0xbc, 0xee, 0xdd
};

/* Unwrap a DER SEQUENCE { INTEGER r, INTEGER s } with short-form lengths
 * (both blobs above are under 128 bytes, so the length octet is never
 * 0x80 or above) into a plain 64-byte r||s pair, dropping the DER pad
 * byte if present and left-padding to exactly 32 bytes per integer.
 * Returns 0, or -1 for anything this narrow unwrapper does not expect. */
static int unwrap_der_sig(const uint8_t *der, size_t der_n, uint8_t sig[64]) {
    size_t p;
    int part;

    if (der_n < 8 || der[0] != 0x30 || (der[1] & 0x80)) {
        return -1;
    }
    if ((size_t)der[1] + 2 != der_n) {
        return -1;
    }
    p = 2;
    for (part = 0; part < 2; part++) {
        const uint8_t *v;
        size_t ilen;

        if (p >= der_n || der[p] != 0x02) {
            return -1;
        }
        p++;
        if (p >= der_n || (der[p] & 0x80)) {
            return -1;
        }
        ilen = der[p++];
        if (p + ilen > der_n) {
            return -1;
        }
        v = der + p;
        p += ilen;
        while (ilen > 0 && v[0] == 0) {
            v++;
            ilen--;
        }
        if (ilen > 32) {
            return -1;
        }
        memset(sig + (size_t)part * 32, 0, 32);
        memcpy(sig + (size_t)part * 32 + (32 - ilen), v, ilen);
    }
    return (p == der_n) ? 0 : -1;
}

int main(void) {
    rsp_credential_t dp, card;
    memset(&dp, 0, sizeof dp);
    memset(&card, 0, sizeof card);
    ok("a DPauth credential loads, standing in for the signing side",
       rsp_pki_dp(0, &dp) == 0);
    ok("a DPpb credential loads, standing in for the eUICC's certificate",
       rsp_pki_dp(1, &card) == 0);

    static const uint8_t msg[] = "serverSigned1 stands in for the real one";
    uint8_t sig[64];

    ok("signing succeeds", rsp_sign(&dp, msg, sizeof msg - 1, sig) == 0);
    ok("the signature verifies with the matching certificate",
       rsp_sign_verify(dp.der, dp.der_len, msg, sizeof msg - 1, sig) == 0);
    /* -1, not just nonzero: card.der parses fine (it is DPpb's real,
       well-formed certificate) and the only reason this fails is that
       mbedtls_ecdsa_verify actually rejects the signature -- the
       "question was asked, answer is no" case include/rsp.h's failure
       convention calls -1, distinct from -2's "never got to ask". */
    ok("it does not verify with another certificate (a real no, not a"
       " parse failure -- see include/rsp.h's failure convention)",
       rsp_sign_verify(card.der, card.der_len, msg, sizeof msg - 1, sig) == -1);
    ok("an unparseable certificate answers -2, not -1: the question of"
       " whether the signature verifies was never actually reached",
       rsp_sign_verify(NULL, 0, msg, sizeof msg - 1, sig) == -2);

    uint8_t bad[sizeof msg - 1];
    memcpy(bad, msg, sizeof bad);
    bad[0] ^= 0x01;
    ok("a tampered message does not verify (-1: a real no)",
       rsp_sign_verify(dp.der, dp.der_len, bad, sizeof bad, sig) == -1);

    sig[0] ^= 0x01;
    ok("a tampered signature does not verify (-1: a real no)",
       rsp_sign_verify(dp.der, dp.der_len, msg, sizeof msg - 1, sig) == -1);

    /* ECDSA is randomised: two signatures over the same message differ, and
       both must verify. An implementation that returns a constant passes
       every check above. */
    uint8_t sig2[64], sig3[64];
    rsp_sign(&dp, msg, sizeof msg - 1, sig2);
    rsp_sign(&dp, msg, sizeof msg - 1, sig3);
    ok("two signatures over the same message differ",
       memcmp(sig2, sig3, 64) != 0);
    ok("both of them verify",
       rsp_sign_verify(dp.der, dp.der_len, msg, sizeof msg - 1, sig2) == 0
       && rsp_sign_verify(dp.der, dp.der_len, msg, sizeof msg - 1, sig3) == 0);

    {
        uint8_t plain_a[64], plain_b[64];

        ok("vector A's OpenSSL DER signature unwraps",
           unwrap_der_sig(VEC_A_SIG_DER, sizeof VEC_A_SIG_DER, plain_a) == 0);
        ok("vector B's OpenSSL DER signature unwraps",
           unwrap_der_sig(VEC_B_SIG_DER, sizeof VEC_B_SIG_DER, plain_b) == 0);
        ok("an OpenSSL-produced signature over vector A's message verifies",
           rsp_sign_verify(dp.der, dp.der_len, VEC_A_MSG, sizeof VEC_A_MSG - 1,
                      plain_a) == 0);
        ok("an OpenSSL-produced signature over vector B's message verifies",
           rsp_sign_verify(dp.der, dp.der_len, VEC_B_MSG, sizeof VEC_B_MSG - 1,
                      plain_b) == 0);
        ok("vector A's signature does not verify against vector B's message",
           rsp_sign_verify(dp.der, dp.der_len, VEC_B_MSG, sizeof VEC_B_MSG - 1,
                      plain_a) != 0);
    }

    rsp_credential_free(&dp);
    rsp_credential_free(&card);
    return fails ? 1 : 0;
}
