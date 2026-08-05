/* Three checks on rsp_ecdh_p256 / rsp_kdf_x963 / rsp_session_init, at three
   different levels of confidence -- each stated plainly rather than
   implied, because a green suite says nothing on its own about which of
   these actually holds:

   - ECDH is pinned to a published vector (RFC 5903 section 8.1; see
     testdata/nist/README.md), and separately to the property that both
     parties independently reach the same shared secret. The symmetry
     property needs no published vector, and it fails for a whole class
     of point-handling mistakes a vector pinned to one fixed direction
     would never exercise.
   - rsp_kdf_x963 is pinned directly to a value computed outside this
     repository with two independent tools (see the comment at that
     assertion for the exact inputs and commands), so the counter's
     width, start value and position in the hash input are anchored by
     an external authority, not by this codebase's own prior output.
   - rsp_session_init carries an absolute pin too, further down: this
     implementation's own measured output for the RFC 5903 vector,
     combined with the split order SGP.22 Annex G, Table 65 states
     (chain, then S-ENC, then S-MAC). That is *not* a GSMA known-answer
     test -- no such published vector with real one-time keys is
     available to this repository -- and the comment there says so.
     The card settles that in the second half of the project.
   - The remaining checks (repeatability, the three keys differing,
     sharedInfo sensitivity) are relative properties with no external
     anchor. They catch a different class of mistake (a derivation that
     is deterministic but structurally wrong in some other way) than
     the pins above, and exist alongside them, not instead of them: a
     mutation that swaps S-ENC and S-MAC's byte ranges, starts the KDF
     counter at 0, or reorders Z/counter/info in the hash input stays
     deterministic and produces three distinct, sharedInfo-sensitive
     keys -- every relative check here still passes. Only the absolute
     pins below catch those. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsp.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if(!good) fails++;
}

/* One hex line from the vector file into bytes. Returns the byte count. */
static size_t hexline(FILE *f, uint8_t *out, size_t cap) {
    char line[300];
    if(!fgets(line, sizeof line, f)) return 0;
    size_t n = strspn(line, "0123456789abcdefABCDEF") / 2;
    if(n > cap) return 0;
    for(size_t i = 0; i < n; i++) {
        unsigned v;
        if(sscanf(line + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return n;
}

/* A fresh one-time P-256 key pair for the ECDH symmetry check below.
   Nothing here is a secret this test needs to protect -- it exists only
   to prove rsp_ecdh_p256 gives the same answer computed from both
   sides, and both key pairs are discarded when main returns. */
static int gen_keypair(uint8_t sk[32], uint8_t pk[65]) {
    static const unsigned char pers[] = "euicc-rsp/test_kdf";
    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi d;
    size_t olen = 0;
    int ret = -1;

    mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&d);

    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent,
                               pers, sizeof(pers) - 1) == 0 &&
        mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_ecp_gen_keypair(&grp, &d, &q,
                                 mbedtls_ctr_drbg_random, &drbg) == 0 &&
        mbedtls_mpi_write_binary(&d, sk, 32) == 0 &&
        mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &olen, pk, 65) == 0 &&
        olen == 65) {
        ret = 0;
    }

    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);
    return ret;
}

int main(void) {
    uint8_t sk[32], pk[65], want[32], z[32];
    FILE *f = fopen("testdata/nist/ecdh-p256.txt", "r");
    ok("the vector file is readable", f != NULL);
    if(!f) return 1;
    ok("the vector holds three values of the right length",
       hexline(f, sk, sizeof sk) == 32
       && hexline(f, pk, sizeof pk) == 65
       && hexline(f, want, sizeof want) == 32);
    fclose(f);

    ok("ECDH P-256 matches the published vector",
       rsp_ecdh_p256(sk, pk, z) == 0 && memcmp(z, want, 32) == 0);

    /* Symmetry: two independently generated key pairs must agree on the
       shared secret computed from either side. This needs no vector at
       all, and it fails for point-handling mistakes a single fixed
       direction would never exercise. */
    {
        uint8_t sk_a[32], pk_a[65], sk_b[32], pk_b[65], z_ab[32], z_ba[32];
        ok("generating two fresh P-256 key pairs for the symmetry check succeeds",
           gen_keypair(sk_a, pk_a) == 0 && gen_keypair(sk_b, pk_b) == 0);
        ok("ECDH agrees from both sides of a fresh key pair",
           rsp_ecdh_p256(sk_a, pk_b, z_ab) == 0 &&
           rsp_ecdh_p256(sk_b, pk_a, z_ba) == 0 &&
           memcmp(z_ab, z_ba, sizeof z_ab) == 0);
    }

    /* rsp_kdf_x963 pinned directly against a value computed outside this
       repository, independent of both the RFC 5903 vector above and of
       rsp_session_init's own pin further down. Z and info here are
       arbitrary fixed test values, not derived from anything else in
       this file; the expected output was computed with two independent
       tools before being written here, and either reproduces it:

           Z="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
           INFO="deadbeef"
           printf '%s' "${Z}00000001${INFO}" | xxd -r -p | openssl dgst -sha256
           printf '%s' "${Z}00000002${INFO}" | xxd -r -p | openssl dgst -sha256
           # cross-checked with `shasum -a 256` in place of `openssl dgst -sha256`;
           # both tools agree.

       This pins the counter's width (4 bytes), its start value (1, not
       0) and its position in the hash input (between Z and info, not
       after info) against that external computation -- a mutation that
       starts the counter at 0, widens or narrows it, or reorders
       Z/counter/info changes this output, and every check above it in
       this file would still pass. */
    {
        static const uint8_t kat_z[32] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
        };
        static const uint8_t kat_info[4] = { 0xde, 0xad, 0xbe, 0xef };
        /* SHA256(Z||00000001||info), then the first 8 bytes of
           SHA256(Z||00000002||info) -- i.e. KeyData[0:40] for this
           Z/info pair. */
        static const uint8_t kat_want[40] = {
            0xca, 0x1c, 0xd0, 0x18, 0xe3, 0x06, 0x04, 0x90,
            0x39, 0xf5, 0x57, 0x8c, 0xb1, 0x3d, 0xd0, 0x1d,
            0xd0, 0x3f, 0xa4, 0x89, 0x25, 0x15, 0xf7, 0xfd,
            0x4e, 0x05, 0x07, 0x71, 0x88, 0xe2, 0xaa, 0xfe,
            0x2a, 0xc9, 0xd7, 0xf9, 0x2a, 0x3a, 0x12, 0x46
        };
        uint8_t kdf_out[40];
        ok("rsp_kdf_x963 matches an external SHA-256 computation for a fixed Z/info pair",
           rsp_kdf_x963(kat_z, sizeof kat_z, kat_info, sizeof kat_info,
                         kdf_out, sizeof kdf_out) == 0 &&
           memcmp(kdf_out, kat_want, sizeof kat_want) == 0);
    }

    /* The derivation is deterministic: the same inputs always give the same
       keys, whatever the right answer turns out to be. */
    static const uint8_t info[]  = { 0x00, 0x00, 0x00, 0x01 };
    static const uint8_t info2[] = { 0x00, 0x00, 0x00, 0x02 };
    rsp_session_t a, b, c;
    ok("session derivation succeeds",
       rsp_session_init(sk, pk, info, sizeof info, &a) == 0);
    ok("session derivation repeats",
       rsp_session_init(sk, pk, info, sizeof info, &b) == 0);
    ok("the two derivations agree", memcmp(&a, &b, sizeof a) == 0);

    /* The three keys must differ. A derivation that returns the same block
       three times passes every other check in this file. */
    ok("S-ENC and S-MAC differ", memcmp(a.s_enc, a.s_mac, 16) != 0);
    ok("S-MAC and the chaining value differ", memcmp(a.s_mac, a.chain, 16) != 0);

    ok("a different sharedInfo gives different keys",
       rsp_session_init(sk, pk, info2, sizeof info2, &c) == 0
       && memcmp(&a, &c, sizeof a) != 0);

    /* Absolute pin: this implementation's own output for
       rsp_session_init(sk, pk, info, sizeof info, &a) above, on the
       RFC 5903 vector, combined with the split order SGP.22 Annex G,
       Table 65 states (KeyData 1..L = initial MAC chaining value,
       L+1..2L = S-ENC, 2L+1..3L = S-MAC, L=16). This is this code's own
       measured output -- reproduced independently before being written
       here, not copied from anywhere -- and *not* a GSMA known-answer
       test: no published SGP.22 vector with real one-time keys is
       available to this repository. It still catches what the relative
       checks above cannot: swapping which 16-byte range is S-ENC versus
       S-MAC versus the chaining value, since a swap keeps all three
       distinct and sharedInfo-sensitive without matching this pin. */
    {
        static const uint8_t want_chain[16] = {
            0x29, 0x0b, 0xac, 0xb7, 0xaf, 0xe4, 0xac, 0x1f,
            0x3f, 0xcc, 0xd2, 0x20, 0x1b, 0xe0, 0xbf, 0x95
        };
        static const uint8_t want_s_enc[16] = {
            0x18, 0x10, 0xa3, 0x04, 0x28, 0xce, 0xdb, 0xd2,
            0xd3, 0x3f, 0xfc, 0xa5, 0xe6, 0x26, 0xb4, 0xda
        };
        static const uint8_t want_s_mac[16] = {
            0x7d, 0x28, 0x42, 0xca, 0x54, 0x39, 0x07, 0x9a,
            0x77, 0x77, 0x47, 0xe6, 0x28, 0x47, 0x3f, 0x54
        };
        ok("rsp_session_init matches its own measured output for the RFC 5903 vector",
           memcmp(a.chain, want_chain, 16) == 0 &&
           memcmp(a.s_enc, want_s_enc, 16) == 0 &&
           memcmp(a.s_mac, want_s_mac, 16) == 0);
    }

    /* Every session above is discarded once this function returns; wipe
       them rather than let their key material sit in stack memory that
       outlives this test (see tests/test_zeroize.c, which checks that
       the wipe actually survives compilation). */
    rsp_session_wipe(&a);
    rsp_session_wipe(&b);
    rsp_session_wipe(&c);
    {
        rsp_session_t zero;
        memset(&zero, 0, sizeof zero);
        ok("rsp_session_wipe zeroes a discarded session",
           memcmp(&a, &zero, sizeof zero) == 0 &&
           memcmp(&b, &zero, sizeof zero) == 0 &&
           memcmp(&c, &zero, sizeof zero) == 0);
    }
    return fails ? 1 : 0;
}
