/*
 * rsp_internal.h -- shared between this library's .c files, never installed.
 *
 * Three things used to exist twice, each edited by hand in two places that
 * had no way to notice if they drifted apart:
 *
 *   - rng_init, between src/rsp_crypto.c and src/rsp_pki.c: mbedTLS's
 *     scalar multiplication takes an RNG for blinding against timing
 *     attacks and refuses a NULL one outright, even in this project's own
 *     uses, where the scalar and point are already fixed and nothing is
 *     actually being generated.
 *   - accept_rsp_certificate_policies, between src/rsp_pki.c and
 *     src/rsp_sign.c: every certificate this project loads carries a
 *     critical certificatePolicies extension naming a GSMA RSP role
 *     policy OID that mbedTLS's built-in parser does not recognize, and
 *     this callback is the documented escape hatch for exactly that one
 *     extension.
 *   - the BER/DER minimal-length-octets rule, between
 *     scp03t_length_octets in src/rsp_crypto.c and der_len_octets in
 *     src/rsp_bpp.c. This third one is not merely cosmetic duplication:
 *     src/rsp_bpp.c's copy writes the length octets actually placed on
 *     the wire, while src/rsp_crypto.c's copy computes the length octets
 *     the SCP03t MAC covers. If the two rules ever disagreed, the MAC
 *     would authenticate a length different from the one on the segment
 *     -- a package that round-trips perfectly against this library's own
 *     rsp_unprotect while a real card, computing the length its own way,
 *     rejects it. One rule, one implementation, one test
 *     (tests/test_der_length.c), closes that off structurally rather
 *     than by convention.
 *
 * All three are small enough, and used unevenly enough across the four
 * .c files that would otherwise each carry their own copy, that a header
 * of "static inline" functions is simpler than a fifth .c file plus a
 * prototype header: no new object to add to SRCS, and a TU that does not
 * call one of these does not need to know it exists ("static inline"
 * itself, unlike plain "static", does not warn as unused under -Wall
 * when a given TU only needs some of the three).
 */
#ifndef RSP_INTERNAL_H
#define RSP_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/oid.h"
#include "mbedtls/x509_crt.h"

/* Seeds ent/drbg from platform entropy, personalized with pers (a short,
 * human-readable, caller-identifying string -- not secret, only there so
 * two callers' RNG instances are not bit-for-bit interchangeable).
 * Returns 0, or -1 if seeding failed (mbedtls_ctr_drbg_seed's own
 * convention). Every call site in this project already has an mpi/ecp
 * operation that requires a non-NULL f_rng regardless of whether it is
 * generating anything the caller considers random. */
static inline int rsp_rng_init(mbedtls_entropy_context *ent,
                                mbedtls_ctr_drbg_context *drbg,
                                const char *pers)
{
    mbedtls_entropy_init(ent);
    mbedtls_ctr_drbg_init(drbg);
    return mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, ent,
                                  (const unsigned char *)pers, strlen(pers));
}

/* mbedtls_x509_crt_parse_der_with_ext_cb's escape hatch for the one
 * critical extension every certificate in testdata/sgp26/ carries that
 * mbedTLS's parser does not otherwise recognize (id-rspRole-*, arc
 * 2.23.146.1.2.1). Accepting it here does not change what the caller's
 * own chain-of-trust or signature check verifies afterwards -- this
 * function's only job is to stop that one OID from making the parse
 * fail outright. */
static inline int rsp_accept_certificate_policies(
    void *p_ctx, mbedtls_x509_crt const *crt, mbedtls_x509_buf const *oid,
    int is_critical, const unsigned char *p, const unsigned char *end)
{
    (void)p_ctx;
    (void)crt;
    (void)p;
    (void)end;
    if (!is_critical) {
        return 0;
    }
    return MBEDTLS_OID_CMP(MBEDTLS_OID_CERTIFICATE_POLICIES, oid) == 0 ? 0 : -1;
}

/* BER/DER length octets for len, minimal encoding (no leading zero byte
 * beyond what the long form needs) -- ITU-T X.690 8.1.3. Writes at most
 * RSP_DER_LEN_OCTETS_MAX bytes to out and sets *n to how many. Handles
 * lengths up to 0xFFFFFFFF (four length bytes plus the one leading
 * "0x84" byte that says so) -- past any BoundProfilePackage or SCP03t
 * segment this project's own callers construct, but general rather than
 * narrowed to either caller's own known-smaller range, since the whole
 * point of having one implementation is that neither caller's copy gets
 * to assume a bound the other one does not also enforce. Returns 0, or
 * -1 if len does not fit even the long form. */
#define RSP_DER_LEN_OCTETS_MAX 5
static inline int rsp_der_length_octets(size_t len,
                                         uint8_t out[RSP_DER_LEN_OCTETS_MAX],
                                         size_t *n)
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
    } else if (len <= 0xFFFFFFUL) {
        out[0] = 0x83;
        out[1] = (uint8_t)(len >> 16);
        out[2] = (uint8_t)(len >> 8);
        out[3] = (uint8_t)len;
        *n = 4;
    } else if (len <= 0xFFFFFFFFUL) {
        out[0] = 0x84;
        out[1] = (uint8_t)(len >> 24);
        out[2] = (uint8_t)(len >> 16);
        out[3] = (uint8_t)(len >> 8);
        out[4] = (uint8_t)len;
        *n = 5;
    } else {
        return -1;
    }
    return 0;
}

#endif /* RSP_INTERNAL_H */
