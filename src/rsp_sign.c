/*
 * rsp_sign.c -- the ECDSA signatures that carry the handshake.
 *
 * SGP.22 v2.2 section 2.6.7.2 "ECDSA" states: "A signature based on ECDSA
 * SHALL be computed as defined in GlobalPlatform Card Specification
 * Amendment E [12] ... with ... key length and HASH function recommended
 * above in section 2.6.5", and every SM-DP+/eUICC signature field in the
 * module (serverSignature1, smdpSignature2, euiccSignature1/2, smdpSign,
 * ...) is defined by cross-reference to that clause. GlobalPlatform Card
 * Specification v2.2 Amendment E ("Security Upgrade for Card Content
 * Management", v1.0.1, July 2014, GPC_SPE_042) section 3.1.3 "ECDSA" then
 * gives the exact encoding: "The signature shall be coded in plain format
 * as specified in [TR 03111], i.e. it is the concatenation of the byte
 * string representation of r and s. Thus the signature will have a fixed
 * length of twice the order length" -- 64 bytes for P-256's 32-byte order,
 * not a DER SEQUENCE of two INTEGERs. The same clause's Table 3-3 pins
 * SHA-256 as the hash for a 256-bit key. Both are read directly from
 * Amendment E's own text, not inferred from this project's prior use of
 * SHA-256 elsewhere.
 *
 * rsp_verify fails closed: every error path -- a certificate that will
 * not parse, a key that is not an EC key, a signature that mbedTLS
 * rejects -- falls through to the same "ret = -1" set before any of it
 * ran. There is exactly one place ret becomes 0.
 */
#include "rsp.h"

#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"

/* mbedtls_ecdsa_sign needs an RNG for the per-signature nonce k (mbedTLS's
 * plain, non-deterministic ECDSA -- the brief calls for mbedtls_ecdsa_sign,
 * not the RFC 6979 deterministic variant, and the test below relies on two
 * signatures over the same message differing). Seeded once and kept for
 * the life of the process: reseeding an entropy-backed DRBG on every call
 * buys nothing and this library is not multi-threaded anywhere else
 * either. mbedtls_ecdsa_verify takes no RNG parameter at all -- verifying
 * an ECDSA signature is pure arithmetic on public values, nothing here is
 * blinded -- so only rsp_sign uses this. */
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static int g_rng_ready;

static int ensure_rng(void)
{
    static const unsigned char pers[] = "euicc-rsp/rsp_sign";

    if (g_rng_ready) {
        return 0;
    }
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);
    if (mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                               pers, sizeof pers - 1) != 0) {
        mbedtls_ctr_drbg_free(&g_drbg);
        mbedtls_entropy_free(&g_entropy);
        return -1;
    }
    g_rng_ready = 1;
    return 0;
}

int rsp_sign(const rsp_credential_t *c, const uint8_t *tbs, size_t tbs_len,
             uint8_t sig[64])
{
    unsigned char hash[32];
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    int ret = -1;

    if (!c || !sig || (!tbs && tbs_len != 0)) {
        return -1;
    }
    if (ensure_rng() != 0) {
        return -1;
    }
    if (mbedtls_sha256(tbs, tbs_len, hash, 0) != 0) {
        return -1;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_mpi_read_binary(&d, c->sk, sizeof c->sk) == 0 &&
        mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, sizeof hash,
                            mbedtls_ctr_drbg_random, &g_drbg) == 0 &&
        mbedtls_mpi_write_binary(&r, sig, 32) == 0 &&
        mbedtls_mpi_write_binary(&s, sig + 32, 32) == 0) {
        ret = 0;
    }

    /* d is a copy of the secret scalar c->sk; mbedtls_mpi_free zeroizes an
     * mpi's limb buffer before releasing it (bignum.c,
     * mbedtls_mpi_zeroize_and_free), which is what covers this copy --
     * not a memset a compiler could prove unobserved and drop. r and s are
     * the signature, not secret, but are freed the same way regardless. */
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    mbedtls_platform_zeroize(hash, sizeof hash);
    return ret;
}

/* Every certificate this project loads (see src/rsp_pki.c) carries a
 * critical certificatePolicies extension naming a GSMA RSP role policy
 * OID that mbedTLS's built-in parser does not recognize; a plain
 * mbedtls_x509_crt_parse_der refuses to look at the certificate at all.
 * This callback is the documented escape hatch, duplicated from
 * rsp_pki.c's accept_rsp_certificate_policies (static there, and this
 * file has no header to share it through) rather than reached into: it
 * accepts exactly that one critical extension and nothing else, so it
 * does not change what rsp_verify actually checks below. */
static int accept_rsp_certificate_policies(void *p_ctx, mbedtls_x509_crt const *crt,
                                            mbedtls_x509_buf const *oid, int is_critical,
                                            const unsigned char *p, const unsigned char *end)
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

int rsp_verify(const uint8_t *cert_der, size_t cert_len,
               const uint8_t *tbs, size_t tbs_len, const uint8_t sig[64])
{
    unsigned char hash[32];
    mbedtls_x509_crt crt;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi r, s;
    int ret = -1;

    if (!cert_der || cert_len == 0 || !sig || (!tbs && tbs_len != 0)) {
        return -1;
    }
    if (mbedtls_sha256(tbs, tbs_len, hash, 0) != 0) {
        return -1;
    }

    mbedtls_x509_crt_init(&crt);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (mbedtls_x509_crt_parse_der_with_ext_cb(&crt, cert_der, cert_len, 1,
                                                accept_rsp_certificate_policies,
                                                NULL) != 0) {
        goto out;
    }
    if (!mbedtls_pk_can_do(&crt.pk, MBEDTLS_PK_ECKEY)) {
        goto out;
    }
    if (mbedtls_ecp_export(mbedtls_pk_ec(crt.pk), &grp, NULL, &q) != 0) {
        goto out;
    }
    if (mbedtls_mpi_read_binary(&r, sig, 32) != 0 ||
        mbedtls_mpi_read_binary(&s, sig + 32, 32) != 0) {
        goto out;
    }
    if (mbedtls_ecdsa_verify(&grp, hash, sizeof hash, &q, &r, &s) != 0) {
        goto out;
    }

    ret = 0;

out:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    mbedtls_x509_crt_free(&crt);
    mbedtls_platform_zeroize(hash, sizeof hash);
    return ret;
}
