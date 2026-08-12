/*
 * rsp_sign.c -- the ECDSA signatures that carry the handshake.
 *
 * SGP.22 v2.6 section 2.6.7.2 "ECDSA" states: "A signature based on ECDSA
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
 * rsp_sign_verify fails closed: every error path -- a certificate that will
 * not parse, a key that is not an EC key, a signature that mbedTLS
 * rejects -- falls through to the same "ret = -1" set before any of it
 * ran. There is exactly one place ret becomes 0.
 */
#include "rsp.h"
#include "rsp_internal.h"

#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"

/* mbedtls_ecdsa_sign_det_ext still takes an RNG, but not for the
 * per-signature nonce k: that comes from RFC 6979's HMAC-DRBG, seeded
 * deterministically from the private key and the message hash, so the
 * same (key, message) pair always produces the same k and therefore the
 * same signature. The RNG that remains is used only for blinding the
 * scalar arithmetic against side-channel attacks -- it does not affect
 * the output. Determinism is wanted here for two reasons: it is what
 * makes a recorded session replayable (the same input must produce the
 * same bytes on a second run), and it is safer -- a random k that repeats
 * or is even slightly biased reveals the private signing key, which RFC
 * 6979 avoids by construction.
 * mbedtls_ecdsa_verify takes no RNG parameter at all -- verifying an
 * ECDSA signature is pure arithmetic on public values, nothing here is
 * blinded -- so only rsp_sign uses this.
 *
 * The RNG is built per call, on the stack, the way src/rsp_pki.c has
 * always built its own. It used to be a file-scope singleton seeded
 * once and kept for the life of the process, on the reasoning that
 * "reseeding an entropy-backed DRBG on every call buys nothing and this
 * library is not multi-threaded anywhere else either". The second half
 * of that stopped being true the moment a server linked this library:
 * the lazy initialisation had no synchronisation at all, so one thread's
 * mbedtls_ctr_drbg_init would memset the context another was already
 * inside mbedtls_ctr_drbg_seed on, and the second would then call a NULL
 * entropy callback. Past MBEDTLS_CTR_DRBG_RESEED_INTERVAL a second race
 * followed, the shared DRBG reseeding inline during a signature and
 * freeing memory on the shared entropy context.
 *
 * A per-call DRBG removes both by removing the sharing, rather than by
 * guarding it: there is no mutex here, and none is needed. It costs one
 * entropy gather per signature, which is small beside the elliptic-curve
 * work it accompanies and is what buys the ability to sign from more
 * than one thread. tests/test_threads.c is what holds this: with the
 * singleton it segfaults, five runs in six. */

int rsp_sign(const rsp_credential_t *c, const uint8_t *tbs, size_t tbs_len,
             uint8_t sig[64])
{
    unsigned char hash[32];
    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    int rng_ok;
    int ret = -1;

    if (!c || !sig || (!tbs && tbs_len != 0)) {
        return -1;
    }
    if (mbedtls_sha256(tbs, tbs_len, hash, 0) != 0) {
        return -1;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    rng_ok = rsp_rng_init(&ent, &drbg, "euicc-rsp/rsp_sign") == 0;

    if (rng_ok &&
        mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_mpi_read_binary(&d, c->sk, sizeof c->sk) == 0 &&
        mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, hash, sizeof hash,
                                    MBEDTLS_MD_SHA256,
                                    mbedtls_ctr_drbg_random, &drbg) == 0 &&
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
    if (rng_ok) {
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
    }
    mbedtls_platform_zeroize(hash, sizeof hash);
    return ret;
}

int rsp_sign_verify(const uint8_t *cert_der, size_t cert_len,
               const uint8_t *tbs, size_t tbs_len, const uint8_t sig[64])
{
    unsigned char hash[32];
    mbedtls_x509_crt crt;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi r, s;
    /* -2 by default: every failure up to and including the ecdsa_verify
     * call itself means the signature was never actually checked (a
     * malformed certificate, a non-EC key, an unreadable signature
     * encoding) -- see include/rsp.h's failure convention. Only
     * mbedtls_ecdsa_verify rejecting the signature is a real "no", and
     * that one site sets ret to -1 explicitly, below. */
    int ret = -2;

    if (!cert_der || cert_len == 0 || !sig || (!tbs && tbs_len != 0)) {
        return -2;
    }
    if (mbedtls_sha256(tbs, tbs_len, hash, 0) != 0) {
        return -2;
    }

    mbedtls_x509_crt_init(&crt);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (mbedtls_x509_crt_parse_der_with_ext_cb(&crt, cert_der, cert_len, 1,
                                                rsp_accept_certificate_policies,
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
        ret = -1; /* the question was asked: this signature does not verify */
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
