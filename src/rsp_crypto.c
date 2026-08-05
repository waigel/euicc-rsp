/*
 * rsp_crypto.c -- session keys from the one-time key agreement.
 *
 * The SM-DP+ and the eUICC each hold a one-time P-256 key pair (SGP.22
 * calls them otPK/otSK.DP.ECKA and otPK/otSK.eUICC.ECKA). An ECDH on those
 * two pairs gives a shared secret that neither side ever transmits; the
 * X9.63 key derivation with SHA-256 turns that secret into the SCP03t
 * session keys everything after this point is protected with. Get this
 * step wrong and every later exchange is silently wrong too -- which is
 * why the ECDH half is checked against a vector this repository did not
 * produce (see testdata/nist/README.md), rather than only against itself.
 *
 * The split of the derived key material into the initial MAC chaining
 * value, S-ENC and S-MAC follows SGP.22 Annex G, "Key Derivation Process
 * (Normative)": KeyData bytes 1..L are the initial MAC chaining value,
 * L+1..2L are S-ENC, 2L+1..3L are S-MAC, with L = 16 for AES-128.
 */
#include "rsp.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"

/* mbedTLS's scalar multiplication takes an RNG for blinding against timing
 * attacks. mbedtls_ecdh_compute_shared documents f_rng as "must not be
 * NULL" -- the same requirement Task 3 already ran into with
 * mbedtls_ecp_mul -- so a real RNG is seeded here too, even though the
 * scalar and point it multiplies are both already fixed by the caller. */
static int rng_init(mbedtls_entropy_context *ent, mbedtls_ctr_drbg_context *drbg)
{
    static const unsigned char pers[] = "euicc-rsp/rsp_crypto";
    mbedtls_entropy_init(ent);
    mbedtls_ctr_drbg_init(drbg);
    return mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, ent,
                                  pers, sizeof(pers) - 1);
}

int rsp_ecdh_p256(const uint8_t sk[32], const uint8_t pk[65], uint8_t z[32])
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi d, shared;
    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context drbg;
    int rng_ok;
    int ret = -1;

    if (!sk || !pk || !z) {
        return -1;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&shared);
    rng_ok = rng_init(&ent, &drbg) == 0;

    if (rng_ok &&
        mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_ecp_point_read_binary(&grp, &q, pk, 65) == 0 &&
        mbedtls_mpi_read_binary(&d, sk, 32) == 0 &&
        mbedtls_ecdh_compute_shared(&grp, &shared, &q, &d,
                                     mbedtls_ctr_drbg_random, &drbg) == 0 &&
        mbedtls_mpi_write_binary(&shared, z, 32) == 0) {
        ret = 0;
    }

    mbedtls_mpi_free(&shared);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);
    return ret;
}

int rsp_kdf_x963(const uint8_t *z, size_t z_len,
                  const uint8_t *info, size_t info_len,
                  uint8_t *out, size_t out_len)
{
    uint8_t *buf;
    size_t buf_len;
    size_t produced = 0;
    uint32_t counter = 1;
    int ret = -1;

    if ((!z && z_len) || (!info && info_len) || (!out && out_len)) {
        return -1;
    }
    if (out_len == 0) {
        return 0;
    }

    /* SHA-256(Z || counter_be32(i) || info) per iteration. z and info do
     * not change between iterations, so they are copied into a scratch
     * buffer once and only the 4-byte counter is rewritten each time. */
    buf_len = z_len + 4 + info_len;
    buf = malloc(buf_len);
    if (!buf) {
        return -1;
    }
    memcpy(buf, z, z_len);
    memcpy(buf + z_len + 4, info, info_len);

    while (produced < out_len) {
        uint8_t digest[32];
        size_t chunk;

        buf[z_len + 0] = (uint8_t)(counter >> 24);
        buf[z_len + 1] = (uint8_t)(counter >> 16);
        buf[z_len + 2] = (uint8_t)(counter >> 8);
        buf[z_len + 3] = (uint8_t)(counter);

        if (mbedtls_sha256(buf, buf_len, digest, 0) != 0) {
            goto out;
        }

        chunk = out_len - produced;
        if (chunk > sizeof digest) {
            chunk = sizeof digest;
        }
        memcpy(out + produced, digest, chunk);
        produced += chunk;
        counter++;
    }
    ret = 0;

out:
    /* buf carries the shared secret Z; it does not outlive this call. */
    memset(buf, 0, buf_len);
    free(buf);
    return ret;
}

int rsp_session_init(const uint8_t otsk_dp[32], const uint8_t otpk_euicc[65],
                      const uint8_t *shared_info, size_t shared_info_len,
                      rsp_session_t *out)
{
    uint8_t z[32];
    uint8_t key_data[48]; /* SGP.22 Annex G: chain (16) | S-ENC (16) | S-MAC (16) */
    int ret = -1;

    if (!otsk_dp || !otpk_euicc || !out) {
        return -1;
    }
    memset(out, 0, sizeof *out);

    if (rsp_ecdh_p256(otsk_dp, otpk_euicc, z) != 0) {
        goto out;
    }
    if (rsp_kdf_x963(z, sizeof z, shared_info, shared_info_len,
                      key_data, sizeof key_data) != 0) {
        goto out;
    }

    memcpy(out->chain, key_data + 0, 16);
    memcpy(out->s_enc, key_data + 16, 16);
    memcpy(out->s_mac, key_data + 32, 16);
    ret = 0;

out:
    memset(z, 0, sizeof z);
    memset(key_data, 0, sizeof key_data);
    if (ret != 0) {
        memset(out, 0, sizeof *out);
    }
    return ret;
}

void rsp_session_wipe(rsp_session_t *s)
{
    if (!s) {
        return;
    }
    memset(s, 0, sizeof *s);
}
