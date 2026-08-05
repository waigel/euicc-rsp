/*
 * rsp.h -- the SM-DP+ role of SGP.22, as a library.
 *
 * It builds a Bound Profile Package for one eUICC. It does not speak to a
 * card and it opens no socket: the caller supplies what the card said, and
 * gets back what to send. That split is what makes the whole path testable
 * without hardware.
 */
#ifndef RSP_H
#define RSP_H

#include <stddef.h>
#include <stdint.h>

/* The library version, for a bug report. */
const char *rsp_version(void);

/* A credential this library signs with: a certificate and the private key
 * that matches it. Both come from the published SGP.26 test material --
 * see testdata/sgp26/README.md. Test material only: a production eUICC
 * rejects it. */
typedef struct {
    uint8_t *der;      /* the certificate, DER, owned by the struct */
    size_t   der_len;
    uint8_t  sk[32];   /* the private key, a big-endian P-256 scalar */
} rsp_credential_t;

/* The published SGP.26 test Certificate Issuer, compiled in. *der points at
 * memory owned by the library; the caller must not free it. Returns 0, or
 * -1 if the arguments are unusable. */
int rsp_pki_test_ci(const uint8_t **der, size_t *len);

/* Load a published SGP.26 DP credential. role is 0 for DPauth
 * (authentication) or 1 for DPpb (profile binding). Returns 0, or -1 for
 * an unknown role or an allocation failure. The result must be released
 * with rsp_credential_free. */
int rsp_pki_dp(int role, rsp_credential_t *out);

/* Verify that c's certificate chains to the test CI from rsp_pki_test_ci,
 * and that the certificate's public key is the one belonging to c->sk.
 * Returns 0 if both hold, or -1 otherwise. */
int rsp_pki_verify(const rsp_credential_t *c);

/* Release a credential obtained from rsp_pki_dp. Wipes the private scalar
 * before freeing. Safe to call on a zeroed or already-freed struct. */
void rsp_credential_free(rsp_credential_t *c);

/* The SCP03t session keys derived from the one-time key agreement between
 * the SM-DP+ and the eUICC (SGP.22 section 2.6.4). Secret: never printed,
 * logged, or otherwise emitted. Wipe with rsp_session_wipe when done. */
typedef struct {
    uint8_t s_enc[16];
    uint8_t s_mac[16];
    uint8_t chain[16];   /* the MAC chaining value; rsp_protect advances it */
} rsp_session_t;

/* ECDH on P-256. pk is an uncompressed point, 65 bytes starting with 0x04.
 * Writes the 32-byte x coordinate of the shared point. Returns 0 or -1. */
int rsp_ecdh_p256(const uint8_t sk[32], const uint8_t pk[65], uint8_t z[32]);

/* The X9.63 key derivation with SHA-256. Returns 0 or -1. */
int rsp_kdf_x963(const uint8_t *z, size_t z_len,
                  const uint8_t *info, size_t info_len,
                  uint8_t *out, size_t out_len);

/* Both together, filling a session: ECDH on (otsk_dp, otpk_euicc), then the
 * X9.63 derivation of S-ENC, S-MAC and the initial chaining value from the
 * shared secret and shared_info. Returns 0 or -1. */
int rsp_session_init(const uint8_t otsk_dp[32], const uint8_t otpk_euicc[65],
                      const uint8_t *shared_info, size_t shared_info_len,
                      rsp_session_t *out);

/* Wipe a session's key material. Safe to call on a zeroed struct. */
void rsp_session_wipe(rsp_session_t *s);

#endif /* RSP_H */
