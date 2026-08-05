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
 * the SM-DP+ and the eUICC (SGP.22 Annex G, "Key Derivation Process
 * (Normative)" -- section 2.6.4 introduces these three keys by name, but
 * the split that assigns KeyData's bytes to them is Annex G's, not
 * 2.6.4's). Secret: never printed, logged, or otherwise emitted. Wipe
 * with rsp_session_wipe when done. */
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
 * shared secret and shared_info. shared_info is passed through to
 * rsp_kdf_x963 exactly as given -- assembling it is the caller's job, not
 * this function's. SGP.22 Annex G fixes its composition to: key type
 * (1 byte) || key length (1 byte) || HostID as length-value || EID as
 * length-value, the same data given as input to "ES8+.InitialiseSecureChannel".
 * Returns 0 or -1. */
int rsp_session_init(const uint8_t otsk_dp[32], const uint8_t otpk_euicc[65],
                      const uint8_t *shared_info, size_t shared_info_len,
                      rsp_session_t *out);

/* Wipe a session's key material. Safe to call on a zeroed struct. */
void rsp_session_wipe(rsp_session_t *s);

/* SCP03t: the secure channel that protects each segment of a Bound Profile
 * Package on its way to the eUICC. SGP.22 v2.6 section 2.5.3 states that
 * "Command TLV encryption and MACing follows SGP.02 [2] section 4.1.3.3",
 * which in turn says the mechanism is inherited from GlobalPlatform's SCP03
 * (Amendment D to the GlobalPlatform Card Specification), restricted to the
 * "MAC + encryption" security level, with the counter that normally drives
 * the ICV replaced by the MAC chaining value (SGP.02 v4.1 section 4.1.3.3:
 * "Otherwise the MAC chaining method SHALL be applied (i.e. the MAC
 * chaining value of the previous command TLV SHALL be used)").
 *
 * A "segment" here is exactly one SCP03t tag-'86' data segment, as SGP.22
 * section 2.5.3 names it ("Each data segment of the PPP is identified by
 * the tag '86' as defined in SGP.02"). rsp_protect returns the segment's
 * value bytes only (ciphertext, then the 8-byte C-MAC) -- the tag and its
 * BER length octets are not written to *out*, because whoever assembles
 * the BoundProfilePackage's [6] IMPLICIT OCTET STRING (Task 2's generated
 * codec) reproduces them from the DER encoding rules; but per GlobalPlatform
 * Amendment D section 6.2.4 / SGP.02 Figure 46, those bytes ARE part of what
 * gets MACed, so rsp_protect and rsp_unprotect compute them internally
 * (tag 0x86, DER-minimal-length of the ciphertext-plus-MAC) purely to feed
 * the MAC input -- see src/rsp_crypto.c for the exact construction and its
 * citations. */

/* Protect one ES8+ command into one SCP03t segment. Advances s->chain.
   Returns the number of bytes written to out, or -1. */
long rsp_protect(rsp_session_t *s, const uint8_t *plain, size_t plain_len,
                 uint8_t *out, size_t out_cap);

/* The inverse, for the round trip and for the self-check before sending.
   Advances s->chain the same way. Returns bytes written, or -1 when the MAC
   does not match. */
long rsp_unprotect(rsp_session_t *s, const uint8_t *seg, size_t seg_len,
                   uint8_t *out, size_t out_cap);

/* AES-CMAC over one block chain, exposed because it has published vectors
 * and therefore deserves its own test. Returns 0 or -1. */
int rsp_cmac(const uint8_t key[16], const uint8_t *msg, size_t len,
             uint8_t mac[16]);

#endif /* RSP_H */
