/*
 * rsp.h -- the SM-DP+ role of SGP.22, as a library.
 *
 * It builds a Bound Profile Package for one eUICC. It does not speak to a
 * card and it opens no socket: the caller supplies what the card said, and
 * gets back what to send. That split is what makes the whole path testable
 * without hardware.
 *
 * No card accepts the BPP rsp_bpp_build produces yet: '87'/'88' groups are
 * placed unprotected, transactionId is a fixed placeholder, hostId is the
 * ICCID rather than the eUICC's EID, and smdpSign is empty. See the comment
 * on rsp_bpp_input_t below for the full account of each gap.
 */
#ifndef RSP_H
#define RSP_H

#include <stddef.h>
#include <stdint.h>

/* Failure convention, for every function declared below.
 *
 * 0 always means success. Most functions here have exactly one way to
 * fail -- a null argument, an allocation that did not happen, a crypto
 * primitive that refused its input -- and for those, plain -1 covers it;
 * there is nothing a caller could usefully tell apart.
 *
 * Four functions are different: their entire job is answering a
 * cryptographic yes/no question (does this verify? does this MAC match?),
 * and each of them used to return the same -1 both when the answer was a
 * real "no" and when the question was never actually reached at all --
 * indistinguishable to a caller, even though the two cases call for
 * different responses (retry/report-and-stop, versus reject-and-move-on).
 * This mirrors the exit-code contract the CLI built on top of this
 * library needs one level up (0 done, 1 a real negative answer, 2 could
 * not answer): for rsp_pki_verify, rsp_verify, rsp_unprotect and
 * rsp_bpp_recover, -1 means the question was asked and the answer is no
 * -- a signature that does not verify, a certificate that does not chain,
 * a MAC that does not match. -2 means the question was never reached --
 * a malformed input, a buffer too small, an allocation or RNG failure.
 * Each of the four says so again at its own declaration below. */

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
 * Returns 0 if both hold. -1 means the question was actually asked and the
 * answer is no: the certificate does not chain to the test CI, or c->sk
 * does not match the certificate's public key. -2 means the question was
 * never reached: a null or empty c->der, a certificate that will not
 * parse, an RNG failure, or a non-EC key. */
int rsp_pki_verify(const rsp_credential_t *c);

/* Release a credential obtained from rsp_pki_dp. Wipes the private scalar
 * before freeing. Safe to call on a zeroed or already-freed struct. */
void rsp_credential_free(rsp_credential_t *c);

/* The handshake signatures (SGP.22 v2.6 section 2.6.7.2, "ECDSA" -- every
 * SM-DP+/eUICC signature field, e.g. serverSignature1, smdpSignature2,
 * euiccSignature1/2, smdpSign, is computed "as described in section
 * 2.6.7.2"). That clause defers the exact computation to GlobalPlatform
 * Card Specification v2.2 Amendment E, whose section 3.1.3 "ECDSA" states
 * the signature is coded "in plain format ... the concatenation of the
 * byte string representation of r and s", 64 bytes for P-256's 32-byte
 * order -- not a DER SEQUENCE of two INTEGERs, which is how X.509
 * (rsp_pki_verify's territory) encodes the same primitive. Amendment E's
 * Table 3-3 pins SHA-256 as the hash for a 256-bit key. */

/* Sign tbs (already the exact bytes to be hashed -- assembling the signed
 * data object's concatenation, per whichever *Signed* structure applies,
 * is the caller's job, not this function's) with c's private key.
 * Returns 0, or -1 on failure. Every call produces a different sig for
 * the same tbs: mbedtls_ecdsa_sign draws a fresh nonce each time. */
int rsp_sign(const rsp_credential_t *c, const uint8_t *tbs, size_t tbs_len,
             uint8_t sig[64]);

/* Verify such a signature against the public key inside a certificate
 * (DER, e.g. rsp_credential_t.der). Does not check the certificate's own
 * chain of trust -- that is rsp_pki_verify's job, done separately, since
 * a message can be signed and verified against a certificate this
 * function has no way to know is untrusted. Returns 0 when the signature
 * holds. -1 means the question was actually asked and the answer is no:
 * mbedtls_ecdsa_verify rejected the signature. -2 means the question was
 * never reached: an unparseable certificate, a non-EC key, or a null/empty
 * argument. Every path other than the single success returns a negative
 * value; there is no way for a malformed input to read as accepted. */
int rsp_verify(const uint8_t *cert_der, size_t cert_len,
               const uint8_t *tbs, size_t tbs_len, const uint8_t sig[64]);

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
   Advances s->chain the same way. Returns bytes written on success. -1
   means the question was actually asked and the answer is no: the MAC
   does not match, or the decrypted padding is not valid SCP03t padding
   (which only happens once the MAC has already matched, so this is still
   a real answer about the segment's content, not an operational failure).
   -2 means the question was never reached: a null argument, a seg_len
   that cannot hold a valid segment, out_cap too small for the recovered
   plaintext, or an allocation/crypto-primitive failure. */
long rsp_unprotect(rsp_session_t *s, const uint8_t *seg, size_t seg_len,
                   uint8_t *out, size_t out_cap);

/* AES-CMAC over one block chain, exposed because it has published vectors
 * and therefore deserves its own test. Returns 0 or -1. */
int rsp_cmac(const uint8_t key[16], const uint8_t *msg, size_t len,
             uint8_t mac[16]);

/* The Bound Profile Package (SGP.22 v2.6 section 2.5.4): the eUICC's
 * one-time public key already agreed on, this assembles what
 * InitialiseSecureChannel, ConfigureISDP and StoreMetadata need, plus the
 * profile itself protected in tag-'86' segments (section 2.5.3). upp is
 * the Unprotected Profile Package -- the profile, DER, exactly as a
 * profile compiler produces it. This library makes no assumption about
 * the UPP's internal structure; section 2.5.3 itself treats it as "a
 * unique block of data".
 *
 * The BoundProfilePackage envelope itself (the outer [54] SEQUENCE and
 * its four SEQUENCE OF fields) is assembled and parsed BY HAND in
 * src/rsp_bpp.c, not through the generated BoundProfilePackage_t / asn_
 * DEF_BoundProfilePackage from Task 2. That is not a stopgap: asn1c's
 * generated encoder and decoder for "SEQUENCE OF [N] OCTET STRING" (the
 * shape all four of those fields use) cannot agree with each other on
 * any wire form for this construct, so there is no upgrade of asn1c that
 * makes the generated pair usable here -- see the long comment at the
 * top of src/rsp_bpp.c for the two independent defects and the direct
 * experiment proving it. InitialiseSecureChannelRequest, ConfigureISDPRequest
 * and StoreMetadataRequest ARE plain SEQUENCEs and unaffected, so those
 * three are still built with Task 2's generated types.
 *
 * Two more scope cuts, beyond the hand-rolled envelope:
 *
 *   - ConfigureISDP ('87') and StoreMetadata ('88') are placed in the
 *     BPP UNPROTECTED -- their own DER-encoded TLV, with no SCP03t
 *     encryption or MAC at all. rsp_protect/rsp_unprotect above only
 *     implement the '86' construction (see their own comment); a real
 *     card requires '87' encrypted-and-MAC'd and '88' MAC'd, and will
 *     refuse a BPP built by rsp_bpp_build. That protection is a
 *     different, narrower construction than '86' and is left to
 *     whichever task first talks to a card.
 *   - Several InitialiseSecureChannelRequest fields have no source in
 *     rsp_bpp_input_t and are filled with fixed placeholders, not real
 *     values: transactionId is the single byte 0x01; controlRefTemplate.
 *     hostId reuses the 10-byte ICCID, which is NOT the correct field --
 *     the real hostId is the eUICC's EID, absent from this input struct;
 *     smdpSign is a zero-length OCTET STRING (wire bytes '5F 37 00'),
 *     left empty rather than filled with same-length filler so it cannot
 *     be mistaken for a real signature -- no ECDSA signing primitive
 *     over arbitrary data exists in this header. A BPP built this way is
 *     not ready for a real ES9+/ES8+ exchange until whichever task wires
 *     that flow supplies transactionId, the EID and a real signature.
 *
 * rsp_bpp_build's own length encoder refuses a UPP whose encoded
 * sequenceOf86 or outer content would need a DER length field longer
 * than 4 octets (a ~4 GiB bound, order of magnitude past any profile
 * this library will plausibly see); it fails with -1, not a truncation,
 * if that bound is ever hit.
 */
typedef struct {
    const uint8_t *upp;        /* the profile package, DER */
    size_t         upp_len;
    const uint8_t *otpk_dp;    /* our one-time public key, 65 bytes */
    const uint8_t *iccid;      /* 10 bytes */
    const char    *profile_name;
    const char    *service_provider_name;
} rsp_bpp_input_t;

/* Build the BPP. *out is malloc'ed and belongs to the caller. The session is
   advanced as segments are protected. Returns 0 or -1. */
int rsp_bpp_build(rsp_session_t *s, const rsp_bpp_input_t *in,
                  uint8_t **out, size_t *out_len);

/* Recover the UPP from a BPP with the same session keys. This exists for the
   self-check before sending and for the test below. Returns 0 on success.
   -1 means the question was actually asked and the answer is no: some
   segment's MAC did not match under these session keys (rsp_unprotect
   returned -1 for it). -2 means the question was never reached: a null
   argument, a malformed envelope (a bad tag, a truncated TLV, a
   sequenceOf86 with no segments at all), an allocation failure, or
   rsp_unprotect itself returning -2 for some segment.

   *upp is malloc'ed and belongs to the caller on success; it is the
   profile in the clear, so it carries whatever the profile itself
   carries (including any key material the profile provisions) -- wipe
   it (mbedtls_platform_zeroize, not memset: a memset on a buffer that is
   about to be freed and never read again is dead-store-eliminated at
   this project's -O2, proven with a stack probe in this project's own
   history -- see src/rsp_crypto.c's comment on rsp_session_init for the
   full account) once you are done with it, the same as any other secret
   this library hands back.

   A BPP whose sequenceOf86 has no segments at all is refused (-1), even
   though the underlying parse would otherwise succeed with nothing to
   unprotect: "recovered nothing" must never read as "recovered", which
   matters most for exactly the self-check-before-sending case this
   function exists for.

   On a mid-stream segment failure, s->chain is left wherever it was
   after the segments that verified before the failing one -- advanced,
   not rolled back -- the same way rsp_bpp_build leaves s->chain advanced
   through whatever it managed to protect before a later failure. Do not
   reuse a session after either function returns a negative value (-1 or
   -2); treat it as consumed. */
int rsp_bpp_recover(rsp_session_t *s, const uint8_t *bpp, size_t bpp_len,
                    uint8_t **upp, size_t *upp_len);

/* A transport carries APDUs and knows nothing else. */
typedef struct rsp_transport rsp_transport_t;
struct rsp_transport {
    /* Send one command APDU, receive one response APDU including its two
       status bytes. Returns the response length, -1 if the card answered
       something unusable, -2 if the exchange could not happen at all. */
    long (*transceive)(rsp_transport_t *t, const uint8_t *cmd, size_t cmd_len,
                       uint8_t *resp, size_t resp_cap);
    void (*close)(rsp_transport_t *t);
    void *ctx;
};

/* A transport that answers from a recording. Returns 0, or -2 if the file
   cannot be read or parsed. */
int rsp_replay_open(const char *path, rsp_transport_t *out);

/* Wrap any transport so every exchange is appended to `path`. The wrapper
   takes ownership of `inner` and must itself be closed. Returns 0 or -2.

   "Takes ownership" is literal, not a suggestion: rsp_record_open copies
   *inner's fields into the wrapper's own storage, and out->close calls
   the inner transport's close for you. Do not call inner->close yourself
   afterward -- the caller's original `inner` struct and the wrapper's
   copy of it both still point at the same underlying resource (the same
   ctx), so closing both is a double close/double free of whatever inner
   owns, not two independent releases. Close the wrapper (`out`) once,
   and treat the `inner` you passed in as consumed. */
int rsp_record_open(rsp_transport_t *inner, const char *path,
                    rsp_transport_t *out);

/* Send one ES10 request to the ISD-R and collect the whole answer, driving
   command chaining outward and 61xx/GET RESPONSE inward (SGP.22 v2.6
   section 5.7.2 -- see src/rsp_es10.c for the full citation trail). `req`
   is the DER of the request; `*out` is malloc'ed and belongs to the
   caller and holds the response without its status bytes. Returns 0;
   -1 when the card answered with a status other than 9000 or 61xx, with
   *sw set to that status; -2 when the exchange could not happen. */
int rsp_es10_send(rsp_transport_t *t, const uint8_t *req, size_t req_len,
                  uint8_t **out, size_t *out_len, unsigned *sw);

#endif /* RSP_H */
