/*
 * rsp.h -- the SM-DP+ role of SGP.22, as a library.
 *
 * It builds a Bound Profile Package for one eUICC, and it can now also
 * read one: a transport abstraction (rsp_transport_t) carries APDUs over a
 * text recording, over a wrapper that records one, or over a real reader
 * through PC/SC (rsp_pcsc_open); on top of that, rsp_es10_send drives one
 * ES10 request to the ISD-R and rsp_card_read_info reads what a card says
 * about itself. The replay transport is what keeps the read path testable
 * without hardware -- the caller supplies what the card said (recorded or
 * live) and gets back what to send.
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
 * Eight functions are different: each of them can fail in two ways that
 * call for different responses (retry/report-and-stop, versus
 * reject-and-move-on), and used to collapse both into the same -1 --
 * indistinguishable to a caller. This mirrors the exit-code contract the
 * CLI built on top of this library needs one level up (0 done, 1 a real
 * negative answer, 2 could not answer), and splits into two senses
 * depending on what the function actually asks a question of:
 *
 * For rsp_pki_verify, rsp_sign_verify, rsp_unprotect and rsp_bpp_recover,
 * the question is put to a cryptographic primitive: -1 means the question
 * was asked and the answer is no -- a signature that does not verify, a
 * certificate that does not chain, a MAC that does not match. -2 means the
 * question was never reached -- a malformed input, a buffer too small, an
 * allocation or RNG failure.
 *
 * For rsp_transport_t.transceive, rsp_es10_send, rsp_card_read_info and
 * rsp_card_read_profiles, the question is put to a card: -1 means an
 * answer came back and it is a no -- a status word other than 9000/61xx,
 * bytes too short to even carry one, or (rsp_card_read_profiles only) a
 * decoded ProfileInfoListError, the card's own refusal of the request
 * rather than a transport-level problem. -2 means no usable answer came
 * back at all -- the reader is gone, the recording ran out or does not
 * match, a caller-supplied buffer was too small for what arrived, or (for
 * rsp_es10_send) a chain that would not terminate. All three transports
 * (src/rsp_transport.c's replay and record, src/rsp_pcsc.c's PC/SC) agree
 * on this split, including the caller-buffer-too-small case: it is -2,
 * because the buffer is the caller's own argument, not something the card
 * was asked and said no to.
 *
 * Each of the eight says so again at its own declaration below. */

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
int rsp_sign_verify(const uint8_t *cert_der, size_t cert_len,
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
       something unusable (fewer than two bytes -- no room for a status
       word), -2 if the exchange could not happen at all: no reader or no
       recorded exchange to answer with, a command that does not match
       what a recording expects, or resp_cap too small for what came back
       -- the last one is -2 rather than -1 in every transport here
       (src/rsp_pcsc.c, src/rsp_transport.c's replay and record), because
       resp_cap is the caller's own argument, not something the card was
       asked and said no to. */
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

   The file opens with a "#" header explaining what it is and, since this
   function has no way to know whether the session it is about to capture
   is read-only or not, warning that a write session's recording can carry
   protected material -- see src/rsp_transport.c's own comment on
   RECORDING_HEADER for the exact text. rsp_replay_open skips it like any
   other comment.

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

/* The transport that carries bytes to actual hardware, over PC/SC. See
   src/rsp_pcsc.c for the citation trail and the three failures a person
   actually hits when using it. */

/* Connect to a reader. `reader` names one, or is NULL to take the only one
   attached. Returns 0; -2 with a message on stderr when there is no reader,
   no card, or the card is held by another process. */
int rsp_pcsc_open(const char *reader, rsp_transport_t *out);

/* The attached readers, NUL-separated and terminated by an empty string.
   The caller frees. Returns the count, or -2. */
long rsp_pcsc_readers(char **out);

/* Send one ES10 request to the ISD-R and collect the whole answer, driving
   command chaining outward and 61xx/GET RESPONSE inward (SGP.22 v2.6
   section 5.7.2 -- see src/rsp_es10.c for the full citation trail). `req`
   is the DER of the request; `*out` is malloc'ed and belongs to the
   caller and holds the response without its status bytes. Returns 0;
   -1 when the card answered with a status other than 9000 or 61xx, with
   *sw set to that status, or when the transport itself already reported
   the answer as unusable (*sw left at 0: there is no status word for a
   transport-level -1 to carry); -2 when the exchange could not happen,
   or the chain would not terminate within this file's own bounds. */
int rsp_es10_send(rsp_transport_t *t, const uint8_t *req, size_t req_len,
                  uint8_t **out, size_t *out_len, unsigned *sw);

/* What a card says about itself, decoded from GetEUICCInfo2 (EUICCInfo2,
   SGP.22 v2.6 section 5.7.13) and GetEID (GetEuiccDataResponse, section
   5.7.11). Strings are NUL-terminated; ci_ids holds ci_count identifiers
   of ci_id_len bytes each, concatenated -- the Certificate Issuer
   SubjectKeyIdentifiers the card lists in euiccCiPKIdListForVerification,
   the ones rsp_card_trusts answers questions about. */
typedef struct {
    uint8_t eid[16];
    int     have_eid;
    char    svn[16];            /* "2.2.0" */
    uint8_t *ci_ids;            /* for verification */
    size_t   ci_count;
    size_t   ci_id_len;
} rsp_card_info_t;

/* Select the ISD-R, then read EUICCInfo2 and the EID. Returns 0, -1 if the
   card refused, -2 if it could not be asked.

   `no_isdr`, if not NULL, is set to 1 when a -1 happened at the very first
   step -- selecting the ISD-R itself came back refused (a real answer,
   commonly '6A82' or another SELECT-specific status, not a chain this
   function did not know how to follow) -- and left at 0 for every other
   outcome, including success and -2. That distinction is for a caller
   like euicc-tools' `card info`: an ISD-R that never answers at all reads
   very differently from a later ES10 request the ISD-R accepted and then
   refused -- the first says the card in the reader may not be an eUICC at
   all, or its ISD-R is locked; the second says it is one, and it said no
   to something specific asked of it. */
int rsp_card_read_info(rsp_transport_t *t, rsp_card_info_t *out, int *no_isdr);

/* Release an rsp_card_info_t obtained from rsp_card_read_info. Safe to call
   on a zeroed struct. Nothing here is secret (see testdata/cards/README.md,
   "What is safe to commit"), so there is no wipe. */
void rsp_card_info_free(rsp_card_info_t *i);

/* Does this card accept the issuer whose SubjectKeyIdentifier is `id`?
   Returns 1 for yes, 0 for no.

   This is the one function in this header where 0 is not "the question
   was asked and the answer is no" in the -1/-2 sense the rest of this
   file documents above -- there is no -1/-2 split here at all, only 1 and
   0. A null `i` or `id`, or an `id_len` that does not match this card's
   own identifier length, answers 0 too, indistinguishable from a real
   "this card does not trust that issuer." That is deliberate: a caller
   with no info to ask the question of has no card to be wrong about
   either, so collapsing "could not ask" into "no" costs nothing a caller
   could otherwise usefully act on differently -- but it does mean a 0
   here is not on its own proof that a real card was consulted and
   disagreed, the way an -1 elsewhere in this file is. */
int rsp_card_trusts(const rsp_card_info_t *i, const uint8_t *id, size_t id_len);

/* One profile as GetProfilesInfo lists it (ProfileInfo, SGP.22 v2.6
   section 5.7.15). Every member of the ASN.1 type is OPTIONAL, and a
   card is free to omit any of them for any profile -- so, the same way
   rsp_card_info_t's have_eid says whether the EID actually arrived, each
   field below that a card can plausibly omit has its own have_* flag
   set only when the card actually sent it; the field itself is left at
   0/NULL otherwise, never used to mean "absent" on its own. iconType and
   icon (up to 1024 bytes of image data, SGP.22's own SIZE bound) are not
   decoded here at all -- nothing in this struct represents them, and
   they are freed unread the same way rsp_card_select_isdr already
   discards a SELECT's FCI in src/rsp_es10.c -- a profile listing is not
   the place to hand back a kilobyte of icon per entry. Strings are
   malloc'ed, NUL-terminated, and owned by the struct. */
typedef struct {
    uint8_t iccid[10];
    int     have_iccid;

    uint8_t isdp_aid[16];
    size_t  isdp_aid_len;      /* 1..16 when have_isdp_aid; 0 otherwise */
    int     have_isdp_aid;

    long    profile_state;     /* ProfileState_disabled(0) / _enabled(1) */
    int     have_profile_state;

    char   *profile_nickname;        /* NULL if the card sent none */
    char   *service_provider_name;
    char   *profile_name;

    long    profile_class;     /* ProfileClass_test(0)/_provisioning(1)/_operational(2) */
    int     have_profile_class;
} rsp_profile_info_t;

/* Select the ISD-R, then ask for every installed profile
   (ProfileInfoListRequest with every member absent, SGP.22 v2.6 section
   5.7.15 -- an empty body asks for all of them, not none: 'BF2D 00' is
   that clause's own worked example of "retrieve the ProfileInfo for all
   installed Profiles"). *out is
   malloc'ed on success, an array of *out_count rsp_profile_info_t,
   released with rsp_card_profiles_free; a card with nothing installed
   answers 0 with *out_count == 0 and *out == NULL, a complete answer,
   not this function's failure to find anything.

   Returns 0, or:

   -1 when an answer came back and it is a refusal: the card sent
   ProfileInfoListError rather than the list. *err, if not NULL, is set
   to which one (ProfileInfoListError_incorrectInputValues == 1 or
   ProfileInfoListError_undefinedError == 127, dist/ProfileInfoListError.h)
   -- a caller that only needs the exit code can pass NULL and ignore the
   distinction, the same as rsp_card_read_info's no_isdr parameter. *err
   is left at 0 for every other outcome, including success; check it only
   after this function itself returns -1.

   -2 when the exchange could not happen, or the response arrived but
   could not be decoded as ProfileInfoListResponse, or as some ProfileInfo
   entry this struct cannot represent (an iccid whose length is not
   exactly 10, an isdpAid longer than isdp_aid can hold or of length 0,
   or an allocation failure) -- the same "cannot make sense of it" -2
   rsp_card_read_info already gives a non-uniform ci_ids list.

   no_isdr follows rsp_card_read_info's own convention exactly: set to 1
   when the very first step -- selecting the ISD-R -- is itself what
   refused (a -1 there, before ProfileInfoListRequest was ever sent), 0
   for every other outcome including success. Left untouched if NULL. */
int rsp_card_read_profiles(rsp_transport_t *t, rsp_profile_info_t **out,
                            size_t *out_count, long *err, int *no_isdr);

/* Release an array obtained from rsp_card_read_profiles: each entry's
   owned strings, then the array itself. Safe to call with profiles ==
   NULL (whether or not count is 0) and safe on a zeroed array. */
void rsp_card_profiles_free(rsp_profile_info_t *profiles, size_t count);

#endif /* RSP_H */
