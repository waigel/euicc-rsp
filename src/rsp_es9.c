/*
 * rsp_es9.c -- ES9+ (LPA -- SM-DP+), SGP.22 v2.6 section 5.6: all three
 * ES9+ functions this library implements as the SM-DP+ role --
 * InitiateAuthentication (5.6.1), AuthenticateClient (5.6.3) and
 * GetBoundProfilePackage (5.6.2), in that order because that is the order
 * an RSP session actually calls them.
 *
 * AuthenticateClient (5.6.3) is the cryptographic core: on reception, the
 * SM-DP+ SHALL
 *
 *   - Verify the validity of CERT.EUM.ECDSA, using PK.CI.ECDSA.
 *   - Verify the validity of CERT.EUICC.ECDSA, using PK.EUM.ECDSA.
 *   - Verify euiccSignature1 using PK.EUICC.ECDSA, as described in section
 *     5.7.13 "ES10b.AuthenticateServer".
 *   - Verify that the transactionId is known and relates to an ongoing RSP
 *     session.
 *   - Verify that the serverChallenge attached to the ongoing RSP session
 *     matches the serverChallenge returned by the eUICC.
 *
 * -- in that order in the spec text, though this file checks transactionId
 * and serverChallenge first: they are cheap memcmp's against *s, and
 * failing on them before doing any certificate parsing or ECDSA
 * verification means a caller who got the session wrong gets refused
 * without this file spending an RNG seed and two chain verifications to
 * tell them so. All five checks the spec text lists are what
 * 5.6.3 actually requires -- nothing here reorders them away, only
 * evaluates them in cheapest-first order, and every one of the five is
 * still evaluated before anything below "otherwise" in 5.6.3's own text.
 *
 * Two further steps 5.6.3 itself defers to ES10b.AuthenticateServer's own
 * definition (5.7.13, already read for Task 2 -- see rsp_dp_initiate_
 * authentication's own top comment):
 *
 *   - "euiccSignature1 SHALL apply on euiccSigned1 data object" -- the
 *     signed bytes are EuiccSigned1's own DER encoding, the same
 *     "encode this struct alone, sign that" pattern InitiateAuthentication
 *     already uses for ServerSigned1/serverSignature1.
 *   - EuiccSigned1 itself (rsp-2.5.asn line 315) carries no EID field at
 *     all: { transactionId, serverAddress, serverChallenge, euiccInfo2,
 *     ctxParams1 }. The EID lives in CERT.EUICC.ECDSA's own Subject
 *     'serialNumber' attribute instead (SGP.22 v2.6 section 4.5.1:
 *     "'serialNumber' SHALL be the EID as a decimal PrintableString" --
 *     that section's own worked example gives "o = ACME, serialNumber =
 *     89049032123451234512345678901235", which is where this project's
 *     EID fixture comes from, not the other way around). extract_eid()
 *     below reads it from the parsed mbedtls_x509_crt's .subject list,
 *     not from euiccSigned1.
 *
 * Everything 5.6.3 does "otherwise" -- Activation Code Retrieval,
 * eligibility, MatchingID/pending-download-order lookup, Confirmation
 * Code, retry limits -- is Profile-order state this stateless library has
 * no database for, exactly the same scope cut InitiateAuthentication
 * already made for CI selection and eligibility. ctxParams1 is decoded
 * (it is part of EuiccSigned1, which must decode for euiccSignature1's own
 * bytes to be reproduced) but never otherwise inspected.
 *
 * profileMetaData is the one output field this file cannot synthesize on
 * its own: this stateless library has no profile-order database to learn
 * a Profile's ICCID/name/service-provider from, so
 * rsp_dp_authenticate_client's own `metadata` parameter is the caller's
 * answer to that gap (see rsp.h) -- decoded far enough to be checked,
 * echoed into the response, and kept whole in *s so that the BPP's '88'
 * group carries those same bytes rather than a second, drifting copy.
 * Kept whole, not reduced to the three fields it used to be reduced to:
 * a rebuilt StoreMetadataRequest silently loses profileClass and every
 * other optional field, so the eUICC and the person reading the LPA's
 * profileMetaData ended up told different things about one Profile.
 *
 * GetBoundProfilePackage (5.6.2) is comparatively small once
 * AuthenticateClient has run: verify euiccSignature2 against the
 * PK.EUICC.ECDSA already attached to *s, derive the SCP03t session keys
 * (rsp_session_init) over Annex G's SharedInfo, and hand the result to
 * rsp_bpp_build together with the otPK.DP.ECKA this file derives from
 * otsk_dp, its own otPK.EUICC.ECKA (rok->euiccSigned2.euiccOtpk -- the same
 * value just used to derive the session, now also part of what
 * rsp_bpp_build's own smdpSign covers, section 5.5.1), s->transaction_id,
 * and a freshly-loaded DPpb credential (rsp_pki_dp(1, ...), loaded and
 * freed in this function, not DPauth -- see this file's own top comment on
 * why the two must never be confused). *bpp and *bpp_len are exactly
 * rsp_bpp_build's own raw BoundProfilePackage bytes -- not wrapped in a
 * GetBoundProfilePackageOk/[58] envelope, for the same reason rsp_bpp_
 * build's own output is not wrapped in one either (see include/rsp.h: the
 * generated codec cannot round-trip BoundProfilePackage's SEQUENCE-OF-
 * tagged-element fields, so nothing in this project ever hands one to
 * der_encode).
 *
 * HostID and EID are two separate fields, not one encoded twice (Annex G:
 * "keyType(1) || keyLen(1) || HostID-LV || EID-LV"). RSP_HOST_ID
 * (src/rsp_internal.h) is a fixed, arbitrary, SM-DP+-chosen identifier --
 * checked against a working reference implementation (osmo-smdpp, which
 * hardcodes its own unrelated string for exactly this field) precisely
 * because this project has a standing instruction not to trust a comment's
 * say-so on a spec point without checking it, and an earlier comment in
 * this exact codebase (src/rsp_bpp.c's build_isc) already got this one
 * wrong. See RSP_HOST_ID's own comment for the full account. Task 4's own
 * controlRefTemplate must read that same constant.
 *
 * Section 5.6.1 itself defers the exact content it hands back to section
 * 5.7.13 "ES10b.AuthenticateServer", which is what the eUICC actually
 * receives once the LPA relays this function's response on:
 *
 *   ServerSigned1 ::= SEQUENCE {
 *       transactionId   [0] TransactionId,   -- generated by the SM-DP+
 *       euiccChallenge  [1] Octet16,         -- echoed back unchanged
 *       serverAddress   [3] UTF8String,      -- the SM-DP+'s own FQDN
 *       serverChallenge [4] Octet16          -- generated by the SM-DP+
 *   }
 *
 * "serverSignature1 SHALL be created using the private key associated to
 * the RSP Server Certificate for authentication" (5.7.13) -- CERT.DPauth.
 * ECDSA, rsp_pki_dp(0, ...), never DPpb (role 1): DPpb signs the Bound
 * Profile Package (rsp_bpp_build), a different key for a different
 * purpose the eUICC has no reason to accept here.
 *
 * The response this file returns (*resp / *resp_len) is the DER encoding
 * of the generated InitiateAuthenticationOkEs9 type: exactly the five
 * fields Table 36 lists (transactionId, serverSigned1, serverSignature1,
 * euiccCiPKIdToBeUsed, serverCertificate), "returned as encoded data
 * objects including the tags defined for them in the
 * AuthenticateServerRequest data object" (5.6.1 Table 36, NOTE 1).
 * ctxParams1 is deliberately not part of it -- that field is the LPA's
 * own contribution to the later AuthenticateServer call, not something
 * the SM-DP+ hands back from InitiateAuthentication, and
 * InitiateAuthenticationOkEs9 (unlike AuthenticateServerRequest) has no
 * such field to fill in the first place.
 *
 * serverAddress used to be a judgement call here, and is not any more.
 * This function once accepted no address at all, so a fixed ".invalid"
 * placeholder was signed in place of one -- real bytes, genuinely
 * signed, but not a real SM-DP+ address. It now takes both addresses
 * section 5.6.1 talks about: its own, which is what serverSigned1
 * carries, and the LPA-supplied smdpAddress of Table 35, which it
 * checks its own against case-insensitively. A mismatch is the one
 * refusal this function has (-1; see rsp.h).
 *
 * One judgement call remains, made because section 5.6.1's own interface
 * gives this function nothing to work with for it -- see
 * task-2-report.md (euicc-tools' write-path SDD folder) for the full
 * account:
 *
 *   - euiccCiPKIdToBeUsed: section 5.6.1 has the SM-DP+ "select the CI
 *     ... according to the priority provided by the eUICC" among
 *     possibly several supported CI Public Keys. This library supports
 *     exactly one CI -- the compiled-in SGP.26 test issuer,
 *     rsp_pki_test_ci -- so there is nothing to select among. Its own
 *     Subject Key Identifier is extracted from the certificate itself
 *     (not hand-copied as a second literal), so it cannot silently drift
 *     from what rsp_pki_verify actually chains DPauth/DPpb against. This
 *     is used unconditionally, without checking it even appears in the
 *     caller's euiccInfo1 -- a real check once a second CI ever exists,
 *     a tautology while only one does.
 *
 * serverChallenge is not a judgement call: section 5.6.1 says to
 * "Generate a serverChallenge", the same verb it uses for transactionId,
 * and this function does so with real entropy. Unlike transactionId,
 * nothing about session replay depends on serverChallenge being
 * caller-supplied (see include/rsp.h's own note on why transactionId
 * is), so it is generated the way the spec actually describes, not
 * threaded through as another parameter.
 */
#include "rsp.h"
#include "rsp_internal.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/x509_crt.h"

#include "AuthenticateClientResponseEs9.h"
#include "AuthenticateServerResponse.h"
#include "Certificate.h"
#include "EUICCInfo1.h"
#include "EUICCSigned2.h"
#include "EuiccSigned1.h"
#include "InitiateAuthenticationOkEs9.h"
#include "PrepareDownloadResponse.h"
#include "ServerSigned1.h"
#include "SmdpSigned2.h"
#include "ber_tlv_length.h"
#include "ber_tlv_tag.h"
#include "NotificationMetadata.h"
#include "OtherSignedNotification.h"
#include "ProfileInstallationResult.h"
#include "StoreMetadataRequest.h"

/* Fold ASCII case only, for section 5.6.1's address comparison.
 * Deliberately not strcasecmp: that folds according to the locale, and a
 * host name is not locale-dependent text -- a Turkish locale maps 'I' to
 * a dotless lowercase, which would make two equal FQDNs compare unequal.
 * Returns 1 when equal. */
static int
ascii_ieq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        unsigned char ca = (unsigned char)*a, cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return *a == '\0' && *b == '\0';
}

/* One RSP session's server-side state -- see the typedef's own doc
 * comment in rsp.h. transactionId and both challenges cross the wire in
 * the clear; the session keys rsp_dp_get_bound_profile_package lands in
 * bpp_session are the first genuinely secret thing here, which is why
 * rsp_dp_session_free's wipe -- present from Task 2 onward, ahead of any
 * task actually needing it -- is now load-bearing rather than merely
 * precautionary. */
struct rsp_dp_session {
    uint8_t transaction_id[16];
    uint8_t euicc_challenge[16];
    uint8_t server_challenge[16];

    /* Set once rsp_dp_authenticate_client succeeds; rsp_dp_get_bound_
       profile_package refuses to run without it -- 5.6.2 assumes 5.6.3's
       own "Attach the PK.EUICC.ECDSA to the ongoing RSP session" already
       happened. euicc_cert_der is CERT.EUICC.ECDSA's DER, malloc'ed, kept
       so euiccSignature2 (5.6.2) can be verified against the same
       certificate 5.6.3 already chained to CERT.EUM -- not secret (it is
       a certificate), so rsp_dp_session_free frees it but does not wipe
       it, the same as rsp_credential_t.der elsewhere in this project.
       eid is the decimal digit string extracted from that certificate's
       Subject serialNumber -- see this file's own top comment for why it
       does not come from euiccSigned1. */
    int authenticated;
    uint8_t *euicc_cert_der;
    size_t euicc_cert_der_len;
    char eid[32];
    size_t eid_len;

    /* rsp_dp_authenticate_client's own metadata parameter, kept whole:
       the caller's encoded StoreMetadataRequest, malloc'ed here, for
       rsp_dp_get_bound_profile_package's own rsp_bpp_input_t. One
       caller-supplied value reused, rather than asking for it a second
       time in a second call that could drift from the first.

       Kept as bytes rather than as the three fields this used to pull out
       of it (iccid, profileName, serviceProviderName). Those three were
       enough to rebuild a StoreMetadataRequest, and a rebuild is exactly
       the problem: everything else the caller had encoded --
       profileClass, iconType/icon, notificationConfigurationInfo,
       profileOwner, profilePolicyRules -- was dropped on the way into the
       BPP's '88' group, while AuthenticateClient's own profileMetaData
       echoed the caller's full version back. The eUICC and whatever the
       LPA showed a person therefore disagreed about the same Profile.
       See include/rsp.h's comment on rsp_bpp_input_t.metadata. */
    uint8_t *metadata;
    size_t   metadata_len;

    /* smdpSignature2 exactly as this session's own AuthenticateClient
       produced it. The eUICC computes euiccSignature2 "over euiccSigned2
       and smdpSignature2" (SGP.22 v2.6 section 3.1.3.2's own procedure
       text, step 3), so verifying it in rsp_dp_get_bound_profile_package
       needs these 64 bytes back -- and they cannot be recomputed there:
       rsp_sign is deterministic, but smdpSigned2's own encoding is not
       kept, and re-deriving it would be a second construction that could
       drift from the one actually sent. Valid only while `authenticated`
       is set. Not secret -- it crossed the wire in the clear. */
    uint8_t smdp_signature2[64];

    /* Set once rsp_dp_get_bound_profile_package succeeds. Secret. */
    int have_bpp_session;
    rsp_session_t bpp_session;
};

/* der_encode's callback interface, and a malloc'ed-buffer wrapper around
 * it. This is deliberately a second copy of src/rsp_bpp.c's own
 * der_encode_alloc/der_collect, not a shared one promoted to
 * rsp_internal.h: that header is also included, unchanged, by
 * euicc-lpa's src/rsp_es10.c through the vendored submodule, and this
 * pair's bodies name asn_TYPE_descriptor_t/der_encode/asn_enc_rval_t --
 * types this header does not otherwise pull in. Adding them to a header
 * every includer already compiles risks breaking euicc-lpa's build over
 * a tidiness gain confined to this one file; rsp_growbuf_t (which this
 * does reuse) has no such dependency, which is exactly why it, and only
 * it, already lives in rsp_internal.h. */
static int der_collect(const void *buf, size_t n, void *key)
{
    return rsp_growbuf_append((rsp_growbuf_t *)key, buf, n) == 0 ? 0 : -1;
}

static int der_encode_alloc(asn_TYPE_descriptor_t *td, const void *sptr,
                             uint8_t **out, size_t *out_len)
{
    rsp_growbuf_t g;
    asn_enc_rval_t r;

    memset(&g, 0, sizeof g);
    r = der_encode(td, sptr, der_collect, &g);
    if (r.encoded < 0) {
        rsp_growbuf_free(&g);
        return -1;
    }
    *out = g.buf;
    *out_len = g.len;
    return 0;
}

int rsp_dp_initiate_authentication(
        const uint8_t *euicc_challenge, size_t challenge_len,
        const uint8_t *euicc_info1, size_t info1_len,
        const uint8_t transaction_id[16],
        const uint8_t server_challenge[16],
        const char *server_address,
        const char *requested_address,
        rsp_dp_session_t **out,
        uint8_t **resp, size_t *resp_len)
{
    InitiateAuthenticationOkEs9_t ok;
    EUICCInfo1_t info1_tmp;
    rsp_credential_t dpauth;
    mbedtls_x509_crt ci_crt;
    const uint8_t *ci_der;
    size_t ci_len;
    uint8_t *ss1_der = NULL;
    size_t ss1_der_len = 0;
    uint8_t sig[64];
    int have_dpauth = 0;
    /* -2 by default: every goto out below is a question never reached.
     * The one genuine refusal -- the section 5.6.1 address check -- sets
     * -1 for itself, explicitly, just below. */
    int ret = -2;

    memset(&ok, 0, sizeof ok);
    memset(&info1_tmp, 0, sizeof info1_tmp);
    memset(&dpauth, 0, sizeof dpauth);
    mbedtls_x509_crt_init(&ci_crt);

    if (!euicc_challenge || challenge_len != 16 || !euicc_info1 ||
        info1_len == 0 || !transaction_id || !server_challenge ||
        !server_address ||
        !out || !resp || !resp_len) {
        goto out;
    }

    /* Section 5.6.1: "Check if the received address matches its own
     * SM-DP+ address, where the comparison SHALL be case-insensitive."
     * This is the only thing this function can genuinely refuse, and it
     * is checked before anything is allocated, seeded or signed --
     * InitiateAuthenticationError.invalidDpAddress(1) on the wire. A
     * NULL requested_address is a caller that received no address to
     * check, not a mismatch. */
    if (requested_address && !ascii_ieq(server_address, requested_address)) {
        ret = -1;
        goto out;
    }

    /* Reject euiccInfo1 that does not even decode -- Table 35 marks it
     * mandatory, and a caller boundary is exactly where garbage input
     * should be refused rather than silently ignored. Not otherwise
     * used: this library has only one CI to offer (see this file's top
     * comment), so euiccInfo1's own CI-Public-Key-ID lists have nothing
     * to select among yet, and its eUICC identity fields are what a
     * later step's euiccSigned1/euiccInfo2 learns, not this one. */
    {
        void *p = &info1_tmp;
        asn_dec_rval_t r = ber_decode(NULL, &asn_DEF_EUICCInfo1, &p,
                                       euicc_info1, info1_len);
        if (r.code != RC_OK) {
            goto out;
        }
    }

    /* ServerSigned1, built directly inside ok: 5.7.13's "serverSignature1
     * SHALL apply on serverSigned1 data object" means the signed bytes
     * are ServerSigned1's own DER encoding -- exactly what encoding
     * ok.serverSigned1 alone, via its own type descriptor, produces
     * before the rest of ok is filled in. ServerSigned1 carries no tag
     * of its own (rsp-2.5.asn) and AUTOMATIC TAGS does not touch it as a
     * field either (InitiateAuthenticationOkEs9's own serverSignature1
     * member already carries an explicit [APPLICATION 55], which is
     * exactly the condition under which X.680 automatic tagging leaves
     * every sibling field's own natural tag alone) -- so this same
     * struct's encoding is byte-identical whether encoded here, alone,
     * or later as part of the whole ok. */
    if (OCTET_STRING_fromBuf(&ok.serverSigned1.transactionId,
                              (const char *)transaction_id, 16) != 0 ||
        OCTET_STRING_fromBuf(&ok.serverSigned1.euiccChallenge,
                              (const char *)euicc_challenge,
                              (int)challenge_len) != 0 ||
        OCTET_STRING_fromBuf(&ok.serverSigned1.serverAddress,
                              server_address,
                              (int)strlen(server_address)) != 0 ||
        OCTET_STRING_fromBuf(&ok.serverSigned1.serverChallenge,
                              (const char *)server_challenge, 16) != 0) {
        goto out;
    }

    if (der_encode_alloc(&asn_DEF_ServerSigned1, &ok.serverSigned1,
                          &ss1_der, &ss1_der_len) != 0) {
        goto out;
    }

    if (rsp_pki_dp(0, &dpauth) != 0) { /* DPauth, not DPpb -- see top comment */
        goto out;
    }
    have_dpauth = 1;

    if (rsp_sign(&dpauth, ss1_der, ss1_der_len, sig) != 0) {
        goto out;
    }

    if (rsp_pki_test_ci(&ci_der, &ci_len) != 0) {
        goto out;
    }
    if (mbedtls_x509_crt_parse_der_with_ext_cb(&ci_crt, ci_der, ci_len, 1,
                                                rsp_accept_certificate_policies,
                                                NULL) != 0) {
        goto out;
    }
    if (ci_crt.subject_key_id.len == 0) {
        goto out; /* the compiled-in test CI is expected to carry one */
    }

    if (OCTET_STRING_fromBuf(&ok.transactionId,
                              (const char *)transaction_id, 16) != 0 ||
        OCTET_STRING_fromBuf(&ok.serverSignature1,
                              (const char *)sig, sizeof sig) != 0 ||
        OCTET_STRING_fromBuf(&ok.euiccCiPKIdToBeUsed,
                              (const char *)ci_crt.subject_key_id.p,
                              (int)ci_crt.subject_key_id.len) != 0) {
        goto out;
    }

    /* Decode CERT.DPauth.ECDSA's own DER (already loaded, already what
     * was just signed with) into ok.serverCertificate in place: passing
     * a non-NULL *struct_ptr makes every asn1c SEQUENCE decoder (see
     * dist/constr_SEQUENCE.c: "st = *struct_ptr; if (st == 0) { st =
     * *struct_ptr = CALLOC(...); }") fill the memory already there
     * instead of allocating a new one -- ok.serverCertificate, already
     * zeroed above, is exactly such memory. No separate certificate
     * struct, no shallow copy, no second free to keep straight. */
    {
        void *p = &ok.serverCertificate;
        asn_dec_rval_t r = ber_decode(NULL, &asn_DEF_Certificate, &p,
                                       dpauth.der, dpauth.der_len);
        if (r.code != RC_OK) {
            goto out;
        }
    }

    if (der_encode_alloc(&asn_DEF_InitiateAuthenticationOkEs9, &ok,
                          resp, resp_len) != 0) {
        goto out;
    }

    {
        rsp_dp_session_t *sess = malloc(sizeof *sess);
        if (!sess) {
            free(*resp);
            *resp = NULL;
            *resp_len = 0;
            goto out;
        }
        memcpy(sess->transaction_id, transaction_id, 16);
        memcpy(sess->euicc_challenge, euicc_challenge, 16);
        memcpy(sess->server_challenge, server_challenge, 16);
        *out = sess;
    }

    ret = 0;

out:
    if (have_dpauth) {
        rsp_credential_free(&dpauth);
    }
    mbedtls_x509_crt_free(&ci_crt);
    ASN_STRUCT_RESET(asn_DEF_EUICCInfo1, &info1_tmp);
    ASN_STRUCT_RESET(asn_DEF_InitiateAuthenticationOkEs9, &ok);
    free(ss1_der);
    return ret;
}

void rsp_dp_session_free(rsp_dp_session_t *s)
{
    if (!s) {
        return;
    }
    free(s->euicc_cert_der);
    free(s->metadata);
    rsp_session_wipe(&s->bpp_session);
    mbedtls_platform_zeroize(s, sizeof *s);
    free(s);
}

/* CERT.EUICC.ECDSA's Subject 'serialNumber' attribute IS the EID (SGP.22
 * v2.6 section 4.5.1) -- see this file's own top comment for why that is
 * where this function looks, not euiccSigned1. Returns 0 and the raw
 * decimal digit bytes (never NUL-terminated) copied into out, or -1 if
 * crt's subject carries no serialNumber attribute at all, or the one it
 * carries does not fit cap. */
static int extract_eid(const mbedtls_x509_crt *crt, char *out, size_t cap,
                        size_t *out_len)
{
    const mbedtls_x509_name *n;

    for (n = &crt->subject; n; n = n->next) {
        if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_SERIAL_NUMBER, &n->oid) == 0) {
            if (n->val.len == 0 || n->val.len > cap) {
                return -1;
            }
            memcpy(out, n->val.p, n->val.len);
            *out_len = n->val.len;
            return 0;
        }
    }
    return -1;
}

int rsp_dp_authenticate_client(rsp_dp_session_t *s,
        const uint8_t *auth_server_resp, size_t resp_len,
        const uint8_t *metadata, size_t metadata_len,
        uint8_t **out, size_t *out_len)
{
    /* Declared once, referenced from the extern-declaring TU that already
       carries its definition (build/sgp26_material.c, generated from
       testdata/sgp26/ci-2017.der) -- see rsp_pki.c's own identically-
       shaped externs for rsp_sgp26_ci_der and friends. Not exposed via
       rsp.h: this is a same-project-only quirk (two certificate objects
       for one CI key -- see testdata/sgp26/README.md), not something a
       caller of this library needs to know about. */
    extern const unsigned char rsp_sgp26_ci2017_der[];
    extern const unsigned int rsp_sgp26_ci2017_der_len;

    AuthenticateServerResponse_t resp;
    StoreMetadataRequest_t md_tmp;
    AuthenticateClientResponseEs9_t ok_resp;
    mbedtls_x509_crt ci, eum, euicc;
    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context drbg;
    const uint8_t *ci_der;
    size_t ci_len;
    uint8_t *es1_der = NULL;
    size_t es1_der_len = 0;
    uint8_t *eum_der_buf = NULL;
    size_t eum_der_buf_len = 0;
    uint8_t *euicc_der_buf = NULL;
    size_t euicc_der_buf_len = 0;
    uint8_t sig[64];
    rsp_credential_t dppb;
    char eid_buf[32];
    size_t eid_len = 0;
    int have_dppb = 0;
    int have_rng = 0;
    int ret = -2;

    memset(&resp, 0, sizeof resp);
    memset(&md_tmp, 0, sizeof md_tmp);
    memset(&ok_resp, 0, sizeof ok_resp);
    memset(&dppb, 0, sizeof dppb);
    mbedtls_x509_crt_init(&ci);
    mbedtls_x509_crt_init(&eum);
    mbedtls_x509_crt_init(&euicc);

    if (!s || !auth_server_resp || resp_len == 0 ||
        !metadata || metadata_len == 0 || !out || !out_len) {
        goto out;
    }

    /* metadata: an encoded StoreMetadataRequest -- see this file's own top
       comment for why this function's own parameter is where that comes
       from. Decoded, not merely accepted as opaque bytes, so garbage is
       refused here rather than forwarded into the response unexamined,
       and so iccid/profileName/serviceProviderName can be pulled out for
       *s below. */
    {
        void *p = &md_tmp;
        asn_dec_rval_t r = ber_decode(NULL, &asn_DEF_StoreMetadataRequest,
                                       &p, metadata, metadata_len);
        if (r.code != RC_OK) {
            goto out;
        }
    }
    if (md_tmp.iccid.size != 10 ||
        md_tmp.profileName.size > 64 ||
        md_tmp.serviceProviderName.size > 32) {
        goto out;
    }

    /* The eUICC's own AuthenticateServerResponse (5.7.13's response,
       relayed here as ES9+.AuthenticateClient's own authenticateServer-
       Response input, Table 41). Only the authenticateResponseOk arm is
       this function's business -- an authenticateResponseError arm is
       something the LPA has already seen for itself and would have no
       reason to relay into a call it expects to succeed. */
    {
        void *p = &resp;
        asn_dec_rval_t r = ber_decode(NULL, &asn_DEF_AuthenticateServerResponse,
                                       &p, auth_server_resp, resp_len);
        if (r.code != RC_OK) {
            goto out;
        }
    }
    if (resp.present != AuthenticateServerResponse_PR_authenticateResponseOk) {
        goto out;
    }

    {
        AuthenticateResponseOk_t *rok = &resp.choice.authenticateResponseOk;

        /* 5.6.3: "Verify that the transactionId is known and relates to
           an ongoing RSP session." */
        if (rok->euiccSigned1.transactionId.size != 16 ||
            memcmp(rok->euiccSigned1.transactionId.buf,
                   s->transaction_id, 16) != 0) {
            ret = -1;
            goto out;
        }

        /* 5.6.3: "Verify that the serverChallenge attached to the ongoing
           RSP session matches the serverChallenge returned by the
           eUICC." */
        if (rok->euiccSigned1.serverChallenge.size != 16 ||
            memcmp(rok->euiccSigned1.serverChallenge.buf,
                   s->server_challenge, 16) != 0) {
            ret = -1;
            goto out;
        }

        have_rng = rsp_rng_init(&ent, &drbg, "euicc-rsp/rsp_es9") == 0;
        if (!have_rng) {
            goto out;
        }

        /* eumCertificate/euiccCertificate arrived as generic Certificate_t
           (the PKIX1Explicit88 SEQUENCE -- unaffected by src/rsp_bpp.c's
           SEQUENCE-OF-tagged-element defect, which only afflicts
           BoundProfilePackage's own four fields), decoded as part of
           `resp` above. Re-encoded here to get back plain DER bytes
           mbedTLS's own X.509 parser can read -- the same technique
           rsp_dp_initiate_authentication already uses in the opposite
           direction for ok.serverCertificate. */
        if (der_encode_alloc(&asn_DEF_Certificate, &rok->eumCertificate,
                              &eum_der_buf, &eum_der_buf_len) != 0) {
            goto out;
        }
        if (der_encode_alloc(&asn_DEF_Certificate, &rok->euiccCertificate,
                              &euicc_der_buf, &euicc_der_buf_len) != 0) {
            goto out;
        }

        if (rsp_pki_test_ci(&ci_der, &ci_len) != 0) {
            goto out;
        }
        /* Both certificate objects for the one test CI key this project
           compiles in, so CERT.EUM's chain check has a trust anchor whose
           issuer/subject Name actually matches -- see testdata/sgp26/
           README.md's "why a second CI certificate exists" for why two
           are needed here and not anywhere else in this library. */
        if (mbedtls_x509_crt_parse_der_with_ext_cb(
                &ci, ci_der, ci_len, 1,
                rsp_accept_certificate_policies_and_name_constraints,
                NULL) != 0) {
            goto out;
        }
        if (mbedtls_x509_crt_parse_der_with_ext_cb(
                &ci, rsp_sgp26_ci2017_der, rsp_sgp26_ci2017_der_len, 1,
                rsp_accept_certificate_policies_and_name_constraints,
                NULL) != 0) {
            goto out;
        }

        if (mbedtls_x509_crt_parse_der_with_ext_cb(
                &eum, eum_der_buf, eum_der_buf_len, 1,
                rsp_accept_certificate_policies_and_name_constraints,
                NULL) != 0) {
            goto out;
        }
        if (mbedtls_x509_crt_parse_der_with_ext_cb(
                &euicc, euicc_der_buf, euicc_der_buf_len, 1,
                rsp_accept_certificate_policies_and_name_constraints,
                NULL) != 0) {
            goto out;
        }

        /* 5.6.3: "Verify the validity of the CERT.EUM.ECDSA, using the
           related public key PK.CI.ECDSA." */
        {
            uint32_t flags = 0;
            if (mbedtls_x509_crt_verify(&eum, &ci, NULL, NULL, &flags,
                                         NULL, NULL) != 0) {
                ret = -1; /* the question was asked: CERT.EUM does not chain */
                goto out;
            }
        }

        /* 5.6.3: "Verify the validity of the CERT.EUICC.ECDSA, using the
           public key PK.EUM.ECDSA." */
        {
            uint32_t flags = 0;
            if (mbedtls_x509_crt_verify(&euicc, &eum, NULL, NULL, &flags,
                                         NULL, NULL) != 0) {
                ret = -1; /* the question was asked: CERT.EUICC does not chain */
                goto out;
            }
        }

        /* 5.6.3 / 5.7.13: "Verify the eUICC signature (euiccSignature1)
           using the PK.EUICC.ECDSA" -- "euiccSignature1 SHALL apply on
           euiccSigned1 data object." */
        if (der_encode_alloc(&asn_DEF_EuiccSigned1, &rok->euiccSigned1,
                              &es1_der, &es1_der_len) != 0) {
            goto out;
        }
        if (rok->euiccSignature1.size != 64) {
            goto out;
        }
        {
            int vr = rsp_sign_verify(euicc_der_buf, euicc_der_buf_len,
                                      es1_der, es1_der_len,
                                      rok->euiccSignature1.buf);
            if (vr != 0) {
                ret = (vr == -1) ? -1 : -2;
                goto out;
            }
        }

        /* The EID, from CERT.EUICC.ECDSA's own Subject, not from
           euiccSigned1 -- see this file's own top comment. */
        if (extract_eid(&euicc, eid_buf, sizeof eid_buf, &eid_len) != 0) {
            goto out;
        }
    }

    /* Every verification above passed without touching *s or *out --
       build the response now. */
    if (OCTET_STRING_fromBuf(
            &ok_resp.choice.authenticateClientOk.transactionId,
            (const char *)s->transaction_id, 16) != 0) {
        goto out;
    }
    /* profileMetaData: re-decode metadata straight into place -- the same
       in-place-decode technique rsp_dp_initiate_authentication already
       uses for ok.serverCertificate. md_tmp above is a separate,
       already-populated copy this function keeps for its own stashing
       into *s below; decoding the same bytes twice is simpler than
       deep-copying asn1c's own generated struct. */
    {
        void *p = &ok_resp.choice.authenticateClientOk.profileMetaData;
        asn_dec_rval_t r = ber_decode(NULL, &asn_DEF_StoreMetadataRequest,
                                       &p, metadata, metadata_len);
        if (r.code != RC_OK) {
            goto out;
        }
    }

    if (OCTET_STRING_fromBuf(
            &ok_resp.choice.authenticateClientOk.smdpSigned2.transactionId,
            (const char *)s->transaction_id, 16) != 0) {
        goto out;
    }
    /* ccRequiredFlag: false -- this stateless library has no Confirmation
       Code state to require one. bppEuiccOtpk: OPTIONAL, left absent --
       this is not a re-bind of a previously-generated BPP (5.6.2's own
       "if the Bound Profile Package has been previously generated for
       this eUICC" case; rsp_bpp_input_t has nothing that models "already
       generated" either). */
    ok_resp.choice.authenticateClientOk.smdpSigned2.ccRequiredFlag = 0;

    {
        uint8_t *sd2_der = NULL;
        size_t sd2_der_len = 0;
        uint8_t *tbs = NULL;
        size_t tbs_len = 0;
        int enc_rc = der_encode_alloc(
                &asn_DEF_SmdpSigned2,
                &ok_resp.choice.authenticateClientOk.smdpSigned2,
                &sd2_der, &sd2_der_len);
        /* smdpSignature2 covers smdpSigned2 AND the eUICC's own
           euiccSignature1 from the AuthenticateServer response just
           verified above -- "Compute the smdpSignature2 over smdpSigned2
           and euiccSignature1 using the SK.DPpb.ECDSA" (SGP.22 v2.6
           section 3.1.3, step 5; 5.6.3's own function description does
           not restate it, which is how signing smdpSigned2 alone survived
           here for as long as it did). A real eUICC answers PrepareDownload
           with downloadErrorCode invalidSignature(2) to the shorter
           version, and the concatenation is not a formality: it is the
           signature chaining that stops one party's message or signature
           being lifted out and replayed under the other's.

           euiccSignature1 goes in as its own encoded TLV, tag '5F37'
           ([APPLICATION 55], rsp-2.5.asn's own annotation on the field) --
           the same "each as its own encoded TLV" convention section 5.5.1
           uses for smdpSign, see src/rsp_bpp.c's build_isc_tbs. Its length
           is 64 and its short-form length octet is therefore a constant:
           the euiccSignature1.size != 64 check further up has already
           refused anything else before this point is reached. */
        if (enc_rc == 0) {
            const OCTET_STRING_t *es1 =
                &resp.choice.authenticateResponseOk.euiccSignature1;
            tbs_len = sd2_der_len + 3 + 64;
            tbs = malloc(tbs_len);
            if (!tbs) {
                enc_rc = -1;
            } else {
                memcpy(tbs, sd2_der, sd2_der_len);
                tbs[sd2_der_len + 0] = 0x5F;
                tbs[sd2_der_len + 1] = 0x37;
                tbs[sd2_der_len + 2] = 64;
                memcpy(tbs + sd2_der_len + 3, es1->buf, 64);
            }
        }
        if (enc_rc == 0) {
            /* DPpb, not DPauth: smdpSigned2/smdpSignature2 bind the
               Profile Package (SGP.22 v2.6 section 2.6.4 -- "the SM-DP+
               plays the role of the OCE" for Profile Protection),
               CERT.DPpb.ECDSA's own purpose, not CERT.DPauth.ECDSA's
               (which already signed InitiateAuthentication's
               serverSigned1 -- see this file's top comment). Getting
               these two backwards is the mistake this project's own
               brief calls out as most worth catching. */
            enc_rc = rsp_pki_dp(1, &dppb);
        }
        if (enc_rc == 0) {
            have_dppb = 1;
            enc_rc = rsp_sign(&dppb, tbs, tbs_len, sig);
        }
        free(sd2_der);
        free(tbs);
        if (enc_rc != 0) {
            goto out;
        }
    }
    if (OCTET_STRING_fromBuf(
            &ok_resp.choice.authenticateClientOk.smdpSignature2,
            (const char *)sig, sizeof sig) != 0) {
        goto out;
    }
    {
        void *p = &ok_resp.choice.authenticateClientOk.smdpCertificate;
        asn_dec_rval_t r = ber_decode(NULL, &asn_DEF_Certificate, &p,
                                       dppb.der, dppb.der_len);
        if (r.code != RC_OK) {
            goto out;
        }
    }
    ok_resp.present = AuthenticateClientResponseEs9_PR_authenticateClientOk;

    if (der_encode_alloc(&asn_DEF_AuthenticateClientResponseEs9, &ok_resp,
                          out, out_len) != 0) {
        goto out;
    }

    /* *s changes only now, after everything above -- including the final
       encoding -- has actually succeeded, so a failing call leaves *s
       exactly as it was. */
    {
        uint8_t *cert_copy = malloc(euicc_der_buf_len);
        /* Both copies are taken before either is committed, so a failure
           to allocate the second cannot leave *s holding the first --
           this block's whole point is that a failing call leaves *s
           exactly as it was. */
        uint8_t *md_copy = malloc(metadata_len);
        if (!cert_copy || !md_copy) {
            free(cert_copy);
            free(md_copy);
            free(*out);
            *out = NULL;
            *out_len = 0;
            goto out;
        }
        memcpy(cert_copy, euicc_der_buf, euicc_der_buf_len);
        free(s->euicc_cert_der);
        s->euicc_cert_der = cert_copy;
        s->euicc_cert_der_len = euicc_der_buf_len;

        memcpy(s->eid, eid_buf, eid_len);
        s->eid_len = eid_len;

        /* The caller's metadata, whole and unmodified -- see this
           struct's own comment on the field. */
        memcpy(md_copy, metadata, metadata_len);
        free(s->metadata);
        s->metadata = md_copy;
        s->metadata_len = metadata_len;

        /* sig still holds smdpSignature2 from the signing block above --
           what the eUICC will fold into euiccSignature2, and what
           rsp_dp_get_bound_profile_package therefore has to verify over.
           Stashed here, with the rest of this function's success state,
           so a failure leaves *s untouched as this function's contract
           in rsp.h promises. */
        memcpy(s->smdp_signature2, sig, sizeof s->smdp_signature2);

        s->authenticated = 1;
    }

    ret = 0;

out:
    if (have_dppb) {
        rsp_credential_free(&dppb);
    }
    if (have_rng) {
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
    }
    mbedtls_x509_crt_free(&ci);
    mbedtls_x509_crt_free(&eum);
    mbedtls_x509_crt_free(&euicc);
    free(eum_der_buf);
    free(euicc_der_buf);
    free(es1_der);
    ASN_STRUCT_RESET(asn_DEF_AuthenticateServerResponse, &resp);
    ASN_STRUCT_RESET(asn_DEF_StoreMetadataRequest, &md_tmp);
    ASN_STRUCT_RESET(asn_DEF_AuthenticateClientResponseEs9, &ok_resp);
    return ret;
}

int rsp_dp_session_eid(const rsp_dp_session_t *s,
        uint8_t *eid, size_t eid_cap, size_t *eid_len)
{
    if (!s || !eid || !eid_len) {
        return -2;
    }
    if (!s->authenticated || s->eid_len == 0 || s->eid_len > eid_cap) {
        return -1; /* the question was asked: no EID this session actually has */
    }
    memcpy(eid, s->eid, s->eid_len);
    *eid_len = s->eid_len;
    return 0;
}

/* otPK.DP.ECKA, the public counterpart of otsk_dp: standard EC scalar
 * multiplication by the curve's base point, the same primitive
 * src/rsp_pki.c already uses (there, to confirm a loaded rsp_credential_t's
 * sk matches its own certificate's public key) -- not a new kind of crypto
 * this project has not already trusted, just a new caller of it. Needed
 * because whoever the SM-DP+ tells its one-time secret key to must also
 * be told the matching public one: InitialiseSecureChannelRequest.smdpOtpk
 * is that public key, and rsp_bpp_input_t has no other source for it.
 * Returns 0, or -1 on any mbedTLS failure (RNG seeding, an invalid scalar,
 * point encoding). */
static int derive_public_key(const uint8_t sk[32], uint8_t pk[65])
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi d;
    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context drbg;
    size_t olen = 0;
    int rng_ok;
    int ret = -1;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&d);
    rng_ok = rsp_rng_init(&ent, &drbg, "euicc-rsp/rsp_es9") == 0;

    if (rng_ok &&
        mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_mpi_read_binary(&d, sk, 32) == 0 &&
        mbedtls_ecp_mul(&grp, &q, &d, &grp.G, mbedtls_ctr_drbg_random,
                         &drbg) == 0 &&
        mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &olen, pk, 65) == 0 &&
        olen == 65) {
        ret = 0;
    }

    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    if (rng_ok) {
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
    }
    return ret;
}

/* Annex G's SharedInfo: keyType(1) || keyLen(1) || HostID-LV || EID-LV --
 * "LV" meaning a one-byte length followed by the value, which is all
 * either field ever needs here (host_id_len is RSP_HOST_ID_LEN, a small
 * compile-time constant; eid_len is at most 32, EUICCInfo1's own EID
 * digit count). Returns 0, or -1 if either length does not fit one byte
 * (never true for this file's own callers) or the assembled SharedInfo
 * does not fit out_cap. */
/* The EID as Annex G's SharedInfo wants it: sixteen octets, not the
   thirty-two decimal characters this session carries.
 *
 * rsp_dp_authenticate_client learns the EID from CERT.EUICC.ECDSA's
 * Subject 'serialNumber', where section 4.5.1 defines it as "the EID as a
 * decimal PrintableString" -- so s->eid holds ASCII digits, which is also
 * what rsp_dp_session_eid hands a caller back and what a person reads.
 * The eUICC's own copy is eidValue, "[APPLICATION 26] Octet16"
 * (rsp-2.5.asn), sixteen binary octets, and that is what it derives its
 * half of the session over. Feeding the digit string into SharedInfo
 * instead makes both the length octet and every value octet differ, so
 * the two sides derive different S-ENC/S-MAC and the first MAC'd element
 * of the Bound Profile Package -- '87', ConfigureISDP -- comes back as
 * errorReason scp03tSecurityError(8) in a ProfileInstallationResult. The
 * InitialiseSecureChannelRequest ahead of it still passes, because that
 * one is signed rather than MAC'd, which is what makes this failure land
 * one element later than its cause.
 *
 * Two decimal digits pack into one octet, most significant nibble first.
 * Returns 0, or -1 if the digit string is not exactly 2*out_cap digits or
 * holds anything but digits. */
static int eid_digits_to_octets(const char *eid, size_t eid_len,
                                 uint8_t *out, size_t out_cap)
{
    size_t i;

    if (eid_len != out_cap * 2) {
        return -1;
    }
    for (i = 0; i < out_cap; i++) {
        char hi = eid[2 * i], lo = eid[2 * i + 1];
        if (hi < '0' || hi > '9' || lo < '0' || lo > '9') {
            return -1;
        }
        out[i] = (uint8_t)(((hi - '0') << 4) | (lo - '0'));
    }
    return 0;
}

static int build_shared_info(const uint8_t *host_id, size_t host_id_len,
                              const uint8_t *eid, size_t eid_len,
                              uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t n = 2 + 1 + host_id_len + 1 + eid_len;

    if (host_id_len > 0xFF || eid_len > 0xFF || n > out_cap) {
        return -1;
    }
    out[0] = 0x88; /* AES key type, GlobalPlatform Card Specification Table 11-16 */
    out[1] = 0x10; /* key length, 16 bytes -- rsp-2.5.asn's own fixed value */
    out[2] = (uint8_t)host_id_len;
    memcpy(out + 3, host_id, host_id_len);
    out[3 + host_id_len] = (uint8_t)eid_len;
    memcpy(out + 3 + host_id_len + 1, eid, eid_len);
    *out_len = n;
    return 0;
}

int rsp_dp_get_bound_profile_package(rsp_dp_session_t *s,
        const uint8_t *prepare_download_resp, size_t resp_len,
        const uint8_t *upp, size_t upp_len,
        const uint8_t otsk_dp[32],
        uint8_t **bpp, size_t *bpp_len)
{
    PrepareDownloadResponse_t resp;
    rsp_session_t session;
    rsp_bpp_input_t in;
    uint8_t otpk_dp[65];
    uint8_t shared_info[2 + 1 + RSP_HOST_ID_LEN + 1 + 32];
    size_t shared_info_len = 0;
    uint8_t *es2_der = NULL;
    size_t es2_der_len = 0;
    rsp_credential_t dppb; /* smdpSign (section 5.5.1), inside rsp_bpp_build's
                               own build_isc -- DPpb, never DPauth, the same
                               distinction rsp_dp_authenticate_client's own
                               top comment already makes for smdpSignature2. */
    int have_dppb = 0;
    int ret = -2;

    memset(&resp, 0, sizeof resp);
    memset(&session, 0, sizeof session);
    memset(&dppb, 0, sizeof dppb);

    if (!s || !prepare_download_resp || resp_len == 0 ||
        !upp || upp_len == 0 || !otsk_dp || !bpp || !bpp_len) {
        goto out;
    }
    /* 5.6.2 presumes 5.6.3 already ran -- "the PK.EUICC.ECDSA attached to
       the ongoing RSP session" has to have gotten there somehow. */
    if (!s->authenticated) {
        goto out;
    }

    {
        void *p = &resp;
        asn_dec_rval_t r = ber_decode(NULL, &asn_DEF_PrepareDownloadResponse,
                                       &p, prepare_download_resp, resp_len);
        if (r.code != RC_OK) {
            goto out;
        }
    }
    if (resp.present != PrepareDownloadResponse_PR_downloadResponseOk) {
        goto out;
    }

    {
        PrepareDownloadResponseOk_t *rok = &resp.choice.downloadResponseOk;

        /* 5.6.2: "Verify that the received transactionId is known and
           relates to an ongoing RSP session." */
        if (rok->euiccSigned2.transactionId.size != 16 ||
            memcmp(rok->euiccSigned2.transactionId.buf,
                   s->transaction_id, 16) != 0) {
            ret = -1;
            goto out;
        }

        /* 5.6.2: "Verify the eUICC signature (euiccSignature2) using the
           PK.EUICC.ECDSA attached to the ongoing RSP session" -- attached
           by rsp_dp_authenticate_client, above.

           That bullet says which key; the procedure text says over what,
           and it is not euiccSigned2 alone: "the SM-DP+ SHALL verify the
           euiccSignature2 performed over euiccSigned2 and
           smdpSignature2" (3.1.3.2, step 6; the eUICC's own side of it is
           step 3, "Compute the euiccSignature2 over euiccSigned2 and
           smdpSignature2"). Verifying over euiccSigned2 alone rejects
           every signature a conformant eUICC produces -- the mirror image
           of the smdpSignature2 construction in rsp_dp_authenticate_
           client, and the same signature chaining: each side signs the
           other's last signature, so neither message can be lifted out
           and replayed against a different one.

           smdpSignature2 goes in as its own TLV, tag '5F37'
           ([APPLICATION 55]), the same convention used there. */
        if (der_encode_alloc(&asn_DEF_EUICCSigned2, &rok->euiccSigned2,
                              &es2_der, &es2_der_len) != 0) {
            goto out;
        }
        if (rok->euiccSignature2.size != 64) {
            goto out;
        }
        {
            size_t tbs_len = es2_der_len + 3 + 64;
            uint8_t *tbs = malloc(tbs_len);
            int vr;
            if (!tbs) {
                goto out;
            }
            memcpy(tbs, es2_der, es2_der_len);
            tbs[es2_der_len + 0] = 0x5F;
            tbs[es2_der_len + 1] = 0x37;
            tbs[es2_der_len + 2] = 64;
            memcpy(tbs + es2_der_len + 3, s->smdp_signature2, 64);

            vr = rsp_sign_verify(s->euicc_cert_der, s->euicc_cert_der_len,
                                  tbs, tbs_len,
                                  rok->euiccSignature2.buf);
            free(tbs);
            if (vr != 0) {
                ret = (vr == -1) ? -1 : -2;
                goto out;
            }
        }

        /* otPK.EUICC.ECKA: an uncompressed P-256 point, 65 bytes. */
        if (rok->euiccSigned2.euiccOtpk.size != 65) {
            goto out;
        }

        {
            uint8_t eid_octets[16];
            if (eid_digits_to_octets(s->eid, s->eid_len,
                                      eid_octets, sizeof eid_octets) != 0) {
                goto out;
            }
            if (build_shared_info(RSP_HOST_ID, RSP_HOST_ID_LEN,
                                   eid_octets, sizeof eid_octets,
                                   shared_info, sizeof shared_info,
                                   &shared_info_len) != 0) {
                goto out;
            }
        }
        if (rsp_session_init(otsk_dp, rok->euiccSigned2.euiccOtpk.buf,
                              shared_info, shared_info_len, &session) != 0) {
            goto out;
        }
        if (derive_public_key(otsk_dp, otpk_dp) != 0) {
            goto out;
        }
    }

    if (rsp_pki_dp(1, &dppb) != 0) { /* DPpb, not DPauth -- see this file's top comment */
        goto out;
    }
    have_dppb = 1;

    memset(&in, 0, sizeof in);
    in.upp = upp;
    in.upp_len = upp_len;
    in.otpk_dp = otpk_dp;
    in.metadata = s->metadata;
    in.metadata_len = s->metadata_len;
    in.transaction_id = s->transaction_id;
    in.euicc_otpk = resp.choice.downloadResponseOk.euiccSigned2.euiccOtpk.buf;
    in.dppb = &dppb;

    if (rsp_bpp_build(&session, &in, bpp, bpp_len) != 0) {
        goto out;
    }

    rsp_session_wipe(&s->bpp_session); /* whatever was there before (a rebind, or nothing) */
    s->bpp_session = session;
    s->have_bpp_session = 1;
    ret = 0;

out:
    /* session is either still all-zero (never reached rsp_session_init),
       or a real key schedule that either failed later or was already
       copied into s->bpp_session above -- either way, this stack copy is
       done being read and gets wiped unconditionally, the same
       "wipe rather than reason about whether it is needed" rule
       rsp_growbuf_free already states for itself. */
    mbedtls_platform_zeroize(&session, sizeof session);
    if (have_dppb) {
        rsp_credential_free(&dppb);
    }
    free(es2_der);
    ASN_STRUCT_RESET(asn_DEF_PrepareDownloadResponse, &resp);
    return ret;
}

/* Locate one TLV's full extent -- tag, length octets and content -- at
 * `off` inside buf, checking it carries the tag `want`. Returns 0 and
 * describes the whole TLV through start and len, or -1.
 *
 * Needed because a signature is over bytes, and the only bytes that can
 * be verified are the ones that arrived. */
static int find_tlv(const uint8_t *buf, size_t buf_len, size_t off,
                     const uint8_t *want, size_t want_len,
                     size_t *start, size_t *len)
{
    ber_tlv_tag_t tag;
    ber_tlv_len_t content;
    ssize_t tl, ll;

    if (off > buf_len) return -1;
    tl = ber_fetch_tag(buf + off, buf_len - off, &tag);
    if (tl <= 0) return -1;
    if ((size_t)tl != want_len || memcmp(buf + off, want, want_len) != 0) {
        return -1;
    }
    ll = ber_fetch_length(BER_TLV_CONSTRUCTED(buf + off), buf + off + tl,
                           buf_len - off - (size_t)tl, &content);
    if (ll <= 0 || content < 0) return -1;
    if ((size_t)content > buf_len - off - (size_t)tl - (size_t)ll) return -1;
    *start = off;
    *len = (size_t)tl + (size_t)ll + (size_t)content;
    return 0;
}

/* See rsp.h for what this answers and why the two questions are kept
 * apart.
 *
 * The signed bytes are taken out of the caller's buffer, not re-encoded
 * from the decoded struct. SGP.22 v2.6 section 2.5.6 puts the signature
 * "across the data object ProfileInstallationResultData (tag 'BF 27')" --
 * that data object, as it arrived. An earlier version of this function
 * re-encoded it instead, which for DER produces the same bytes and so
 * appeared to work; but it verifies a reconstruction rather than the
 * thing that was signed, and the two part company the moment a card
 * sends anything the decoder normalizes -- a non-minimal length, say,
 * which BER permits and ber_decode accepts. A conformant card would then
 * have a genuine signature rejected. Slicing cannot drift that way: what
 * is verified is what came in. */
int rsp_dp_verify_installation_result(const rsp_dp_session_t *s,
        const uint8_t *pir, size_t pir_len,
        int *installed, long *bpp_command_id, long *error_reason)
{
    ProfileInstallationResult_t *r = NULL;
    uint8_t *data_der = NULL;
    size_t data_der_len = 0;
    int ret = -2;

    if (!s || !pir || pir_len == 0 || !installed) {
        return -2;
    }
    if (!s->authenticated || !s->euicc_cert_der) {
        return -2;
    }

    {
        asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_ProfileInstallationResult,
                                       (void **)&r, pir, pir_len);
        if (dr.code != RC_OK || !r) {
            goto out;
        }
    }

    ProfileInstallationResultData_t *d = &r->profileInstallationResultData;

    /* This session's download, or someone else's report. Checked before
       the signature for the same reason rsp_dp_authenticate_client checks
       its own transactionId first: it is a memcmp, and a caller who got
       the session wrong should not cost an RNG seed and an ECDSA
       verification to be told so. */
    if (d->transactionId.size != 16 ||
        memcmp(d->transactionId.buf, s->transaction_id, 16) != 0) {
        ret = -1;
        goto out;
    }

    if (r->euiccSignPIR.size != 64) {
        goto out;
    }
    /* profileInstallationResultData is ProfileInstallationResult's first
       member, so it begins immediately after the outer [55] header. Both
       tags are two octets ('BF 37', 'BF 27'): high-tag-number form, since
       55 and 39 do not fit the five bits of a single-octet tag. */
    {
        static const uint8_t tag_pir[2]  = { 0xBF, 0x37 };
        static const uint8_t tag_data[2] = { 0xBF, 0x27 };
        size_t outer_start = 0, outer_len = 0, hdr = 0;
        size_t data_off = 0;

        if (find_tlv(pir, pir_len, 0, tag_pir, sizeof tag_pir,
                      &outer_start, &outer_len) != 0) {
            goto out;
        }
        {
            ber_tlv_tag_t t;
            ber_tlv_len_t cl;
            ssize_t tl = ber_fetch_tag(pir, pir_len, &t);
            ssize_t ll;
            if (tl <= 0) goto out;
            ll = ber_fetch_length(BER_TLV_CONSTRUCTED(pir), pir + tl,
                                   pir_len - (size_t)tl, &cl);
            if (ll <= 0) goto out;
            hdr = (size_t)tl + (size_t)ll;
        }
        data_off = hdr;
        if (find_tlv(pir, pir_len, data_off, tag_data, sizeof tag_data,
                      &outer_start, &data_der_len) != 0) {
            goto out;
        }
        data_der = malloc(data_der_len);
        if (!data_der) {
            goto out;
        }
        memcpy(data_der, pir + outer_start, data_der_len);
    }
    {
        int vr = rsp_sign_verify(s->euicc_cert_der, s->euicc_cert_der_len,
                                  data_der, data_der_len,
                                  r->euiccSignPIR.buf);
        if (vr != 0) {
            ret = (vr == -1) ? -1 : -2;
            goto out;
        }
    }

    /* Genuine. Only now is what it says worth reading. */
    if (d->finalResult.present ==
        ProfileInstallationResultData__finalResult_PR_successResult) {
        *installed = 1;
    } else if (d->finalResult.present ==
               ProfileInstallationResultData__finalResult_PR_errorResult) {
        *installed = 0;
        if (bpp_command_id) {
            (void)asn_INTEGER2long(
                &d->finalResult.choice.errorResult.bppCommandId,
                bpp_command_id);
        }
        if (error_reason) {
            (void)asn_INTEGER2long(
                &d->finalResult.choice.errorResult.errorReason,
                error_reason);
        }
    } else {
        /* Neither arm: a signed report this function cannot read. The
           signature held, so the bytes are the card's -- but there is
           nothing here to report as installed or not, and guessing either
           way would be inventing an answer. */
        goto out;
    }
    ret = 0;

out:
    free(data_der);
    if (r) ASN_STRUCT_FREE(asn_DEF_ProfileInstallationResult, r);
    return ret;
}

/* ---------------------------------------------------------------------
 * Reading the response fields apart, for the ES9+ JSON binding.
 * See include/rsp.h for the contract; the short version is that these
 * cut rather than decode, so what a server base64-encodes is what was
 * signed.
 * ------------------------------------------------------------------ */

/* Parse the TLV at off. *val_off / *val_len become its value, and
 * *next_off where the next TLV begins. Multi-byte tags and long-form
 * lengths both occur here -- 'BF25', and certificates longer than 127
 * bytes -- so neither may be assumed away. Returns 0, or -1 when the
 * buffer runs out, when the length is the indefinite form (which DER
 * forbids), or when it is wider than a size_t. */
static int
parse_tlv(const uint8_t *buf, size_t end, size_t off,
          size_t *val_off, size_t *val_len, size_t *next_off) {
    size_t p = off, len = 0;

    if (p >= end) return -1;
    /* Tag: low five bits all set means it continues into further bytes,
     * each with its high bit set while more follow. */
    if ((buf[p] & 0x1f) == 0x1f) {
        p++;
        while (p < end && (buf[p] & 0x80)) p++;
        if (p >= end) return -1;
    }
    p++;
    if (p >= end) return -1;

    /* Length: short form is the byte itself. Long form has the low seven
     * bits give how many bytes follow; 0x80 alone is the indefinite
     * form, which DER forbids and this walker refuses. */
    if (buf[p] < 0x80) {
        len = buf[p];
        p++;
    } else {
        size_t n = (size_t)(buf[p] & 0x7f), i;
        p++;
        if (n == 0 || n > sizeof(size_t) || n > end - p) return -1;
        for (i = 0; i < n; i++) len = (len << 8) | buf[p + i];
        p += n;
    }
    if (len > end - p) return -1;

    *val_off  = p;
    *val_len  = len;
    *next_off = p + len;
    return 0;
}

/* Cut the field at *off out whole -- tag and length included, which is
 * what the JSON binding base64-encodes -- and move *off past it. */
static int
take_field(const uint8_t *buf, size_t end, size_t *off,
           const uint8_t **tlv, size_t *tlv_len) {
    size_t v_off, v_len, next;

    if (parse_tlv(buf, end, *off, &v_off, &v_len, &next) != 0) return -1;
    *tlv     = buf + *off;
    *tlv_len = next - *off;
    *off     = next;
    return 0;
}

int
rsp_dp_initiate_fields(const uint8_t *resp, size_t resp_len,
        rsp_dp_initiate_fields_t *out) {
    rsp_dp_initiate_fields_t f;
    size_t v_off, v_len, next, off, end;

    if (!resp || !out) return -2;
    memset(&f, 0, sizeof f);

    /* resp is the InitiateAuthenticationOkEs9 SEQUENCE itself; step
     * inside it and walk its five members in order. */
    if (parse_tlv(resp, resp_len, 0, &v_off, &v_len, &next) != 0) return -1;
    off = v_off;
    end = v_off + v_len;

    if (take_field(resp, end, &off, &f.transaction_id,
                   &f.transaction_id_len) != 0 ||
        take_field(resp, end, &off, &f.server_signed1,
                   &f.server_signed1_len) != 0 ||
        take_field(resp, end, &off, &f.server_signature1,
                   &f.server_signature1_len) != 0 ||
        take_field(resp, end, &off, &f.euicc_ci_pkid,
                   &f.euicc_ci_pkid_len) != 0 ||
        take_field(resp, end, &off, &f.server_certificate,
                   &f.server_certificate_len) != 0) {
        return -1;
    }

    *out = f;
    return 0;
}

int
rsp_dp_authenticate_fields(const uint8_t *resp, size_t resp_len,
        rsp_dp_authenticate_fields_t *out) {
    rsp_dp_authenticate_fields_t g;
    size_t v_off, v_len, next, off, end;

    if (!resp || !out) return -2;
    memset(&g, 0, sizeof g);

    /* resp is the AuthenticateClientResponseEs9 CHOICE (tag 'BF3B').
     * Step inside it to reach the authenticateClientOk SEQUENCE, then
     * inside that to reach its five members. */
    if (parse_tlv(resp, resp_len, 0, &v_off, &v_len, &next) != 0) return -1;
    if (parse_tlv(resp, v_off + v_len, v_off, &v_off, &v_len, &next) != 0)
        return -1;
    off = v_off;
    end = v_off + v_len;

    if (take_field(resp, end, &off, &g.transaction_id,
                   &g.transaction_id_len) != 0 ||
        take_field(resp, end, &off, &g.profile_metadata,
                   &g.profile_metadata_len) != 0 ||
        take_field(resp, end, &off, &g.smdp_signed2,
                   &g.smdp_signed2_len) != 0 ||
        take_field(resp, end, &off, &g.smdp_signature2,
                   &g.smdp_signature2_len) != 0 ||
        take_field(resp, end, &off, &g.smdp_certificate,
                   &g.smdp_certificate_len) != 0) {
        return -1;
    }

    *out = g;
    return 0;
}

/* ---------------------------------------------------------------------
 * Notifications: what an eUICC says after the download is over.
 * ------------------------------------------------------------------ */

int
rsp_dp_session_euicc_cert(const rsp_dp_session_t *s,
        const uint8_t **der, size_t *len)
{
    if (!s || !der || !len) return -2;
    if (!s->euicc_cert_der || s->euicc_cert_der_len == 0) return -1;
    *der = s->euicc_cert_der;
    *len = s->euicc_cert_der_len;
    return 0;
}

/* Copy the NotificationMetadata fields a caller needs for routing into
 * the verdict. Returns 0, or -1 when the metadata cannot be described
 * honestly -- an ICCID that is not ten octets, or a seqNumber wider than
 * a long. */
static int
notification_meta(const NotificationMetadata_t *m, rsp_notification_t *out)
{
    long seq = 0;
    int bit = -1, found = -1;
    size_t byte;

    if (asn_INTEGER2long(&m->seqNumber, &seq) != 0) return -1;
    out->seq_number = seq;

    /* NotificationEvent is a BIT STRING with exactly one bit set here
     * (section 5.7.11). Report which, or -1 when the eUICC set none or
     * several -- a value this struct cannot describe. */
    for (byte = 0; m->profileManagementOperation.buf &&
                   byte < (size_t)m->profileManagementOperation.size; byte++) {
        for (bit = 0; bit < 8; bit++) {
            if (byte + 1 == (size_t)m->profileManagementOperation.size &&
                bit >= 8 - m->profileManagementOperation.bits_unused) {
                break;
            }
            if (m->profileManagementOperation.buf[byte] & (0x80 >> bit)) {
                if (found >= 0) { found = -1; goto done_bits; }
                found = (int)(byte * 8 + (size_t)bit);
            }
        }
    }
done_bits:
    out->operation = found;

    if (m->iccid) {
        if (m->iccid->size != 10) return -1;
        memcpy(out->iccid, m->iccid->buf, 10);
        out->have_iccid = 1;
    }
    return 0;
}

/* Verify a ProfileInstallationResult against a certificate given from
 * outside. It carries none of its own -- see rsp.h -- so this is the arm
 * that needs the caller to have kept CERT.EUICC.ECDSA from the download. */
static int
verify_installation_notification(const uint8_t *cert_der, size_t cert_len,
        const uint8_t *pir, size_t pir_len, rsp_notification_t *out)
{
    ProfileInstallationResult_t *r = NULL;
    uint8_t *data_der = NULL;
    size_t data_der_len = 0;
    int ret = -2;

    if (!cert_der || cert_len == 0) return -2;

    {
        asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_ProfileInstallationResult,
                                       (void **)&r, pir, pir_len);
        if (dr.code != RC_OK || !r) goto out;
    }
    if (r->euiccSignPIR.size != 64) goto out;

    /* The signature is over the received ProfileInstallationResultData
     * ('BF 27') as it arrived, not over a re-encoding of the decode --
     * the same rule commit 8928231 established for the in-session check. */
    {
        static const uint8_t tag_pir[2]  = { 0xBF, 0x37 };
        static const uint8_t tag_data[2] = { 0xBF, 0x27 };
        size_t start = 0, len = 0, hdr = 0;

        if (find_tlv(pir, pir_len, 0, tag_pir, sizeof tag_pir, &start, &len) != 0) {
            goto out;
        }
        {
            ber_tlv_tag_t t;
            ber_tlv_len_t cl;
            ssize_t tl = ber_fetch_tag(pir, pir_len, &t);
            ssize_t ll;
            if (tl <= 0) goto out;
            ll = ber_fetch_length(BER_TLV_CONSTRUCTED(pir), pir + tl,
                                   pir_len - (size_t)tl, &cl);
            if (ll <= 0) goto out;
            hdr = (size_t)tl + (size_t)ll;
        }
        if (find_tlv(pir, pir_len, hdr, tag_data, sizeof tag_data,
                      &start, &data_der_len) != 0) {
            goto out;
        }
        data_der = malloc(data_der_len);
        if (!data_der) goto out;
        memcpy(data_der, pir + start, data_der_len);
    }

    {
        int vr = rsp_sign_verify(cert_der, cert_len, data_der, data_der_len,
                                  r->euiccSignPIR.buf);
        if (vr != 0) { ret = (vr == -1) ? -1 : -2; goto out; }
    }

    if (notification_meta(&r->profileInstallationResultData.notificationMetadata,
                          out) != 0) {
        goto out;
    }
    out->is_installation_result = 1;
    out->installed =
        r->profileInstallationResultData.finalResult.present ==
        ProfileInstallationResultData__finalResult_PR_successResult;
    ret = 0;

out:
    free(data_der);
    if (r) ASN_STRUCT_FREE(asn_DEF_ProfileInstallationResult, r);
    return ret;
}

/* Step over the TLV at *off. *val is its value and *val_len that value's
 * length; *whole / *whole_len are the field as it arrived, tag and length
 * included. Used positionally, because OtherSignedNotification's two
 * certificates share tag '30' and a tag search would find the first
 * twice. */
static int
step_tlv(const uint8_t *buf, size_t end, size_t *off,
         const uint8_t **whole, size_t *whole_len,
         const uint8_t **val, size_t *val_len)
{
    ber_tlv_tag_t t;
    ber_tlv_len_t cl;
    ssize_t tl, ll;
    size_t hdr;

    if (*off >= end) return -1;
    tl = ber_fetch_tag(buf + *off, end - *off, &t);
    if (tl <= 0) return -1;
    ll = ber_fetch_length(BER_TLV_CONSTRUCTED(buf + *off), buf + *off + tl,
                           end - *off - (size_t)tl, &cl);
    if (ll <= 0 || cl < 0) return -1;
    hdr = (size_t)tl + (size_t)ll;
    if ((size_t)cl > end - *off - hdr) return -1;

    *whole = buf + *off;
    *whole_len = hdr + (size_t)cl;
    *val = buf + *off + hdr;
    *val_len = (size_t)cl;
    *off += *whole_len;
    return 0;
}

/* Verify an OtherSignedNotification. Unlike a ProfileInstallationResult
 * this one is self-contained: it carries CERT.EUICC.ECDSA and CERT.EUM
 * with it, so the chain can be checked against the compiled-in test CI
 * and no stored certificate is needed. When one is given anyway it must
 * be the same certificate -- otherwise a genuine notification from one
 * eUICC would verify while being filed against another's Profile. */
static int
verify_other_notification(const uint8_t *cert_der, size_t cert_len,
        const uint8_t *osn, size_t osn_len, rsp_notification_t *out)
{
    OtherSignedNotification_t *o = NULL;
    mbedtls_x509_crt ci, eum, euicc;
    const uint8_t *ci_der = NULL;
    size_t ci_len = 0;
    const uint8_t *tbs = NULL, *sig_tlv = NULL, *euicc_c = NULL, *eum_c = NULL;
    size_t tbs_len = 0, sig_len = 0, euicc_c_len = 0, eum_c_len = 0;
    int ret = -2, have_ci = 0, have_eum = 0, have_euicc = 0;

    mbedtls_x509_crt_init(&ci);
    mbedtls_x509_crt_init(&eum);
    mbedtls_x509_crt_init(&euicc);

    {
        asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_OtherSignedNotification,
                                       (void **)&o, osn, osn_len);
        if (dr.code != RC_OK || !o) goto out; 
    }
    if (o->euiccNotificationSignature.size != 64) goto out; 

    /* Walk the received bytes for the four members: the signature is over
     * tbsOtherNotification as it arrived, and the two certificates go to
     * mbedTLS as they arrived. Re-encoding either would be a different
     * message wherever BER and DER disagree. */
    {
        size_t off = 0, end = 0;
        const uint8_t *w = NULL, *v = NULL;
        size_t wl = 0, vl = 0;

        if (step_tlv(osn, osn_len, &off, &w, &wl, &v, &vl) != 0) goto out;  
        off = (size_t)(v - osn);
        end = off + vl;

        if (step_tlv(osn, end, &off, &tbs, &tbs_len, &v, &vl) != 0) goto out;  
        if (step_tlv(osn, end, &off, &sig_tlv, &sig_len, &v, &vl) != 0) goto out;  
        if (step_tlv(osn, end, &off, &euicc_c, &euicc_c_len, &v, &vl) != 0) goto out;  
        if (step_tlv(osn, end, &off, &eum_c, &eum_c_len, &v, &vl) != 0) goto out;  
    }

    if (cert_der && cert_len > 0) {
        if (cert_len != euicc_c_len || memcmp(cert_der, euicc_c, cert_len) != 0) {
            ret = -1;   /* asked, and this is a different eUICC */
            goto out;
        }
    }

    /* The same callback and copy flag every other parse in this file
     * uses. CERT.EUM carries a name-constraints extension mbedTLS marks
     * critical and does not otherwise recognise, so the narrower
     * policies-only callback refuses it -- which is what a first attempt
     * here did, on bytes that were byte-identical to the certificate
     * that parses fine two hundred lines up. */
    if (rsp_pki_test_ci(&ci_der, &ci_len) != 0) goto out;
    if (mbedtls_x509_crt_parse_der_with_ext_cb(
            &ci, ci_der, ci_len, 1,
            rsp_accept_certificate_policies_and_name_constraints,
            NULL) != 0) {
        goto out;
    }
    /* Declared at the point of use, as rsp_dp_authenticate_client also
     * does -- build/sgp26_material.c defines it. */
    {
        extern const unsigned char rsp_sgp26_ci2017_der[];
        extern const unsigned int rsp_sgp26_ci2017_der_len;
    /* Both certificate objects for the one test CI key this project
     * compiles in, exactly as rsp_dp_authenticate_client does: CERT.EUM's
     * chain check needs a trust anchor whose Name matches the issuer it
     * names, and only the second one has it. Parsing just the first
     * leaves a chain that fails for a reason that reads like a bad
     * certificate rather than a missing anchor. */
    if (mbedtls_x509_crt_parse_der_with_ext_cb(
            &ci, rsp_sgp26_ci2017_der, rsp_sgp26_ci2017_der_len, 1,
            rsp_accept_certificate_policies_and_name_constraints,
            NULL) != 0) {
        goto out;
    }
    }
    have_ci = 1;
    if (mbedtls_x509_crt_parse_der_with_ext_cb(
            &eum, eum_c, eum_c_len, 1,
            rsp_accept_certificate_policies_and_name_constraints,
            NULL) != 0) {
        goto out;
    }
    have_eum = 1;
    if (mbedtls_x509_crt_parse_der_with_ext_cb(
            &euicc, euicc_c, euicc_c_len, 1,
            rsp_accept_certificate_policies_and_name_constraints,
            NULL) != 0) {
        goto out;
    }
    have_euicc = 1;

    {
        uint32_t flags = 0;
        if (mbedtls_x509_crt_verify(&eum, &ci, NULL, NULL, &flags,
                                     NULL, NULL) != 0) {
            ret = -1;   /* CERT.EUM does not chain to the CI */
            goto out;
        }
        flags = 0;
        if (mbedtls_x509_crt_verify(&euicc, &eum, NULL, NULL, &flags,
                                     NULL, NULL) != 0) {
            ret = -1;   /* CERT.EUICC does not chain to CERT.EUM */
            goto out;
        }
    }

    {
        int vr = rsp_sign_verify(euicc_c, euicc_c_len, tbs, tbs_len,
                                  o->euiccNotificationSignature.buf);
        if (vr != 0) { ret = (vr == -1) ? -1 : -2; goto out; }
    }

    if (notification_meta(&o->tbsOtherNotification, out) != 0) goto out; 
    out->is_installation_result = 0;
    ret = 0;

out:
    if (have_ci) mbedtls_x509_crt_free(&ci);
    if (have_eum) mbedtls_x509_crt_free(&eum);
    if (have_euicc) mbedtls_x509_crt_free(&euicc);
    if (o) ASN_STRUCT_FREE(asn_DEF_OtherSignedNotification, o);
    return ret;
}

int
rsp_dp_notification_metadata(const uint8_t *notification,
        size_t notification_len, rsp_notification_t *out)
{
    int ret = -2;

    if (!notification || notification_len < 2 || !out) return -2;
    memset(out, 0, sizeof *out);
    out->operation = -1;

    if (notification[0] == 0xBF && notification[1] == 0x37) {
        ProfileInstallationResult_t *r = NULL;
        asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_ProfileInstallationResult,
                                       (void **)&r, notification,
                                       notification_len);
        if (dr.code == RC_OK && r &&
            notification_meta(&r->profileInstallationResultData
                                   .notificationMetadata, out) == 0) {
            out->is_installation_result = 1;
            ret = 0;
        }
        if (r) ASN_STRUCT_FREE(asn_DEF_ProfileInstallationResult, r);
        return ret;
    }
    if ((notification[0] & 0x1f) == 0x10) {
        OtherSignedNotification_t *o = NULL;
        asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_OtherSignedNotification,
                                       (void **)&o, notification,
                                       notification_len);
        if (dr.code == RC_OK && o &&
            notification_meta(&o->tbsOtherNotification, out) == 0) {
            ret = 0;
        }
        if (o) ASN_STRUCT_FREE(asn_DEF_OtherSignedNotification, o);
        return ret;
    }
    return -2;
}

int
rsp_dp_verify_notification(const uint8_t *cert_euicc_der, size_t cert_len,
        const uint8_t *notification, size_t notification_len,
        rsp_notification_t *out)
{
    if (!notification || notification_len < 2 || !out) return -2;
    memset(out, 0, sizeof *out);
    out->operation = -1;

    /* PendingNotification is a CHOICE whose first alternative carries
     * [55], so automatic tagging is off for it: a ProfileInstallation
     * Result keeps 'BF 37' and an OtherSignedNotification keeps its
     * SEQUENCE tag. The two arms are told apart by that, not guessed. */
    if (notification[0] == 0xBF && notification[1] == 0x37) {
        return verify_installation_notification(cert_euicc_der, cert_len,
                                                notification,
                                                notification_len, out);
    }
    /* A SEQUENCE: tag number 16 in the low five bits. Masking six bits
     * instead, as this once did, never matches -- 0x30 & 0x3f is 0x30. */
    if ((notification[0] & 0x1f) == 0x10) {
        return verify_other_notification(cert_euicc_der, cert_len,
                                         notification, notification_len, out);
    }
    return -2;
}
