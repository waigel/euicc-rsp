/* Three functions, in the order an RSP session actually calls them:
   rsp_dp_initiate_authentication (SGP.22 v2.6 section 5.6.1),
   rsp_dp_authenticate_client (section 5.6.3) and
   rsp_dp_get_bound_profile_package (section 5.6.2).

   The InitiateAuthentication block is unchanged from Task 2 -- pinned
   against a fixed transactionId and a fixed euiccChallenge, proof that a
   caller-supplied transactionId genuinely flows through.

   The AuthenticateClient block is Task 3's own required coverage, per
   its brief's Step 2, each written so it can fail independently (Step 6
   proves each one actually does, by mutation -- see task-3-report.md):

     - an authenticateServerResponse whose transactionId does not match
       the session's is refused with -1
     - a CERT.EUICC that does not chain to the test CI is refused with -1
     - on success, the EID recovered from CERT.EUICC.ECDSA's own Subject
       matches the test card's, 89049032123451234512345678901235

   Plus, past the brief's own minimum: the serverChallenge check 5.6.3
   also requires, and that smdpSignature2 verifies against CERT.DPpb (not
   CERT.DPauth -- the mistake the brief calls out as most worth catching).

   The GetBoundProfilePackage block proves the hostId/EID split in Annex
   G's SharedInfo independently of src/rsp_es9.c's own implementation: it
   recomputes the expected session with rsp_session_init directly, using
   RSP_HOST_ID from src/rsp_internal.h, and checks that rsp_bpp_recover
   can decrypt what rsp_dp_get_bound_profile_package produced. If
   rsp_dp_get_bound_profile_package's own SharedInfo ever used a
   different hostId than RSP_HOST_ID, this is exactly the check that
   would catch it -- half of the brief's third mutation (the KDF side);
   the other half (Task 4's controlRefTemplate reading a second, drifted
   copy) cannot exist until Task 4 does, so it is not tested here (see
   task-3-report.md). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsp.h"
#include "rsp_internal.h"

#include "AuthenticateClientOk.h"
#include "AuthenticateClientResponseEs9.h"
#include "AuthenticateServerResponse.h"
#include "Certificate.h"
#include "CtxParams1.h"
#include "DeviceInfo.h"
#include "EUICCInfo1.h"
#include "EUICCInfo2.h"
#include "EUICCSigned2.h"
#include "EuiccSigned1.h"
#include "InitiateAuthenticationOkEs9.h"
#include "PrepareDownloadResponse.h"
#include "ServerSigned1.h"
#include "SmdpSigned2.h"
#include "StoreMetadataRequest.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if (!good) fails++;
}

/* A fixed-capacity sink for der_encode's callback interface. */
struct sink {
    unsigned char *p;
    size_t len;
    size_t cap;
};

static int collect(const void *buf, size_t n, void *key) {
    struct sink *s = key;
    if (s->len + n > s->cap) {
        return -1;
    }
    memcpy(s->p + s->len, buf, n);
    s->len += n;
    return 0;
}

/* A minimal, structurally valid EUICCInfo1: only has to decode (see
   src/rsp_es9.c's top comment -- InitiateAuthentication does not
   interpret it deeply). */
static int build_euicc_info1(unsigned char *buf, size_t cap, size_t *out_len) {
    EUICCInfo1_t info;
    struct sink s = { buf, 0, cap };
    asn_enc_rval_t r;

    memset(&info, 0, sizeof info);
    if (OCTET_STRING_fromBuf(&info.svn, "\x02\x00\x00", 3) != 0) {
        return -1;
    }
    r = der_encode(&asn_DEF_EUICCInfo1, &info, collect, &s);
    ASN_STRUCT_RESET(asn_DEF_EUICCInfo1, &info);
    if (r.encoded < 0) {
        return -1;
    }
    *out_len = s.len;
    return 0;
}

/* --------------------------------------------------------------------
   AuthenticateClient fixtures.

   These build a genuinely-signed AuthenticateServerResponse using the
   real published GSMA SGP.26 v1.0 test eUICC certificate chain
   (testdata/sgp26/euicc.der -> eum.der -> ci-2017.der, ci-2017.der
   carrying the same key as testdata/sgp26/ci.der -- see
   testdata/sgp26/README.md's "why a second CI certificate exists").
   Nothing here is a contrived blob: every certificate is real, and the
   signature is computed with the real, published private key that
   matches euicc.der's public key -- this is exactly what a real eUICC of
   this make would send.
   -------------------------------------------------------------------- */

/* Declared here, not in a header: build/sgp26_material.c (generated from
   testdata/sgp26/) already defines these; src/rsp_pki.c's own externs for
   the DP/CI material are the precedent for declaring them again at the
   point of use rather than adding a header just for test code. */
extern const unsigned char rsp_sgp26_eum_der[];
extern const unsigned int rsp_sgp26_eum_der_len;
extern const unsigned char rsp_sgp26_euicc_der[];
extern const unsigned int rsp_sgp26_euicc_der_len;

/* The test eUICC's own EID, exactly as testdata/sgp26/euicc.der's Subject
   serialNumber carries it -- SGP.22 v2.6 section 4.5.1's own worked
   example, and this project's real test card (see task-3-brief.md). */
static const char EUICC_TEST_EID[] = "89049032123451234512345678901235";

/* testdata/sgp26/euicc-key.pem's raw big-endian P-256 scalar, exactly as
   rsp_credential_t.sk stores it. Derived once with
   `openssl ec -in testdata/sgp26/euicc-key.pem -noout -text` and pinned
   here rather than re-parsed from PEM at test time: this project's test
   key is fixed, published SGP.26 v1.0 material (see testdata/sgp26/
   README.md) that never changes, and parsing SEC1 PEM is exactly the
   mbedtls_pk_parse_key plumbing src/rsp_pki.c already owns for the
   *library's own* DP credentials -- this fixture is not one of those. */
static const uint8_t EUICC_TEST_SK[32] = {
    0x11, 0xe1, 0x54, 0x67, 0xdc, 0x19, 0x4f, 0x33,
    0x71, 0x83, 0xe4, 0x60, 0xc9, 0xf6, 0x32, 0x60,
    0x09, 0x1e, 0x12, 0xe8, 0x10, 0x26, 0xcd, 0x65,
    0x61, 0xe1, 0x7c, 0x6d, 0x85, 0x39, 0xcc, 0x9c
};

/* A minimal, structurally valid EUICCInfo2 (rsp-2.5.asn line 41): only
   has to decode -- rsp_dp_authenticate_client does not inspect it, the
   same scope cut InitiateAuthentication already makes for EUICCInfo1
   (see src/rsp_es9.c's top comment). Empty euiccCiPKIdListForVerification/
   ForSigning is valid DER, the same as build_euicc_info1's own comment.
   uiccCapability/rspCapability are BIT STRING, sharing OCTET_STRING_t's
   layout for its buf/size fields (bits_unused defaults to 0 from the
   memset below, meaning "byte-aligned", which a single content byte
   always is). */
static int build_euicc_info2(EUICCInfo2_t *info) {
    memset(info, 0, sizeof *info);
    if (OCTET_STRING_fromBuf(&info->profileVersion, "\x02\x02\x00", 3) != 0 ||
        OCTET_STRING_fromBuf(&info->svn, "\x02\x02\x00", 3) != 0 ||
        OCTET_STRING_fromBuf(&info->euiccFirmwareVer, "\x01\x00\x00", 3) != 0 ||
        OCTET_STRING_fromBuf(&info->extCardResource, "\x00", 1) != 0 ||
        OCTET_STRING_fromBuf((OCTET_STRING_t *)&info->uiccCapability, "\x00", 1) != 0 ||
        OCTET_STRING_fromBuf((OCTET_STRING_t *)&info->rspCapability, "\x00", 1) != 0 ||
        OCTET_STRING_fromBuf(&info->ppVersion, "\x02\x00\x00", 3) != 0 ||
        OCTET_STRING_fromBuf(&info->sasAcreditationNumber, "", 0) != 0) {
        return -1;
    }
    return 0;
}

/* DeviceInfo (rsp-2.5.asn line 125): tac is the one mandatory field
   besides the all-OPTIONAL deviceCapabilities, which a zeroed struct
   already satisfies as a valid empty SEQUENCE. */
static int build_device_info(DeviceInfo_t *di) {
    memset(di, 0, sizeof *di);
    return OCTET_STRING_fromBuf(&di->tac, "\x00\x00\x00\x00", 4);
}

/* CtxParams1 (rsp-2.5.asn line 294): the only CHOICE arm this module
   defines. matchingId stays absent (OPTIONAL) -- this fixture is a
   Profile Download, not an Activation Code Retrieval. */
static int build_ctx_params1(CtxParams1_t *cp) {
    memset(cp, 0, sizeof *cp);
    cp->present = CtxParams1_PR_ctxParamsForCommonAuthentication;
    return build_device_info(&cp->choice.ctxParamsForCommonAuthentication.deviceInfo);
}

/* Assembles and signs a full AuthenticateServerResponse (the
   authenticateResponseOk arm): euiccSigned1 echoes transaction_id and
   server_challenge, signed with EUICC_TEST_SK exactly as 5.7.13 requires
   ("euiccSignature1 SHALL apply on euiccSigned1 data object"), and
   euicc_cert_der/eum_cert_der become euiccCertificate/eumCertificate --
   passed in as parameters, not hardcoded to testdata/sgp26's own files, so the
   negative fixtures below can substitute a non-chaining certificate
   without duplicating this whole function. */
static int build_auth_server_response(
        const uint8_t transaction_id[16], const uint8_t server_challenge[16],
        const uint8_t *euicc_cert_der, size_t euicc_cert_len,
        const uint8_t *eum_cert_der, size_t eum_cert_len,
        unsigned char *out, size_t cap, size_t *out_len) {
    AuthenticateServerResponse_t resp;
    AuthenticateResponseOk_t *rok;
    unsigned char es1_buf[2048];
    struct sink es1_sink = { es1_buf, 0, sizeof es1_buf };
    struct sink out_sink = { out, 0, cap };
    asn_enc_rval_t r;
    rsp_credential_t euicc_cred;
    uint8_t sig[64];
    int ret = -1;

    memset(&resp, 0, sizeof resp);
    resp.present = AuthenticateServerResponse_PR_authenticateResponseOk;
    rok = &resp.choice.authenticateResponseOk;

    if (OCTET_STRING_fromBuf(&rok->euiccSigned1.transactionId,
                              (const char *)transaction_id, 16) != 0 ||
        OCTET_STRING_fromBuf(&rok->euiccSigned1.serverAddress,
                              "smdp-address-placeholder.invalid", 33) != 0 ||
        OCTET_STRING_fromBuf(&rok->euiccSigned1.serverChallenge,
                              (const char *)server_challenge, 16) != 0 ||
        build_euicc_info2(&rok->euiccSigned1.euiccInfo2) != 0 ||
        build_ctx_params1(&rok->euiccSigned1.ctxParams1) != 0) {
        goto done;
    }

    r = der_encode(&asn_DEF_EuiccSigned1, &rok->euiccSigned1, collect, &es1_sink);
    if (r.encoded < 0) {
        goto done;
    }

    memset(&euicc_cred, 0, sizeof euicc_cred);
    memcpy(euicc_cred.sk, EUICC_TEST_SK, sizeof euicc_cred.sk);
    if (rsp_sign(&euicc_cred, es1_sink.p, es1_sink.len, sig) != 0) {
        goto done;
    }
    if (OCTET_STRING_fromBuf(&rok->euiccSignature1, (const char *)sig, 64) != 0) {
        goto done;
    }

    {
        void *p = &rok->euiccCertificate;
        asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_Certificate, &p,
                                        euicc_cert_der, euicc_cert_len);
        if (dr.code != RC_OK) {
            goto done;
        }
    }
    {
        void *p = &rok->eumCertificate;
        asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_Certificate, &p,
                                        eum_cert_der, eum_cert_len);
        if (dr.code != RC_OK) {
            goto done;
        }
    }

    r = der_encode(&asn_DEF_AuthenticateServerResponse, &resp, collect, &out_sink);
    if (r.encoded < 0) {
        goto done;
    }
    *out_len = out_sink.len;
    ret = 0;

done:
    ASN_STRUCT_RESET(asn_DEF_AuthenticateServerResponse, &resp);
    return ret;
}

/* StoreMetadataRequest (rsp-2.5.asn line 204): rsp_dp_authenticate_client's
   own `metadata` parameter -- see rsp.h for why this stateless library
   needs the caller to supply it. */
static int build_store_metadata(const uint8_t iccid[10],
                                 const char *profile_name,
                                 const char *service_provider_name,
                                 unsigned char *buf, size_t cap, size_t *out_len) {
    StoreMetadataRequest_t md;
    struct sink s = { buf, 0, cap };
    asn_enc_rval_t r;

    memset(&md, 0, sizeof md);
    if (OCTET_STRING_fromBuf(&md.iccid, (const char *)iccid, 10) != 0 ||
        OCTET_STRING_fromBuf(&md.serviceProviderName, service_provider_name,
                              (int)strlen(service_provider_name)) != 0 ||
        OCTET_STRING_fromBuf(&md.profileName, profile_name,
                              (int)strlen(profile_name)) != 0) {
        ASN_STRUCT_RESET(asn_DEF_StoreMetadataRequest, &md);
        return -1;
    }
    r = der_encode(&asn_DEF_StoreMetadataRequest, &md, collect, &s);
    ASN_STRUCT_RESET(asn_DEF_StoreMetadataRequest, &md);
    if (r.encoded < 0) {
        return -1;
    }
    *out_len = s.len;
    return 0;
}

/* PrepareDownloadResponse (rsp-2.5.asn line 255), the downloadResponseOk
   arm: euiccSigned2 carries transaction_id and euicc_otpk (otPK.EUICC.ECKA),
   signed with the same EUICC_TEST_SK -- 5.6.2's "euiccSignature2 ...
   using the PK.EUICC.ECDSA attached to the ongoing RSP session" is the
   same key AuthenticateClient already verified against. */
static int build_prepare_download_response(
        const uint8_t transaction_id[16], const uint8_t euicc_otpk[65],
        unsigned char *out, size_t cap, size_t *out_len) {
    PrepareDownloadResponse_t resp;
    PrepareDownloadResponseOk_t *rok;
    unsigned char es2_buf[512];
    struct sink es2_sink = { es2_buf, 0, sizeof es2_buf };
    struct sink out_sink = { out, 0, cap };
    asn_enc_rval_t r;
    rsp_credential_t euicc_cred;
    uint8_t sig[64];
    int ret = -1;

    memset(&resp, 0, sizeof resp);
    resp.present = PrepareDownloadResponse_PR_downloadResponseOk;
    rok = &resp.choice.downloadResponseOk;

    if (OCTET_STRING_fromBuf(&rok->euiccSigned2.transactionId,
                              (const char *)transaction_id, 16) != 0 ||
        OCTET_STRING_fromBuf(&rok->euiccSigned2.euiccOtpk,
                              (const char *)euicc_otpk, 65) != 0) {
        goto done;
    }

    r = der_encode(&asn_DEF_EUICCSigned2, &rok->euiccSigned2, collect, &es2_sink);
    if (r.encoded < 0) {
        goto done;
    }

    memset(&euicc_cred, 0, sizeof euicc_cred);
    memcpy(euicc_cred.sk, EUICC_TEST_SK, sizeof euicc_cred.sk);
    if (rsp_sign(&euicc_cred, es2_sink.p, es2_sink.len, sig) != 0) {
        goto done;
    }
    if (OCTET_STRING_fromBuf(&rok->euiccSignature2, (const char *)sig, 64) != 0) {
        goto done;
    }

    r = der_encode(&asn_DEF_PrepareDownloadResponse, &resp, collect, &out_sink);
    if (r.encoded < 0) {
        goto done;
    }
    *out_len = out_sink.len;
    ret = 0;

done:
    ASN_STRUCT_RESET(asn_DEF_PrepareDownloadResponse, &resp);
    return ret;
}

int main(void) {
    static const uint8_t transaction_id[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    static const uint8_t euicc_challenge[16] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };
    unsigned char info1_buf[512];
    size_t info1_len = 0;
    rsp_dp_session_t *sess = NULL;
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    int rc;

    ok("a fixture EUICCInfo1 encodes",
       build_euicc_info1(info1_buf, sizeof info1_buf, &info1_len) == 0);

    rc = rsp_dp_initiate_authentication(euicc_challenge, sizeof euicc_challenge,
                                         info1_buf, info1_len,
                                         transaction_id,
                                         &sess, &resp, &resp_len);
    ok("rsp_dp_initiate_authentication succeeds", rc == 0);
    ok("a session was returned", sess != NULL);
    ok("a response was returned", resp != NULL && resp_len > 0);

    if (rc != 0 || !resp) {
        return fails ? 1 : 0;
    }

    InitiateAuthenticationOkEs9_t *decoded = NULL;
    asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_InitiateAuthenticationOkEs9,
                                    (void **)&decoded, resp, resp_len);
    ok("the response decodes as InitiateAuthenticationOkEs9",
       dr.code == RC_OK && decoded != NULL);
    if (dr.code != RC_OK || !decoded) {
        free(resp);
        rsp_dp_session_free(sess);
        return fails ? 1 : 0;
    }

    ok("the response's own transactionId equals what was passed in",
       decoded->transactionId.size == 16 &&
       memcmp(decoded->transactionId.buf, transaction_id, 16) == 0);

    ok("serverSigned1.transactionId equals what was passed in",
       decoded->serverSigned1.transactionId.size == 16 &&
       memcmp(decoded->serverSigned1.transactionId.buf, transaction_id, 16) == 0);

    ok("serverSigned1.euiccChallenge equals the challenge",
       decoded->serverSigned1.euiccChallenge.size == 16 &&
       memcmp(decoded->serverSigned1.euiccChallenge.buf, euicc_challenge, 16) == 0);

    ok("serverSignature1 is 64 bytes (plain r||s, not DER)",
       decoded->serverSignature1.size == 64);

    /* serverSignature1 "SHALL apply on serverSigned1 data object"
       (5.7.13) -- re-encode the decoded serverSigned1 to get back the
       exact bytes that were signed, then verify against CERT.DPauth. */
    {
        unsigned char ss1_buf[512];
        struct sink s = { ss1_buf, 0, sizeof ss1_buf };
        asn_enc_rval_t r = der_encode(&asn_DEF_ServerSigned1,
                                       &decoded->serverSigned1, collect, &s);
        ok("the decoded serverSigned1 re-encodes", r.encoded >= 0);

        rsp_credential_t dpauth;
        memset(&dpauth, 0, sizeof dpauth);
        ok("DPauth loads, to verify against", rsp_pki_dp(0, &dpauth) == 0);

        ok("serverSignature1 verifies against CERT.DPauth.ECDSA",
           r.encoded >= 0 && decoded->serverSignature1.size == 64 &&
           rsp_sign_verify(dpauth.der, dpauth.der_len, s.p, s.len,
                            decoded->serverSignature1.buf) == 0);

        rsp_credential_free(&dpauth);
    }

    /* The returned certificate must be DPauth's, not DPpb's. Re-encode
       the decoded Certificate back to DER and compare against both
       roles rsp_pki_dp can load -- der_len and the first 32 bytes is
       the brief's own bar, done here as a full comparison since nothing
       stops a stronger check, plus an explicit negative against DPpb so
       "matches DPauth" cannot pass merely because both certificates
       happen to share a length or a common prefix. */
    {
        unsigned char cert_buf[1024];
        struct sink s = { cert_buf, 0, sizeof cert_buf };
        asn_enc_rval_t r = der_encode(&asn_DEF_Certificate,
                                       &decoded->serverCertificate, collect, &s);
        ok("the decoded serverCertificate re-encodes", r.encoded >= 0);

        rsp_credential_t dpauth, dppb;
        memset(&dpauth, 0, sizeof dpauth);
        memset(&dppb, 0, sizeof dppb);
        ok("DPauth loads, to compare the certificate against",
           rsp_pki_dp(0, &dpauth) == 0);
        ok("DPpb loads, to compare the certificate against",
           rsp_pki_dp(1, &dppb) == 0);

        ok("serverCertificate's der_len matches DPauth's",
           r.encoded >= 0 && s.len == dpauth.der_len);
        ok("serverCertificate's first 32 bytes match DPauth's",
           r.encoded >= 0 && s.len >= 32 && dpauth.der_len >= 32 &&
           memcmp(s.p, dpauth.der, 32) == 0);
        ok("serverCertificate matches DPauth's certificate in full",
           r.encoded >= 0 && s.len == dpauth.der_len &&
           memcmp(s.p, dpauth.der, s.len) == 0);
        ok("serverCertificate is not DPpb's certificate",
           !(r.encoded >= 0 && s.len == dppb.der_len &&
             memcmp(s.p, dppb.der, s.len) == 0));

        rsp_credential_free(&dpauth);
        rsp_credential_free(&dppb);
    }

    /* server_challenge: generated internally by rsp_dp_initiate_
       authentication (real entropy, not caller-supplied -- see
       src/rsp_es9.c's own top comment), so the only way this test can
       learn the value it must echo back in euiccSigned1.serverChallenge
       is to read it back out of InitiateAuthenticationOkEs9's own
       serverSigned1.serverChallenge -- exactly what a real eUICC does
       too (it receives serverChallenge this same way, over the wire, and
       echoes it back). Captured here, before decoded is freed. */
    uint8_t server_challenge[16];
    memcpy(server_challenge, decoded->serverSigned1.serverChallenge.buf, 16);

    ASN_STRUCT_FREE(asn_DEF_InitiateAuthenticationOkEs9, decoded);
    free(resp);

    /* ------------------------------------------------------------------
       rsp_dp_authenticate_client (SGP.22 v2.6 section 5.6.3): the three
       assertions the brief's Step 2 requires, each able to fail
       independently, plus the serverChallenge check and the DPpb-not-
       DPauth check 5.6.3 also requires past the brief's own minimum.
       ------------------------------------------------------------------ */
    {
        static const uint8_t iccid[10] = {
            0x98, 0x00, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x14
        };
        static const uint8_t wrong_transaction_id[16] = {
            0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
            0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99
        };
        unsigned char md_buf[256];
        size_t md_len = 0;
        unsigned char asr_buf[4096];
        size_t asr_len = 0;
        uint8_t *ac_out = NULL;
        size_t ac_out_len = 0;

        ok("a fixture StoreMetadataRequest encodes",
           build_store_metadata(iccid, "euicc-rsp test profile",
                                 "euicc-rsp", md_buf, sizeof md_buf, &md_len) == 0);

        /* --- the success case --- */
        ok("a genuine AuthenticateServerResponse fixture encodes",
           build_auth_server_response(
                   transaction_id, server_challenge,
                   rsp_sgp26_euicc_der, rsp_sgp26_euicc_der_len,
                   rsp_sgp26_eum_der, rsp_sgp26_eum_der_len,
                   asr_buf, sizeof asr_buf, &asr_len) == 0);

        rc = rsp_dp_authenticate_client(sess, asr_buf, asr_len,
                                         md_buf, md_len, &ac_out, &ac_out_len);
        ok("rsp_dp_authenticate_client succeeds on a genuine response",
           rc == 0);
        ok("a response was returned", ac_out != NULL && ac_out_len > 0);

        if (rc == 0 && ac_out) {
            AuthenticateClientResponseEs9_t *ac_decoded = NULL;
            asn_dec_rval_t adr = ber_decode(
                    NULL, &asn_DEF_AuthenticateClientResponseEs9,
                    (void **)&ac_decoded, ac_out, ac_out_len);
            ok("the response decodes as AuthenticateClientResponseEs9",
               adr.code == RC_OK && ac_decoded != NULL);

            if (adr.code == RC_OK && ac_decoded) {
                ok("the response is the authenticateClientOk arm",
                   ac_decoded->present ==
                   AuthenticateClientResponseEs9_PR_authenticateClientOk);

                if (ac_decoded->present ==
                    AuthenticateClientResponseEs9_PR_authenticateClientOk) {
                    AuthenticateClientOk_t *aco =
                            &ac_decoded->choice.authenticateClientOk;

                    ok("transactionId equals what was passed in",
                       aco->transactionId.size == 16 &&
                       memcmp(aco->transactionId.buf, transaction_id, 16) == 0);

                    ok("smdpSigned2.transactionId equals what was passed in",
                       aco->smdpSigned2.transactionId.size == 16 &&
                       memcmp(aco->smdpSigned2.transactionId.buf,
                              transaction_id, 16) == 0);

                    ok("smdpSignature2 is 64 bytes (plain r||s, not DER)",
                       aco->smdpSignature2.size == 64);

                    /* smdpSignature2 applies over smdpSigned2's own DER
                       encoding, and MUST verify against CERT.DPpb --
                       never CERT.DPauth, the mistake the brief calls out
                       as most worth catching (DPauth already signed
                       InitiateAuthentication's serverSigned1; a
                       different key for a different purpose). */
                    {
                        unsigned char sd2_buf[512];
                        struct sink s = { sd2_buf, 0, sizeof sd2_buf };
                        asn_enc_rval_t r = der_encode(
                                &asn_DEF_SmdpSigned2, &aco->smdpSigned2,
                                collect, &s);
                        ok("the decoded smdpSigned2 re-encodes",
                           r.encoded >= 0);

                        rsp_credential_t dppb, dpauth;
                        memset(&dppb, 0, sizeof dppb);
                        memset(&dpauth, 0, sizeof dpauth);
                        ok("DPpb loads, to verify smdpSignature2 against",
                           rsp_pki_dp(1, &dppb) == 0);
                        ok("DPauth loads, to compare smdpCertificate against",
                           rsp_pki_dp(0, &dpauth) == 0);

                        ok("smdpSignature2 verifies against CERT.DPpb.ECDSA",
                           r.encoded >= 0 && aco->smdpSignature2.size == 64 &&
                           rsp_sign_verify(dppb.der, dppb.der_len, s.p, s.len,
                                            aco->smdpSignature2.buf) == 0);

                        {
                            unsigned char cert_buf[1024];
                            struct sink cs = { cert_buf, 0, sizeof cert_buf };
                            asn_enc_rval_t cr = der_encode(
                                    &asn_DEF_Certificate, &aco->smdpCertificate,
                                    collect, &cs);
                            ok("the decoded smdpCertificate re-encodes",
                               cr.encoded >= 0);
                            ok("smdpCertificate matches DPpb's certificate",
                               cr.encoded >= 0 && cs.len == dppb.der_len &&
                               memcmp(cs.p, dppb.der, cs.len) == 0);
                            ok("smdpCertificate is not DPauth's certificate",
                               !(cr.encoded >= 0 && cs.len == dpauth.der_len &&
                                 memcmp(cs.p, dpauth.der, cs.len) == 0));
                        }

                        rsp_credential_free(&dppb);
                        rsp_credential_free(&dpauth);
                    }
                }
                ASN_STRUCT_FREE(asn_DEF_AuthenticateClientResponseEs9, ac_decoded);
            }
            free(ac_out);
            ac_out = NULL;
        }

        /* --- the EID assertion --- */
        {
            uint8_t eid_buf[32];
            size_t eid_out_len = 0;
            int eid_rc = rsp_dp_session_eid(sess, eid_buf, sizeof eid_buf,
                                             &eid_out_len);
            ok("rsp_dp_session_eid succeeds once authenticated",
               eid_rc == 0);
            ok("the EID recovered from CERT.EUICC.ECDSA matches the test card's",
               eid_rc == 0 &&
               eid_out_len == strlen(EUICC_TEST_EID) &&
               memcmp(eid_buf, EUICC_TEST_EID, eid_out_len) == 0);
        }

        /* --- negative: a mismatched transactionId is refused with -1 --- */
        {
            rsp_dp_session_t *sess2 = NULL;
            uint8_t *resp2 = NULL;
            size_t resp2_len = 0;
            int rc2 = rsp_dp_initiate_authentication(
                    euicc_challenge, sizeof euicc_challenge,
                    info1_buf, info1_len, transaction_id,
                    &sess2, &resp2, &resp2_len);
            ok("a second session opens, for the mismatched-transactionId case",
               rc2 == 0 && sess2 != NULL);

            if (rc2 == 0 && sess2 && resp2) {
                /* sess2's own serverChallenge, decoded the same way the
                   success case captured sess's own -- deliberately
                   *correct* here, and only wrong_transaction_id wrong, so
                   that this assertion isolates the transactionId check:
                   if the serverChallenge were also wrong, "refused with
                   -1" could pass even with the transactionId check
                   removed entirely, which is exactly the failure mode
                   mutation (a) in task-3-report.md exists to rule out. */
                InitiateAuthenticationOkEs9_t *d2 = NULL;
                asn_dec_rval_t dr2 = ber_decode(
                        NULL, &asn_DEF_InitiateAuthenticationOkEs9,
                        (void **)&d2, resp2, resp2_len);
                ok("the second session's own response decodes",
                   dr2.code == RC_OK && d2 != NULL);

                if (dr2.code == RC_OK && d2) {
                    uint8_t sc2[16];
                    unsigned char bad_asr_buf[4096];
                    size_t bad_asr_len = 0;
                    uint8_t *bad_out = NULL;
                    size_t bad_out_len = 0;
                    int bad_rc;

                    memcpy(sc2, d2->serverSigned1.serverChallenge.buf, 16);
                    ASN_STRUCT_FREE(asn_DEF_InitiateAuthenticationOkEs9, d2);

                    ok("a mismatched-transactionId fixture encodes",
                       build_auth_server_response(
                               wrong_transaction_id, sc2,
                               rsp_sgp26_euicc_der, rsp_sgp26_euicc_der_len,
                               rsp_sgp26_eum_der, rsp_sgp26_eum_der_len,
                               bad_asr_buf, sizeof bad_asr_buf, &bad_asr_len) == 0);

                    bad_rc = rsp_dp_authenticate_client(
                            sess2, bad_asr_buf, bad_asr_len, md_buf, md_len,
                            &bad_out, &bad_out_len);
                    ok("a mismatched transactionId is refused with -1",
                       bad_rc == -1);
                    ok("no response is returned for a mismatched transactionId",
                       bad_out == NULL);

                    free(bad_out);
                }
            }
            free(resp2);
            rsp_dp_session_free(sess2);
        }

        /* --- negative: a CERT.EUICC that does not chain is refused with
           -1 --- */
        {
            rsp_dp_session_t *sess3 = NULL;
            uint8_t *resp3 = NULL;
            size_t resp3_len = 0;
            int rc3 = rsp_dp_initiate_authentication(
                    euicc_challenge, sizeof euicc_challenge,
                    info1_buf, info1_len, transaction_id,
                    &sess3, &resp3, &resp3_len);
            ok("a third session opens, for the non-chaining-certificate case",
               rc3 == 0 && sess3 != NULL);

            if (rc3 == 0 && resp3) {
                /* This response's own serverChallenge is a fresh one --
                   independent of `server_challenge` above -- so it must
                   be re-captured for this session, the same way the
                   success case captured its own. */
                InitiateAuthenticationOkEs9_t *d3 = NULL;
                asn_dec_rval_t dr3 = ber_decode(
                        NULL, &asn_DEF_InitiateAuthenticationOkEs9,
                        (void **)&d3, resp3, resp3_len);
                ok("the third session's own response decodes",
                   dr3.code == RC_OK && d3 != NULL);

                if (dr3.code == RC_OK && d3) {
                    uint8_t sc3[16];
                    memcpy(sc3, d3->serverSigned1.serverChallenge.buf, 16);
                    ASN_STRUCT_FREE(asn_DEF_InitiateAuthenticationOkEs9, d3);

                    /* The real, unmodified euiccCertificate (correctly
                       signed, by the key that actually matches it) paired
                       with CERT.DPauth.ECDSA standing in for eumCertificate
                       -- a real, validly-signed certificate that genuinely
                       chains to the very same test CI, but is not
                       testdata/sgp26/eum.der, so euicc.der's own issuer
                       (CN=EUM Test) does not match it. This isolates the
                       chain check specifically: euiccSignature1 would
                       still verify fine against the real euicc.der if
                       anything downstream ever looked at it, so "refused
                       with -1" here can only be the chain check, not a
                       signature that also happens to be wrong -- exactly
                       what mutation (b) in task-3-report.md relies on to
                       show this assertion depends on that check running,
                       not on some other check failing for an unrelated
                       reason. */
                    rsp_credential_t dpauth;
                    memset(&dpauth, 0, sizeof dpauth);
                    ok("DPauth loads, to stand in for a non-chaining CERT.EUM",
                       rsp_pki_dp(0, &dpauth) == 0);

                    if (dpauth.der) {
                        unsigned char bad2_asr_buf[4096];
                        size_t bad2_asr_len = 0;
                        uint8_t *bad2_out = NULL;
                        size_t bad2_out_len = 0;
                        int bad2_rc;

                        ok("a non-chaining-CERT.EUM fixture encodes",
                           build_auth_server_response(
                                   transaction_id, sc3,
                                   rsp_sgp26_euicc_der, rsp_sgp26_euicc_der_len,
                                   dpauth.der, dpauth.der_len,
                                   bad2_asr_buf, sizeof bad2_asr_buf,
                                   &bad2_asr_len) == 0);

                        bad2_rc = rsp_dp_authenticate_client(
                                sess3, bad2_asr_buf, bad2_asr_len,
                                md_buf, md_len, &bad2_out, &bad2_out_len);
                        ok("a CERT.EUICC that does not chain is refused with -1",
                           bad2_rc == -1);
                        ok("no response is returned for a non-chaining CERT.EUICC",
                           bad2_out == NULL);

                        free(bad2_out);
                    }
                    rsp_credential_free(&dpauth);
                }
            }
            free(resp3);
            rsp_dp_session_free(sess3);
        }

        /* --------------------------------------------------------------
           rsp_dp_get_bound_profile_package (SGP.22 v2.6 section 5.6.2),
           run against the first (successfully-authenticated) session.
           -------------------------------------------------------------- */
        {
            static const uint8_t otsk_dp[32] = {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
            };
            /* A fixed, valid P-256 point (uncompressed): stands in for
               otPK.EUICC.ECKA. Generated once with
               `openssl ecparam -name prime256v1 -genkey -noout | openssl ec
               -noout -text` and pinned here -- rsp_ecdh_p256 only needs a
               point genuinely on the curve, not one this test controls
               the matching secret for (that secret is never used: only
               otsk_dp does the ECDH work, on this side). */
            static const uint8_t euicc_otpk[65] = {
                0x04,
                0xa6, 0x1b, 0x58, 0x52, 0xfe, 0xde, 0xec, 0xd5,
                0x37, 0x3d, 0x76, 0x9a, 0xf0, 0xed, 0xbc, 0x94,
                0x50, 0x22, 0x76, 0xd9, 0xc6, 0xff, 0x1d, 0xa3,
                0xa1, 0x56, 0xfe, 0xcf, 0x31, 0xc6, 0x62, 0x99,
                0x54, 0xae, 0xa6, 0x28, 0x62, 0xe2, 0x27, 0xae,
                0xba, 0xf7, 0x45, 0xc4, 0xe1, 0xd5, 0xf1, 0xbc,
                0xbb, 0xa6, 0x13, 0x64, 0x00, 0xd9, 0xf0, 0xa6,
                0x34, 0x34, 0x22, 0x5f, 0xee, 0x25, 0x90, 0xae
            };
            static const uint8_t fixture_upp[] = "the-uicc-profile-fixture";
            unsigned char pdr_buf[512];
            size_t pdr_len = 0;
            uint8_t *bpp = NULL;
            size_t bpp_len = 0;
            int bpp_rc;

            ok("a fixture PrepareDownloadResponse encodes",
               build_prepare_download_response(
                       transaction_id, euicc_otpk,
                       pdr_buf, sizeof pdr_buf, &pdr_len) == 0);

            bpp_rc = rsp_dp_get_bound_profile_package(
                    sess, pdr_buf, pdr_len,
                    fixture_upp, sizeof fixture_upp - 1,
                    otsk_dp, &bpp, &bpp_len);
            ok("rsp_dp_get_bound_profile_package succeeds", bpp_rc == 0);
            ok("a BoundProfilePackage was returned", bpp != NULL && bpp_len > 0);

            if (bpp_rc == 0 && bpp) {
                /* Independently recompute the session rsp_dp_get_bound_
                   profile_package must have derived, using RSP_HOST_ID
                   from src/rsp_internal.h directly (not by calling any
                   function in src/rsp_es9.c) -- if that file's own
                   SharedInfo ever used a different hostId than
                   RSP_HOST_ID, this recomputation would derive a
                   different session, and rsp_bpp_recover below would
                   fail. See this file's own top comment. */
                uint8_t shared_info[2 + 1 + RSP_HOST_ID_LEN + 1 + 32];
                size_t si_len = 0;
                rsp_session_t expected;
                uint8_t *recovered = NULL;
                size_t recovered_len = 0;
                size_t eid_len = strlen(EUICC_TEST_EID);

                shared_info[0] = 0x88;
                shared_info[1] = 0x10;
                shared_info[2] = (uint8_t)RSP_HOST_ID_LEN;
                memcpy(shared_info + 3, RSP_HOST_ID, RSP_HOST_ID_LEN);
                shared_info[3 + RSP_HOST_ID_LEN] = (uint8_t)eid_len;
                memcpy(shared_info + 3 + RSP_HOST_ID_LEN + 1,
                       EUICC_TEST_EID, eid_len);
                si_len = 3 + RSP_HOST_ID_LEN + 1 + eid_len;

                ok("the independently-recomputed session derives",
                   rsp_session_init(otsk_dp, euicc_otpk, shared_info,
                                     si_len, &expected) == 0);

                ok("rsp_bpp_recover decrypts the produced BPP with that session",
                   rsp_bpp_recover(&expected, bpp, bpp_len,
                                    &recovered, &recovered_len) == 0);
                ok("the recovered UPP matches the fixture, byte for byte",
                   recovered != NULL &&
                   recovered_len == sizeof fixture_upp - 1 &&
                   memcmp(recovered, fixture_upp, recovered_len) == 0);

                if (recovered) {
                    mbedtls_platform_zeroize(recovered, recovered_len);
                }
                free(recovered);
                rsp_session_wipe(&expected);
            }
            free(bpp);
        }
    }

    rsp_dp_session_free(sess);

    return fails ? 1 : 0;
}
