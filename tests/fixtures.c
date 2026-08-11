/*
 * fixtures.c -- see fixtures.h.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsp.h"
#include "rsp_internal.h"

#include "ber_tlv_length.h"
#include "ber_tlv_tag.h"

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
#include "ProfileInstallationResult.h"
#include "ServerSigned1.h"
#include "SmdpSigned2.h"
#include "StoreMetadataRequest.h"
#include "fixtures.h"
/* SGP.22 v2.6 section 5.6.1 has the SM-DP+ compare the address the LPA
   sent against its own "case-insensitive[ly]". A host name is ASCII, and
   strcasecmp folds according to the locale, so these three state the
   property in the only terms that hold everywhere. SMDP_ADDR is also
   what the fixtures below echo back, so that what the eUICC is made to
   say it saw is what the server was actually given. */
const char SMDP_ADDR[]  = "smdp.example.com";
const char SMDP_UPPER[] = "SMDP.EXAMPLE.COM";
const char SMDP_OTHER[] = "other.example.com";

int collect(const void *buf, size_t n, void *key) {
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
int build_euicc_info1(unsigned char *buf, size_t cap, size_t *out_len) {
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

/* The test eUICC's own EID, exactly as testdata/sgp26/euicc.der's Subject
   serialNumber carries it -- SGP.22 v2.6 section 4.5.1's own worked
   example, and this project's real test card (see task-3-brief.md). */
const char EUICC_TEST_EID[] = "89049032123451234512345678901235";

/* testdata/sgp26/euicc-key.pem's raw big-endian P-256 scalar, exactly as
   rsp_credential_t.sk stores it. Derived once with
   `openssl ec -in testdata/sgp26/euicc-key.pem -noout -text` and pinned
   here rather than re-parsed from PEM at test time: this project's test
   key is fixed, published SGP.26 v1.0 material (see testdata/sgp26/
   README.md) that never changes, and parsing SEC1 PEM is exactly the
   mbedtls_pk_parse_key plumbing src/rsp_pki.c already owns for the
   *library's own* DP credentials -- this fixture is not one of those. */
const uint8_t EUICC_TEST_SK[32] = {
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
int build_euicc_info2(EUICCInfo2_t *info) {
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
int build_device_info(DeviceInfo_t *di) {
    memset(di, 0, sizeof *di);
    return OCTET_STRING_fromBuf(&di->tac, "\x00\x00\x00\x00", 4);
}

/* CtxParams1 (rsp-2.5.asn line 294): the only CHOICE arm this module
   defines. matchingId stays absent (OPTIONAL) -- this fixture is a
   Profile Download, not an Activation Code Retrieval. */
int build_ctx_params1(CtxParams1_t *cp) {
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
int build_auth_server_response(
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
        /* The eUICC echoes back the serverAddress it was sent, so this
           fixture must echo the one the server actually signed. The
           length is strlen, not sizeof: the previous literal passed 33
           for a 32-character string and carried the NUL into the
           UTF8String. */
        OCTET_STRING_fromBuf(&rok->euiccSigned1.serverAddress,
                              SMDP_ADDR, (int)strlen(SMDP_ADDR)) != 0 ||
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
int build_store_metadata(const uint8_t iccid[10],
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


/* A ProfileInstallationResult the way a real eUICC builds one: the
   profileInstallationResultData object, then euiccSignPIR over that
   object's own DER -- "across the data object
   ProfileInstallationResultData (tag 'BF 27')", SGP.22 v2.6 section
   2.5.6 -- signed with the same EUICC_TEST_SK the other fixtures here
   use, so it verifies against the same CERT.EUICC the session holds. */
int build_installation_result(
        const uint8_t transaction_id[16], int success,
        unsigned char *out, size_t cap, size_t *out_len) {
    ProfileInstallationResult_t pir;
    ProfileInstallationResultData_t *d;
    unsigned char data_buf[512];
    struct sink data_sink = { data_buf, 0, sizeof data_buf };
    struct sink out_sink = { out, 0, cap };
    asn_enc_rval_t r;
    rsp_credential_t euicc_cred;
    uint8_t sig[64];
    int ret = -1;

    memset(&pir, 0, sizeof pir);
    d = &pir.profileInstallationResultData;

    static const uint8_t aid[16] = {
        0xA0,0x00,0x00,0x05,0x59,0x10,0x10,0xFF,
        0xFF,0xFF,0xFF,0x89,0x00,0x00,0x11,0x00
    };
    if (OCTET_STRING_fromBuf(&d->transactionId,
                              (const char *)transaction_id, 16) != 0 ||
        asn_long2INTEGER(&d->notificationMetadata.seqNumber, 1) != 0 ||
        OCTET_STRING_fromBuf(
            (OCTET_STRING_t *)&d->notificationMetadata.profileManagementOperation,
            "\x80", 1) != 0 ||
        OCTET_STRING_fromBuf(&d->notificationMetadata.notificationAddress,
                              "smdp-address-placeholder.invalid", 32) != 0) {
        goto done;
    }
    /* smdpOid: any well-formed OID -- this function is about the
       signature, and nothing in rsp_dp_verify_installation_result reads
       this field. 2.999 is the ITU-T "example" arc. */
    {
        static const asn_oid_arc_t arcs[2] = { 2, 999 };
        if (OBJECT_IDENTIFIER_set_arcs(&d->smdpOid, arcs, 2) != 0) {
            goto done;
        }
    }
    if (success) {
        d->finalResult.present =
            ProfileInstallationResultData__finalResult_PR_successResult;
        if (OCTET_STRING_fromBuf(&d->finalResult.choice.successResult.aid,
                                  (const char *)aid, sizeof aid) != 0 ||
            OCTET_STRING_fromBuf(
                &d->finalResult.choice.successResult.simaResponse,
                "\x30\x00", 2) != 0) {
            goto done;
        }
    } else {
        d->finalResult.present =
            ProfileInstallationResultData__finalResult_PR_errorResult;
        if (asn_long2INTEGER(
                &d->finalResult.choice.errorResult.bppCommandId, 5) != 0 ||
            asn_long2INTEGER(
                &d->finalResult.choice.errorResult.errorReason, 12) != 0) {
            goto done;
        }
    }

    r = der_encode(&asn_DEF_ProfileInstallationResultData, d, collect,
                   &data_sink);
    if (r.encoded < 0) {
        goto done;
    }

    memset(&euicc_cred, 0, sizeof euicc_cred);
    memcpy(euicc_cred.sk, EUICC_TEST_SK, sizeof euicc_cred.sk);
    if (rsp_sign(&euicc_cred, data_sink.p, data_sink.len, sig) != 0) {
        goto done;
    }
    if (OCTET_STRING_fromBuf(&pir.euiccSignPIR, (const char *)sig, 64) != 0) {
        goto done;
    }

    r = der_encode(&asn_DEF_ProfileInstallationResult, &pir, collect,
                   &out_sink);
    if (r.encoded < 0) {
        goto done;
    }
    *out_len = out_sink.len;
    ret = 0;

done:
    ASN_STRUCT_RESET(asn_DEF_ProfileInstallationResult, &pir);
    return ret;
}

/* PrepareDownloadResponse (rsp-2.5.asn line 255), the downloadResponseOk
   arm: euiccSigned2 carries transaction_id and euicc_otpk (otPK.EUICC.ECKA),
   signed with the same EUICC_TEST_SK -- 5.6.2's "euiccSignature2 ...
   using the PK.EUICC.ECDSA attached to the ongoing RSP session" is the
   same key AuthenticateClient already verified against.

   What is signed is euiccSigned2 AND smdpSignature2, concatenated:
   "Compute the euiccSignature2 over euiccSigned2 and smdpSignature2"
   (SGP.22 v2.6 section 3.1.3.2, step 3). smdp_signature2 is the one the
   AuthenticateClient step actually produced, copied out of that response
   by the caller -- a real eUICC signs over the bytes it was handed in
   PrepareDownload, and a fixture that signed over anything else would be
   testing a card that does not exist. It goes in as its own TLV, tag
   '5F37' ([APPLICATION 55]), written as literals here for the same
   reason the assertion above does. */
int build_prepare_download_response(
        const uint8_t transaction_id[16], const uint8_t euicc_otpk[65],
        const uint8_t smdp_signature2[64],
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

    if (es2_sink.len + 3 + 64 > es2_sink.cap) {
        goto done;
    }
    es2_sink.p[es2_sink.len + 0] = 0x5F;
    es2_sink.p[es2_sink.len + 1] = 0x37;
    es2_sink.p[es2_sink.len + 2] = 64;
    memcpy(es2_sink.p + es2_sink.len + 3, smdp_signature2, 64);
    es2_sink.len += 3 + 64;

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

