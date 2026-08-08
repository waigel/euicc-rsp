/* rsp_dp_initiate_authentication (SGP.22 v2.6 section 5.6.1), pinned
   against a fixed transactionId and a fixed euiccChallenge: this is the
   test src/rsp_es9.c's own top comment and task-2-report.md both point
   at as proof that a caller-supplied transactionId genuinely flows
   through, rather than being ignored -- see mutation (c) below, which is
   why this file exists in the shape it does.

   Decodes the response with the same generated codec that built it
   (asn_DEF_InitiateAuthenticationOkEs9), then checks, per the task
   brief's own Step 2:

     - serverSigned1.transactionId equals what was passed in
     - serverSigned1.euiccChallenge equals the challenge
     - serverSignature1 verifies against CERT.DPauth with rsp_sign_verify
     - the returned certificate is DPauth's, not DPpb's (der_len and the
       first 32 bytes -- and, since nothing forbids checking more, the
       whole thing) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsp.h"

#include "Certificate.h"
#include "EUICCInfo1.h"
#include "InitiateAuthenticationOkEs9.h"
#include "ServerSigned1.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if (!good) fails++;
}

/* A fixed-capacity sink for der_encode's callback interface -- everything
   this test encodes (a minimal EUICCInfo1 fixture, a re-encoded
   ServerSigned1, a re-encoded Certificate) is well under 2048 bytes, and
   a capacity check turns "too big" into a test failure rather than a
   buffer overrun, the same caution test_codec.c's own fixed 512-byte
   buffers take for the smaller StoreMetadataRequest it re-encodes. */
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

/* A minimal, structurally valid EUICCInfo1: this test's own euicc_info1
   input, not something rsp_dp_initiate_authentication interprets deeply
   yet (see src/rsp_es9.c's top comment) -- it only has to decode. Empty
   euiccCiPKIdListForVerification/ForSigning (a SEQUENCE OF with zero
   elements) is valid DER; svn is EUICCInfo1's one fixed-size(3) field
   and is given an arbitrary version, "2.0.0", since nothing here checks
   its value either. */
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

    ASN_STRUCT_FREE(asn_DEF_InitiateAuthenticationOkEs9, decoded);
    free(resp);
    rsp_dp_session_free(sess);

    return fails ? 1 : 0;
}
