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

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if (!good) fails++;
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
    /* Fixed for the same reason transaction_id is: with the last value
       this function used to draw from entropy now supplied by the
       caller, a whole session becomes reproducible, and reproducible is
       what makes a recorded fixture possible. */
    static const uint8_t server_challenge_in[16] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f
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
                                         transaction_id, server_challenge_in,
                                         SMDP_ADDR, SMDP_ADDR,
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

    ok("serverSigned1.serverChallenge is the one that was passed in",
       decoded->serverSigned1.serverChallenge.size == 16 &&
       memcmp(decoded->serverSigned1.serverChallenge.buf,
              server_challenge_in, 16) == 0);

    /* With the serverChallenge supplied rather than drawn, and rsp_sign
       signing deterministically, this function is a pure function of
       its inputs. That is the property tools/session-fixtures stands
       on: a session recorded once replays anywhere. */
    {
        rsp_dp_session_t *sr = NULL;
        uint8_t *rr = NULL;
        size_t rr_len = 0;
        int rcr = rsp_dp_initiate_authentication(
                euicc_challenge, sizeof euicc_challenge,
                info1_buf, info1_len, transaction_id, server_challenge_in,
                SMDP_ADDR, SMDP_ADDR, &sr, &rr, &rr_len);
        ok("the same inputs open a session again", rcr == 0);
        ok("and produce a byte-identical response",
           rcr == 0 && rr_len == resp_len &&
           memcmp(rr, resp, resp_len) == 0);
        free(rr);
        rsp_dp_session_free(sr);
    }

    /* serverSigned1.serverAddress is the SM-DP+'s own FQDN (5.7.13), and
       it is now the caller's to supply. Before this, a fixed
       ".invalid" placeholder was signed in its place. */
    ok("serverSigned1 carries the address it was given",
       decoded->serverSigned1.serverAddress.size == strlen(SMDP_ADDR) &&
       memcmp(decoded->serverSigned1.serverAddress.buf,
              SMDP_ADDR, strlen(SMDP_ADDR)) == 0);

    /* The placeholder ended in RFC 2606's reserved ".invalid". Checking
       the tail rather than searching the whole string keeps this to
       plain C89 -- memmem is a GNU/BSD extension and would need
       _GNU_SOURCE on the Linux CI runner. */
    ok("no placeholder address survives",
       decoded->serverSigned1.serverAddress.size >= 8 &&
       memcmp(decoded->serverSigned1.serverAddress.buf +
                  decoded->serverSigned1.serverAddress.size - 8,
              ".invalid", 8) != 0);

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

    /* --- rsp_dp_initiate_fields: the five fields the JSON binding names
       (SGP.22 v2.6 section 6.5.2.6), cut out of the response rather
       than decoded and rebuilt ------------------------------------- */
    {
        rsp_dp_initiate_fields_t f;
        memset(&f, 0, sizeof f);

        ok("initiate fields slice out",
           rsp_dp_initiate_fields(resp, resp_len, &f) == 0);
        ok("every initiate field is non-empty",
           f.transaction_id_len && f.server_signed1_len &&
           f.server_signature1_len && f.euicc_ci_pkid_len &&
           f.server_certificate_len);
        ok("initiate fields borrow from the response",
           f.transaction_id >= resp &&
           f.server_certificate + f.server_certificate_len <= resp + resp_len);

        /* serverSigned1 and serverCertificate are both untagged
           SEQUENCEs encoding with tag '30'. A tag search would find the
           first and call it the second, so the walk must be positional
           -- these two assertions are what would catch that. */
        ok("serverSigned1 precedes serverSignature1",
           f.server_signed1 < f.server_signature1);
        ok("serverCertificate follows serverSignature1",
           f.server_certificate > f.server_signature1);

        ok("serverSignature1 carries its own tag ([APPLICATION 55], 5F37)",
           f.server_signature1_len > 2 && f.server_signature1[0] == 0x5f &&
           f.server_signature1[1] == 0x37);
        /* [0] over an OCTET STRING, and rsp-2.5.asn is AUTOMATIC TAGS,
           so the tag is implicit and primitive -- 80, not the
           constructed A0 an explicit tag would give. Pinned here
           because the slice's first byte is what a server base64s. */
        ok("transactionId carries its own tag ([0] implicit, 80)",
           f.transaction_id_len > 2 && f.transaction_id[0] == 0x80);

        ok("a truncated response is refused, not misread",
           rsp_dp_initiate_fields(resp, resp_len / 2, &f) == -1);
        ok("a null response is -2",
           rsp_dp_initiate_fields(NULL, resp_len, &f) == -2);
        ok("a null out is -2",
           rsp_dp_initiate_fields(resp, resp_len, NULL) == -2);
    }

    /* The whole point of slicing: what comes out is what went in.
       Re-encode ServerSigned1 from the decode above and require the
       bytes to be identical to the slice. If they ever differ, this
       function has started reconstructing rather than cutting, and a
       BER response would silently change on the wire -- the failure
       commit 8928231 removed elsewhere. */
    {
        rsp_dp_initiate_fields_t f;
        unsigned char again[512];
        struct sink sk = { again, 0, sizeof again };
        asn_enc_rval_t er;

        memset(&f, 0, sizeof f);
        ok("fields for the round trip",
           rsp_dp_initiate_fields(resp, resp_len, &f) == 0);
        er = der_encode(&asn_DEF_ServerSigned1, &decoded->serverSigned1,
                        collect, &sk);
        ok("serverSigned1 re-encodes", er.encoded > 0);
        ok("and the slice is byte-identical to it",
           sk.len == f.server_signed1_len &&
           memcmp(again, f.server_signed1, f.server_signed1_len) == 0);
    }

    /* --- the section 5.6.1 address check itself, four ways ------------
       "Check if the received address matches its own SM-DP+ address,
       where the comparison SHALL be case-insensitive." Each of these
       opens its own session, because a refusal must not leave one
       behind. */
    {
        rsp_dp_session_t *s2 = NULL;
        uint8_t *r2 = NULL;
        size_t r2_len = 0;
        int rc2 = rsp_dp_initiate_authentication(
                euicc_challenge, sizeof euicc_challenge,
                info1_buf, info1_len, transaction_id, server_challenge_in,
                SMDP_ADDR, SMDP_UPPER, &s2, &r2, &r2_len);
        ok("a case-only difference is accepted", rc2 == 0);
        free(r2);
        rsp_dp_session_free(s2);
    }

    {
        rsp_dp_session_t *s3 = NULL;
        uint8_t *r3 = NULL;
        size_t r3_len = 0;
        int rc3 = rsp_dp_initiate_authentication(
                euicc_challenge, sizeof euicc_challenge,
                info1_buf, info1_len, transaction_id, server_challenge_in,
                SMDP_ADDR, SMDP_OTHER, &s3, &r3, &r3_len);
        ok("a different address is refused with -1", rc3 == -1);
        ok("a refusal returns no session", s3 == NULL);
        ok("a refusal returns no response", r3 == NULL);
    }

    {
        /* A missing own-address is a question never reached, not a no. */
        rsp_dp_session_t *s4 = NULL;
        uint8_t *r4 = NULL;
        size_t r4_len = 0;
        int rc4 = rsp_dp_initiate_authentication(
                euicc_challenge, sizeof euicc_challenge,
                info1_buf, info1_len, transaction_id, server_challenge_in,
                NULL, SMDP_ADDR, &s4, &r4, &r4_len);
        ok("a null server address is -2, not -1", rc4 == -2);
    }

    {
        /* No address to check against is legitimate -- a caller that
           never received one. The comparison is skipped; the signing
           is not. */
        rsp_dp_session_t *s5 = NULL;
        uint8_t *r5 = NULL;
        size_t r5_len = 0;
        InitiateAuthenticationOkEs9_t *d5 = NULL;
        int rc5 = rsp_dp_initiate_authentication(
                euicc_challenge, sizeof euicc_challenge,
                info1_buf, info1_len, transaction_id, server_challenge_in,
                SMDP_ADDR, NULL, &s5, &r5, &r5_len);
        ok("a null requested address skips the check", rc5 == 0);
        if (rc5 == 0 && r5) {
            asn_dec_rval_t dr5 = ber_decode(
                    NULL, &asn_DEF_InitiateAuthenticationOkEs9,
                    (void **)&d5, r5, r5_len);
            ok("and still signs the real address",
               dr5.code == RC_OK && d5 != NULL &&
               d5->serverSigned1.serverAddress.size == strlen(SMDP_ADDR) &&
               memcmp(d5->serverSigned1.serverAddress.buf,
                      SMDP_ADDR, strlen(SMDP_ADDR)) == 0);
            ASN_STRUCT_FREE(asn_DEF_InitiateAuthenticationOkEs9, d5);
        }
        free(r5);
        rsp_dp_session_free(s5);
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
        /* smdpSignature2, copied out of the AuthenticateClient response
           while it still exists: ac_out is freed further down, and the
           PrepareDownloadResponse fixture built after that has to sign
           over these exact bytes (SGP.22 v2.6 section 3.1.3.2 step 3,
           "over euiccSigned2 and smdpSignature2"). */
        uint8_t smdp_sig2[64];
        int have_smdp_sig2 = 0;

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

        /* --- rsp_dp_authenticate_fields: the five fields of section
           6.5.2.8. This response is an AuthenticateClientResponseEs9 --
           the CHOICE, tag 'BF3B' -- not the bare Ok SEQUENCE that
           InitiateAuthentication returns, so the walk has one more
           level to step through. --------------------------------- */
        if (rc == 0 && ac_out) {
            rsp_dp_authenticate_fields_t g;
            memset(&g, 0, sizeof g);

            ok("authenticate fields slice out",
               rsp_dp_authenticate_fields(ac_out, ac_out_len, &g) == 0);
            ok("every authenticate field is non-empty",
               g.transaction_id_len && g.profile_metadata_len &&
               g.smdp_signed2_len && g.smdp_signature2_len &&
               g.smdp_certificate_len);
            ok("authenticate fields borrow from the response",
               g.transaction_id >= ac_out &&
               g.smdp_certificate + g.smdp_certificate_len
                   <= ac_out + ac_out_len);
            ok("profileMetadata carries its own tag ([37], BF25)",
               g.profile_metadata_len > 2 && g.profile_metadata[0] == 0xbf &&
               g.profile_metadata[1] == 0x25);
            ok("smdpSignature2 carries its own tag ([APPLICATION 55], 5F37)",
               g.smdp_signature2_len > 2 && g.smdp_signature2[0] == 0x5f &&
               g.smdp_signature2[1] == 0x37);
            /* smdpSigned2 and smdpCertificate are the pair of untagged
               SEQUENCEs here -- same positional requirement. */
            ok("smdpCertificate follows smdpSignature2",
               g.smdp_certificate > g.smdp_signature2);
            ok("a truncated authenticate response is refused",
               rsp_dp_authenticate_fields(ac_out, ac_out_len / 2, &g) == -1);
            ok("a null authenticate response is -2",
               rsp_dp_authenticate_fields(NULL, ac_out_len, &g) == -2);
        }

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

                    if (aco->smdpSignature2.size == 64) {
                        memcpy(smdp_sig2, aco->smdpSignature2.buf, 64);
                        have_smdp_sig2 = 1;
                    }

                    /* smdpSignature2 applies over smdpSigned2 AND the
                       eUICC's own euiccSignature1, concatenated (SGP.22
                       v2.6 section 3.1.3, step 5) -- not over smdpSigned2
                       alone, which is what this assertion used to pin and
                       what a real eUICC answered PrepareDownload's
                       invalidSignature(2) to.
                       euiccSignature1 goes in as its own TLV, tag '5F37'
                       ([APPLICATION 55]); the two literal tag bytes are
                       written out here rather than taken from the
                       implementation, so a test borrowing the same
                       constant cannot agree with it by construction.

                       And it MUST verify against CERT.DPpb -- never
                       CERT.DPauth, the mistake the brief calls out as
                       most worth catching (DPauth already signed
                       InitiateAuthentication's serverSigned1; a
                       different key for a different purpose).

                       euiccSignature1 is read back out of the very
                       fixture this call consumed (asr_buf), not
                       recomputed here: the point is that the SM-DP+
                       signed over what the eUICC actually sent. */
                    {
                        unsigned char sd2_buf[512];
                        struct sink s = { sd2_buf, 0, sizeof sd2_buf };
                        asn_enc_rval_t r = der_encode(
                                &asn_DEF_SmdpSigned2, &aco->smdpSigned2,
                                collect, &s);
                        ok("the decoded smdpSigned2 re-encodes",
                           r.encoded >= 0);

                        AuthenticateServerResponse_t *asr_back = NULL;
                        asn_dec_rval_t ar = ber_decode(
                                NULL, &asn_DEF_AuthenticateServerResponse,
                                (void **)&asr_back, asr_buf, asr_len);
                        int have_es1 =
                            ar.code == RC_OK && asr_back &&
                            asr_back->present ==
                                AuthenticateServerResponse_PR_authenticateResponseOk &&
                            asr_back->choice.authenticateResponseOk
                                .euiccSignature1.size == 64;
                        ok("the fixture's own euiccSignature1 is recoverable",
                           have_es1);

                        if (have_es1 && r.encoded >= 0 &&
                            s.len + 3 + 64 <= s.cap) {
                            s.p[s.len + 0] = 0x5F;
                            s.p[s.len + 1] = 0x37;
                            s.p[s.len + 2] = 64;
                            memcpy(s.p + s.len + 3,
                                   asr_back->choice.authenticateResponseOk
                                       .euiccSignature1.buf, 64);
                            s.len += 3 + 64;
                        }
                        if (asr_back) {
                            ASN_STRUCT_FREE(asn_DEF_AuthenticateServerResponse,
                                            asr_back);
                        }

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
                    info1_buf, info1_len, transaction_id, server_challenge_in,
                    SMDP_ADDR, SMDP_ADDR,
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
                    info1_buf, info1_len, transaction_id, server_challenge_in,
                    SMDP_ADDR, SMDP_ADDR,
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

            ok("the AuthenticateClient step yielded an smdpSignature2 to "
               "chain euiccSignature2 onto", have_smdp_sig2);
            ok("a fixture PrepareDownloadResponse encodes",
               have_smdp_sig2 &&
               build_prepare_download_response(
                       transaction_id, euicc_otpk, smdp_sig2,
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
                   fail. See this file's own top comment.

                   The EID goes in as its sixteen octets, not as the
                   thirty-two decimal characters EUICC_TEST_EID spells it
                   with: Annex G's EID-LV is the eidValue an eUICC holds,
                   "[APPLICATION 26] Octet16". Packed here digit pair by
                   digit pair rather than by calling src/rsp_es9.c's own
                   converter, so a bug in that converter cannot agree with
                   this recomputation by construction -- the same reason
                   RSP_HOST_ID is read from the header instead of from a
                   function. */
                uint8_t shared_info[2 + 1 + RSP_HOST_ID_LEN + 1 + 16];
                size_t si_len = 0;
                rsp_session_t expected;
                uint8_t *recovered = NULL;
                size_t recovered_len = 0;
                uint8_t eid_octets[16];
                size_t i;

                ok("the test EID is thirty-two decimal digits",
                   strlen(EUICC_TEST_EID) == 32);
                for (i = 0; i < 16; i++) {
                    eid_octets[i] = (uint8_t)
                        (((EUICC_TEST_EID[2 * i] - '0') << 4) |
                          (EUICC_TEST_EID[2 * i + 1] - '0'));
                }

                shared_info[0] = 0x88;
                shared_info[1] = 0x10;
                shared_info[2] = (uint8_t)RSP_HOST_ID_LEN;
                memcpy(shared_info + 3, RSP_HOST_ID, RSP_HOST_ID_LEN);
                shared_info[3 + RSP_HOST_ID_LEN] = (uint8_t)sizeof eid_octets;
                memcpy(shared_info + 3 + RSP_HOST_ID_LEN + 1,
                       eid_octets, sizeof eid_octets);
                si_len = 3 + RSP_HOST_ID_LEN + 1 + sizeof eid_octets;

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

    /* The eUICC's own report, and whether this library can tell a genuine
       one from bytes that merely claim to be one. Before
       rsp_dp_verify_installation_result existed, a ProfileInstallationResult
       was believed because it arrived -- so the assertions that matter here
       are the two mutations, not the happy path: a check that only ever
       answers "genuine" is worse than no check, because it reads like one.

       The fixture is signed with EUICC_TEST_SK over
       profileInstallationResultData's own DER, which is what SGP.22 v2.6
       section 2.5.6 requires ("across the data object
       ProfileInstallationResultData (tag 'BF 27')"), and verifies against
       the CERT.EUICC this session attached in AuthenticateClient above. */
    {
        unsigned char pir[768];
        size_t pir_len = 0;
        int installed = -1;

        ok("a fixture ProfileInstallationResult encodes",
           build_installation_result(transaction_id, 1, pir, sizeof pir,
                                      &pir_len) == 0);

        ok("a genuine result verifies",
           rsp_dp_verify_installation_result(sess, pir, pir_len, &installed,
                                              NULL, NULL) == 0);
        ok("...and reports the profile as installed", installed == 1);

        /* Mutation 1: one byte of the signature. The signed bytes are
           untouched, so this is exactly the case a check that never looks
           at euiccSignPIR would pass. -1, not -2: the question was asked
           of a cryptographic primitive and the answer is no. */
        {
            unsigned char bad[768];
            memcpy(bad, pir, pir_len);
            /* The last byte of the encoding is inside euiccSignPIR: it is
               the final field, and its 64 content octets end the outer
               SEQUENCE. */
            bad[pir_len - 1] ^= 0xFF;
            int inst = -1;
            ok("a tampered signature is refused with -1",
               rsp_dp_verify_installation_result(sess, bad, pir_len, &inst,
                                                  NULL, NULL) == -1);
        }

        /* Mutation 2: a report for a different session. The signature is
           genuine for what it covers -- it is simply not this download's
           report, which a check that only verified the signature would
           accept. */
        {
            unsigned char other[768];
            size_t other_len = 0;
            uint8_t other_tid[16];
            memcpy(other_tid, transaction_id, 16);
            other_tid[0] ^= 0xFF;
            int inst = -1;
            ok("a result for another transactionId encodes",
               build_installation_result(other_tid, 1, other, sizeof other,
                                          &other_len) == 0);
            ok("...and is refused with -1, though its signature is genuine",
               rsp_dp_verify_installation_result(sess, other, other_len,
                                                  &inst, NULL, NULL) == -1);
        }

        /* The fidelity case, and the reason this function slices the
           signed bytes out of what arrived instead of re-encoding them.

           SGP.22 v2.6 section 2.5.6 puts the signature "across the data
           object ProfileInstallationResultData (tag 'BF 27')" -- those
           bytes. BER permits a non-minimal length octet where a shorter
           one would do, ber_decode accepts it, and der_encode normalizes
           it away. So a report encoded that way, with a signature
           genuinely computed over it, is one a re-encoding verifier
           rejects and a slicing one accepts. A real card sends DER and
           would never produce it, which is exactly why it has to be
           constructed here: the earlier, re-encoding version of this
           function passed every other assertion in this file.

           The TLVs are located rather than counted: the outer BF37 is
           already past 128 bytes, so its own length is in long form, and
           an earlier draft of this block that assumed short form got the
           offsets wrong -- caught by asserting the layout instead of
           trusting it. */
        {
            unsigned char ber[900];
            size_t ber_len = 0;
            int inst = -1;
            ber_tlv_tag_t tg;
            ber_tlv_len_t clen;
            ssize_t tl, ll;
            size_t outer_hdr = 0, dhdr = 0, dlen = 0, tail_off = 0, tail = 0;
            int laid_out = 0;

            tl = ber_fetch_tag(pir, pir_len, &tg);
            if (tl > 0) {
                ll = ber_fetch_length(1, pir + tl, pir_len - (size_t)tl, &clen);
                if (ll > 0) {
                    outer_hdr = (size_t)tl + (size_t)ll;
                    tl = ber_fetch_tag(pir + outer_hdr, pir_len - outer_hdr, &tg);
                    if (tl > 0) {
                        ll = ber_fetch_length(1, pir + outer_hdr + (size_t)tl,
                                               pir_len - outer_hdr - (size_t)tl,
                                               &clen);
                        if (ll > 0) {
                            dhdr = (size_t)tl + (size_t)ll;
                            dlen = (size_t)clen;
                            tail_off = outer_hdr + dhdr + dlen;
                            tail = pir_len - tail_off;
                            laid_out = 1;
                        }
                    }
                }
            }
            ok("the fixture's two headers parse", laid_out);
            ok("...and the data object is BF27",
               laid_out && pir[outer_hdr] == 0xBF && pir[outer_hdr + 1] == 0x27);
            /* euiccSignPIR is 5F37 40 <64 bytes>. */
            ok("...and the tail is the 67-byte euiccSignPIR TLV",
               laid_out && tail == 67 && pir[tail_off] == 0x5F &&
               pir[tail_off + 1] == 0x37 && pir[tail_off + 2] == 64);

            if (laid_out && tail == 67 && dlen < 128) {
                /* The same content under a two-octet long-form length:
                   valid BER, not DER. */
                unsigned char data_obj[600];
                uint8_t sig2[64];
                rsp_credential_t cred;
                size_t obj_len = 4 + dlen;

                data_obj[0] = 0xBF; data_obj[1] = 0x27;
                data_obj[2] = 0x81; data_obj[3] = (unsigned char)dlen;
                memcpy(data_obj + 4, pir + outer_hdr + dhdr, dlen);

                memset(&cred, 0, sizeof cred);
                memcpy(cred.sk, EUICC_TEST_SK, sizeof cred.sk);
                ok("the non-minimal data object signs",
                   rsp_sign(&cred, data_obj, obj_len, sig2) == 0);

                ber[0] = 0xBF; ber[1] = 0x37;
                ber[2] = 0x81;
                ber[3] = (unsigned char)(obj_len + tail);
                memcpy(ber + 4, data_obj, obj_len);
                memcpy(ber + 4 + obj_len, pir + tail_off, tail);
                memcpy(ber + 4 + obj_len + 3, sig2, 64);
                ber_len = 4 + obj_len + tail;

                ok("a genuine signature over a non-minimal encoding verifies",
                   rsp_dp_verify_installation_result(sess, ber, ber_len,
                                                      &inst, NULL, NULL) == 0);
                ok("...and still reports the profile as installed", inst == 1);
            }
        }

        /* A signed refusal is a complete answer, not an error: the card
           said truthfully that it could not install, and establishing that
           the card said it is this function's whole job. */
        {
            unsigned char err[768];
            size_t err_len = 0;
            int inst = -1;
            long cmd = -1, reason = -1;
            ok("a fixture errorResult encodes",
               build_installation_result(transaction_id, 0, err, sizeof err,
                                          &err_len) == 0);
            ok("a genuine refusal verifies, and is not an error",
               rsp_dp_verify_installation_result(sess, err, err_len, &inst,
                                                  &cmd, &reason) == 0);
            ok("...reporting the profile as not installed", inst == 0);
            ok("...and naming loadProfileElements(5)", cmd == 5);
            ok("...and installFailedDueToPEProcessingError(12)", reason == 12);
        }
    }

    rsp_dp_session_free(sess);

    /* ---- rsp_dp_verify_notification ----------------------------------
       A notification arrives with no session behind it, so this is the
       session-free check. The two arms are not symmetric: a
       ProfileInstallationResult carries no certificates and needs one
       kept from the download, while an OtherSignedNotification carries
       CERT.EUICC and CERT.EUM itself. */
    {
        rsp_credential_t euicc_cert;
        memset(&euicc_cert, 0, sizeof euicc_cert);

        /* --- the installation-result arm --- */
        {
            unsigned char pir[1024];
            size_t pir_len = 0;
            rsp_notification_t v;

            ok("a ProfileInstallationResult fixture encodes",
               build_installation_result(transaction_id, 1, pir, sizeof pir,
                                          &pir_len) == 0);
            memset(&v, 0, sizeof v);
            ok("it verifies against the eUICC's certificate",
               rsp_dp_verify_notification(rsp_sgp26_euicc_der,
                                           rsp_sgp26_euicc_der_len,
                                           pir, pir_len, &v) == 0);
            ok("...and is reported as an installation result", v.is_installation_result == 1);
            ok("...that says the profile was installed", v.installed == 1);
            ok("...carrying the metadata a server routes by",
               v.seq_number == 1 && v.operation == 0);

            /* Without a certificate there is nothing to check against,
               and this arm cannot fall back on anything embedded. */
            memset(&v, 0, sizeof v);
            ok("without a certificate the question cannot be asked",
               rsp_dp_verify_notification(NULL, 0, pir, pir_len, &v) == -2);

            /* The DP's certificate is a real, well-formed certificate --
               just not this eUICC's. A -1, not a -2: the question was
               asked. */
            {
                rsp_credential_t dpauth;
                memset(&dpauth, 0, sizeof dpauth);
                ok("DPauth loads, to check against the wrong certificate",
                   rsp_pki_dp(0, &dpauth) == 0);
                memset(&v, 0, sizeof v);
                ok("another certificate is a refusal, not a failure to ask",
                   rsp_dp_verify_notification(dpauth.der, dpauth.der_len,
                                               pir, pir_len, &v) == -1);
                rsp_credential_free(&dpauth);
            }

            /* One byte of the signed data changed. */
            if (pir_len > 40) {
                unsigned char tampered[1024];
                memcpy(tampered, pir, pir_len);
                tampered[pir_len - 40] ^= 0x01;
                memset(&v, 0, sizeof v);
                ok("a tampered notification does not verify",
                   rsp_dp_verify_notification(rsp_sgp26_euicc_der,
                                               rsp_sgp26_euicc_der_len,
                                               tampered, pir_len, &v) != 0);
            }
        }

        /* --- the self-contained arm --- */
        {
            unsigned char osn[2048];
            size_t osn_len = 0;
            rsp_notification_t v;

            ok("an OtherSignedNotification fixture encodes",
               build_other_notification(7, 3, rsp_sgp26_euicc_der,
                                         rsp_sgp26_euicc_der_len,
                                         rsp_sgp26_eum_der,
                                         rsp_sgp26_eum_der_len,
                                         osn, sizeof osn, &osn_len) == 0);

            /* No certificate given: this arm carries its own, and the
               chain is checked against the compiled-in test CI. */
            memset(&v, 0, sizeof v);
            ok("it verifies with no certificate given at all",
               rsp_dp_verify_notification(NULL, 0, osn, osn_len, &v) == 0);
            ok("...and is not reported as an installation result",
               v.is_installation_result == 0);
            ok("...naming the operation and sequence number it reports",
               v.seq_number == 7 && v.operation == 3);

            /* Given the matching certificate it still verifies. */
            memset(&v, 0, sizeof v);
            ok("it verifies against the matching certificate too",
               rsp_dp_verify_notification(rsp_sgp26_euicc_der,
                                           rsp_sgp26_euicc_der_len,
                                           osn, osn_len, &v) == 0);

            /* Given a different one it must not: a genuine notification
               from one eUICC would otherwise be filed against another's
               Profile. */
            {
                rsp_credential_t dpauth;
                memset(&dpauth, 0, sizeof dpauth);
                ok("DPauth loads, for the mismatched-certificate case",
                   rsp_pki_dp(0, &dpauth) == 0);
                memset(&v, 0, sizeof v);
                ok("a certificate that is not the embedded one is refused",
                   rsp_dp_verify_notification(dpauth.der, dpauth.der_len,
                                               osn, osn_len, &v) == -1);
                rsp_credential_free(&dpauth);
            }
        }
        (void)euicc_cert;
    }

    return fails ? 1 : 0;
}
