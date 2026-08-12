/*
 * session-fixtures -- write one whole RSP session's bytes to disk, so
 * something that is not this repository can replay it.
 *
 * Every input here is fixed, and rsp_dp_initiate_authentication is a pure
 * function of its inputs since the serverChallenge stopped being drawn
 * internally (see include/rsp.h). Running this twice produces identical
 * files; that is the property which makes the output a fixture rather
 * than a recording of one particular afternoon.
 *
 * The eUICC-side answers are built with the SGP.26 test material by the
 * same builders tests/test_es9.c uses (tests/fixtures.h) -- one copy, so
 * a fixture and the test that pins it cannot drift apart.
 *
 * The three server-side outputs are written too, not just the inputs. A
 * consumer replaying this session can then check that what it produced is
 * byte-identical to what this library produced, which is a much stronger
 * statement than "the call returned 0".
 *
 * These are SGP.26 *test* credentials. They work on test eUICCs and
 * nowhere else -- see testdata/sgp26/README.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsp.h"

#include "fixtures.h"

/* The same fixed values tests/test_es9.c uses, so the fixture and the
   test that exercises the same path cannot disagree about them. */
static const uint8_t TRANSACTION_ID[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};
static const uint8_t EUICC_CHALLENGE[16] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};
static const uint8_t SERVER_CHALLENGE[16] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f
};
static const uint8_t OTSK_DP[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};
static const uint8_t ICCID[10] = {
    0x98, 0x00, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x14
};
/* A fixed, valid uncompressed P-256 point, standing in for otPK.EUICC --
   the matching secret is never needed here, only otsk_dp does ECDH work
   on this side. Same point tests/test_es9.c uses. */
static const uint8_t EUICC_OTPK[65] = {
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
static const char UPP[] = "the-uicc-profile-fixture";
static const char SMDP_ADDRESS[] = "smdp.example.com";

static const char *g_dir;

/* Write one blob, or die saying which one. A fixture that is silently
   short is worse than no fixture at all. */
static void
put(const char *name, const void *buf, size_t len) {
    char path[1024];
    FILE *f;

    if (snprintf(path, sizeof path, "%s/%s", g_dir, name) >= (int)sizeof path) {
        fprintf(stderr, "session-fixtures: path too long: %s/%s\n", g_dir, name);
        exit(1);
    }
    f = fopen(path, "wb");
    if (!f) {
        perror(path);
        exit(1);
    }
    if (len && fwrite(buf, 1, len, f) != len) {
        fprintf(stderr, "session-fixtures: short write: %s\n", path);
        exit(1);
    }
    if (fclose(f) != 0) {
        perror(path);
        exit(1);
    }
    printf("  %-32s %zu bytes\n", name, len);
}

static void
die(const char *step, int rc) {
    fprintf(stderr, "session-fixtures: %s returned %d\n", step, rc);
    exit(1);
}

int
main(int argc, char **argv) {
    unsigned char info1[512], asr[4096], md[512], pdr[512];
    size_t info1_len = 0, asr_len = 0, md_len = 0, pdr_len = 0;
    rsp_dp_session_t *sess = NULL;
    uint8_t *init_resp = NULL, *ac_resp = NULL, *bpp = NULL;
    size_t init_len = 0, ac_len = 0, bpp_len = 0;
    rsp_dp_authenticate_fields_t f;
    uint8_t smdp_sig2[64];
    int rc;

    if (argc != 2) {
        fprintf(stderr, "usage: session-fixtures <directory>\n");
        return 2;
    }
    g_dir = argv[1];
    printf("writing an RSP session to %s\n", g_dir);

    /* --- the eUICC's opening move ---------------------------------- */
    if (build_euicc_info1(info1, sizeof info1, &info1_len) != 0) {
        die("build_euicc_info1", -1);
    }

    /* --- ES9+ InitiateAuthentication (5.6.1) ----------------------- */
    rc = rsp_dp_initiate_authentication(
            EUICC_CHALLENGE, sizeof EUICC_CHALLENGE,
            info1, info1_len,
            TRANSACTION_ID, SERVER_CHALLENGE,
            SMDP_ADDRESS, SMDP_ADDRESS,
            &sess, &init_resp, &init_len);
    if (rc != 0) die("rsp_dp_initiate_authentication", rc);

    /* --- the eUICC answers it (ES10b.AuthenticateServer, 5.7.13) --- */
    if (build_auth_server_response(
                TRANSACTION_ID, SERVER_CHALLENGE,
                rsp_sgp26_euicc_der, rsp_sgp26_euicc_der_len,
                rsp_sgp26_eum_der, rsp_sgp26_eum_der_len,
                asr, sizeof asr, &asr_len) != 0) {
        die("build_auth_server_response", -1);
    }

    /* This library has no profile-order database, so the Profile's own
       metadata is supplied from outside -- exactly as a server would. */
    if (build_store_metadata(ICCID, "euicc-rsp test profile", "euicc-rsp",
                              md, sizeof md, &md_len) != 0) {
        die("build_store_metadata", -1);
    }

    /* --- ES9+ AuthenticateClient (5.6.3) --------------------------- */
    rc = rsp_dp_authenticate_client(sess, asr, asr_len, md, md_len,
                                     &ac_resp, &ac_len);
    if (rc != 0) die("rsp_dp_authenticate_client", rc);

    /* euiccSignature2 chains onto smdpSignature2 -- each side signs the
       other's signature -- so the next eUICC-side fixture needs the raw
       64 bytes out of the response. The accessor hands back the whole
       TLV ('5F 37 40' then the value), so step over its three-byte
       header rather than assuming an offset into the response. */
    if (rsp_dp_authenticate_fields(ac_resp, ac_len, &f) != 0) {
        die("rsp_dp_authenticate_fields", -1);
    }
    if (f.smdp_signature2_len != 67) {
        fprintf(stderr,
                "session-fixtures: smdpSignature2 is %zu bytes, expected 67 "
                "('5F 37 40' and 64 of signature)\n", f.smdp_signature2_len);
        return 1;
    }
    memcpy(smdp_sig2, f.smdp_signature2 + 3, 64);

    /* --- the eUICC answers again (ES10b.PrepareDownload, 5.7.5) ---- */
    if (build_prepare_download_response(TRANSACTION_ID, EUICC_OTPK, smdp_sig2,
                                         pdr, sizeof pdr, &pdr_len) != 0) {
        die("build_prepare_download_response", -1);
    }

    /* --- ES9+ GetBoundProfilePackage (5.6.2) ----------------------- */
    rc = rsp_dp_get_bound_profile_package(
            sess, pdr, pdr_len,
            (const uint8_t *)UPP, sizeof UPP - 1,
            OTSK_DP, &bpp, &bpp_len);
    if (rc != 0) die("rsp_dp_get_bound_profile_package", rc);

    /* --- what went in --------------------------------------------- */
    put("euicc-challenge.bin", EUICC_CHALLENGE, sizeof EUICC_CHALLENGE);
    put("transaction-id.bin", TRANSACTION_ID, sizeof TRANSACTION_ID);
    put("server-challenge.bin", SERVER_CHALLENGE, sizeof SERVER_CHALLENGE);
    put("otsk-dp.bin", OTSK_DP, sizeof OTSK_DP);
    put("euicc-info1.der", info1, info1_len);
    put("auth-server-response.der", asr, asr_len);
    put("store-metadata.der", md, md_len);
    put("prepare-download-response.der", pdr, pdr_len);
    put("upp.der", UPP, sizeof UPP - 1);

    /* A PendingNotification, for anything that has to exercise ES9+
       HandleNotification. The eUICC sends one after every install; this
       is the same structure, signed by the same test key, so a consumer
       can post it at a server and see what happens without a card. */
    {
        unsigned char pn[1024];
        size_t pn_len = 0;
        if (build_installation_result(TRANSACTION_ID, 1, pn, sizeof pn,
                                       &pn_len) != 0) {
            die("build_installation_result", -1);
        }
        put("pending-notification.der", pn, pn_len);
    }

    /* --- and what this library made of it -------------------------- */
    put("initiate-response.der", init_resp, init_len);
    put("authenticate-response.der", ac_resp, ac_len);
    put("bound-profile-package.der", bpp, bpp_len);

    free(init_resp);
    free(ac_resp);
    free(bpp);
    rsp_dp_session_free(sess);
    printf("done\n");
    return 0;
}
