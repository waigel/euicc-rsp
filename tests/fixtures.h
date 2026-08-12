/*
 * fixtures.h -- the eUICC side of an RSP session, built with the SGP.26
 * test material.
 *
 * These were static helpers inside tests/test_es9.c. They are shared now
 * because tools/session-fixtures writes the same structures to disk for
 * something outside this repository to replay, and two copies of a
 * fixture builder is exactly the drift this repository designs against
 * everywhere else.
 *
 * Every builder returns 0 on success and -1 on any failure, and none of
 * them allocates: the caller supplies the buffer.
 */
#ifndef RSP_TEST_FIXTURES_H
#define RSP_TEST_FIXTURES_H

#include <stddef.h>
#include <stdint.h>

#include "CtxParams1.h"
#include "DeviceInfo.h"
#include "EUICCInfo2.h"

/* A fixed-capacity sink for der_encode's callback interface. */
struct sink {
    unsigned char *p;
    size_t len;
    size_t cap;
};

int collect(const void *buf, size_t n, void *key);

/* The addresses the section 5.6.1 comparison is exercised with. SMDP_ADDR
   is also what the eUICC-side fixtures echo back, so what the card is
   made to say it saw is what the server was actually given. */
extern const char SMDP_ADDR[];
extern const char SMDP_UPPER[];
extern const char SMDP_OTHER[];

/* build/sgp26_material.c (generated from testdata/sgp26/) defines these.
   They used to be declared at the point of use, on the grounds that
   adding a header just for test code was not worth it -- that reasoning
   ended when this header appeared for a different reason, and one
   declaration is better than three. */
extern const unsigned char rsp_sgp26_eum_der[];
extern const unsigned int rsp_sgp26_eum_der_len;
extern const unsigned char rsp_sgp26_euicc_der[];
extern const unsigned int rsp_sgp26_euicc_der_len;

/* The SGP.26 test eUICC's own EID, as CERT.EUICC.ECDSA's Subject
   serialNumber carries it, and the private key the fixtures sign with. */
extern const char EUICC_TEST_EID[];
extern const uint8_t EUICC_TEST_SK[32];

int build_euicc_info1(unsigned char *buf, size_t cap, size_t *out_len);
int build_euicc_info2(EUICCInfo2_t *info);
int build_device_info(DeviceInfo_t *di);
int build_ctx_params1(CtxParams1_t *cp);

int build_auth_server_response(
        const uint8_t transaction_id[16],
        const uint8_t server_challenge[16],
        const uint8_t *euicc_cert_der, size_t euicc_cert_len,
        const uint8_t *eum_cert_der, size_t eum_cert_len,
        unsigned char *out, size_t cap, size_t *out_len);

int build_store_metadata(const uint8_t iccid[10],
        const char *profile_name,
        const char *service_provider_name,
        unsigned char *buf, size_t cap, size_t *out_len);

int build_installation_result(
        const uint8_t transaction_id[16],
        int success,
        unsigned char *out, size_t cap, size_t *out_len);

/* An OtherSignedNotification: what an eUICC sends after an enable,
   disable or delete. Unlike a ProfileInstallationResult it carries
   CERT.EUICC.ECDSA and CERT.EUM with it, so it can be verified without
   anything having been kept from a download.

   operation_bit is which NotificationEvent bit to set: 1 enable,
   2 disable, 3 delete. */
int build_other_notification(
        long seq_number, int operation_bit,
        const uint8_t *euicc_cert_der, size_t euicc_cert_len,
        const uint8_t *eum_cert_der, size_t eum_cert_len,
        unsigned char *out, size_t cap, size_t *out_len);

int build_prepare_download_response(
        const uint8_t transaction_id[16],
        const uint8_t euicc_otpk[65],
        const uint8_t smdp_signature2[64],
        unsigned char *out, size_t cap, size_t *out_len);

#endif /* RSP_TEST_FIXTURES_H */
