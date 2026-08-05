/* Both sides of the handshake, played locally. A signature that verifies
   against the wrong key, or a tampered message that still verifies, is the
   failure that matters -- and neither shows up if the test only signs and
   checks the happy path.

   The dispatch for this task quotes rsp_pki_mint("test DPauth", 0, &dp) as
   how to get two distinct stand-in credentials. That function does not
   exist: Task 3's own dispatch withdrew it before Task 3 was built --
   SGP.26 publishes complete DPauth/DPpb certificates and secret keys, not
   a CI private key to mint under, so there is nothing to mint, and
   rsp_pki_dp(role, ...) loads the published material instead (see
   task-3-report.md, "Scope change from the brief", and rsp.h's actual
   declarations). Two calls to rsp_pki_dp with different roles give the
   same thing this test actually needs -- two credentials with two
   different, real key pairs -- through the interface that exists. */
#include <stdio.h>
#include <string.h>
#include "rsp.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if(!good) fails++;
}

int main(void) {
    rsp_credential_t dp, card;
    memset(&dp, 0, sizeof dp);
    memset(&card, 0, sizeof card);
    ok("a DPauth credential loads, standing in for the signing side",
       rsp_pki_dp(0, &dp) == 0);
    ok("a DPpb credential loads, standing in for the eUICC's certificate",
       rsp_pki_dp(1, &card) == 0);

    static const uint8_t msg[] = "serverSigned1 stands in for the real one";
    uint8_t sig[64];

    ok("signing succeeds", rsp_sign(&dp, msg, sizeof msg - 1, sig) == 0);
    ok("the signature verifies with the matching certificate",
       rsp_verify(dp.der, dp.der_len, msg, sizeof msg - 1, sig) == 0);
    ok("it does not verify with another certificate",
       rsp_verify(card.der, card.der_len, msg, sizeof msg - 1, sig) != 0);

    uint8_t bad[sizeof msg - 1];
    memcpy(bad, msg, sizeof bad);
    bad[0] ^= 0x01;
    ok("a tampered message does not verify",
       rsp_verify(dp.der, dp.der_len, bad, sizeof bad, sig) != 0);

    sig[0] ^= 0x01;
    ok("a tampered signature does not verify",
       rsp_verify(dp.der, dp.der_len, msg, sizeof msg - 1, sig) != 0);

    /* ECDSA is randomised: two signatures over the same message differ, and
       both must verify. An implementation that returns a constant passes
       every check above. */
    uint8_t sig2[64], sig3[64];
    rsp_sign(&dp, msg, sizeof msg - 1, sig2);
    rsp_sign(&dp, msg, sizeof msg - 1, sig3);
    ok("two signatures over the same message differ",
       memcmp(sig2, sig3, 64) != 0);
    ok("both of them verify",
       rsp_verify(dp.der, dp.der_len, msg, sizeof msg - 1, sig2) == 0
       && rsp_verify(dp.der, dp.der_len, msg, sizeof msg - 1, sig3) == 0);

    rsp_credential_free(&dp);
    rsp_credential_free(&card);
    return fails ? 1 : 0;
}
