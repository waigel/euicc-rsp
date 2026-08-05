/* The card refuses anything it cannot chain to a Certificate Issuer it
   knows, so rsp_pki_verify is the gate before any crypto matters, and a
   mismatched key pair here is exactly the failure mode that would
   otherwise only surface at the card, where the answer is a status word.
   This test exercises that gate directly against the published SGP.26
   test material, and proves the gate is not vacuously true by corrupting
   a certificate byte and watching the same call refuse it. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsp.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if (!good) fails++;
}

static void check_role(const char *name, int role) {
    char label[160];
    rsp_credential_t cred;

    memset(&cred, 0, sizeof cred);

    snprintf(label, sizeof label, "%s loads", name);
    ok(label, rsp_pki_dp(role, &cred) == 0);

    snprintf(label, sizeof label, "%s carries a certificate", name);
    ok(label, cred.der != NULL && cred.der_len > 0);

    snprintf(label, sizeof label,
              "%s chains to the test CI and its key matches its certificate",
              name);
    ok(label, rsp_pki_verify(&cred) == 0);

    /* A verifier that always answers 0 would pass every "ok" line above.
       Flip one byte in the middle of the certificate -- still the same
       length, still parseable as *something* most of the time -- and
       confirm the exact same call now refuses it. */
    if (cred.der && cred.der_len > 8) {
        rsp_credential_t corrupt = cred;
        corrupt.der = malloc(cred.der_len);
        if (corrupt.der) {
            memcpy(corrupt.der, cred.der, cred.der_len);
            corrupt.der[cred.der_len / 2] ^= 0xFF;
            snprintf(label, sizeof label,
                      "corrupting one byte of %s's certificate makes verification fail",
                      name);
            ok(label, rsp_pki_verify(&corrupt) != 0);
            free(corrupt.der);
        }
    }

    rsp_credential_free(&cred);
}

int main(void) {
    const uint8_t *ci_der;
    size_t ci_len;

    ok("the published SGP.26 test CI is compiled in",
       rsp_pki_test_ci(&ci_der, &ci_len) == 0);
    ok("the test CI certificate is non-empty", ci_der != NULL && ci_len > 0);

    check_role("DPauth", 0);
    check_role("DPpb", 1);

    {
        rsp_credential_t unused;
        memset(&unused, 0, sizeof unused);
        ok("an unknown role is rejected", rsp_pki_dp(2, &unused) == -1);
    }

    ok("a null credential answers -2: the chain/key question was never"
       " reached, not answered no (include/rsp.h's failure convention)",
       rsp_pki_verify(NULL) == -2);

    /* DPauth's certificate combined with DPpb's secret key: the
       certificate itself is real and chains fine (it is unmodified), so
       this fails specifically at the "does c->sk match this
       certificate's public key" check -- a real -1 answer, not a -2
       parse/chain failure, and a deterministic one (unlike corrupting a
       byte above, which can land on either failure mode depending on
       which byte). */
    {
        rsp_credential_t dpauth, dppb, mismatched;
        memset(&dpauth, 0, sizeof dpauth);
        memset(&dppb, 0, sizeof dppb);
        ok("DPauth loads, for the deterministic key-mismatch case",
           rsp_pki_dp(0, &dpauth) == 0);
        ok("DPpb loads, for the deterministic key-mismatch case",
           rsp_pki_dp(1, &dppb) == 0);

        mismatched = dpauth;
        memcpy(mismatched.sk, dppb.sk, sizeof mismatched.sk);
        ok("DPauth's certificate with DPpb's key answers -1: chains fine,"
           " key does not match (a real no, not a parse failure)",
           rsp_pki_verify(&mismatched) == -1);

        rsp_credential_free(&dpauth);
        rsp_credential_free(&dppb);
    }

    return fails ? 1 : 0;
}
