/* rsp_sign from many threads at once.
 *
 * This library had a shared, lazily-initialised RNG in src/rsp_sign.c:
 * three file-scope statics and an unsynchronised "if (g_rng_ready)".
 * Two threads entering it together would have one memset the DRBG
 * context the other was already seeding, and the second would then call
 * a NULL entropy callback. Every crash seen from euicc-smdp landed
 * there. A second race followed it: past
 * MBEDTLS_CTR_DRBG_RESEED_INTERVAL the shared DRBG reseeds inline
 * during signing and frees memory on the shared entropy context.
 *
 * Both are gone now because rsp_sign builds its RNG per call on the
 * stack, the way src/rsp_pki.c always has -- so there is no shared
 * mutable state left to race over.
 *
 * This test is what keeps it that way. It is not a probabilistic
 * nice-to-have: with the old code it segfaults, reliably enough that
 * sixteen of thirty runs failed when it was measured. THREADS and
 * ROUNDS are chosen to cross MBEDTLS_CTR_DRBG_RESEED_INTERVAL (10000)
 * in total signatures, so the reseed race is reached too, not only the
 * initialisation one. */
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "rsp.h"

#define THREADS 8
#define ROUNDS 1600 /* 8 * 1600 = 12800 signatures, past the 10000 reseed
                       interval, so the second race is reached as well */

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if (!good) fails++;
}

static rsp_credential_t dpauth;

/* Every thread signs the same message with the same key. RFC 6979 makes
   the signature deterministic -- the RNG only blinds the scalar
   arithmetic -- so every thread must produce byte-identical output. A
   thread that does not has either raced or changed the algorithm. */
static const unsigned char MESSAGE[] = "euicc-rsp thread-safety probe";

struct result {
    int signed_ok;
    unsigned char first[64];
};

/* Deliberately no signature before the threads start. An earlier draft
   of this test signed once in main to have something to compare
   against, and that one call initialised the shared RNG -- so the
   threads never raced the initialisation and the test passed against
   the very bug it exists to catch. The comparison value is taken from
   thread 0 afterwards instead. */
static void *worker(void *arg) {
    struct result *out = arg;
    unsigned char sig[64];
    int i;

    out->signed_ok = 1;
    for (i = 0; i < ROUNDS; i++) {
        if (rsp_sign(&dpauth, MESSAGE, sizeof MESSAGE - 1, sig) != 0) {
            out->signed_ok = 0;
            return NULL;
        }
        if (i == 0) {
            memcpy(out->first, sig, sizeof sig);
        }
    }
    return NULL;
}

int main(void) {
    pthread_t th[THREADS];
    struct result res[THREADS];
    int i, all_signed = 1, all_identical = 1, spawned = 1;

    memset(&dpauth, 0, sizeof dpauth);
    ok("DPauth loads", rsp_pki_dp(0, &dpauth) == 0);

    for (i = 0; i < THREADS; i++) {
        memset(&res[i], 0, sizeof res[i]);
        if (pthread_create(&th[i], NULL, worker, &res[i]) != 0) {
            spawned = 0;
            break;
        }
    }
    ok("every thread starts", spawned);

    for (i = 0; i < THREADS; i++) {
        if (i < THREADS && spawned) {
            pthread_join(th[i], NULL);
            if (!res[i].signed_ok) all_signed = 0;
            if (memcmp(res[i].first, res[0].first, 64) != 0) all_identical = 0;
        }
    }

    /* Reaching this line at all is most of the point: the old code did
       not, it died of SIGSEGV inside mbedtls_ctr_drbg_seed. */
    ok("all threads returned without crashing", spawned);
    ok("every signature succeeded", all_signed);
    ok("every thread produced the same deterministic signature", all_identical);

    rsp_credential_free(&dpauth);
    return fails ? 1 : 0;
}
