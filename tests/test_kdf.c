/* ECDH is pinned to a published vector, and separately to the property that
   both parties reach the same secret. The derivation is pinned only to its
   own output: that catches a change, not a mistake. The card settles the
   derivation in the second half of the project. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsp.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if(!good) fails++;
}

/* One hex line from the vector file into bytes. Returns the byte count. */
static size_t hexline(FILE *f, uint8_t *out, size_t cap) {
    char line[300];
    if(!fgets(line, sizeof line, f)) return 0;
    size_t n = strspn(line, "0123456789abcdefABCDEF") / 2;
    if(n > cap) return 0;
    for(size_t i = 0; i < n; i++) {
        unsigned v;
        if(sscanf(line + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return n;
}

int main(void) {
    uint8_t sk[32], pk[65], want[32], z[32];
    FILE *f = fopen("testdata/nist/ecdh-p256.txt", "r");
    ok("the vector file is readable", f != NULL);
    if(!f) return 1;
    ok("the vector holds three values of the right length",
       hexline(f, sk, sizeof sk) == 32
       && hexline(f, pk, sizeof pk) == 65
       && hexline(f, want, sizeof want) == 32);
    fclose(f);

    ok("ECDH P-256 matches the published vector",
       rsp_ecdh_p256(sk, pk, z) == 0 && memcmp(z, want, 32) == 0);

    /* The derivation is deterministic: the same inputs always give the same
       keys, whatever the right answer turns out to be. */
    static const uint8_t info[]  = { 0x00, 0x00, 0x00, 0x01 };
    static const uint8_t info2[] = { 0x00, 0x00, 0x00, 0x02 };
    rsp_session_t a, b, c;
    ok("session derivation succeeds",
       rsp_session_init(sk, pk, info, sizeof info, &a) == 0);
    ok("session derivation repeats",
       rsp_session_init(sk, pk, info, sizeof info, &b) == 0);
    ok("the two derivations agree", memcmp(&a, &b, sizeof a) == 0);

    /* The three keys must differ. A derivation that returns the same block
       three times passes every other check in this file. */
    ok("S-ENC and S-MAC differ", memcmp(a.s_enc, a.s_mac, 16) != 0);
    ok("S-MAC and the chaining value differ", memcmp(a.s_mac, a.chain, 16) != 0);

    ok("a different sharedInfo gives different keys",
       rsp_session_init(sk, pk, info2, sizeof info2, &c) == 0
       && memcmp(&a, &c, sizeof a) != 0);
    return fails ? 1 : 0;
}
