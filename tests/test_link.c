/* Does the library link, and does the crypto inside it work? A build that
   compiles but resolves no mbedTLS symbol passes every other test in this
   suite, because every other test would be skipped. This one is the floor. */
#include <stdio.h>
#include <string.h>
#include "rsp.h"
#include "mbedtls/sha256.h"

/* The same macro the Makefile hands to src/rsp_version.c's build (DEF :=
   -DRSP_VERSION=..., folded into ALL_CFLAGS, which every object in this
   project -- tests included -- is compiled with): comparing rsp_version()
   against it, rather than against a second hand-typed copy of the version
   string, means there is exactly one source for what "the right answer"
   is, and a build that links against a stale or differently-configured
   library object has an actual chance of failing this -- unlike a bare
   non-empty-string check, which passes for any string at all. */
#ifndef RSP_VERSION
#define RSP_VERSION "0.1"
#endif

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if(!good) fails++;
}

int main(void) {
    static const unsigned char want[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    unsigned char got[32];
    mbedtls_sha256((const unsigned char *)"abc", 3, got, 0);
    ok("mbedTLS computes the FIPS 180-4 SHA-256 of \"abc\"",
       memcmp(got, want, 32) == 0);
    ok("the library reports the version the Makefile's VERSION sets",
       rsp_version() != NULL && strcmp(rsp_version(), RSP_VERSION) == 0);
    return fails ? 1 : 0;
}
