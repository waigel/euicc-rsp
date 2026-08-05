/* rsp_der_length_octets (src/rsp_internal.h) is the one shared
   implementation of the BER/DER minimal-length-octets rule that
   src/rsp_crypto.c (what the SCP03t MAC covers) and src/rsp_bpp.c (what
   actually goes on the wire) both call, replacing two copies that used
   to exist independently -- see src/rsp_internal.h's own comment for why
   a disagreement between those two copies would have been a real defect,
   not just untidy duplication. This is that rule's dedicated test: one
   rule, one implementation, one test, pinned against ITU-T X.690 8.1.3
   at each length-form boundary. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "rsp_internal.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if (!good) fails++;
}

static int check(size_t len, const uint8_t *want, size_t want_n) {
    uint8_t got[RSP_DER_LEN_OCTETS_MAX];
    size_t got_n = 0;
    if (rsp_der_length_octets(len, got, &got_n) != 0) {
        return 0;
    }
    return got_n == want_n && memcmp(got, want, want_n) == 0;
}

int main(void) {
    /* Short form, X.690 8.1.3.4: a single byte, bit 8 clear, for 0..127. */
    ok("0 encodes as the single byte 0x00",
       check(0, (const uint8_t[]){ 0x00 }, 1));
    ok("127 (0x7F) is the short form's own upper bound",
       check(0x7F, (const uint8_t[]){ 0x7F }, 1));

    /* Long form, X.690 8.1.3.5: first byte is 0x80 | (number of
       following length octets), each boundary below is exactly where
       the previous form's range runs out -- not one before or after. */
    ok("128 (0x80) is the long form's own lower bound: 0x81 0x80",
       check(0x80, (const uint8_t[]){ 0x81, 0x80 }, 2));
    ok("255 (0xFF) is the one-length-byte long form's upper bound",
       check(0xFF, (const uint8_t[]){ 0x81, 0xFF }, 2));
    ok("256 (0x100) needs two length bytes: 0x82 0x01 0x00",
       check(0x100, (const uint8_t[]){ 0x82, 0x01, 0x00 }, 3));
    ok("65535 (0xFFFF) is the two-length-byte form's upper bound",
       check(0xFFFF, (const uint8_t[]){ 0x82, 0xFF, 0xFF }, 3));
    ok("65536 (0x10000) needs three length bytes: 0x83 0x01 0x00 0x00",
       check(0x10000, (const uint8_t[]){ 0x83, 0x01, 0x00, 0x00 }, 4));
    ok("0xFFFFFF is the three-length-byte form's upper bound",
       check(0xFFFFFF, (const uint8_t[]){ 0x83, 0xFF, 0xFF, 0xFF }, 4));
    ok("0x1000000 needs four length bytes: 0x84 0x01 0x00 0x00 0x00",
       check(0x1000000UL,
             (const uint8_t[]){ 0x84, 0x01, 0x00, 0x00, 0x00 }, 5));
    ok("0xFFFFFFFF is this implementation's own upper bound",
       check(0xFFFFFFFFUL,
             (const uint8_t[]){ 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, 5));

#if SIZE_MAX > 0xFFFFFFFFUL
    /* Only meaningful where size_t is wider than 32 bits -- on a
       platform where it is not, 0xFFFFFFFF + 1 does not exist as a
       size_t value in the first place. */
    ok("one past 0xFFFFFFFF does not fit even the long form and is refused",
       !check(0x100000000ULL, NULL, 0));
#endif

    return fails ? 1 : 0;
}
