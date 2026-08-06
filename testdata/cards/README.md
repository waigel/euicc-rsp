# Card recordings

A recording is a text log of one session with a physical eUICC in a card
reader: every command APDU sent and every response APDU received, in the
exact order they crossed the wire. `rsp_record_open` (see `include/rsp.h`
and `src/rsp_transport.c`) writes one while talking to real hardware;
`rsp_replay_open` reads one back and answers the command layer exactly as
the card did, so the same code path runs in CI with no reader attached.

The format is plain text on purpose, not a binary capture:

- a line beginning `> ` is a command APDU, in hex
- a line beginning `< ` is the response, in hex, including its two
  trailing status bytes
- `#` and blank lines are comments
- whitespace inside a hex line is insignificant

That is what lets a recording be read directly in a code review, diffed
meaningfully when it changes, and hand-edited into the failure cases a
healthy card will not itself produce -- a wrong status word, a truncated
response, a segment out of order. `tests/test_recording.c` is itself an
example of a hand-written recording used this way.

Replay expects the recorded sequence strictly: a command that does not
match what comes next, or a command sent after the recording is
exhausted, is refused. A committed recording is a pin on the bytes that
crossed the wire, not a lenient stub that answers whatever it is asked.

## What is safe to commit

This round only reads a card: selecting applets, listing profiles,
fetching public identifiers such as the EID. None of that is secret, and
a recording of it is public data, safe to commit and safe to paste into
an issue or a review comment.

That stops being true the moment a recording covers a *write* session --
loading a profile, or any exchange that carries SCP03t-protected
segments, session keys, or profile content. Those recordings carry
protected material by construction, the same material `rsp_session_t`
and `rsp_credential_t` elsewhere in this library exist to keep off
`stdout`/`stderr`/logs. A recording like that must not be pasted into an
issue, a chat message, or a bug report unexamined -- read what it
actually contains first, the same as you would before sharing a core
dump.

## `synthetic-info.log`

No card was involved in producing this one: `tests/test_es10.c` needs a
recording whose `EUICCInfo2` and `GetEuiccDataResponse` payloads are real
DER, and a hand-invented blob that the generated decoder happens to accept
would prove nothing about the decoder -- it would prove only that two
mistakes agree. So those two payloads were produced by the generated
*encoder* instead, with the following throwaway program (compiled and run
once, not part of the build):

```c
/* Throwaway program: fills an EUICCInfo2 and a GetEuiccDataResponse with the
 * generated types from ~/git/waigel/euicc-rsp/dist and encodes each with the
 * generated der_encode, then prints the result as hex. The output is pasted
 * into testdata/cards/synthetic-info.log -- see testdata/cards/README.md.
 *
 * Not part of the build: compiled and run once by hand.
 *
 *   cd ~/git/waigel/euicc-rsp
 *   cc -std=c99 -Wall -idirafter dist -Idist \
 *       /path/to/gen_synthetic_info.c dist/*.o -o /tmp/gen_synthetic_info
 *   /tmp/gen_synthetic_info
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "EUICCInfo2.h"
#include "GetEuiccDataResponse.h"

static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02X", b[i]);
    printf("\n");
}

static int collect(const void *buf, size_t n, void *key) {
    struct { uint8_t *p; size_t len; } *o = key;
    memcpy(o->p + o->len, buf, n);
    o->len += n;
    return 0;
}

static void set_version(VersionType_t *v, uint8_t a, uint8_t b, uint8_t c) {
    uint8_t bytes[3] = { a, b, c };
    OCTET_STRING_fromBuf(v, (const char *)bytes, 3);
}

static void set_bits(BIT_STRING_t *b, uint8_t byte) {
    b->buf = malloc(1);
    b->buf[0] = byte;
    b->size = 1;
    b->bits_unused = 0;
}

int main(void) {
    EUICCInfo2_t info;
    memset(&info, 0, sizeof info);

    set_version(&info.profileVersion, 2, 1, 0);
    set_version(&info.svn, 2, 2, 0);           /* "2.2.0", what the test asserts */
    set_version(&info.euiccFirmwareVer, 6, 0, 0);
    OCTET_STRING_fromBuf(&info.extCardResource, "\x81\x02\x01\x00\x82\x02\x01\x00", 8);
    set_bits(&info.uiccCapability, 0x00);
    set_bits(&info.rspCapability, 0x00);

    /* Two Certificate Issuer identifiers "supported for verification" --
     * SubjectKeyIdentifier is a bare OCTET_STRING (no SIZE constraint of
     * its own), but a real SKI is the 20-byte SHA-1 of the issuer's public
     * key (RFC 5280 section 4.2.1.2), so 20 bytes here too. */
    static const uint8_t ci_a[20] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,
        0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14
    };
    static const uint8_t ci_b[20] = {
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22,0x33,0x44,
        0x55,0x66,0x77,0x88,0x99,0x00,0xA1,0xB2,0xC3,0xD4
    };
    SubjectKeyIdentifier_t *ski_a = calloc(1, sizeof *ski_a);
    OCTET_STRING_fromBuf(ski_a, (const char *)ci_a, sizeof ci_a);
    ASN_SEQUENCE_ADD(&info.euiccCiPKIdListForVerification.list, ski_a);
    SubjectKeyIdentifier_t *ski_b = calloc(1, sizeof *ski_b);
    OCTET_STRING_fromBuf(ski_b, (const char *)ci_b, sizeof ci_b);
    ASN_SEQUENCE_ADD(&info.euiccCiPKIdListForVerification.list, ski_b);

    /* One identifier for signing -- distinct from the verification pair
     * above, so nothing downstream could confuse the two lists. */
    static const uint8_t ci_sign[20] = {
        0x99,0x98,0x97,0x96,0x95,0x94,0x93,0x92,0x91,0x90,
        0x89,0x88,0x87,0x86,0x85,0x84,0x83,0x82,0x81,0x80
    };
    SubjectKeyIdentifier_t *ski_sign = calloc(1, sizeof *ski_sign);
    OCTET_STRING_fromBuf(ski_sign, (const char *)ci_sign, sizeof ci_sign);
    ASN_SEQUENCE_ADD(&info.euiccCiPKIdListForSigning.list, ski_sign);

    set_version(&info.ppVersion, 2, 1, 0);
    OCTET_STRING_fromBuf(&info.sasAcreditationNumber, "", 0);
    /* ts102241Version, globalplatformVersion, euiccCategory,
       forbiddenProfilePolicyRules, certificationDataObject: left NULL,
       all OPTIONAL in the module (rsp-2.5.asn). */

    uint8_t buf1[1024];
    struct { uint8_t *p; size_t len; } o1 = { buf1, 0 };
    asn_enc_rval_t r1 = der_encode(&asn_DEF_EUICCInfo2, &info, collect, &o1);
    if (r1.encoded < 0) { fprintf(stderr, "EUICCInfo2 encode failed\n"); return 1; }

    printf("# EUICCInfo2, %zu bytes\n", o1.len);
    print_hex(o1.p, o1.len);

    GetEuiccDataResponse_t eid;
    memset(&eid, 0, sizeof eid);
    static const uint8_t eidval[16] = {
        0x89,0x03,0x30,0x12,0x11,0x22,0x33,0x44,
        0x55,0x66,0x77,0x88,0x99,0x00,0x11,0xFF
    };
    OCTET_STRING_fromBuf(&eid.eidValue, (const char *)eidval, sizeof eidval);

    uint8_t buf2[64];
    struct { uint8_t *p; size_t len; } o2 = { buf2, 0 };
    asn_enc_rval_t r2 = der_encode(&asn_DEF_GetEuiccDataResponse, &eid, collect, &o2);
    if (r2.encoded < 0) { fprintf(stderr, "GetEuiccDataResponse encode failed\n"); return 1; }

    printf("# GetEuiccDataResponse, %zu bytes\n", o2.len);
    print_hex(o2.p, o2.len);

    ASN_STRUCT_RESET(asn_DEF_EUICCInfo2, &info);
    ASN_STRUCT_RESET(asn_DEF_GetEuiccDataResponse, &eid);
    return 0;
}
```

Its output, byte-for-byte what `synthetic-info.log` carries for those two
exchanges:

```
# EUICCInfo2, 113 bytes
BF226E810302010082030202008303060000840881020100820201008502000088020000A92C04140102030405060708090A0B0C0D0E0F10111213140414AABBCCDDEEFF11223344556677889900A1B2C3D4AA160414999897969594939291908988878685848382818004030201000C00
# GetEuiccDataResponse, 21 bytes
BF3E125A10890330121122334455667788990011FF
```

The SELECT of the ISD-R and the STORE DATA framing (CLA/INS/P1/P2/Lc/Le)
around each ES10 request and response are hand-assembled in
`synthetic-info.log` itself, per the citations in `src/rsp_es10.c`'s file
header -- only the two ES10 payloads above needed the generated encoder,
since those are the only two fields a hand-written blob could get subtly
wrong without the decoder noticing. `svn` is `02 02 00`, decoding to
"2.2.0"; the EID and both CI identifier lists are otherwise arbitrary
synthetic bytes, not tied to any real card or issuer.

To regenerate: save the program above, compile and run it exactly as its
own header comment says, then splice its two hex lines into
`synthetic-info.log` in place of the current `EUICCInfo2`/
`GetEuiccDataResponse` response lines (keep the trailing ` 9000` each
already carries).
