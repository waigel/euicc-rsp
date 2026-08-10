/* A codec that loses a field usually still encodes something. Comparing the
   second encoding against the first is what catches the loss. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsp.h"
#include "Certificate.h"
#include "StoreMetadataRequest.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if(!good) fails++;
}

static int collect(const void *buf, size_t n, void *key) {
    struct { unsigned char *p; size_t len; } *out = key;
    memcpy(out->p + out->len, buf, n);
    out->len += n;
    return 0;
}

int main(void) {
    static const unsigned char iccid[10] = {
        0x98,0x00,0x10,0x32,0x54,0x76,0x98,0x10,0x32,0x14
    };
    unsigned char buf1[512], buf2[512];
    struct { unsigned char *p; size_t len; } o1 = { buf1, 0 }, o2 = { buf2, 0 };

    StoreMetadataRequest_t md;
    memset(&md, 0, sizeof md);
    OCTET_STRING_fromBuf(&md.iccid, (const char *)iccid, sizeof iccid);
    OCTET_STRING_fromBuf(&md.serviceProviderName, "euicc-tools", 11);
    OCTET_STRING_fromBuf(&md.profileName, "example", 7);
    /* profileClass has a DEFAULT in the module ("DEFAULT operational"), so
       asn1c generates it as an OPTIONAL pointer (ProfileClass_t *), not a
       plain value -- the generated StoreMetadataRequest.h is the truth
       about the module, not this file's first draft. A value equal to the
       default is exactly what DER canonicalizes away, so a decode of it
       comes back NULL, not a pointer to the default -- asn1c does not
       synthesize the default on absence. Using the non-default value
       "test" here keeps the field on the wire and exercises it.

       ProfileClass_t is an INTEGER_t rather than a long since the codec
       started being generated with -fwide-types (see the Makefile's codec
       rule), so this is calloc + asn_long2INTEGER, not malloc + assign:
       the INTEGER_t has to start zeroed for asn_long2INTEGER to be
       allowed to free and replace its buffer. */
    md.profileClass = calloc(1, sizeof(*md.profileClass));
    ok("profileClass is settable",
       md.profileClass &&
       asn_long2INTEGER(md.profileClass, ProfileClass_test) == 0);

    ok("encoding succeeds",
       der_encode(&asn_DEF_StoreMetadataRequest, &md, collect, &o1).encoded > 0);

    StoreMetadataRequest_t *back = NULL;
    asn_dec_rval_t r = ber_decode(NULL, &asn_DEF_StoreMetadataRequest,
                                  (void **)&back, buf1, o1.len);
    ok("decoding consumes the whole encoding",
       r.code == RC_OK && r.consumed == o1.len);

    if(back) {
        ok("re-encoding succeeds",
           der_encode(&asn_DEF_StoreMetadataRequest, back, collect, &o2).encoded > 0);
        ok("the two encodings are identical",
           o1.len == o2.len && memcmp(buf1, buf2, o1.len) == 0);
        ASN_STRUCT_FREE(asn_DEF_StoreMetadataRequest, back);
    }
    ASN_STRUCT_RESET(asn_DEF_StoreMetadataRequest, &md);

    /* A certificate serial number is an unconstrained INTEGER (RFC 3280
       CertificateSerialNumber, third_party/pkix/), and RFC 5280 section
       4.1.2.2 lets it run to twenty octets. asn1c's default is to give an
       unconstrained INTEGER the C type "long", which holds eight -- so a
       nine-octet serial makes ber_decode fail outright, and every
       structure carrying a Certificate (AuthenticateResponseOk's
       euiccCertificate and eumCertificate, among others) fails with it.
       The codec is generated with -fwide-types for this reason; see the
       Makefile's codec rule.

       The fixture is this project's own test CI, whose serial is
       B874F3ABFA6C44D3 -- eight significant bytes with the high bit set,
       so DER prefixes the 0x00 that makes it nine. Nothing decoded it
       through asn1c before: certificates reach mbedtls by way of
       rsp_pki_verify, which has its own parser and its own integer
       handling, so this gap survived every test in this suite until a
       real eUICC sent a certificate that hit it. */
    {
        const uint8_t *ci_der = NULL;
        size_t ci_len = 0;
        ok("the test CI certificate is available",
           rsp_pki_test_ci(&ci_der, &ci_len) == 0 && ci_der && ci_len > 0);

        Certificate_t *crt = NULL;
        asn_dec_rval_t cr = ber_decode(NULL, &asn_DEF_Certificate,
                                       (void **)&crt, ci_der, ci_len);
        ok("a certificate with a nine-octet serial number decodes",
           cr.code == RC_OK && cr.consumed == ci_len);
        if(crt) ASN_STRUCT_FREE(asn_DEF_Certificate, crt);
    }

    return fails ? 1 : 0;
}
