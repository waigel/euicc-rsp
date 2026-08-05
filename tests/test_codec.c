/* A codec that loses a field usually still encodes something. Comparing the
   second encoding against the first is what catches the loss. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
       asn1c generates it as an OPTIONAL pointer (ProfileClass_t *, aka
       long *), not a plain long -- the generated StoreMetadataRequest.h is
       the truth about the module, not this file's first draft. A value
       equal to the default is exactly what DER canonicalizes away, so a
       decode of it comes back NULL, not a pointer to the default -- asn1c
       does not synthesize the default on absence. Using the non-default
       value "test" here keeps the field on the wire and exercises it. */
    md.profileClass = malloc(sizeof(*md.profileClass));
    *md.profileClass = ProfileClass_test;

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
    return fails ? 1 : 0;
}
