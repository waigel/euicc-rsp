/*
 * bpp-dump -- build a Bound Profile Package from a profile and show what
 * came out.
 *
 * This exists to make the artifact visible. The test suite proves the BPP is
 * correct; it does not let you look at one. Run it against a profile and it
 * prints the envelope group by group, so the structure SGP.22 describes and
 * the bytes on the wire sit next to each other.
 *
 *     make tools/bpp-dump
 *     ./tools/bpp-dump testdata/profile.der
 *
 * Two things it is not. The session keys are fixed demo values, not the
 * result of a key agreement with a card -- a real download derives them from
 * the eUICC's one-time public key, which arrives only over ES10b. And the
 * package it prints is not one a card would accept: the '87' and '88' groups
 * are unprotected and three fields of initialiseSecureChannelRequest are
 * placeholders. rsp.h says which and why.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsp.h"

/* The same fixed keys tests/test_bpp.c uses, so a dump here can be compared
   against the values the suite pins. */
static void demo_session(rsp_session_t *s) {
    memset(s, 0, sizeof *s);
    for(int i = 0; i < 16; i++) { s->s_enc[i] = i; s->s_mac[i] = 0x40 + i; }
}

static uint8_t *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if(!f) return NULL;
    if(fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if(n < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t *b = malloc((size_t)n ? (size_t)n : 1);
    if(!b) { fclose(f); return NULL; }
    if(fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
    fclose(f);
    *len = (size_t)n;
    return b;
}

static void hexdump(const uint8_t *p, size_t n, size_t max, const char *indent) {
    size_t shown = n < max ? n : max;
    for(size_t i = 0; i < shown; i += 16) {
        printf("%s", indent);
        for(size_t j = 0; j < 16; j++)
            if(i + j < shown) printf("%02X ", p[i + j]); else printf("   ");
        printf(" |");
        for(size_t j = 0; j < 16 && i + j < shown; j++) {
            uint8_t c = p[i + j];
            putchar(c >= 0x20 && c < 0x7F ? c : '.');
        }
        printf("|\n");
    }
    if(shown < n) printf("%s... %zu more bytes\n", indent, n - shown);
}

/* One TLV, BER: returns the total length consumed, or 0 if it does not fit.
   Deliberately its own small reader rather than the library's -- this program
   is here to look at the bytes, so it should not depend on the code that
   produced them to tell it what they mean. */
static size_t tlv(const uint8_t *p, size_t n, unsigned *tag, size_t *hdr, size_t *len) {
    size_t i = 0;
    if(n < 2) return 0;
    *tag = p[i++];
    if((*tag & 0x1F) == 0x1F) {                 /* high tag number form */
        if(i >= n) return 0;
        *tag = (*tag << 8) | p[i++];
    }
    if(i >= n) return 0;
    size_t l = p[i++];
    if(l & 0x80) {
        size_t k = l & 0x7F;
        if(k == 0 || k > 4 || i + k > n) return 0;
        l = 0;
        while(k--) l = (l << 8) | p[i++];
    }
    *hdr = i;
    *len = l;
    return i + l > n ? 0 : i + l;
}

static const char *group_name(unsigned tag) {
    switch(tag) {
    case 0xBF36: return "BoundProfilePackage";
    case 0xBF23: return "initialiseSecureChannelRequest";
    case 0xA0:   return "firstSequenceOf87  (configureISDP)";
    case 0xA1:   return "sequenceOf88       (storeMetadata)";
    case 0xA2:   return "secondSequenceOf87 (replaceSessionKeys)";
    case 0xA3:   return "sequenceOf86       (the profile segments)";
    case 0x86:   return "'86' protected segment";
    case 0x87:   return "'87' element";
    case 0x88:   return "'88' element";
    default:     return NULL;
    }
}

static void walk(const uint8_t *p, size_t n, int depth) {
    size_t off = 0;
    while(off < n) {
        unsigned tag; size_t hdr, len;
        size_t total = tlv(p + off, n - off, &tag, &hdr, &len);
        if(!total) {
            printf("%*s(%zu trailing bytes that are not a TLV)\n", depth * 2, "", n - off);
            return;
        }
        const char *name = group_name(tag);
        printf("%*s%04X  %-38s %6zu bytes\n", depth * 2, "",
               tag, name ? name : "(unknown tag)", len);

        /* Descend into the constructed groups; show the leaves as bytes. A
           protected segment is ciphertext followed by its 8-byte C-MAC, and
           seeing that split is most of the point of this program. */
        if(tag == 0xBF36 || (tag >= 0xA0 && tag <= 0xA3)) {
            walk(p + off + hdr, len, depth + 1);
        } else if(tag == 0x86 && len > 8) {
            printf("%*sciphertext %zu bytes:\n", (depth + 1) * 2, "", len - 8);
            hexdump(p + off + hdr, len - 8, 32, "      ");
            printf("%*sC-MAC:\n", (depth + 1) * 2, "");
            hexdump(p + off + hdr + len - 8, 8, 8, "      ");
        } else {
            hexdump(p + off + hdr, len, 32, "      ");
        }
        off += total;
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "testdata/profile.der";

    size_t upp_len = 0;
    uint8_t *upp = slurp(path, &upp_len);
    if(!upp) { fprintf(stderr, "bpp-dump: cannot read %s\n", path); return 2; }
    if(upp_len == 0) { fprintf(stderr, "bpp-dump: %s is empty\n", path); free(upp); return 2; }

    /* A placeholder one-time public key: the point at infinity's encoding is
       not valid, but rsp_bpp_build only copies these 65 bytes into the
       envelope. A real download puts our generated ephemeral key here. */
    uint8_t otpk[65]; memset(otpk, 0, sizeof otpk); otpk[0] = 0x04;
    uint8_t iccid[10] = { 0x98, 0x00, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x14 };

    rsp_bpp_input_t in = {
        .upp = upp, .upp_len = upp_len, .otpk_dp = otpk, .iccid = iccid,
        .profile_name = "bpp-dump", .service_provider_name = "euicc-rsp"
    };

    rsp_session_t s;
    demo_session(&s);

    uint8_t *bpp = NULL; size_t bpp_len = 0;
    int rc = rsp_bpp_build(&s, &in, &bpp, &bpp_len);
    if(rc != 0) {
        fprintf(stderr, "bpp-dump: rsp_bpp_build returned %d\n", rc);
        free(upp);
        rsp_session_wipe(&s);
        return rc == -1 ? 1 : 2;
    }

    printf("profile  %s, %zu bytes\n", path, upp_len);
    printf("package  %zu bytes, %.1f%% overhead\n\n",
           bpp_len, 100.0 * (double)(bpp_len - upp_len) / (double)upp_len);
    walk(bpp, bpp_len, 0);

    /* The self-check the design describes: decrypt what we just built with a
       second session holding the same keys, and require the original back.
       It is what the tool would do before sending anything to a card. */
    rsp_session_t back_s;
    demo_session(&back_s);
    uint8_t *back = NULL; size_t back_len = 0;
    int r2 = rsp_bpp_recover(&back_s, bpp, bpp_len, &back, &back_len);
    printf("\nself-check: ");
    if(r2 == 0 && back_len == upp_len && memcmp(back, upp, upp_len) == 0)
        printf("the package decrypts back to the profile, byte for byte\n");
    else
        printf("FAILED (rsp_bpp_recover returned %d, %zu bytes back)\n", r2, back_len);

    free(back);
    free(bpp);
    free(upp);
    rsp_session_wipe(&s);
    rsp_session_wipe(&back_s);
    return 0;
}
