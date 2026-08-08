/*
 * rsp_internal.h -- shared between this library's .c files, never installed.
 *
 * Three things used to exist twice, each edited by hand in two places that
 * had no way to notice if they drifted apart:
 *
 *   - rng_init, between src/rsp_crypto.c and src/rsp_pki.c: mbedTLS's
 *     scalar multiplication takes an RNG for blinding against timing
 *     attacks and refuses a NULL one outright, even in this project's own
 *     uses, where the scalar and point are already fixed and nothing is
 *     actually being generated.
 *   - accept_rsp_certificate_policies, between src/rsp_pki.c and
 *     src/rsp_sign.c: every certificate this project loads carries a
 *     critical certificatePolicies extension naming a GSMA RSP role
 *     policy OID that mbedTLS's built-in parser does not recognize, and
 *     this callback is the documented escape hatch for exactly that one
 *     extension.
 *   - the BER/DER minimal-length-octets rule, between
 *     scp03t_length_octets in src/rsp_crypto.c and der_len_octets in
 *     src/rsp_bpp.c. This third one is not merely cosmetic duplication:
 *     src/rsp_bpp.c's copy writes the length octets actually placed on
 *     the wire, while src/rsp_crypto.c's copy computes the length octets
 *     the SCP03t MAC covers. If the two rules ever disagreed, the MAC
 *     would authenticate a length different from the one on the segment
 *     -- a package that round-trips perfectly against this library's own
 *     rsp_unprotect while a real card, computing the length its own way,
 *     rejects it. One rule, one implementation, one test
 *     (tests/test_der_length.c), closes that off structurally rather
 *     than by convention.
 *
 * A fourth thing existed twice by the time this round added it, and had
 * already drifted before anyone noticed: a growable byte buffer, between
 * src/rsp_bpp.c's growbuf_append/growbuf_free and es10_append, then in
 * this same file's src/rsp_es10.c and now in euicc-lpa's, which reaches
 * this header through the vendored submodule. The two disagreed on their
 * starting capacity (512 vs. 64) and, more importantly, on whether the
 * buffer was wiped before release -- rsp_bpp.c's zeroized, es10_append's
 * did not. Harmless while es10_append only ever accumulated an EID or an
 * EUICCInfo2 answer, neither secret; not harmless the first time a
 * write-round caller uses the same accumulator for a
 * ProfileInstallationResult. rsp_growbuf_t below is the one
 * implementation both files call, keeping the zeroizing free.
 *
 * All four are small enough, and used unevenly enough across the files
 * that would otherwise each carry their own copy, that a header of
 * "static inline" functions is simpler than a fifth .c file plus a
 * prototype header: no new object to add to SRCS, and a TU that does not
 * call one of these does not need to know it exists ("static inline"
 * itself, unlike plain "static", does not warn as unused under -Wall
 * when a given TU only needs some of the four).
 */
#ifndef RSP_INTERNAL_H
#define RSP_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/x509_crt.h"

/* Seeds ent/drbg from platform entropy, personalized with pers (a short,
 * human-readable, caller-identifying string -- not secret, only there so
 * two callers' RNG instances are not bit-for-bit interchangeable).
 * Returns 0, or -1 if seeding failed (mbedtls_ctr_drbg_seed's own
 * convention). Every call site in this project already has an mpi/ecp
 * operation that requires a non-NULL f_rng regardless of whether it is
 * generating anything the caller considers random. */
static inline int rsp_rng_init(mbedtls_entropy_context *ent,
                                mbedtls_ctr_drbg_context *drbg,
                                const char *pers)
{
    mbedtls_entropy_init(ent);
    mbedtls_ctr_drbg_init(drbg);
    return mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, ent,
                                  (const unsigned char *)pers, strlen(pers));
}

/* mbedtls_x509_crt_parse_der_with_ext_cb's escape hatch for the one
 * critical extension every certificate in testdata/sgp26/ carries that
 * mbedTLS's parser does not otherwise recognize (id-rspRole-*, arc
 * 2.23.146.1.2.1). Accepting it here does not change what the caller's
 * own chain-of-trust or signature check verifies afterwards -- this
 * function's only job is to stop that one OID from making the parse
 * fail outright. */
static inline int rsp_accept_certificate_policies(
    void *p_ctx, mbedtls_x509_crt const *crt, mbedtls_x509_buf const *oid,
    int is_critical, const unsigned char *p, const unsigned char *end)
{
    (void)p_ctx;
    (void)crt;
    (void)p;
    (void)end;
    if (!is_critical) {
        return 0;
    }
    return MBEDTLS_OID_CMP(MBEDTLS_OID_CERTIFICATE_POLICIES, oid) == 0 ? 0 : -1;
}

/* Like rsp_accept_certificate_policies above, but also accepts a critical
 * id-ce-nameConstraints extension (2.5.29.30). Needed for exactly one
 * certificate this project loads: testdata/sgp26/eum.der (GSMA's own
 * published SGP.26 v1.0 test EUM certificate) carries a critical Name
 * Constraints extension restricting the EIDs it may issue for ("Permitted:
 * DirName:O = RSP Test EUM, serialNumber = 89049032") -- a real GSMA
 * convention for scoping an EUM to its assigned IIN range, encoded as a
 * directoryName constraint even though the "serialNumber = 89049032" value
 * is a prefix, not a literal RDN a compliant subtree match would ever
 * accept (confirmed independently: `openssl verify` rejects this exact
 * chain with "permitted subtree violation", error 47, for precisely this
 * reason). mbedTLS has no Name Constraints support at all (verified by
 * reading vendor/mbedtls/library/x509_crt.c: no "name_constraint" match
 * anywhere in it), so accepting the OID here only lets the certificate
 * parse; it does not make this project enforce -- or even read -- the
 * constraint's content. That is not a gap this project introduces: the
 * IIN-range eligibility check the constraint is standing in for belongs
 * with Profile-order/eligibility logic (SGP.22 5.6.3, Annex F), which this
 * stateless library does not implement at all (see src/rsp_es9.c). */
static inline int rsp_accept_certificate_policies_and_name_constraints(
    void *p_ctx, mbedtls_x509_crt const *crt, mbedtls_x509_buf const *oid,
    int is_critical, const unsigned char *p, const unsigned char *end)
{
    (void)p_ctx;
    (void)crt;
    (void)p;
    (void)end;
    if (!is_critical) {
        return 0;
    }
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_CERTIFICATE_POLICIES, oid) == 0) {
        return 0;
    }
    return MBEDTLS_OID_CMP(MBEDTLS_OID_NAME_CONSTRAINTS, oid) == 0 ? 0 : -1;
}

/* The SM-DP+'s own Host ID, for the Control Reference Template (ControlRef-
 * Template.hostId, rsp-2.5.asn line 474) and for the matching HostID-LV
 * component of Annex G's KDF SharedInfo (SGP.22 v2.6 Annex G:
 * "keyType(1) || keyLen(1) || HostID-LV || EID-LV" -- HostID and EID are
 * two separate LV fields, not the same value encoded twice).
 *
 * This is NOT the eUICC's EID. That is a real, previously-shipped mistake
 * in this project worth recording precisely: src/rsp_bpp.c's build_isc
 * currently comments that "the real hostId is the eUICC's EID, absent from
 * this input struct". Checked against a working reference implementation
 * rather than trusted on that comment's say-so: osmo-smdpp (Osmocom's
 * pySim-based SM-DP+, github.com/osmocom/pysim, osmo-smdpp.py) hardcodes
 * `ss.host_id = b'mahlzeit'` -- an arbitrary, unrelated ASCII string --
 * completely independent of `ss.eid` (which it reads from the eUICC
 * certificate's subject serialNumber a few lines away, and which is passed
 * as the *separate* eid_lv argument to its own KDF call,
 * BspInstance.from_kdf(shared_secret, key_type, key_length, host_id, eid)
 * in pySim/esim/bsp.py). GlobalPlatform Amendment F's SCP11a, which SGP.22
 * section 2.6.4 says this protocol is based on, calls the off-card entity
 * (here, the SM-DP+) the "Host" -- hostId identifies that Host, not the
 * Card (eUICC) on the other end of the exchange. Task 4's own
 * controlRefTemplate must read this same constant, not re-derive a hostId
 * from the EID: if the two sides of a key derivation start from different
 * hostId bytes, they derive different session keys with no useful
 * diagnostic (see include/rsp.h's own note on rsp_session_init).
 *
 * 9 bytes, well inside ControlRefTemplate.hostId's OctetTo16 SIZE(1..16)
 * ceiling. */
#define RSP_HOST_ID     ((const uint8_t *)"euicc-rsp")
#define RSP_HOST_ID_LEN 9

/* BER/DER length octets for len, minimal encoding (no leading zero byte
 * beyond what the long form needs) -- ITU-T X.690 8.1.3. Writes at most
 * RSP_DER_LEN_OCTETS_MAX bytes to out and sets *n to how many. Handles
 * lengths up to 0xFFFFFFFF (four length bytes plus the one leading
 * "0x84" byte that says so) -- past any BoundProfilePackage or SCP03t
 * segment this project's own callers construct, but general rather than
 * narrowed to either caller's own known-smaller range, since the whole
 * point of having one implementation is that neither caller's copy gets
 * to assume a bound the other one does not also enforce. Returns 0, or
 * -1 if len does not fit even the long form. */
#define RSP_DER_LEN_OCTETS_MAX 5
static inline int rsp_der_length_octets(size_t len,
                                         uint8_t out[RSP_DER_LEN_OCTETS_MAX],
                                         size_t *n)
{
    if (len < 0x80) {
        out[0] = (uint8_t)len;
        *n = 1;
    } else if (len <= 0xFF) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        *n = 2;
    } else if (len <= 0xFFFF) {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)len;
        *n = 3;
    } else if (len <= 0xFFFFFFUL) {
        out[0] = 0x83;
        out[1] = (uint8_t)(len >> 16);
        out[2] = (uint8_t)(len >> 8);
        out[3] = (uint8_t)len;
        *n = 4;
    } else if (len <= 0xFFFFFFFFUL) {
        out[0] = 0x84;
        out[1] = (uint8_t)(len >> 24);
        out[2] = (uint8_t)(len >> 16);
        out[3] = (uint8_t)(len >> 8);
        out[4] = (uint8_t)len;
        *n = 5;
    } else {
        return -1;
    }
    return 0;
}

/* A growable byte buffer: appends data (n bytes) to g, growing g->cap as
 * needed. Returns 0, or -1 on an allocation failure (g->buf is unchanged
 * and still owned by the caller either way). Shared by src/rsp_bpp.c
 * (hand-assembling TLVs, der_encode's callback interface, concatenating
 * recovered segments) and euicc-lpa's src/rsp_es10.c (accumulating a
 * chained inward response), which reaches this header through the
 * vendored submodule -- see this header's own top comment for why a
 * fourth copy was the one this file exists to prevent. */
typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
} rsp_growbuf_t;

static inline int rsp_growbuf_append(rsp_growbuf_t *g, const void *data,
                                      size_t n)
{
    if (g->len + n > g->cap) {
        size_t newcap = g->cap ? g->cap * 2 : 512;
        while (newcap < g->len + n) {
            newcap *= 2;
        }
        uint8_t *p = realloc(g->buf, newcap);
        if (!p) {
            return -1;
        }
        g->buf = p;
        g->cap = newcap;
    }
    if (n) {
        memcpy(g->buf + g->len, data, n);
    }
    g->len += n;
    return 0;
}

/* Wipes the whole allocation (up to g->cap, not just g->len -- a previous
 * grow may have left old content further out that was never explicitly
 * overwritten by a later append) before releasing it, unconditionally: a
 * caller that only sometimes holds secret material is exactly the case
 * where deciding "this instance doesn't need it" quietly becomes wrong the
 * first time a new caller reuses the buffer for something that does. */
static inline void rsp_growbuf_free(rsp_growbuf_t *g)
{
    if (g->buf) {
        mbedtls_platform_zeroize(g->buf, g->cap);
    }
    free(g->buf);
    g->buf = NULL;
    g->len = 0;
    g->cap = 0;
}

#endif /* RSP_INTERNAL_H */
