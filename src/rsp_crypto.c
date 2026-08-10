/*
 * rsp_crypto.c -- session keys from the one-time key agreement.
 *
 * The SM-DP+ and the eUICC each hold a one-time P-256 key pair (SGP.22
 * calls them otPK/otSK.DP.ECKA and otPK/otSK.eUICC.ECKA). An ECDH on those
 * two pairs gives a shared secret that neither side ever transmits; the
 * X9.63 key derivation with SHA-256 turns that secret into the SCP03t
 * session keys everything after this point is protected with. Get this
 * step wrong and every later exchange is silently wrong too -- which is
 * why the ECDH half is checked against a vector this repository did not
 * produce (see testdata/nist/README.md), rather than only against itself.
 *
 * The split of the derived key material into the initial MAC chaining
 * value, S-ENC and S-MAC follows SGP.22 Annex G, "Key Derivation Process
 * (Normative)": KeyData bytes 1..L are the initial MAC chaining value,
 * L+1..2L are S-ENC, 2L+1..3L are S-MAC, with L = 16 for AES-128.
 */
#include "rsp.h"
#include "rsp_internal.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

int rsp_ecdh_p256(const uint8_t sk[32], const uint8_t pk[65], uint8_t z[32])
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi d, shared;
    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context drbg;
    int rng_ok;
    int ret = -1;

    if (!sk || !pk || !z) {
        return -1;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&shared);
    /* mbedTLS's scalar multiplication takes an RNG for blinding against
     * timing attacks. mbedtls_ecdh_compute_shared documents f_rng as
     * "must not be NULL" -- the same requirement src/rsp_pki.c already
     * ran into with mbedtls_ecp_mul -- so a real RNG is seeded here too,
     * even though the scalar and point it multiplies are both already
     * fixed by the caller. */
    rng_ok = rsp_rng_init(&ent, &drbg, "euicc-rsp/rsp_crypto") == 0;

    if (rng_ok &&
        mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_ecp_point_read_binary(&grp, &q, pk, 65) == 0 &&
        mbedtls_mpi_read_binary(&d, sk, 32) == 0 &&
        mbedtls_ecdh_compute_shared(&grp, &shared, &q, &d,
                                     mbedtls_ctr_drbg_random, &drbg) == 0 &&
        mbedtls_mpi_write_binary(&shared, z, 32) == 0) {
        ret = 0;
    }

    mbedtls_mpi_free(&shared);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);
    return ret;
}

int rsp_kdf_x963(const uint8_t *z, size_t z_len,
                  const uint8_t *info, size_t info_len,
                  uint8_t *out, size_t out_len)
{
    uint8_t *buf;
    size_t buf_len;
    size_t produced = 0;
    uint32_t counter = 1;
    int ret = -1;

    if ((!z && z_len) || (!info && info_len) || (!out && out_len)) {
        return -1;
    }
    if (out_len == 0) {
        return 0;
    }

    /* SHA-256(Z || counter_be32(i) || info) per iteration. z and info do
     * not change between iterations, so they are copied into a scratch
     * buffer once and only the 4-byte counter is rewritten each time. */
    buf_len = z_len + 4 + info_len;
    buf = malloc(buf_len);
    if (!buf) {
        return -1;
    }
    memcpy(buf, z, z_len);
    memcpy(buf + z_len + 4, info, info_len);

    while (produced < out_len) {
        uint8_t digest[32];
        size_t chunk;

        buf[z_len + 0] = (uint8_t)(counter >> 24);
        buf[z_len + 1] = (uint8_t)(counter >> 16);
        buf[z_len + 2] = (uint8_t)(counter >> 8);
        buf[z_len + 3] = (uint8_t)(counter);

        if (mbedtls_sha256(buf, buf_len, digest, 0) != 0) {
            /* digest is uninitialized SHA-256 scratch on this path, not
             * derived key material, but it shares the array with the
             * success path below -- wipe unconditionally rather than
             * make a future reader reason about which path needs it. */
            mbedtls_platform_zeroize(digest, sizeof digest);
            goto out;
        }

        chunk = out_len - produced;
        if (chunk > sizeof digest) {
            chunk = sizeof digest;
        }
        memcpy(out + produced, digest, chunk);
        produced += chunk;
        counter++;
        /* digest is a fresh stack array each iteration (its lifetime
         * does not span iterations), but it is still live in this
         * frame's memory until something overwrites it -- wipe the
         * copy of the key material it just handed to "out" before the
         * next iteration reuses (or the function returns and leaves)
         * this slot. A plain memset here is exactly the pattern that
         * -O2 removed elsewhere in this file: digest is never read
         * again after this point, so the compiler can prove the store
         * dead and drop it. mbedtls_platform_zeroize is written so
         * that proof cannot go through. */
        mbedtls_platform_zeroize(digest, sizeof digest);
    }
    ret = 0;

out:
    /* buf carries the shared secret Z; it does not outlive this call.
     * This memset was checked separately (see the fix report) to
     * survive at -O2 as a bzero call -- free() taking its address is
     * enough here to block the dead-store proof -- but there is no
     * harm in using the primitive that does not depend on that. */
    mbedtls_platform_zeroize(buf, buf_len);
    free(buf);
    if (ret != 0) {
        /* A failed derivation must not leave whatever partial key
         * material earlier iterations already wrote into the caller's
         * buffer. rsp_session_init happens to re-zero its own output on
         * failure regardless, but a caller of rsp_kdf_x963 directly
         * does not get that for free unless this function does it. */
        mbedtls_platform_zeroize(out, out_len);
    }
    return ret;
}

int rsp_session_init(const uint8_t otsk_dp[32], const uint8_t otpk_euicc[65],
                      const uint8_t *shared_info, size_t shared_info_len,
                      rsp_session_t *out)
{
    uint8_t z[32];
    uint8_t key_data[48]; /* SGP.22 Annex G: chain (16) | S-ENC (16) | S-MAC (16) */
    int ret = -1;

    if (!otsk_dp || !otpk_euicc || !out) {
        return -1;
    }
    memset(out, 0, sizeof *out);

    if (rsp_ecdh_p256(otsk_dp, otpk_euicc, z) != 0) {
        goto out;
    }
    if (rsp_kdf_x963(z, sizeof z, shared_info, shared_info_len,
                      key_data, sizeof key_data) != 0) {
        goto out;
    }

    memcpy(out->chain, key_data + 0, 16);
    memcpy(out->s_enc, key_data + 16, 16);
    memcpy(out->s_mac, key_data + 32, 16);
    /* The encryption counter's initial state, SGP.22 v2.6 section 2.5.3:
       "the value on 16 bytes is '00...01'". Annex G derives the chaining
       value, S-ENC and S-MAC and nothing else -- this one is a constant,
       not part of KeyData. */
    memset(out->enc_counter, 0, sizeof out->enc_counter);
    out->enc_counter[sizeof out->enc_counter - 1] = 0x01;
    ret = 0;

out:
    /* z and key_data are locals that are never read again after this
     * point and never escape this function, so a plain memset here is
     * a proven-dead store at this project's -O2 and is removed: no
     * wipe instruction survives on the success path (confirmed by
     * reading the generated assembly, and independently by a runtime
     * probe that found the just-returned chain/S-ENC/S-MAC values
     * still present in stack memory -- see tests/test_zeroize.c and
     * the fix report). mbedtls_platform_zeroize exists specifically to
     * defeat that proof; use it here instead of memset. */
    mbedtls_platform_zeroize(z, sizeof z);
    mbedtls_platform_zeroize(key_data, sizeof key_data);
    if (ret != 0) {
        /* out is caller-visible: the same dead-store risk as the memset
         * this replaces on rsp_session_wipe applies here too, since
         * nothing forces a future caller to read *out again on this
         * path before its own frame ends. */
        mbedtls_platform_zeroize(out, sizeof *out);
    }
    return ret;
}

void rsp_session_wipe(rsp_session_t *s)
{
    if (!s) {
        return;
    }
    /* s is exactly the public-facing counterpart of the dead-store problem
     * documented on rsp_session_init above: a plain memset on a struct the
     * caller is about to stop using is a store the compiler can prove
     * nothing reads again, and is free to drop -- provably so without
     * LTO even, once this call is inlined into a caller whose own use of
     * *s also ends here. mbedtls_platform_zeroize is written so that
     * proof cannot go through; use it for the one function whose entire
     * job is this wipe. */
    mbedtls_platform_zeroize(s, sizeof *s);
}

/*
 * SCP03t: the secure channel that protects each SCP03t data segment sent to
 * the eUICC, in the ES8+/BPP path (SGP.22 Annex uses the term "data
 * segment" for one tag-'86' TLV -- see SGP.22 v2.6 section 2.5.3: "Each
 * data segment of the PPP is identified by the tag '86' as defined in
 * SGP.02 [2]").
 *
 * SGP.22 v2.6 section 2.5.3 does not define the byte-level construction
 * itself; it says: "Command TLV encryption and MACing follows SGP.02 [2]
 * section 4.1.3.3." SGP.02 v4.1 section 4.1.3.3, in turn, says SCP03t is
 * "a secure channel protocol based on GlobalPlatform's SCP03 usable for
 * TLV structures" and that, apart from the TLV framing, "the security
 * mechanisms are exactly the same as SCP03" (GlobalPlatform Card
 * Specification Amendment D, "Secure Channel Protocol '03'"). The three
 * rules below each cite the document and clause they actually came from --
 * none of this was taken from memory or another implementation.
 *
 * 1. Padding (GlobalPlatform Card Specification v2.3.1, Annex B.2.3, "AES
 *    Padding", which Amendment D section 6.2.6 points to: "Prior to
 *    encrypting the data, the data shall be padded as defined in [GPCS]
 *    section B.2.3"): append a single '80' byte, then append '00' bytes
 *    until the length is a multiple of 16. This always adds between 1 and
 *    16 bytes -- a plaintext that is already block-aligned still gets a
 *    full extra block of padding, which is exactly what SGP.22 section
 *    2.5.3's own sizing note assumes ("Considering the necessary padding
 *    during encryption (16 bytes length block encryption and necessary
 *    '80' byte padding)").
 *
 * 2. The ICV (Amendment D section 6.2.6, "APDU Command C-MAC and
 *    C-DECRYPTION Generation and Verification"): "the off-card entity
 *    shall increment an encryption counter ... This block shall be
 *    encrypted with S-ENC to produce the ICV for command encryption." So
 *    ICV = AES-128-ECB-Encrypt(S-ENC, encryption counter), and the counter
 *    is its own 16-byte value, NOT the MAC chaining value.
 *
 *    An earlier version of this file conflated the two, reading SGP.02
 *    v4.1 section 4.1.3.3's "Otherwise the MAC chaining method SHALL be
 *    applied (i.e. the MAC chaining value of the previous command TLV
 *    SHALL be used)" as if it redefined the ICV. It does not: SGP.22
 *    v2.6 section 2.5.3 carries that same "Otherwise" sentence and, in
 *    the clause immediately before it, names the two separately -- random
 *    key mode supplies "the initial MAC chaining value" AND resets "the
 *    encryption counter for ICV calculation ... to its initial state
 *    (i.e. the value on 16 bytes is '00...01')". The "Otherwise" governs
 *    the chaining value alone. Section 2.5.4 then gives the counter its
 *    own rule, quoted below. A real eUICC rejected the first '87' of a
 *    Bound Profile Package built the conflated way with errorReason
 *    scp03tSecurityError(8), which is what turned the reading up.
 *
 * 3. The MAC (Amendment D section 6.2.4, "APDU Command C-MAC Generation
 *    and Verification", Figure 6-1, as SGP.02's Figure 46 "TLV Command
 *    Data Field Encryption" carries over for the TLV case): CMAC(S-MAC,
 *    chain || tag || Lcc || ciphertext), where tag is the segment's TLV
 *    tag ('86') and Lcc is that TLV's BER length octets over
 *    len(ciphertext) + 8. The appended MAC is the 8 most significant bytes
 *    of the 16-byte CMAC output (Figure 6-1's "C-MAC (8)"; SGP.02's own
 *    section 2.5.3 sizing note counts "8 bytes MAC" per segment). The full
 *    16-byte CMAC output becomes the new chaining value (Amendment D
 *    section 6.2.3: "the full 16-byte C-MAC of the previous command
 *    becomes the 'MAC chaining value' for the subsequent C-MAC
 *    verification").
 *
 * rsp_protect and rsp_protect_mac_only both take the segment's TLV tag as a
 * parameter now, not a hard-coded constant: SGP.22 Table 4 uses the exact
 * same encrypt-and-MAC construction for tag '87' (ConfigureISDP) as it does
 * for '86' (the PPP itself) -- "protected with session keys resulting from
 * the key agreement (S-ENC, S-CMAC)" is Table 4's own wording for both --
 * so rsp_protect below is the one function for both, distinguished only by
 * which tag its caller passes. '88' (StoreMetadata) is different: Table 4
 * says it is "MAC protected ... (i.e. not encrypted)", which is why it gets
 * its own function, rsp_protect_mac_only, rather than a flag on rsp_protect
 * that skips encryption -- the two constructions genuinely differ (no ICV,
 * no padding, no ciphertext), not just in which bytes get MACed.
 *
 * Both functions share the same MAC computation, scp03t_mac below, now
 * parametrized by tag for the same reason: rule 3 folds the tag byte into
 * what gets MACed, so a MAC computed with the wrong tag baked in verifies
 * against nothing a real eUICC (which authenticates using the tag it
 * actually parsed the segment under) would ever compute to match.
 *
 * SGP.22 v2.6 section 2.5.4's own text: "The encryption counter for ICV
 * calculation is incremented each time a TLV with tag '86', '87' or '88' is
 * received." Read against rule 2's own citation (GlobalPlatform Amendment D
 * section 6.2.6, the counter SCP03t's chaining value replaces) and rule 3's
 * (the full 16-byte CMAC output becomes the chaining value for what
 * follows): this is one shared counter -- realized here as the single
 * s->chain field -- advanced by every one of '86', '87' and '88', in
 * whatever order they are actually sent, not three independent per-tag
 * counters. Concretely: firstSequenceOf87's '87' TLV advances the chain
 * that sequenceOf88's '88' TLV then reads as its own MAC input, which in
 * turn advances the chain that sequenceOf86's first '86' segment reads. A
 * card computing its own MACs to compare against therefore expects
 * *exactly this* interleaved advancement -- an implementation that keeps a
 * separate chain per tag, or that skips advancing it for '88' because '88'
 * has no encryption step to reset a counter for, silently disagrees with
 * every '86' segment's MAC from that point on, with no diagnostic pointing
 * at '88' as the cause. rsp_protect_mac_only advances s->chain from its own
 * MAC's full CMAC output for exactly this reason, even though it never
 * computes an ICV (there being nothing to encrypt) -- see its own comment
 * below.
 *
 * *out* holds only the segment's value bytes (ciphertext-or-plaintext,
 * then the 8-byte MAC) -- not the tag or its length octets, since those are
 * exactly what a BER/DER encoder reproduces from a plain byte count when
 * the segment is placed into a TLV (see include/rsp.h for why that is safe
 * to leave to the caller). The tag and length octets are still computed
 * here, internally, because per rule 3 above they are part of what the MAC
 * covers, even though they are never written to *out*.
 *
 * rsp_unprotect and rsp_unprotect_mac_only are the inverse pair, tag-generic
 * for the identical reason: src/rsp_bpp.c's rsp_bpp_recover must now
 * actually verify the single '87' element and every '88' element it finds
 * (not merely skip their TLVs, the way it did before this construction was
 * implemented), purely to replay the same chain advancement rsp_protect and
 * rsp_protect_mac_only performed while building -- without that replay, the
 * chain rsp_unprotect reads for the first '86' segment would still be the
 * pre-'87'/'88' initial value, while the chain rsp_protect actually used to
 * MAC that same '86' segment during build had already moved twice; every
 * '86' segment's MAC would then fail to verify, for a reason with no
 * connection to the '86' segment itself.
 */
#define RSP_SCP03T_MAC_LEN  8

/* CMAC(S-MAC, chain || tag || Lcc || data) -- rule 3 above, generalized to
 * take the tag it MACs as a parameter (see this file's SCP03t comment for
 * why: '86' and '87' share this exact construction, differing only in
 * their tag byte). "data" is the segment's ciphertext for the encrypt-and-
 * MAC callers (rsp_protect, rsp_unprotect) or its plaintext for the MAC-
 * only caller (rsp_protect_mac_only) -- rule 3 itself does not care which,
 * only that it is exactly the bytes that end up on the wire as the
 * segment's value. Always produces the full 16-byte CMAC; the caller
 * decides how much of it is appended to the wire and how much becomes the
 * next chaining value.
 *
 * Lcc -- the length octets the MAC covers -- comes from
 * rsp_der_length_octets (src/rsp_internal.h), the same implementation
 * src/rsp_bpp.c uses to write the length octets that actually go on the
 * wire. See src/rsp_internal.h's own comment for why sharing that one
 * implementation, rather than each file keeping its own copy of the DER
 * length rule, is load-bearing here and not just tidiness: this is the
 * length the MAC authenticates, and it must be computed exactly the way
 * the wire bytes it is authenticating were computed. */
static int scp03t_mac(const uint8_t s_mac[16], const uint8_t chain[16],
                       uint8_t tag,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       uint8_t mac16[16])
{
    uint8_t len_octets[RSP_DER_LEN_OCTETS_MAX];
    size_t len_octets_n;
    uint8_t *buf;
    size_t buf_len;
    int ret = -1;

    if (rsp_der_length_octets(ciphertext_len + RSP_SCP03T_MAC_LEN,
                               len_octets, &len_octets_n) != 0) {
        return -1;
    }

    buf_len = 16 + 1 + len_octets_n + ciphertext_len;
    buf = malloc(buf_len);
    if (!buf) {
        return -1;
    }
    memcpy(buf, chain, 16);
    buf[16] = tag;
    memcpy(buf + 17, len_octets, len_octets_n);
    if (ciphertext_len) {
        memcpy(buf + 17 + len_octets_n, ciphertext, ciphertext_len);
    }

    ret = rsp_cmac(s_mac, buf, buf_len, mac16);

    /* buf carries the current chaining value, which this project treats
     * with the same care as other session state even though the tag,
     * length and ciphertext bytes copied alongside it are already public
     * wire data. */
    mbedtls_platform_zeroize(buf, buf_len);
    free(buf);
    return ret;
}

/* ICV = AES-128-ECB-Encrypt(S-ENC, encryption counter) -- rule 2 above. */
static int scp03t_icv(const uint8_t s_enc[16], const uint8_t counter[16],
                       uint8_t icv[16])
{
    mbedtls_aes_context aes;
    int ret;

    mbedtls_aes_init(&aes);
    ret = mbedtls_aes_setkey_enc(&aes, s_enc, 128);
    if (ret == 0) {
        ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, counter, icv);
    }
    mbedtls_aes_free(&aes);
    return ret == 0 ? 0 : -1;
}

/* The encryption counter, one further on: a 16-byte big-endian integer,
   incremented by one. Called once per '86'/'87'/'88' TLV -- see rule 2 and
   rsp_session_t's own comment on the field. Wrapping past all-ones would
   need 2^128 segments, so the carry simply runs off the front. */
static void scp03t_counter_advance(uint8_t counter[16])
{
    size_t i = 16;

    while (i-- > 0) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

int rsp_cmac(const uint8_t key[16], const uint8_t *msg, size_t len,
             uint8_t mac[16])
{
    /* mbedtls_cipher_cmac rejects a NULL input pointer outright, even when
     * len is 0 (mbedtls_cipher_cmac_update checks "input == NULL" before
     * ever looking at ilen) -- but NIST SP 800-38B's own AES-128 CMAC test
     * vector for the empty message passes msg == NULL, len == 0, which
     * this function must accept. Substituting a non-NULL placeholder is
     * safe here because it is never read: ilen is 0. */
    static const uint8_t empty = 0;
    const mbedtls_cipher_info_t *info;

    if (!key || !mac || (!msg && len != 0)) {
        return -1;
    }
    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (!info) {
        return -1;
    }
    return mbedtls_cipher_cmac(info, key, 128, msg ? msg : &empty, len, mac) == 0
        ? 0 : -1;
}

long rsp_protect(rsp_session_t *s, const uint8_t *plain, size_t plain_len,
                  uint8_t tag, uint8_t *out, size_t out_cap)
{
    size_t pad_len, padded_len;
    uint8_t *padded = NULL;
    uint8_t icv[16];
    uint8_t mac16[16];
    long ret = -1;

    if (!s || (!plain && plain_len != 0) || !out) {
        return -1;
    }

    /* Guard the two additions below (padding, then the MAC) before either
     * can wrap. Without this, a plain_len near SIZE_MAX makes padded_len
     * wrap to something small, which then passes the capacity check that
     * follows and lets the memcpy a few lines down copy the full,
     * enormous plain_len into a heap buffer sized for the wrapped value.
     * Rule 1 never adds more than 16 bytes of padding, and at most
     * RSP_SCP03T_MAC_LEN bytes of MAC follow that, so this is the most
     * headroom either addition needs. */
    if (plain_len > SIZE_MAX - 16 - RSP_SCP03T_MAC_LEN) {
        return -1;
    }

    /* Rule 1: always 1-16 bytes of padding, never zero. */
    pad_len = 16 - (plain_len % 16);
    padded_len = plain_len + pad_len;

    /* padded_len + RSP_SCP03T_MAC_LEN > out_cap alone is sufficient:
     * RSP_SCP03T_MAC_LEN is a positive constant, so padded_len > out_cap
     * is already true whenever this is (adding a positive constant to
     * padded_len only makes the left side larger), making that disjunct
     * this check used to also test dead. One check is enough. */
    if (padded_len + RSP_SCP03T_MAC_LEN > out_cap) {
        return -1;
    }

    padded = malloc(padded_len);
    if (!padded) {
        return -1;
    }
    if (plain_len) {
        memcpy(padded, plain, plain_len);
    }
    padded[plain_len] = 0x80;
    if (pad_len > 1) {
        memset(padded + plain_len + 1, 0, pad_len - 1);
    }

    if (scp03t_icv(s->s_enc, s->enc_counter, icv) != 0) {
        goto out;
    }

    /* Encrypt straight into out: mbedtls_aes_crypt_cbc allows separate
     * input/output buffers, and out's first padded_len bytes are exactly
     * the segment's ciphertext. */
    {
        mbedtls_aes_context aes;
        int rc;
        mbedtls_aes_init(&aes);
        rc = mbedtls_aes_setkey_enc(&aes, s->s_enc, 128);
        if (rc == 0) {
            rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len,
                                       icv, padded, out);
        }
        mbedtls_aes_free(&aes);
        if (rc != 0) {
            goto out;
        }
    }

    if (scp03t_mac(s->s_mac, s->chain, tag, out, padded_len, mac16) != 0) {
        goto out;
    }
    memcpy(out + padded_len, mac16, RSP_SCP03T_MAC_LEN);

    /* The full 16-byte MAC becomes the chaining value for the next
     * segment (rule 3), only once everything above has succeeded. The
     * encryption counter moves with it, but separately: it counted this
     * TLV, and the ICV above read it before it moved. */
    memcpy(s->chain, mac16, 16);
    scp03t_counter_advance(s->enc_counter);
    ret = (long)(padded_len + RSP_SCP03T_MAC_LEN);

out:
    if (padded) {
        mbedtls_platform_zeroize(padded, padded_len);
        free(padded);
    }
    mbedtls_platform_zeroize(icv, sizeof icv);
    mbedtls_platform_zeroize(mac16, sizeof mac16);
    return ret;
}

/* Table 4's '88' construction: "MAC protected ... (i.e. not encrypted)".
 * Same rule 3 MAC as rsp_protect (scp03t_mac, above, with this call's own
 * tag folded in), computed directly over plain -- there is no ciphertext
 * to MAC instead, and therefore no rule-1 padding and no rule-2 ICV either:
 * both of those exist only to support the encryption step this
 * construction does not have. *out* is plain_len bytes of plaintext,
 * unchanged, followed by the 8-byte MAC -- recoverable by a caller (or a
 * test) with nothing more than "read plain_len bytes, then check the MAC",
 * no decryption step of any kind.
 *
 * s->chain still advances from the full 16-byte CMAC output, exactly the
 * way rsp_protect's does: see this file's own SCP03t comment for why an
 * implementation that only advances the chain for encrypted tags ('86',
 * '87') and leaves it alone for '88' silently disagrees with a real
 * eUICC's own chaining from that point on. */
long rsp_protect_mac_only(rsp_session_t *s, const uint8_t *plain,
                           size_t plain_len, uint8_t tag,
                           uint8_t *out, size_t out_cap)
{
    uint8_t mac16[16];
    long ret = -1;

    if (!s || (!plain && plain_len != 0) || !out) {
        return -1;
    }
    /* Same overflow guard rsp_protect uses, narrowed to the one addition
     * this function actually performs (no padding to also account for). */
    if (plain_len > SIZE_MAX - RSP_SCP03T_MAC_LEN) {
        return -1;
    }
    if (plain_len + RSP_SCP03T_MAC_LEN > out_cap) {
        return -1;
    }

    if (scp03t_mac(s->s_mac, s->chain, tag, plain, plain_len, mac16) != 0) {
        goto out;
    }
    if (plain_len) {
        memcpy(out, plain, plain_len);
    }
    memcpy(out + plain_len, mac16, RSP_SCP03T_MAC_LEN);

    /* The full 16-byte MAC becomes the chaining value for the next
     * segment (rule 3), only once everything above has succeeded --
     * mirroring rsp_protect's own placement of this line. The encryption
     * counter advances here too, even though this function never computed
     * an ICV: section 2.5.4 counts every '86', '87' AND '88' TLV, so a
     * '88' that left the counter alone would put every later '86' one
     * step behind the card's own. */
    memcpy(s->chain, mac16, 16);
    scp03t_counter_advance(s->enc_counter);
    ret = (long)(plain_len + RSP_SCP03T_MAC_LEN);

out:
    mbedtls_platform_zeroize(mac16, sizeof mac16);
    return ret;
}

long rsp_unprotect(rsp_session_t *s, const uint8_t *seg, size_t seg_len,
                    uint8_t tag, uint8_t *out, size_t out_cap)
{
    const uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t mac16[16];
    uint8_t icv[16];
    uint8_t *padded = NULL;
    size_t pad_idx, min_idx;
    /* -2 by default: everything up to and including a successful MAC
     * check and a successful decrypt is "the question was never
     * reached" -- a malformed seg_len, an allocation failure, a crypto
     * primitive refusing its input, a caller buffer too small -- see
     * include/rsp.h's failure convention. The MAC mismatch and the
     * invalid-padding checks below are the two places this segment's
     * validity is actually decided, and each sets ret to -1 explicitly. */
    long ret = -2;

    if (!s || !seg || !out) {
        return -2;
    }
    /* At least one full ciphertext block plus the 8-byte MAC, and the
     * ciphertext portion must be a whole number of AES blocks. */
    if (seg_len < 16 + RSP_SCP03T_MAC_LEN ||
        (seg_len - RSP_SCP03T_MAC_LEN) % 16 != 0) {
        return -2;
    }
    ciphertext = seg;
    ciphertext_len = seg_len - RSP_SCP03T_MAC_LEN;

    if (scp03t_mac(s->s_mac, s->chain, tag, ciphertext,
                    ciphertext_len, mac16) != 0) {
        goto out;
    }

    /* Verify the MAC before touching the padding at all: a tampered
     * segment must be refused, not decrypted and then found invalid.
     *
     * mbedtls_ct_memcmp, not memcmp: plain memcmp is explicitly permitted
     * by the C standard to be a chunked or vectorised comparison that
     * returns as soon as it finds a mismatch, so the time it takes can
     * leak how many leading bytes of the MAC matched -- a padding-oracle
     * shaped side channel, just on the MAC instead of the padding.
     * mbedtls_ct_memcmp (vendor/mbedtls/include/mbedtls/constant_time.h)
     * is documented as constant-time with respect to whether its inputs
     * are equal. Do not "simplify" this back to memcmp: rsp_unprotect is
     * an exported entry point that a card's responses will eventually
     * feed, not only this repository's own locally generated segments. */
    if (mbedtls_ct_memcmp(mac16, seg + ciphertext_len, RSP_SCP03T_MAC_LEN) != 0) {
        ret = -1; /* the question was asked: this segment's MAC does not match */
        goto out;
    }

    if (scp03t_icv(s->s_enc, s->enc_counter, icv) != 0) {
        goto out;
    }

    padded = malloc(ciphertext_len);
    if (!padded) {
        goto out;
    }
    {
        mbedtls_aes_context aes;
        int rc;
        mbedtls_aes_init(&aes);
        rc = mbedtls_aes_setkey_dec(&aes, s->s_enc, 128);
        if (rc == 0) {
            rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ciphertext_len,
                                       icv, ciphertext, padded);
        }
        mbedtls_aes_free(&aes);
        if (rc != 0) {
            goto out;
        }
    }

    /* Undo rule 1: scan back from the end past any '00' pad bytes to the
     * mandatory '80' marker. Padding is never more than one block, so a
     * marker that is not found within the last 16 bytes is invalid
     * padding, not a search that should keep going into the plaintext. */
    min_idx = ciphertext_len >= 16 ? ciphertext_len - 16 : 0;
    pad_idx = ciphertext_len;
    while (pad_idx > min_idx && padded[pad_idx - 1] == 0x00) {
        pad_idx--;
    }
    if (pad_idx == min_idx || padded[pad_idx - 1] != 0x80) {
        /* The MAC already matched, so this is still a real answer about
         * the segment's content -- not an operational failure -- even
         * though it is only reachable at all because something upstream
         * (a different, MAC-consistent key derivation, say) is wrong. */
        ret = -1;
        goto out;
    }
    pad_idx--; /* now the length of the plaintext that was protected */

    if (pad_idx > out_cap) {
        /* -2, not -1: the segment itself is fine, the caller's buffer is
         * just too small to receive it -- the question was never reached. */
        goto out;
    }
    if (pad_idx) {
        memcpy(out, padded, pad_idx);
    }

    memcpy(s->chain, mac16, 16);
    scp03t_counter_advance(s->enc_counter);
    ret = (long)pad_idx;

out:
    if (padded) {
        mbedtls_platform_zeroize(padded, ciphertext_len);
        free(padded);
    }
    mbedtls_platform_zeroize(icv, sizeof icv);
    mbedtls_platform_zeroize(mac16, sizeof mac16);
    return ret;
}

/* The inverse of rsp_protect_mac_only: verify the MAC over chain || tag ||
 * Lcc || plain (rule 3, no ICV/decryption step, mirroring rsp_protect_
 * mac_only's own construction), and if it matches, copy plain_len bytes of
 * plaintext to *out and advance s->chain from the full CMAC output.
 *
 * This exists for the same reason rsp_unprotect does: a caller needs to
 * verify a '88' segment it did not produce itself, and rsp_bpp_recover
 * needs to replay '88's own chain advancement to stay in step with
 * whatever '86' segments follow it (see this file's SCP03t comment) --
 * without decrypting anything, since there is nothing to decrypt. Returns
 * plain_len on success. -1 means the question was actually asked and the
 * answer is no: the MAC does not match. -2 means the question was never
 * reached: a null argument, a seg_len too short to even hold a MAC,
 * out_cap too small for plain_len, or an allocation/crypto-primitive
 * failure. */
long rsp_unprotect_mac_only(rsp_session_t *s, const uint8_t *seg,
                             size_t seg_len, uint8_t tag,
                             uint8_t *out, size_t out_cap)
{
    size_t plain_len;
    uint8_t mac16[16];
    long ret = -2;

    if (!s || !seg || !out) {
        return -2;
    }
    if (seg_len < RSP_SCP03T_MAC_LEN) {
        return -2;
    }
    plain_len = seg_len - RSP_SCP03T_MAC_LEN;

    if (scp03t_mac(s->s_mac, s->chain, tag, seg, plain_len, mac16) != 0) {
        goto out;
    }

    /* Constant-time, for the same reason rsp_unprotect's own comparison
     * is: this is an exported entry point, not only fed by this
     * repository's own locally generated segments. */
    if (mbedtls_ct_memcmp(mac16, seg + plain_len, RSP_SCP03T_MAC_LEN) != 0) {
        ret = -1; /* the question was asked: this segment's MAC does not match */
        goto out;
    }

    if (plain_len > out_cap) {
        goto out; /* -2: the segment itself is fine, out_cap is just too small */
    }
    if (plain_len) {
        memcpy(out, seg, plain_len);
    }

    memcpy(s->chain, mac16, 16);
    scp03t_counter_advance(s->enc_counter);
    ret = (long)plain_len;

out:
    mbedtls_platform_zeroize(mac16, sizeof mac16);
    return ret;
}
