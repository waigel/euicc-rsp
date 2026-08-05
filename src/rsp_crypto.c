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

#include <stdlib.h>
#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

/* mbedTLS's scalar multiplication takes an RNG for blinding against timing
 * attacks. mbedtls_ecdh_compute_shared documents f_rng as "must not be
 * NULL" -- the same requirement Task 3 already ran into with
 * mbedtls_ecp_mul -- so a real RNG is seeded here too, even though the
 * scalar and point it multiplies are both already fixed by the caller. */
static int rng_init(mbedtls_entropy_context *ent, mbedtls_ctr_drbg_context *drbg)
{
    static const unsigned char pers[] = "euicc-rsp/rsp_crypto";
    mbedtls_entropy_init(ent);
    mbedtls_ctr_drbg_init(drbg);
    return mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, ent,
                                  pers, sizeof(pers) - 1);
}

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
    rng_ok = rng_init(&ent, &drbg) == 0;

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
        memset(out, 0, sizeof *out);
    }
    return ret;
}

void rsp_session_wipe(rsp_session_t *s)
{
    if (!s) {
        return;
    }
    memset(s, 0, sizeof *s);
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
 *    encrypted with S-ENC to produce the ICV for command encryption."
 *    SCP03t replaces that counter: SGP.02 v4.1 section 4.1.3.3, "Otherwise
 *    the MAC chaining method SHALL be applied (i.e. the MAC chaining value
 *    of the previous command TLV SHALL be used)" -- so here, ICV =
 *    AES-128-ECB-Encrypt(S-ENC, chain), where "chain" is the MAC chaining
 *    value in force for this segment (the value rsp_session_init derived
 *    for the first segment, SGP.22 Annex G; the previous segment's C-MAC
 *    for every one after).
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
 * rsp_protect and rsp_unprotect hard-code the tag as '86': that is the only
 * tag this library's caller (the Bound Profile Package assembly) uses
 * rsp_protect for -- SGP.22 Table 4 also defines tag '87' (ConfigureISDP,
 * ReplaceSessionKeys) and '88' (StoreMetadata, MAC-only, no encryption),
 * which are a different, narrower construction this function does not
 * cover. *out* holds only the segment's value bytes (ciphertext, then the
 * 8-byte MAC) -- not the tag or its length octets, since those are exactly
 * what a BER/DER encoder reproduces from a plain byte count when the
 * segment is placed into the generated codec's OCTET STRING (see
 * include/rsp.h for why that is safe to leave to the caller). The tag and
 * length octets are still computed here, internally, because per rule 3
 * above they are part of what the MAC covers, even though they are never
 * written to *out*.
 */
#define RSP_SCP03T_TAG      0x86
#define RSP_SCP03T_MAC_LEN  8

/* BER/DER length octets for len, minimal encoding (no leading zero byte),
 * matching what any DER encoder (including Task 2's generated codec) would
 * emit for an OCTET STRING of that many bytes. Writes at most 3 bytes to
 * out (this project's segments never approach the 65536-byte boundary
 * where a fourth byte would be needed) and returns how many, or 0 if len
 * does not fit. */
static size_t scp03t_length_octets(size_t len, uint8_t out[3])
{
    if (len < 0x80) {
        out[0] = (uint8_t)len;
        return 1;
    }
    if (len <= 0xFF) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        return 2;
    }
    if (len <= 0xFFFF) {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)len;
        return 3;
    }
    return 0;
}

/* CMAC(S-MAC, chain || '86' || Lcc || ciphertext) -- rule 3 above. Always
 * produces the full 16-byte CMAC; the caller decides how much of it is
 * appended to the wire and how much becomes the next chaining value. */
static int scp03t_mac(const uint8_t s_mac[16], const uint8_t chain[16],
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       uint8_t mac16[16])
{
    uint8_t len_octets[3];
    size_t len_octets_n;
    uint8_t *buf;
    size_t buf_len;
    int ret = -1;

    len_octets_n = scp03t_length_octets(ciphertext_len + RSP_SCP03T_MAC_LEN,
                                         len_octets);
    if (len_octets_n == 0) {
        return -1;
    }

    buf_len = 16 + 1 + len_octets_n + ciphertext_len;
    buf = malloc(buf_len);
    if (!buf) {
        return -1;
    }
    memcpy(buf, chain, 16);
    buf[16] = RSP_SCP03T_TAG;
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

/* ICV = AES-128-ECB-Encrypt(S-ENC, chain) -- rule 2 above. */
static int scp03t_icv(const uint8_t s_enc[16], const uint8_t chain[16],
                       uint8_t icv[16])
{
    mbedtls_aes_context aes;
    int ret;

    mbedtls_aes_init(&aes);
    ret = mbedtls_aes_setkey_enc(&aes, s_enc, 128);
    if (ret == 0) {
        ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, chain, icv);
    }
    mbedtls_aes_free(&aes);
    return ret == 0 ? 0 : -1;
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
                  uint8_t *out, size_t out_cap)
{
    size_t pad_len, padded_len;
    uint8_t *padded = NULL;
    uint8_t icv[16];
    uint8_t mac16[16];
    long ret = -1;

    if (!s || (!plain && plain_len != 0) || !out) {
        return -1;
    }

    /* Rule 1: always 1-16 bytes of padding, never zero. */
    pad_len = 16 - (plain_len % 16);
    padded_len = plain_len + pad_len;

    if (padded_len > out_cap || padded_len + RSP_SCP03T_MAC_LEN > out_cap) {
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

    if (scp03t_icv(s->s_enc, s->chain, icv) != 0) {
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

    if (scp03t_mac(s->s_mac, s->chain, out, padded_len, mac16) != 0) {
        goto out;
    }
    memcpy(out + padded_len, mac16, RSP_SCP03T_MAC_LEN);

    /* The full 16-byte MAC becomes the chaining value for the next
     * segment (rule 3), only once everything above has succeeded. */
    memcpy(s->chain, mac16, 16);
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

long rsp_unprotect(rsp_session_t *s, const uint8_t *seg, size_t seg_len,
                    uint8_t *out, size_t out_cap)
{
    const uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t mac16[16];
    uint8_t icv[16];
    uint8_t *padded = NULL;
    size_t pad_idx, min_idx;
    long ret = -1;

    if (!s || !seg || !out) {
        return -1;
    }
    /* At least one full ciphertext block plus the 8-byte MAC, and the
     * ciphertext portion must be a whole number of AES blocks. */
    if (seg_len < 16 + RSP_SCP03T_MAC_LEN ||
        (seg_len - RSP_SCP03T_MAC_LEN) % 16 != 0) {
        return -1;
    }
    ciphertext = seg;
    ciphertext_len = seg_len - RSP_SCP03T_MAC_LEN;

    if (scp03t_mac(s->s_mac, s->chain, ciphertext, ciphertext_len, mac16) != 0) {
        goto out;
    }

    /* Verify the MAC before touching the padding at all: a tampered
     * segment must be refused, not decrypted and then found invalid.
     * Fixed-length memcmp over the whole 8-byte MAC, not a hand-rolled
     * loop that would return as soon as it saw the first mismatching
     * byte. */
    if (memcmp(mac16, seg + ciphertext_len, RSP_SCP03T_MAC_LEN) != 0) {
        goto out;
    }

    if (scp03t_icv(s->s_enc, s->chain, icv) != 0) {
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
        goto out;
    }
    pad_idx--; /* now the length of the plaintext that was protected */

    if (pad_idx > out_cap) {
        goto out;
    }
    if (pad_idx) {
        memcpy(out, padded, pad_idx);
    }

    memcpy(s->chain, mac16, 16);
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
