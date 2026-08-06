/*
 * rsp_es10.c -- one ES10 request driven to the ISD-R and the whole answer
 * collected back, chaining outward in blocks and inward through 61xx/GET
 * RESPONSE.
 *
 * SGP.22 v2.6 section 5.7.2 "Transport Command" states: "One generic APDU
 * is used on the interfaces ES10a, ES10b and ES10c to transport all command
 * request and command response data. All functions use the command message
 * STORE DATA as defined in GlobalPlatform Card Specification [8] with the
 * specific coding defined below" (Table 47):
 *
 *     CLA   '80'-'83' or 'C0'-'CF'   (GPCS [8] section 11.1.4)
 *     INS   'E2'                     STORE DATA
 *     P1    '11' or '91'             see Table 48
 *     P2    'xx'                     Block number
 *     Lc    Var.
 *     Data  the DER-encoded ES10 command/response data object
 *     Le    '00'
 *
 * Table 48 gives P1's bits: b8 is "More blocks/Last block" (0/1); the
 * fixed bits below it (b7b6='00' no general encryption info, b5b4='10'
 * BER-TLV data, b1='1' ISO case 4) are the same for every ES10 exchange,
 * so the two P1 values actually used are '11' (more blocks follow) and
 * '91' (this is the last block) -- exactly GPCS's own STORE DATA P1
 * table (section 11.11.2.1, Table 11-89) restricted to those two shapes.
 * P2 is "Block number"; GPCS section 11.11.2.2 pins the concrete rule
 * SGP.22 only names: "coded sequentially from '00' to 'FF'", reset at the
 * start of a session -- SGP.22 v2.6 section 2.5.5 says the same for a BPP
 * segment ("At the beginning of each segment the block number of the
 * STORE DATA commands SHALL be reset"). This code resets it to 0 for
 * every call, since one rsp_es10_send call is exactly one such session.
 *
 * The CLA byte's range leaves room for a logical channel number in its
 * low bits (GPCS section 11.1.4.1, Table 11-11: '80'-'83' is "GlobalPlatform
 * command, no secure messaging", channel 0-3 in b2b1); this library has no
 * notion of a logical channel, so it always uses channel 0, CLA '80'.
 *
 * The maximum block size is not restated in section 5.7.2 itself, but
 * SGP.22 v2.6 section 2.5.5 ("Segmented Bound Profile Package") and
 * section 5.7.6 (LoadBoundProfilePackage) both give it for the same STORE
 * DATA mechanism: "Each segment ... that is up to 255 bytes is transported
 * in one APDU. Larger TLVs are sent in blocks of 255 bytes for the first
 * blocks and a last block that MAY be shorter." This matches GPCS section
 * 11.1.5: "All GlobalPlatform APDU command messages (excluding the APDU
 * header) are limited to 255 bytes in length" -- an Lc that is one byte
 * wide, the short-APDU form Table 47 uses (Lc 'Var.', no extended length
 * anywhere in this clause).
 *
 * For the answer, section 5.7.2 continues: "if the size of the response is
 * bigger than 256 bytes, the chaining of the commands SHALL be done as
 * defined in ISO/IEC 7816-4 [14]. The responses SHALL be retrieved by the
 * Device using several GET RESPONSE commands" -- the same rule GPCS section
 * 11.1.5.2 "Response Chaining" states for any GlobalPlatform command:
 * "the chaining mechanism defined in [ISO 7816-4], using the '61xx' status
 * word and multiple GET RESPONSE commands, should be used." GET RESPONSE's
 * own encoding (CLA '00', INS 'C0', P1 '00', P2 '00', Le = the SW2 that
 * accompanied '61xx') is ISO/IEC 7816-4's, which neither SGP.22 nor GPCS
 * restates; this is the ordinary GET RESPONSE any ISO 7816-4 reader issues
 * after a '61xx' procedure byte.
 *
 * Section 5.7.2's "Processing State Returned in the Response Message"
 * gives the status words that end an exchange successfully: "A successful
 * execution of the APDU command SHALL be indicated by the status bytes
 * '90 00' if no proactive command is pending and by '91 XX' if a proactive
 * command (e.g., REFRESH) is pending." This function's contract (see
 * rsp.h) only treats a bare '90 00' as the terminal success and anything
 * that is not '90 00' or '61xx' as a refusal reported through *sw -- so a
 * '91 XX' (a real, spec-defined success that also signals a pending
 * proactive command) reads as a refusal here. That is narrower than
 * section 5.7.2 allows; deciding what to do about a pending proactive
 * command is left to whichever caller needs it, not this function.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsp.h"

#include "EUICCInfo2.h"
#include "GetEuiccDataResponse.h"

#define ES10_MAX_BLOCK 255u  /* SGP.22 v2.6 section 2.5.5 / 5.7.6 */

#define ES10_CLA     0x80u   /* GPCS section 11.1.4.1: channel 0, no SM */
#define ES10_INS     0xE2u   /* STORE DATA */
#define ES10_P1_MORE 0x11u   /* SGP.22 v2.6 section 5.7.2, Table 48 */
#define ES10_P1_LAST 0x91u

#define GETRESP_CLA 0x00u
#define GETRESP_INS 0xC0u    /* GET RESPONSE, ISO/IEC 7816-4 */

/* Growable output buffer: appends data (n bytes) to *buf, growing *cap as
 * needed and updating *len. Returns 0, or -1 on an allocation failure
 * (the caller frees *buf either way). */
static int es10_append(uint8_t **buf, size_t *len, size_t *cap,
                       const uint8_t *data, size_t n)
{
    if (n == 0) return 0;

    if (*len + n > *cap) {
        size_t newcap = *cap ? *cap * 2 : 64;
        while (newcap < *len + n) newcap *= 2;
        uint8_t *p = realloc(*buf, newcap);
        if (!p) return -1;
        *buf = p;
        *cap = newcap;
    }
    memcpy(*buf + *len, data, n);
    *len += n;
    return 0;
}

int rsp_es10_send(rsp_transport_t *t, const uint8_t *req, size_t req_len,
                  uint8_t **out, size_t *out_len, unsigned *sw)
{
    if (!t || !t->transceive || !out || !out_len || !sw) return -2;

    *out = NULL;
    *out_len = 0;
    *sw = 0;

    uint8_t *acc = NULL;
    size_t acc_len = 0, acc_cap = 0;

    uint8_t cmd[6 + ES10_MAX_BLOCK]; /* CLA,INS,P1,P2,Lc + up to 255 data + Le */
    uint8_t resp[258]; /* up to 256 bytes of data plus the two status bytes */

    size_t sent = 0;
    unsigned block_no = 0;

    for (;;) {
        size_t remain = req_len - sent;
        size_t chunk = remain > ES10_MAX_BLOCK ? ES10_MAX_BLOCK : remain;
        int last = (sent + chunk >= req_len);

        cmd[0] = (uint8_t)ES10_CLA;
        cmd[1] = (uint8_t)ES10_INS;
        cmd[2] = (uint8_t)(last ? ES10_P1_LAST : ES10_P1_MORE);
        cmd[3] = (uint8_t)(block_no & 0xFFu);
        cmd[4] = (uint8_t)chunk;
        if (chunk) memcpy(cmd + 5, req + sent, chunk);
        cmd[5 + chunk] = 0x00; /* Le */

        long n = t->transceive(t, cmd, 5 + chunk + 1, resp, sizeof resp);
        sent += chunk;
        block_no++;

        if (!last) {
            /* An intermediate block carries no response data of its own
             * (GPCS section 11.1.5.1: "a response of '9000' with no
             * additional response data shall be returned" for every
             * command in the sequence but the last); anything else means
             * the exchange cannot continue. */
            if (n < 2) {
                free(acc);
                return -2;
            }
            unsigned isw = (unsigned)((resp[(size_t)n - 2] << 8) |
                                      resp[(size_t)n - 1]);
            if (n != 2 || isw != 0x9000u) {
                free(acc);
                *sw = isw;
                return -1;
            }
            continue;
        }

        /* The last block was just sent: collect the (possibly chained)
         * response that follows it. */
        for (;;) {
            if (n < 2) {
                free(acc);
                return -2;
            }

            unsigned this_sw = (unsigned)((resp[(size_t)n - 2] << 8) |
                                          resp[(size_t)n - 1]);
            size_t data_len = (size_t)n - 2;

            if ((this_sw & 0xFF00u) == 0x6100u) {
                if (es10_append(&acc, &acc_len, &acc_cap, resp, data_len) != 0) {
                    free(acc);
                    return -2;
                }
                uint8_t gr[5] = {
                    (uint8_t)GETRESP_CLA, (uint8_t)GETRESP_INS,
                    0x00, 0x00, (uint8_t)(this_sw & 0xFFu)
                };
                n = t->transceive(t, gr, sizeof gr, resp, sizeof resp);
                continue;
            }

            if (this_sw == 0x9000u) {
                if (es10_append(&acc, &acc_len, &acc_cap, resp, data_len) != 0) {
                    free(acc);
                    return -2;
                }
                *out = acc;
                *out_len = acc_len;
                return 0;
            }

            free(acc);
            *sw = this_sw;
            return -1;
        }
    }
}

/*
 * rsp_card_select_isdr / rsp_card_read_info / rsp_card_info_free /
 * rsp_card_trusts -- the three read-only ES10 commands this round asks of a
 * card, plus the yes/no question the round exists to answer.
 *
 * The ISD-R AID below (A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 01 00) is
 * the one the eUICC card-reading task brief gives; it must be selected
 * before any ES10 STORE DATA exchange, since ES10 commands are ISD-R
 * application commands, not commands the card answers on whatever applet
 * happened to be selected before. SELECT itself is plain ISO/IEC 7816-4
 * (CLA '00', INS 'A4', P1 '04' select-by-name, P2 '00' first-or-only
 * occurrence), not part of SGP.22 or GPCS's STORE DATA mechanism above, so
 * it does not go through rsp_es10_send.
 */

#define ISDR_AID_LEN 16

static const uint8_t isdr_aid[ISDR_AID_LEN] = {
    0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF,
    0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00
};

/* Select the ISD-R. Returns 0, -1 if the card refused (a non-9000 status,
   whatever it carries -- there is no *sw out-parameter here since nothing
   above needs to distinguish one refusal from another for a SELECT), -2 if
   the exchange could not happen at all. */
static int rsp_card_select_isdr(rsp_transport_t *t)
{
    uint8_t cmd[5 + ISDR_AID_LEN + 1];
    uint8_t resp[258];

    cmd[0] = 0x00; /* CLA */
    cmd[1] = 0xA4; /* INS: SELECT */
    cmd[2] = 0x04; /* P1: select by name (DF name / AID) */
    cmd[3] = 0x00; /* P2: first or only occurrence, no FCI return requested */
    cmd[4] = (uint8_t)ISDR_AID_LEN; /* Lc */
    memcpy(cmd + 5, isdr_aid, ISDR_AID_LEN);
    cmd[5 + ISDR_AID_LEN] = 0x00; /* Le */

    long n = t->transceive(t, cmd, sizeof cmd, resp, sizeof resp);
    if (n < 2) return -2;

    unsigned sw = (unsigned)((resp[(size_t)n - 2] << 8) | resp[(size_t)n - 1]);
    if (sw != 0x9000u) return -1;
    return 0;
}

/* Both requests are the fixed, argument-less encodings the brief gives
   directly from rsp-2.5.asn, so they are written out here rather than
   assembled through the generated encoder -- there is nothing for an
   encoder to get wrong about three and six constant bytes. */
static const uint8_t es10_info2_req[] = { 0xBF, 0x22, 0x00 };
static const uint8_t es10_eid_req[]   = { 0xBF, 0x3E, 0x03, 0x5C, 0x01, 0x5A };

int rsp_card_read_info(rsp_transport_t *t, rsp_card_info_t *out)
{
    if (!t || !t->transceive || !out) return -2;
    memset(out, 0, sizeof *out);

    int rc = rsp_card_select_isdr(t);
    if (rc != 0) return rc;

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    unsigned sw = 0;

    rc = rsp_es10_send(t, es10_info2_req, sizeof es10_info2_req,
                       &resp, &resp_len, &sw);
    if (rc != 0) return rc;

    EUICCInfo2_t *info2 = NULL;
    asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_EUICCInfo2, (void **)&info2,
                                   resp, resp_len);
    free(resp);
    if (dr.code != RC_OK) {
        if (info2) ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, info2);
        return -2;
    }

    if (info2->svn.size == 3) {
        snprintf(out->svn, sizeof out->svn, "%u.%u.%u",
                 info2->svn.buf[0], info2->svn.buf[1], info2->svn.buf[2]);
    }

    size_t n = (size_t)info2->euiccCiPKIdListForVerification.list.count;
    if (n > 0) {
        /* rsp_card_info_t's own contract (include/rsp.h) is a single
           ci_id_len for every entry in ci_ids; a card whose list is not
           actually uniform cannot be represented that way, so that shape
           is treated the same as any other answer this function cannot
           make sense of: -2, not a silent truncation to the entries that
           happen to fit. */
        size_t id_len = info2->euiccCiPKIdListForVerification.list.array[0]->size;
        uint8_t *ids = malloc(n * id_len);
        if (!ids) {
            ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, info2);
            return -2;
        }
        int uniform = 1;
        for (size_t i = 0; i < n; i++) {
            SubjectKeyIdentifier_t *ski =
                info2->euiccCiPKIdListForVerification.list.array[i];
            if (ski->size != id_len) { uniform = 0; break; }
            memcpy(ids + i * id_len, ski->buf, id_len);
        }
        if (!uniform) {
            free(ids);
            ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, info2);
            return -2;
        }
        out->ci_ids = ids;
        out->ci_count = n;
        out->ci_id_len = id_len;
    }

    ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, info2);

    resp = NULL;
    resp_len = 0;
    sw = 0;
    rc = rsp_es10_send(t, es10_eid_req, sizeof es10_eid_req,
                       &resp, &resp_len, &sw);
    if (rc != 0) {
        free(out->ci_ids);
        out->ci_ids = NULL;
        out->ci_count = 0;
        out->ci_id_len = 0;
        return rc;
    }

    GetEuiccDataResponse_t *eidresp = NULL;
    dr = ber_decode(NULL, &asn_DEF_GetEuiccDataResponse, (void **)&eidresp,
                    resp, resp_len);
    free(resp);
    if (dr.code != RC_OK || eidresp->eidValue.size != 16) {
        if (eidresp) ASN_STRUCT_FREE(asn_DEF_GetEuiccDataResponse, eidresp);
        free(out->ci_ids);
        out->ci_ids = NULL;
        out->ci_count = 0;
        out->ci_id_len = 0;
        return -2;
    }

    memcpy(out->eid, eidresp->eidValue.buf, 16);
    out->have_eid = 1;
    ASN_STRUCT_FREE(asn_DEF_GetEuiccDataResponse, eidresp);

    return 0;
}

void rsp_card_info_free(rsp_card_info_t *i)
{
    if (!i) return;
    free(i->ci_ids);
    i->ci_ids = NULL;
    i->ci_count = 0;
    i->ci_id_len = 0;
    i->have_eid = 0;
}

int rsp_card_trusts(const rsp_card_info_t *i, const uint8_t *id, size_t id_len)
{
    if (!i || !id || id_len != i->ci_id_len) return 0;

    /* Plain memcmp, not mbedtls_ct_memcmp: both operands are public
       identifiers (a Certificate Issuer's SubjectKeyIdentifier -- the hash
       of a public key, not a secret), and this project's constant-time
       rule exists for comparisons where a timing side channel could leak
       something an attacker should not learn. Nothing compared here is
       secret, so there is nothing for a timing channel to leak. */
    for (size_t k = 0; k < i->ci_count; k++) {
        if (memcmp(i->ci_ids + k * i->ci_id_len, id, id_len) == 0) return 1;
    }
    return 0;
}
