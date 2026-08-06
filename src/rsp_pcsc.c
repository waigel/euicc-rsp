/*
 * rsp_pcsc.c -- the transport that carries bytes to actual hardware, PC/SC.
 *
 * PC/SC (PC/Smart Card, the interface both macOS and Linux expose under the
 * same function names, winscard.h) is the one place in this library that
 * touches a card reader instead of a recording. It implements the same
 * rsp_transport_t the replay transport (src/rsp_transport.c) does, and
 * nothing above this file -- rsp_es10_send, rsp_card_read_info, the command
 * layer later tasks build -- can tell the two apart.
 *
 * macOS ships PC/SC as a framework: <PCSC/winscard.h> and <PCSC/wintypes.h>,
 * linked with -framework PCSC. Linux has no PC/SC of its own; pcsc-lite is
 * the interface's reference implementation there, and its single header is
 * plain <winscard.h> (it already pulls in pcsclite.h, which is where
 * wintypes.h's macOS split lives on that side). The two are not textually
 * identical, but they define the same names -- SCARDCONTEXT, SCardConnect,
 * SCARD_PCI_T0, and so on -- so everything past this #if is written once.
 *
 * PC/SC's own functions return a signed LONG; every nonzero value is a
 * failure and SCARD_S_SUCCESS (0) is the only success. This file only ever
 * surfaces two of the numbers rsp.h defines: 0 for done, and -2 for "the
 * exchange could not happen" -- transceive's own -1 ("the card answered
 * something unusable") is reserved for an answer that arrived and made no
 * sense, which is not something PC/SC's return code, only the response
 * bytes, could ever tell us. Every failure here also prints a sentence:
 * pcsc_stringify_error's own text for the ones this file has no more to
 * say about, and a hand-written one for the three failures a person
 * actually hits -- no reader attached, a reader with an empty tray, and
 * another process already holding the card (SCARD_E_SHARING_VIOLATION),
 * which on macOS is almost always the system's own card services, not
 * this program's fault at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

#include "rsp.h"

typedef struct {
    SCARDCONTEXT ctx;
    SCARDHANDLE  card;
    DWORD        protocol;   /* SCARD_PROTOCOL_T0 or _T1, whichever SCardConnect settled on */
} rsp_pcsc_state_t;

/* SCardListReaders' own multi-string: names separated by one NUL, the
 * whole list terminated by a second (an empty final name). Walked the
 * same way in rsp_pcsc_readers, rsp_pcsc_open below and tests/test_card.c.
 *
 * Called with ctx already established. *out is malloc'ed and always set
 * on success -- to a one-byte "\0" when no reader is attached, not left
 * NULL, so the caller can always free() it uniformly. Returns the count
 * of names, or -2 with a message on stderr. */
static long pcsc_list(SCARDCONTEXT ctx, char **out)
{
    *out = NULL;

    DWORD needed = 0;
    LONG rv = SCardListReaders(ctx, NULL, NULL, &needed);
    if (rv == (LONG)SCARD_E_NO_READERS_AVAILABLE || (rv == SCARD_S_SUCCESS && needed == 0)) {
        char *empty = malloc(1);
        if (!empty) return -2;
        empty[0] = '\0';
        *out = empty;
        return 0;
    }
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "rsp_pcsc: cannot list readers: %s\n", pcsc_stringify_error(rv));
        return -2;
    }

    char *buf = malloc(needed);
    if (!buf) return -2;

    DWORD got = needed;
    rv = SCardListReaders(ctx, NULL, buf, &got);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "rsp_pcsc: cannot list readers: %s\n", pcsc_stringify_error(rv));
        free(buf);
        return -2;
    }

    long count = 0;
    for (const char *p = buf; *p; p += strlen(p) + 1) count++;
    *out = buf;
    return count;
}

long rsp_pcsc_readers(char **out)
{
    if (!out) return -2;
    *out = NULL;

    SCARDCONTEXT ctx;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "rsp_pcsc: cannot reach the system's smart card "
                         "service: %s\n", pcsc_stringify_error(rv));
        return -2;
    }

    long n = pcsc_list(ctx, out);
    SCardReleaseContext(ctx);
    return n;
}

static long pcsc_transceive(rsp_transport_t *t, const uint8_t *cmd,
                            size_t cmd_len, uint8_t *resp, size_t resp_cap)
{
    rsp_pcsc_state_t *st = t->ctx;
    if (!st || !cmd || !resp) return -2;
    /* DWORD is 32 bits; no caller of this library ever builds a command
     * or a response buffer anywhere near that size, but a silent
     * truncation of cmd_len on the way into SCardTransmit would be worse
     * than refusing outright. */
    if (cmd_len > 0xFFFFFFFFu || resp_cap > 0xFFFFFFFFu) return -2;

    LPCSCARD_IO_REQUEST pci = (st->protocol == SCARD_PROTOCOL_T1) ? SCARD_PCI_T1 : SCARD_PCI_T0;

    DWORD recv_len = (DWORD)resp_cap;
    LONG rv = SCardTransmit(st->card, pci, cmd, (DWORD)cmd_len, NULL, resp, &recv_len);
    if (rv != SCARD_S_SUCCESS) {
        if (rv == (LONG)SCARD_W_REMOVED_CARD) {
            fprintf(stderr, "rsp_pcsc: the card was removed mid-exchange\n");
        } else if (rv == (LONG)SCARD_E_NO_SMARTCARD) {
            fprintf(stderr, "rsp_pcsc: the reader is there, but the card in "
                             "it is gone\n");
        } else if (rv == (LONG)SCARD_E_SHARING_VIOLATION) {
            fprintf(stderr, "rsp_pcsc: another process holds the card; on "
                             "macOS this is usually the system's own card "
                             "services\n");
        } else {
            fprintf(stderr, "rsp_pcsc: the exchange failed: %s\n", pcsc_stringify_error(rv));
        }
        return -2;
    }

    /* An APDU response always carries its two status bytes; anything
     * shorter is not a response this transport can hand back as one --
     * rsp.h's -1, an answer that arrived but made no sense, not this
     * function's -2. */
    if (recv_len < 2) return -1;
    return (long)recv_len;
}

static void pcsc_close(rsp_transport_t *t)
{
    rsp_pcsc_state_t *st = t->ctx;
    if (!st) return;
    SCardDisconnect(st->card, SCARD_LEAVE_CARD);
    SCardReleaseContext(st->ctx);
    free(st);
    t->ctx = NULL;
}

int rsp_pcsc_open(const char *reader, rsp_transport_t *out)
{
    if (!out) return -2;

    SCARDCONTEXT ctx;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "rsp_pcsc: cannot reach the system's smart card "
                         "service: %s\n", pcsc_stringify_error(rv));
        return -2;
    }

    char *list = NULL;
    const char *use = reader;
    if (!use) {
        long n = pcsc_list(ctx, &list);
        if (n < 0) {
            SCardReleaseContext(ctx);
            return -2;
        }
        if (n == 0) {
            fprintf(stderr, "rsp_pcsc: no reader is attached\n");
            free(list);
            SCardReleaseContext(ctx);
            return -2;
        }
        if (n > 1) {
            fprintf(stderr, "rsp_pcsc: more than one reader is attached; "
                             "name the one to use\n");
            free(list);
            SCardReleaseContext(ctx);
            return -2;
        }
        use = list;   /* the sole name, NUL-terminated */
    }

    SCARDHANDLE card;
    DWORD active_protocol = 0;
    rv = SCardConnect(ctx, use, SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                      &card, &active_protocol);
    free(list);

    if (rv != SCARD_S_SUCCESS) {
        if (rv == (LONG)SCARD_E_NO_SMARTCARD) {
            fprintf(stderr, "rsp_pcsc: the reader is there, but no card is "
                             "in it\n");
        } else if (rv == (LONG)SCARD_E_SHARING_VIOLATION) {
            fprintf(stderr, "rsp_pcsc: another process holds the card; on "
                             "macOS this is usually the system's own card "
                             "services -- close whatever else has it open "
                             "and try again\n");
        } else if (rv == (LONG)SCARD_E_UNKNOWN_READER) {
            fprintf(stderr, "rsp_pcsc: no reader by that name is attached\n");
        } else {
            fprintf(stderr, "rsp_pcsc: cannot connect to the card: %s\n", pcsc_stringify_error(rv));
        }
        SCardReleaseContext(ctx);
        return -2;
    }

    rsp_pcsc_state_t *st = malloc(sizeof *st);
    if (!st) {
        SCardDisconnect(card, SCARD_LEAVE_CARD);
        SCardReleaseContext(ctx);
        return -2;
    }
    st->ctx = ctx;
    st->card = card;
    st->protocol = active_protocol;

    out->transceive = pcsc_transceive;
    out->close = pcsc_close;
    out->ctx = st;
    return 0;
}
