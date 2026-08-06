/*
 * rsp_transport.c -- the transport interface (rsp_transport_t) and its two
 * built-in implementations: a replay transport that answers from a text
 * recording, and a recorder that wraps any other transport and writes one
 * down as it runs.
 *
 * The command layer above this (later tasks) sends and receives APDUs
 * through rsp_transport_t alone; it never knows whether the far end is a
 * physical reader or a file. That split is what lets the same command path
 * run in CI with no hardware attached.
 *
 * The recording format is deliberately plain text, not a binary capture:
 * a line beginning "> " is a command APDU in hex, a line beginning "< " is
 * the response including its two trailing status bytes, "#" and blank
 * lines are comments, and whitespace inside a hex line is insignificant.
 * That is what lets a recording be read in a code review, diffed
 * meaningfully, and hand-edited into the failure cases a healthy card will
 * not itself produce (a wrong status word, a truncated response, a
 * reordered exchange).
 *
 * The whole file is parsed at rsp_replay_open into a fixed array of
 * exchanges; nothing under transceive() allocates. A transport that could
 * fail to answer for a reason unrelated to the card (an allocation failing
 * mid-replay) would defeat the point of replaying at all.
 *
 * Nothing in a recording is treated as secret in this round -- see
 * testdata/cards/README.md -- so mismatches are reported on stderr with
 * both the expected and the received bytes, and no buffer here is wiped.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsp.h"

/* ---- shared hex helpers ------------------------------------------------ */

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes the hex digits in s (whitespace between them is skipped, per the
 * format's own rule) into a freshly malloc'ed buffer. Returns 0, or -1 if
 * s holds anything other than whitespace and hex digits, an odd number of
 * digits, or the allocation fails. A zero-digit line decodes to a valid,
 * zero-length buffer (out set to a one-byte allocation, *out_len 0) rather
 * than NULL, so the caller can always free() it uniformly. */
static int parse_hexline(const char *s, uint8_t **out, size_t *out_len)
{
    size_t ndigits = 0;
    for (const char *p = s; *p; p++) {
        if (isspace((unsigned char)*p)) continue;
        if (hex_digit(*p) < 0) return -1;
        ndigits++;
    }
    if (ndigits % 2 != 0) return -1;

    size_t n = ndigits / 2;
    uint8_t *buf = malloc(n ? n : 1);
    if (!buf) return -1;

    size_t bi = 0;
    int hi = -1;
    for (const char *p = s; *p; p++) {
        if (isspace((unsigned char)*p)) continue;
        int v = hex_digit(*p);
        if (hi < 0) {
            hi = v;
        } else {
            buf[bi++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    *out = buf;
    *out_len = n;
    return 0;
}

static void print_hex(FILE *f, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%02X", b[i]);
    }
}

/* ---- replay ------------------------------------------------------------- */

typedef struct {
    uint8_t *cmd;
    size_t   cmd_len;
    uint8_t *resp;
    size_t   resp_len;
} rsp_exchange_t;

typedef struct {
    rsp_exchange_t *ex;
    size_t n;
    size_t pos;   /* index of the next exchange transceive() must match */
} rsp_replay_state_t;

static void free_exchanges(rsp_exchange_t *ex, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free(ex[i].cmd);
        free(ex[i].resp);
    }
    free(ex);
}

static long replay_transceive(rsp_transport_t *t, const uint8_t *cmd,
                              size_t cmd_len, uint8_t *resp, size_t resp_cap)
{
    rsp_replay_state_t *st = t->ctx;

    if (st->pos >= st->n) {
        fprintf(stderr,
            "rsp_replay: no recorded exchange left to answer command %zu "
            "(the recording has %zu)\n", st->pos, st->n);
        return -1;
    }

    rsp_exchange_t *e = &st->ex[st->pos];
    if (e->cmd_len != cmd_len || memcmp(e->cmd, cmd, cmd_len) != 0) {
        fprintf(stderr, "rsp_replay: exchange %zu: command does not match "
                         "the recording\n", st->pos);
        fprintf(stderr, "  expected: ");
        print_hex(stderr, e->cmd, e->cmd_len);
        fprintf(stderr, "\n  received: ");
        print_hex(stderr, cmd, cmd_len);
        fprintf(stderr, "\n");
        return -1;
    }

    if (e->resp_len > resp_cap) {
        fprintf(stderr, "rsp_replay: exchange %zu: recorded response is "
                         "%zu bytes, resp_cap is only %zu\n",
                st->pos, e->resp_len, resp_cap);
        return -1;
    }

    memcpy(resp, e->resp, e->resp_len);
    st->pos++;
    return (long)e->resp_len;
}

static void replay_close(rsp_transport_t *t)
{
    rsp_replay_state_t *st = t->ctx;
    if (!st) return;
    free_exchanges(st->ex, st->n);
    free(st);
    t->ctx = NULL;
}

int rsp_replay_open(const char *path, rsp_transport_t *out)
{
    if (!path || !out) return -2;

    FILE *f = fopen(path, "r");
    if (!f) return -2;

    rsp_exchange_t *ex = NULL;
    size_t n = 0, cap = 0;

    uint8_t *pending_cmd = NULL;
    size_t pending_cmd_len = 0;
    int have_cmd = 0;

    char *line = NULL;
    size_t linecap = 0;
    ssize_t got;
    int malformed = 0;

    while (!malformed && (got = getline(&line, &linecap, f)) != -1) {
        size_t len = (size_t)got;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        if (len == 0 || line[0] == '#') {
            continue; /* blank or comment */
        }

        if (len >= 2 && line[0] == '>' && line[1] == ' ') {
            if (have_cmd) {
                fprintf(stderr, "rsp_replay_open: %s: two commands in a row "
                                 "with no response between them\n", path);
                malformed = 1;
                break;
            }
            if (parse_hexline(line + 2, &pending_cmd, &pending_cmd_len) != 0) {
                fprintf(stderr, "rsp_replay_open: %s: unparseable command "
                                 "line: %s\n", path, line);
                malformed = 1;
                break;
            }
            have_cmd = 1;
        } else if (len >= 2 && line[0] == '<' && line[1] == ' ') {
            if (!have_cmd) {
                fprintf(stderr, "rsp_replay_open: %s: a response with no "
                                 "command before it\n", path);
                malformed = 1;
                break;
            }
            uint8_t *resp;
            size_t resp_len;
            if (parse_hexline(line + 2, &resp, &resp_len) != 0) {
                fprintf(stderr, "rsp_replay_open: %s: unparseable response "
                                 "line: %s\n", path, line);
                free(pending_cmd);
                malformed = 1;
                break;
            }
            if (n == cap) {
                size_t newcap = cap ? cap * 2 : 8;
                rsp_exchange_t *p = realloc(ex, newcap * sizeof *ex);
                if (!p) {
                    free(pending_cmd);
                    free(resp);
                    malformed = 1;
                    break;
                }
                ex = p;
                cap = newcap;
            }
            ex[n].cmd = pending_cmd;
            ex[n].cmd_len = pending_cmd_len;
            ex[n].resp = resp;
            ex[n].resp_len = resp_len;
            n++;
            pending_cmd = NULL;
            have_cmd = 0;
        } else {
            fprintf(stderr, "rsp_replay_open: %s: a line is neither a "
                             "comment nor \"> \"/\"< \": %s\n", path, line);
            malformed = 1;
        }
    }
    free(line);
    fclose(f);

    if (!malformed && have_cmd) {
        fprintf(stderr, "rsp_replay_open: %s: a trailing command has no "
                         "response\n", path);
        free(pending_cmd);
        malformed = 1;
    }

    if (malformed) {
        free_exchanges(ex, n);
        return -2;
    }

    rsp_replay_state_t *st = malloc(sizeof *st);
    if (!st) {
        free_exchanges(ex, n);
        return -2;
    }
    st->ex = ex;
    st->n = n;
    st->pos = 0;

    out->transceive = replay_transceive;
    out->close = replay_close;
    out->ctx = st;
    return 0;
}

/* ---- record -------------------------------------------------------------
 *
 * Wraps any transport: forward the call, then append what happened to the
 * file in the same format rsp_replay_open reads, so recording a replayed
 * session and replaying the result again reproduces the original. */

typedef struct {
    rsp_transport_t inner;
    FILE *f;
} rsp_record_state_t;

static long record_transceive(rsp_transport_t *t, const uint8_t *cmd,
                              size_t cmd_len, uint8_t *resp, size_t resp_cap)
{
    rsp_record_state_t *st = t->ctx;

    long n = st->inner.transceive(&st->inner, cmd, cmd_len, resp, resp_cap);

    fprintf(st->f, "> ");
    print_hex(st->f, cmd, cmd_len);
    fprintf(st->f, "\n< ");
    if (n > 0) {
        print_hex(st->f, resp, (size_t)n);
    }
    fprintf(st->f, "\n");
    fflush(st->f);

    return n;
}

static void record_close(rsp_transport_t *t)
{
    rsp_record_state_t *st = t->ctx;
    if (!st) return;
    if (st->f) {
        fclose(st->f);
    }
    if (st->inner.close) {
        st->inner.close(&st->inner);
    }
    free(st);
    t->ctx = NULL;
}

int rsp_record_open(rsp_transport_t *inner, const char *path,
                    rsp_transport_t *out)
{
    if (!inner || !path || !out) return -2;

    FILE *f = fopen(path, "w");
    if (!f) return -2;

    rsp_record_state_t *st = malloc(sizeof *st);
    if (!st) {
        fclose(f);
        return -2;
    }
    st->inner = *inner;
    st->f = f;

    out->transceive = record_transceive;
    out->close = record_close;
    out->ctx = st;
    return 0;
}
