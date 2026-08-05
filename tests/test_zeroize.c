/* Verifies that rsp_session_init and rsp_credential_free leave no copy of
   the secret material they touch on the stack once they return. A memset
   on a local that is never read again and never escapes is a dead store
   at -O2 -- the compiler is entitled to remove it, and on this project's
   own build it did: reading the generated assembly showed no wipe
   instruction on the success path, and a probe like this one found the
   session's chain, S-ENC and S-MAC values still sitting in stack memory
   after rsp_session_init had already returned. That is exactly the
   defect this test exists to catch; it is what found the bug in the
   first place, kept here so the same defect cannot come back unnoticed.

   Reading stack memory below the current frame is not standard C, and
   this test relies on it anyway: it is the only way to see what a wipe
   left behind rather than trust that source code implies compiled
   behavior. It is deliberately narrow -- a bounded window, read
   immediately after the call, with no other call permitted in between,
   using __builtin_frame_address (supported by both GCC and Clang, the
   two compilers this project is built with). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "rsp.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if (!good) fails++;
}

static size_t hexline(FILE *f, uint8_t *out, size_t cap) {
    char line[300];
    if (!fgets(line, sizeof line, f)) return 0;
    size_t n = strspn(line, "0123456789abcdefABCDEF") / 2;
    if (n > cap) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(line + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return n;
}

/* A window of stack memory below this frame, generous enough to cover
   every frame rsp_session_init's call chain used (measured: mbedTLS's
   entropy + CTR-DRBG contexts alone are over 1KB; this leaves a wide
   margin). noinline keeps this a real, separate frame rather than
   something the caller's own frame could be folded into. */
#define WINDOW 8192

/* Copies that window into a heap buffer and scans the copy, rather than
   scanning the stack memory directly: window used to be a same-size
   array in this function's own frame, at [fp - WINDOW, fp) -- exactly
   the range being read -- so the copy's source and destination
   overlapped (this frame's own locals, including window, live inside
   that range). memcpy's behaviour on overlapping regions is undefined,
   and it is not merely academic here: ASan's memcpy-param-overlap check
   catches it and aborts, which means this test could not be run under a
   sanitizer at all. A heap buffer for the destination has no address in
   common with the stack range being read, so the copy is no longer
   overlapping while the property under test -- what is actually sitting
   in the stack memory below this frame -- is unchanged. */
static int __attribute__((noinline)) count_in_window(const uint8_t *needle, size_t needle_len)
{
    uint8_t *window = malloc(WINDOW);
    uint8_t *fp = (uint8_t *)__builtin_frame_address(0);
    int n = 0;
    size_t i;

    if (!window) {
        return -1;
    }
    memcpy(window, fp - WINDOW, WINDOW);
    for (i = 0; i + needle_len <= WINDOW; i++) {
        if (memcmp(window + i, needle, needle_len) == 0) {
            n++;
        }
    }
    free(window);
    return n;
}

/* Sibling call to count_in_window, called from main at the same depth,
   so the two share the same stack address range: this one's callees
   (rsp_session_init and everything under it) leave their frame content
   at the addresses count_in_window will read moments later. */
static int __attribute__((noinline)) run_session(
    const uint8_t *sk, const uint8_t *pk, const uint8_t *info, size_t info_len,
    rsp_session_t *out)
{
    return rsp_session_init(sk, pk, info, info_len, out);
}

static int __attribute__((noinline)) run_credential_free(rsp_credential_t *c)
{
    rsp_credential_free(c);
    return 0;
}

int main(void)
{
    uint8_t sk[32], pk[65];
    static const uint8_t info[] = { 0x00, 0x00, 0x00, 0x01 };
    rsp_session_t session;
    uint8_t chain[16], s_enc[16], s_mac[16];
    int init_rc, n_chain, n_enc, n_mac;

    FILE *f = fopen("testdata/nist/ecdh-p256.txt", "r");
    ok("the vector file is readable", f != NULL);
    if (!f) return 1;
    {
        uint8_t want[32];
        ok("the vector holds three values of the right length",
           hexline(f, sk, sizeof sk) == 32
           && hexline(f, pk, sizeof pk) == 65
           && hexline(f, want, sizeof want) == 32);
    }
    fclose(f);

    /* Nothing but the call itself between run_session returning and the
       three count_in_window scans: any printf or other call here would
       overwrite the very stack memory being inspected with its own
       frame, and the test would find "0 copies" whether or not the
       library actually wiped anything -- a false pass that proves
       nothing. */
    init_rc = run_session(sk, pk, info, sizeof info, &session);
    memcpy(chain, session.chain, sizeof chain);
    memcpy(s_enc, session.s_enc, sizeof s_enc);
    memcpy(s_mac, session.s_mac, sizeof s_mac);
    n_chain = count_in_window(chain, sizeof chain);
    n_enc   = count_in_window(s_enc, sizeof s_enc);
    n_mac   = count_in_window(s_mac, sizeof s_mac);

    /* Counts, not key bytes: how many times each 16-byte value was
       found in the window, for a reader debugging a future failure. */
    fprintf(stderr, "wipe probe: chain copies=%d s_enc copies=%d s_mac copies=%d\n",
            n_chain, n_enc, n_mac);

    ok("session derivation for the wipe probe succeeds", init_rc == 0);
    ok("no copy of the chaining value survives on the stack after rsp_session_init",
       n_chain == 0);
    ok("no copy of S-ENC survives on the stack after rsp_session_init",
       n_enc == 0);
    ok("no copy of S-MAC survives on the stack after rsp_session_init",
       n_mac == 0);

    rsp_session_wipe(&session);
    {
        rsp_session_t zero;
        memset(&zero, 0, sizeof zero);
        ok("rsp_session_wipe zeroes the session struct",
           memcmp(&session, &zero, sizeof zero) == 0);
    }

    /* Same technique against rsp_credential_free's private-key wipe
       (src/rsp_pki.c), which has the identical dead-store pattern. */
    {
        rsp_credential_t cred;
        uint8_t sk_copy[32];
        int n_sk;

        ok("DPauth loads for the wipe probe", rsp_pki_dp(0, &cred) == 0);
        memcpy(sk_copy, cred.sk, sizeof sk_copy);

        run_credential_free(&cred);
        n_sk = count_in_window(sk_copy, sizeof sk_copy);
        ok("no copy of the DPauth private key survives on the stack after rsp_credential_free",
           n_sk == 0);
    }

    return fails ? 1 : 0;
}
