/* Chaining is where card drivers fail, so it is tested in both directions
   before anything talks to hardware. These recordings are synthetic: they
   prove the logic, not the fidelity. Task 5 adds a real capture.

   The command line in every recording below is the real STORE DATA APDU
   for req = { 0xBF, 0x22, 0x00 } (3 bytes, one block, so P1 is always
   "last block"): CLA '80' (SGP.22 v2.6 section 5.7.2 Table 47's range is
   '80'-'83' or 'C0'-'CF'; this library always uses channel 0, no secure
   messaging -- GPCS section 11.1.4.1), INS 'E2' (STORE DATA), P1 '91'
   (Table 48: b8=1 "last block", plus the fixed bits for "no general
   encryption info", "BER-TLV", "ISO case 4"), P2 '00' (the first and only
   block), Lc '03', the 3 data bytes, Le '00'. See src/rsp_es10.c's
   top-of-file comment for the full citation trail. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsp.h"

static int fails = 0;
static void ok(const char *what, int cond) {
    printf("%s   %s\n", cond ? "ok  " : "FAIL", what);
    if(!cond) fails = 1;
}

static void write_file(const char *path, const char *body) {
    FILE *f = fopen(path, "w"); if(f) { fputs(body, f); fclose(f); }
}

int main(void) {
    /* A short request and a short answer: no chaining either way. */
    const char *simple = "/tmp/rsp-apdu-simple.log";
    write_file(simple,
        "> 80E2910003BF220000\n"
        "< BF220102 9000\n");

    rsp_transport_t t;
    ok("the simple recording opens", rsp_replay_open(simple, &t) == 0);

    const uint8_t req[] = { 0xBF, 0x22, 0x00 };
    uint8_t *out = NULL; size_t out_len = 0; unsigned sw = 0;
    ok("a short exchange succeeds",
       rsp_es10_send(&t, req, sizeof req, &out, &out_len, &sw) == 0);
    ok("the status bytes are stripped from the answer", out_len == 4);
    ok("the answer is the response DER",
       out && out[0] == 0xBF && out[1] == 0x22);
    free(out); out = NULL;
    t.close(&t);

    /* A long answer: the card reports 61xx and the rest arrives through
       GET RESPONSE. The driver must join the parts and strip both
       statuses. The TLV declares a 6-byte value (BF 22 06 ...) but only 3
       of those 6 bytes are in this response; 61 03 says 3 more are
       waiting. GET RESPONSE (CLA '00', INS 'C0', ISO/IEC 7816-4, per
       SGP.22 v2.6 section 5.7.2 / GPCS section 11.1.5.2) asks for exactly
       those 3 (Le '03') and gets them, followed by 9000. The joined
       answer is the tag+length (2) plus all 6 value bytes: 8 bytes. */
    const char *chained = "/tmp/rsp-apdu-chained.log";
    write_file(chained,
        "> 80E2910003BF220000\n"
        "< BF22 06 010203 6103\n"
        "> 00C0000003\n"
        "< 040506 9000\n");
    ok("the chained recording opens", rsp_replay_open(chained, &t) == 0);
    ok("a chained answer succeeds",
       rsp_es10_send(&t, req, sizeof req, &out, &out_len, &sw) == 0);
    ok("the parts are joined in order",
       out_len == 9 && out[5] == 0x03 && out[6] == 0x04 && out[8] == 0x06);
    free(out); out = NULL;
    t.close(&t);

    /* A status the driver cannot use is a real negative answer, and the
       caller must be able to see which one it was. */
    const char *refused = "/tmp/rsp-apdu-refused.log";
    write_file(refused,
        "> 80E2910003BF220000\n"
        "< 6A82\n");
    ok("the refusal recording opens", rsp_replay_open(refused, &t) == 0);
    ok("a refusal is a real negative answer",
       rsp_es10_send(&t, req, sizeof req, &out, &out_len, &sw) == -1);
    ok("and the status word is reported", sw == 0x6A82);
    ok("and nothing is handed back", out == NULL);
    t.close(&t);

    /* A truncated chain: the card promises more and the exchange ends.
       This must fail, not return the part that did arrive. */
    const char *truncated = "/tmp/rsp-apdu-truncated.log";
    write_file(truncated,
        "> 80E2910003BF220000\n"
        "< BF22 06 010203 6103\n");
    ok("the truncated recording opens", rsp_replay_open(truncated, &t) == 0);
    ok("a truncated chain fails rather than returning a fragment",
       rsp_es10_send(&t, req, sizeof req, &out, &out_len, &sw) < 0);
    ok("and still hands nothing back", out == NULL);
    t.close(&t);

    return fails ? 1 : 0;
}
