/* The commands, end to end against a recording: select, EUICCInfo2, EID.
   The response DER here was produced with the generated encoder, not written
   by hand -- see testdata/cards/README.md for the command that makes it. */
#include <stdio.h>
#include <string.h>
#include "rsp.h"

static int fails = 0;
static void ok(const char *what, int cond) {
    printf("%s   %s\n", cond ? "ok  " : "FAIL", what);
    if(!cond) fails = 1;
}

int main(void) {
    rsp_transport_t t;
    ok("the recording opens",
       rsp_replay_open("testdata/cards/synthetic-info.log", &t) == 0);

    rsp_card_info_t info;
    memset(&info, 0, sizeof info);
    ok("the card is read", rsp_card_read_info(&t, &info) == 0);
    ok("the EID arrived", info.have_eid);
    ok("the version is parsed", strcmp(info.svn, "2.2.0") == 0);
    ok("at least one issuer is listed", info.ci_count >= 1);

    /* The identifier the recording carries must be recognised, and one that
       differs in a single byte must not be. */
    uint8_t known[20]; memcpy(known, info.ci_ids, info.ci_id_len);
    ok("a listed issuer is trusted",
       rsp_card_trusts(&info, known, info.ci_id_len) == 1);
    known[0] ^= 0xFF;
    ok("an unlisted issuer is not trusted",
       rsp_card_trusts(&info, known, info.ci_id_len) == 0);

    rsp_card_info_free(&info);
    t.close(&t);
    return fails ? 1 : 0;
}
