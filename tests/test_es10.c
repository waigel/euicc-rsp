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

    /* Fix round 1, finding 3: the id_len check must precede any memcmp,
       so a shorter, longer, or zero-length id -- and specifically a
       genuine PREFIX of a listed identifier, not just any wrong length --
       can never read as trusted. Restore known's first byte first: this
       block asks about known-as-a-listed-issuer's own bytes, truncated or
       extended, not about the flipped-byte value above. */
    known[0] ^= 0xFF;
    ok("known is a listed issuer again, for the length checks below",
       rsp_card_trusts(&info, known, info.ci_id_len) == 1);

    ok("a shorter identifier -- a genuine prefix of a listed one -- is not trusted",
       rsp_card_trusts(&info, known, info.ci_id_len - 1) == 0);

    uint8_t longer[21];
    memcpy(longer, known, info.ci_id_len);
    longer[info.ci_id_len] = 0x00; /* one byte past what any listed id has */
    ok("a longer identifier is not trusted",
       rsp_card_trusts(&info, longer, info.ci_id_len + 1) == 0);

    ok("a zero-length identifier is not trusted",
       rsp_card_trusts(&info, known, 0) == 0);

    /* An eUICC that lists no issuer at all must not crash the check, and
       must not be trusted for anything, including a zero-length id (which
       would otherwise match ci_id_len == 0 on a zeroed struct and reach
       the loop body -- except the loop body never runs when ci_count is
       0, so there is nothing for it to dereference). */
    rsp_card_info_t empty;
    memset(&empty, 0, sizeof empty);
    ok("an eUICC with an empty issuer list trusts nothing",
       rsp_card_trusts(&empty, known, info.ci_id_len) == 0);
    ok("...not even a zero-length id against an empty list",
       rsp_card_trusts(&empty, known, 0) == 0);

    rsp_card_info_free(&info);
    t.close(&t);

    /* Fix round 2, real hardware: this project's own test eUICC answers
       SELECT of the ISD-R with '61 21', ISO/IEC 7816-4 response chaining,
       not a bare '9000' -- and the first version of rsp_card_select_isdr
       treated anything but an exact '9000' as a refusal, so it never got
       past the very first exchange against real hardware. synthetic-info.log
       above now carries exactly that '61xx' shape, copied byte-for-byte
       from a probe against the real card, so "the card is read" already
       exercises the chaining. This second recording pins the other shape
       ISO/IEC 7816-4 also permits -- a SELECT answering 9000 directly,
       with no FCI at all -- so that path stays covered too. */
    rsp_transport_t t2;
    ok("the direct-SELECT recording opens",
       rsp_replay_open("testdata/cards/synthetic-info-direct-select.log", &t2) == 0);
    rsp_card_info_t info2;
    memset(&info2, 0, sizeof info2);
    ok("the card is read when SELECT answers 9000 directly",
       rsp_card_read_info(&t2, &info2) == 0);
    rsp_card_info_free(&info2);
    t2.close(&t2);

    return fails ? 1 : 0;
}
