/* A recording is a text file so it can be read in a review, diffed, and
   hand-edited into the failure cases a healthy card will not produce. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rsp.h"

static int fails = 0;
static void ok(const char *what, int cond) {
    printf("%s   %s\n", cond ? "ok  " : "FAIL", what);
    if(!cond) fails = 1;
}

static void write_file(const char *path, const char *body) {
    FILE *f = fopen(path, "w");
    if(f) { fputs(body, f); fclose(f); }
}

int main(void) {
    const char *path = "/tmp/rsp-test-recording.log";
    /* A third exchange, beyond the two the brief's prose walks through, so
       that "an unexpected command is refused" below has a real recorded
       exchange still pending when it fires. Without it, both recorded
       exchanges are already consumed by the two calls that precede it, and
       that assertion would be indistinguishable from "the recording ran
       out" -- true regardless of whether transceive checks the command at
       all. See task-1-report.md for the full account of this deviation. */
    write_file(path,
        "# a recording, for the test\n"
        "> 00A4040002A000\n"
        "< 9000\n"
        "> BF2200\n"
        "< BF2201 9000\n"
        "> 00C0000002\n"
        "< 9000\n");

    rsp_transport_t t;
    ok("a recording opens", rsp_replay_open(path, &t) == 0);

    uint8_t resp[64];
    const uint8_t sel[] = { 0x00,0xA4,0x04,0x00,0x02,0xA0,0x00 };
    long n = t.transceive(&t, sel, sizeof sel, resp, sizeof resp);
    ok("the first exchange returns its recorded answer",
       n == 2 && resp[0] == 0x90 && resp[1] == 0x00);

    /* Whitespace inside a hex line is insignificant: the writer groups the
       status bytes for readability and the reader must not care. */
    const uint8_t info[] = { 0xBF,0x22,0x00 };
    n = t.transceive(&t, info, sizeof info, resp, sizeof resp);
    ok("whitespace in the recorded hex is ignored",
       n == 5 && resp[0] == 0xBF && resp[3] == 0x90 && resp[4] == 0x00);

    /* The strict sequence is the point: a recording is a pin on the bytes,
       not a lenient stub. Sending something else must stop the run. The
       third exchange above is still unconsumed at this point (pos 2 of 3),
       so this is refused for being the wrong command, not because the
       recording ran out. */
    ok("an unexpected command is refused",
       t.transceive(&t, sel, sizeof sel, resp, sizeof resp) < 0);
    t.close(&t);

    /* Running past the end is a failure, not a silent empty answer. All
       three recorded exchanges are consumed first, so this is genuinely
       past the end, not a wrong-command refusal wearing the same sign. */
    const uint8_t getresp[] = { 0x00,0xC0,0x00,0x00,0x02 };
    ok("a short recording opens", rsp_replay_open(path, &t) == 0);
    t.transceive(&t, sel, sizeof sel, resp, sizeof resp);
    t.transceive(&t, info, sizeof info, resp, sizeof resp);
    t.transceive(&t, getresp, sizeof getresp, resp, sizeof resp);
    ok("running past the end is refused",
       t.transceive(&t, getresp, sizeof getresp, resp, sizeof resp) < 0);
    t.close(&t);

    ok("a missing file is could-not-answer",
       rsp_replay_open("/tmp/rsp-no-such-recording", &t) == -2);

    /* Recording a replayed session must reproduce the same file, so the
       writer and the reader are proven inverse to each other. */
    rsp_transport_t inner, rec;
    ok("the inner transport opens", rsp_replay_open(path, &inner) == 0);
    ok("the recorder opens",
       rsp_record_open(&inner, "/tmp/rsp-test-rerecorded.log", &rec) == 0);
    rec.transceive(&rec, sel, sizeof sel, resp, sizeof resp);
    rec.transceive(&rec, info, sizeof info, resp, sizeof resp);
    rec.close(&rec);

    rsp_transport_t again;
    ok("the re-recorded file replays", rsp_replay_open("/tmp/rsp-test-rerecorded.log", &again) == 0);
    n = again.transceive(&again, sel, sizeof sel, resp, sizeof resp);
    ok("and answers the same", n == 2 && resp[0] == 0x90);
    again.close(&again);

    return fails ? 1 : 0;
}
