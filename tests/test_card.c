/* The real card. Not part of `make check`: it needs a reader, and a test
 * that silently passes when the hardware is absent is worse than no test.
 * Run it with `make check-card`.
 *
 * An optional first argument names a file: when given, every exchange with
 * the card is also appended to it via rsp_record_open, producing a
 * recording later rounds can replay with no reader attached (Task 5). Plain
 * `make check-card` passes no argument, so the default run neither writes
 * nor depends on one. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsp.h"

int main(int argc, char **argv) {
    char *readers = NULL;
    long n = rsp_pcsc_readers(&readers);
    if(n <= 0) {
        fprintf(stderr, "no reader attached; this test needs one\n");
        return 2;
    }
    printf("readers:\n");
    for(const char *p = readers; *p; p += strlen(p) + 1) printf("  %s\n", p);
    free(readers);

    rsp_transport_t t;
    int rc = rsp_pcsc_open(NULL, &t);
    if(rc != 0) { fprintf(stderr, "cannot open the card: %d\n", rc); return 2; }

    if(argc > 1) {
        /* rsp_record_open takes ownership of t: the pcsc transport passed
           in must not be closed separately afterward (include/rsp.h). */
        rsp_transport_t recorded;
        rc = rsp_record_open(&t, argv[1], &recorded);
        if(rc != 0) {
            fprintf(stderr, "cannot open the recording %s: %d\n", argv[1], rc);
            return 2;
        }
        t = recorded;
    }

    rsp_card_info_t info;
    memset(&info, 0, sizeof info);
    rc = rsp_card_read_info(&t, &info, NULL);
    if(rc != 0) { fprintf(stderr, "cannot read the card: %d\n", rc); t.close(&t); return rc == -1 ? 1 : 2; }

    printf("ok   the card answered\n");
    printf("     EID  ");
    for(int i = 0; i < 16; i++) printf("%02X", info.eid[i]);
    printf("\n     SVN  %s\n     issuers %zu\n", info.svn, info.ci_count);

    rsp_card_info_free(&info);
    t.close(&t);
    return 0;
}
