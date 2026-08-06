/* The real card. Not part of `make check`: it needs a reader, and a test
 * that silently passes when the hardware is absent is worse than no test.
 * Run it with `make check-card`. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsp.h"

int main(void) {
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

    rsp_card_info_t info;
    memset(&info, 0, sizeof info);
    rc = rsp_card_read_info(&t, &info);
    if(rc != 0) { fprintf(stderr, "cannot read the card: %d\n", rc); t.close(&t); return rc == -1 ? 1 : 2; }

    printf("ok   the card answered\n");
    printf("     EID  ");
    for(int i = 0; i < 16; i++) printf("%02X", info.eid[i]);
    printf("\n     SVN  %s\n     issuers %zu\n", info.svn, info.ci_count);

    rsp_card_info_free(&info);
    t.close(&t);
    return 0;
}
