/*
 * rsp.h -- the SM-DP+ role of SGP.22, as a library.
 *
 * It builds a Bound Profile Package for one eUICC. It does not speak to a
 * card and it opens no socket: the caller supplies what the card said, and
 * gets back what to send. That split is what makes the whole path testable
 * without hardware.
 */
#ifndef RSP_H
#define RSP_H

#include <stddef.h>
#include <stdint.h>

/* The library version, for a bug report. */
const char *rsp_version(void);

#endif /* RSP_H */
