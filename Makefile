# euicc-rsp -- the SM-DP+ role of SGP.22 as a library.
#
#     make          the library
#     make check    the tests
#     make clean    everything the build produced
#
# asn1c is not vendored here: it is already a submodule of euicc-schema, and
# euicc-tools passes the one it built. Standalone, any asn1c on PATH does.

CC      ?= cc
CFLAGS  ?= -O2 -g
STD     := -std=c99
WARN    := -Wall -Wextra -Wno-unused-parameter \
           -Werror=implicit-function-declaration -Werror=int-conversion

VERSION := 0.1
MBED    := vendor/mbedtls

INC     := -Iinclude -Isrc -I$(MBED)/include
DEF     := -DRSP_VERSION='"$(VERSION)"'
EXTRA   := -D_DEFAULT_SOURCE
ifeq ($(shell uname -s),Darwin)
EXTRA   += -D_DARWIN_C_SOURCE
endif

ALL_CFLAGS = $(STD) $(WARN) $(CFLAGS) $(EXTRA) $(INC) $(DEF)

SRCS    := $(wildcard src/*.c)
OBJS    := $(SRCS:.c=.o)
LIB     := librsp.a

MBED_LIBS := $(MBED)/library/libmbedx509.a $(MBED)/library/libmbedcrypto.a

TESTS   := tests/run-link

.PHONY: all check clean mbedtls

all: $(LIB)

# mbedTLS builds only the two libraries this needs. libmbedtls (the TLS
# stack) is never linked: there is no socket in this project.
$(MBED_LIBS):
	@test -e $(MBED)/.git || { \
	    echo "the submodule is missing: git submodule update --init --recursive" >&2; \
	    exit 1; }
	$(MAKE) -C $(MBED)/library libmbedcrypto.a libmbedx509.a

mbedtls: $(MBED_LIBS)

%.o: %.c $(MBED_LIBS)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(LIB): $(OBJS)
	ar rcs $@ $(OBJS)

tests/run-%: tests/test_%.c $(LIB) $(MBED_LIBS)
	$(CC) $(ALL_CFLAGS) $< $(LIB) $(MBED_LIBS) -o $@
	@# On Darwin, a -g link auto-generates a companion run-%.dSYM directory.
	@# tests/run-tests globs "run-*", so that bundle would be picked up and
	@# "run" as if it were a test binary. Drop it: it is a build byproduct,
	@# not a test.
	@rm -rf $@.dSYM

check: $(TESTS)
	./tests/run-tests

clean:
	rm -f $(OBJS) $(LIB) $(TESTS)
	$(MAKE) -C $(MBED)/library clean 2>/dev/null || true
