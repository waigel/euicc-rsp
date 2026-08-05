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

# build/sgp26_material.c embeds the published SGP.26 test material (see
# testdata/sgp26/) as byte arrays, generated with xxd -i so the vendored
# DER/PEM files stay the single source and no one hand-edits a C array.
# Not committed, like dist/: the rule below regenerates it from testdata/.
SRCS    := $(wildcard src/*.c) build/sgp26_material.c
OBJS    := $(SRCS:.c=.o)
LIB     := librsp.a

MBED_LIBS := $(MBED)/library/libmbedx509.a $(MBED)/library/libmbedcrypto.a

SGP26_DIR := testdata/sgp26
SGP26_SRCS := \
	$(SGP26_DIR)/ci.der \
	$(SGP26_DIR)/dpauth.der $(SGP26_DIR)/dpauth-key.pem \
	$(SGP26_DIR)/dppb.der $(SGP26_DIR)/dppb-key.pem

# The DP secret keys are SEC1 PEM text, and mbedtls_pk_parse_key requires a
# null-terminated buffer for PEM input with keylen == strlen(pem) + 1; xxd
# -i alone emits exactly the file's bytes with no terminator, so a NUL is
# appended before xxd sees it. The CI has no private key to embed -- SGP.26
# publishes the CI certificate only, never withheld from redistribution.
build/sgp26_material.c: $(SGP26_SRCS)
	@mkdir -p build
	@{ echo '/* Generated from testdata/sgp26. Do not edit. */'; \
	   echo '#include <stddef.h>'; \
	   xxd -i -n rsp_sgp26_ci_der          < $(SGP26_DIR)/ci.der; \
	   xxd -i -n rsp_sgp26_dpauth_der      < $(SGP26_DIR)/dpauth.der; \
	   { cat $(SGP26_DIR)/dpauth-key.pem; printf '\0'; } \
	       | xxd -i -n rsp_sgp26_dpauth_key_pem; \
	   xxd -i -n rsp_sgp26_dppb_der        < $(SGP26_DIR)/dppb.der; \
	   { cat $(SGP26_DIR)/dppb-key.pem; printf '\0'; } \
	       | xxd -i -n rsp_sgp26_dppb_key_pem; \
	 } > $@

# The codec, generated from the RSP module. asn1c is a path, not a submodule:
# euicc-schema already vendors one and euicc-tools passes it in. Standalone,
# ASN1C defaults to whatever is on PATH.
ASN1C    ?= asn1c
SKELDIR  ?= $(shell dirname $$(command -v $(ASN1C)))/../share/asn1c
RSP_ASN  := rsp-2.5.asn
DIST     := dist

# RSPDefinitions imports Certificate, CertificateList, Time and
# SubjectKeyIdentifier from the PKIX modules. asn1c does not ship them, and
# this repository does not depend on the sibling that extracts them from the
# RFC text (euicc-schema, via its asn1c submodule's rfc3280.txt + perl
# script). Vendored here instead, generated once, so euicc-rsp stands alone.
PKIX_DIR     := third_party/pkix
PKIX_SOURCES := \
	$(PKIX_DIR)/rfc3280-PKIX1Explicit88.asn1 \
	$(PKIX_DIR)/rfc3280-PKIX1Implicit88.asn1

$(DIST)/BoundProfilePackage.h: $(RSP_ASN) $(PKIX_SOURCES)
	mkdir -p $(DIST)
	$(ASN1C) -S $(SKELDIR) -pdu=auto -fcompound-names -D $(DIST) $(RSP_ASN) $(PKIX_SOURCES)

# Generated code is compiled with warnings off. It is not ours to correct.
# -idirafter, never -I: the PKIX types generate a Time.h that would hide the
# system <time.h> on a case-insensitive filesystem (macOS's default HFS+/APFS
# case-insensitive mode). -I. puts "." ahead of the system include path even
# for angle-bracket includes, so <time.h> resolves to ./Time.h there instead
# of the real header -- struct tm stays an incomplete forward declaration and
# timegm() is undeclared. Quoted includes ("Foo.h") already search the
# including file's own directory first regardless of -I/-idirafter, so local
# headers still resolve correctly with -idirafter.
# converter-example.c is asn1c's -pdu=auto sample front end. It needs -DPDU
# and -DASN_PDU_COLLECTION to compile (see its own #error otherwise) and this
# library has no use for a converter binary, so it is excluded here rather
# than given defines it would never use.
$(DIST)/.stamp: $(DIST)/BoundProfilePackage.h
	cd $(DIST) && $(CC) $(STD) $(CFLAGS) $(EXTRA) -w -idirafter . -c $$(ls *.c | grep -v '^converter-example\.c$$')
	@touch $@

codec: $(DIST)/.stamp

INC     := -Iinclude -Isrc -I$(MBED)/include
GEN_INC := -idirafter $(DIST)

TESTS   := tests/run-link tests/run-codec tests/run-pki tests/run-kdf

.PHONY: all check clean mbedtls codec

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

tests/run-%: tests/test_%.c $(LIB) $(MBED_LIBS) $(DIST)/.stamp
	$(CC) $(ALL_CFLAGS) $(GEN_INC) $< $(LIB) $(DIST)/*.o $(MBED_LIBS) -o $@
	@# On Darwin, a -g link auto-generates a companion run-%.dSYM directory.
	@# tests/run-tests globs "run-*", so that bundle would be picked up and
	@# "run" as if it were a test binary. Drop it: it is a build byproduct,
	@# not a test.
	@rm -rf $@.dSYM

check: $(TESTS)
	./tests/run-tests

clean:
	rm -f $(OBJS) $(LIB) $(TESTS)
	rm -rf $(DIST) build
	$(MAKE) -C $(MBED)/library clean 2>/dev/null || true
