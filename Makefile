# euicc-rsp -- the SM-DP+ role of SGP.22 as a library.
#
#     make          the library
#     make check    the tests
#     make clean    everything the build produced
#
# asn1c is not vendored here: it is already a submodule of euicc-schema, and
# euicc-tools passes the one it built. Standalone, any asn1c on PATH does.

# Without this, a recipe that redirects its output to its target (every
# generated-file rule below does) and then fails partway leaves whatever
# it had already written on disk, with a fresh mtime. The next "make"
# then sees that half-written file as newer than its prerequisites and
# calls it up to date -- a stale, silently wrong build, not a failed one.
.DELETE_ON_ERROR:

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
# testdata/sgp26/) as byte arrays, generated with tools/bin2c so the
# vendored DER/PEM files stay the single source and no one hand-edits a C
# array. Not committed, like dist/: the rule below regenerates it from
# testdata/. Not xxd: ubuntu-latest's default runner image has no xxd (it
# ships in vim-common, which that image does not install), and this
# project builds on a bare toolchain, not whatever a runner happens to
# have installed for an unrelated reason.
SRCS    := $(wildcard src/*.c) build/sgp26_material.c
OBJS    := $(SRCS:.c=.o)
LIB     := librsp.a

# Neither header is named per source file below: every translation unit in
# this library reaches rsp.h, directly or through rsp_internal.h, so listing
# both against every object is an over-approximation, not a guess. Without
# this, "touch include/rsp.h" changed nothing make could see, and a caller
# further up the chain (euicc-lpa's Makefile delegates librsp.a's own
# staleness to this one, and euicc-tools' delegates to euicc-lpa's in turn)
# would link a library that never noticed the header moved.
HDRS    := include/rsp.h src/rsp_internal.h

MBED_LIBS := $(MBED)/library/libmbedx509.a $(MBED)/library/libmbedcrypto.a

# mbedTLS commits five generated sources for this pinned tag, but its own
# library/Makefile decides per file whether to trust that or regenerate.
# Three of them (error.c, version_features.c, ssl_debug_helpers_generated.c)
# use an order-only prerequisite on their generator, so they are only
# rebuilt if actually missing -- safe, since we keep them. The PSA driver
# wrapper pair does not: its rule depends plainly (mtime-checked) on
# generate_driver_wrappers.py and two .jinja templates, so whenever those
# LOOK newer -- which neither a fresh clone nor a copied tree can promise
# one way or the other, since mtimes there are checkout-order artifacts,
# not something either of those workflows sets deliberately -- make
# demands a Python interpreter this project forbids, to regenerate a file
# already correct and pinned. We do not patch the submodule for this: we
# assert freshness ourselves before it gets a chance to decide otherwise.
MBED_GENERATED := \
	$(MBED)/library/error.c \
	$(MBED)/library/version_features.c \
	$(MBED)/library/ssl_debug_helpers_generated.c \
	$(MBED)/library/psa_crypto_driver_wrappers.h \
	$(MBED)/library/psa_crypto_driver_wrappers_no_static.c

SGP26_DIR := testdata/sgp26
SGP26_SRCS := \
	$(SGP26_DIR)/ci.der \
	$(SGP26_DIR)/dpauth.der $(SGP26_DIR)/dpauth-key.pem \
	$(SGP26_DIR)/dppb.der $(SGP26_DIR)/dppb-key.pem \
	$(SGP26_DIR)/ci-2017.der \
	$(SGP26_DIR)/eum.der \
	$(SGP26_DIR)/euicc.der $(SGP26_DIR)/euicc-key.pem

# The DP secret keys are SEC1 PEM text, and mbedtls_pk_parse_key requires a
# null-terminated buffer for PEM input with keylen == strlen(pem) + 1;
# bin2c, like xxd -i, emits exactly the bytes it is given with no
# terminator, so a NUL is appended before it reads the stream. The CI has
# no private key to embed -- SGP.26 publishes the CI certificate only,
# never withheld from redistribution.
BIN2C := tools/bin2c

build/sgp26_material.c: $(SGP26_SRCS) $(BIN2C)
	@mkdir -p build
	@{ echo '/* Generated from testdata/sgp26. Do not edit. */'; \
	   echo '#include <stddef.h>'; \
	   $(BIN2C) rsp_sgp26_ci_der          < $(SGP26_DIR)/ci.der && \
	   $(BIN2C) rsp_sgp26_dpauth_der      < $(SGP26_DIR)/dpauth.der && \
	   $(BIN2C) -z rsp_sgp26_dpauth_key_pem < $(SGP26_DIR)/dpauth-key.pem && \
	   $(BIN2C) rsp_sgp26_dppb_der        < $(SGP26_DIR)/dppb.der && \
	   $(BIN2C) -z rsp_sgp26_dppb_key_pem < $(SGP26_DIR)/dppb-key.pem && \
	   $(BIN2C) rsp_sgp26_ci2017_der      < $(SGP26_DIR)/ci-2017.der && \
	   $(BIN2C) rsp_sgp26_eum_der         < $(SGP26_DIR)/eum.der && \
	   $(BIN2C) rsp_sgp26_euicc_der       < $(SGP26_DIR)/euicc.der && \
	   $(BIN2C) -z rsp_sgp26_euicc_key_pem < $(SGP26_DIR)/euicc-key.pem; \
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

# -fwide-types is load-bearing, not a preference. asn1c's default C type for
# an unconstrained INTEGER is "long", which holds eight octets; RFC 5280
# section 4.1.2.2 lets a certificate serial number run to twenty, and real
# eUICC certificates use more than eight. Without this flag ber_decode fails
# outright on such a certificate, and so on every structure that carries one
# -- AuthenticateResponseOk's euiccCertificate and eumCertificate, which is
# to say every ES9+ session with a real card. The flag turns those into
# INTEGER_t (arbitrary precision) instead. tests/test_codec.c pins it with
# this project's own test CI, whose serial needs nine octets.
$(DIST)/BoundProfilePackage.h: $(RSP_ASN) $(PKIX_SOURCES)
	mkdir -p $(DIST)
	$(ASN1C) -S $(SKELDIR) -pdu=auto -fcompound-names -fwide-types -D $(DIST) $(RSP_ASN) $(PKIX_SOURCES)

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

GEN_INC := -idirafter $(DIST)

# Hand-maintained once, and a forgotten entry here used to mean "make check"
# passed without ever running the new test -- a green suite that quietly
# checked less than it claimed to. Derived from the test sources themselves
# instead: adding tests/test_whatever.c is now sufficient on its own.
TESTS   := $(patsubst tests/test_%.c,tests/run-%,$(wildcard tests/test_*.c))

# The eUICC-side fixture builders, shared by every test binary and by
# tools/session-fixtures -- see tests/fixtures.h for why they are not
# static inside one test any more.
FIXTURES := tests/fixtures.c

.PHONY: all check clean mbedtls codec

# build/sgp26_material.c is the first target textually in this file, so
# without this, GNU Make's default goal (what bare "make" builds) would be
# that generated C file, not the library -- silently doing far less than
# "make" is documented to do above. .DEFAULT_GOAL overrides the file-order
# rule regardless of where "all" itself sits.
.DEFAULT_GOAL := all

all: $(LIB)

# mbedTLS builds only the two libraries this needs. libmbedtls (the TLS
# stack) is never linked: there is no socket in this project.
#
# $(MBED_LIBS) names two files built by one submake invocation below, and a
# rule with multiple targets and one recipe is exactly the shape GNU Make
# (without the 4.3+-only grouped-target "&:" syntax, which the Make Apple
# ships on Darwin -- 3.81, for GPLv3 reasons -- does not have) is free to
# treat as "run this recipe once per target that needs it": under "make -j"
# with both .a files missing, that can mean two concurrent submakes racing
# to write the same files, each also re-touching $(MBED_GENERATED). Routing
# both targets through one stamp file makes the actual submake invocation a
# single target again, so there is exactly one recipe instance to run no
# matter how many of $(MBED_LIBS) triggered it.
build/mbed.stamp:
	@mkdir -p $(dir $@)
	@test -e $(MBED)/.git || { \
	    echo "the submodule is missing: git submodule update --init --recursive" >&2; \
	    exit 1; }
	@for f in $(MBED_GENERATED); do \
	    test -s "$$f" || { \
	        echo "missing generated mbedTLS source: $$f" >&2; \
	        echo "this build does not regenerate it (no interpreter is" >&2; \
	        echo "allowed); check the submodule checkout instead of" >&2; \
	        echo "touching it into existence" >&2; \
	        exit 1; \
	    }; \
	done
	@touch $(MBED_GENERATED)
	$(MAKE) -C $(MBED)/library libmbedcrypto.a libmbedx509.a
	@touch $@

$(MBED_LIBS): build/mbed.stamp

mbedtls: $(MBED_LIBS)


# src/rsp_bpp.c reaches into the generated codec (BoundProfilePackage_t and
# friends) directly, so every object -- not just the tests -- now needs
# $(DIST)/.stamp built first and $(GEN_INC) on its command line. -idirafter,
# not -I, for the same case-insensitive-Time.h reason the tests use it.
#
# Makefile itself is a prerequisite too, for the same reason euicc-lpa's
# Makefile names itself against its objects and its tests/run-% rule: ALL_CFLAGS
# (VERSION via -D, warning flags, include paths) is compiled in, not read at
# run time, so an edit to a flag or to VERSION here is invisible to make
# without this -- make tracks prerequisite mtimes, not recipe or variable
# text. Without it, bumping VERSION and running "make check" can report green
# while still linking the stale object built under the old value.
%.o: %.c $(HDRS) $(MBED_LIBS) $(DIST)/.stamp Makefile
	$(CC) $(ALL_CFLAGS) $(GEN_INC) -c $< -o $@

$(LIB): $(OBJS)
	ar rcs $@ $(OBJS)

# Makefile is a prerequisite here for the same reason as the %.o rule above:
# this recipe's own link line lives here, not in any test_*.c, so make has
# no other way to notice the line changed and would otherwise reuse an
# already-built tests/run-% binary that no longer matches this recipe.
# -pthread is for tests/test_threads.c, which signs from several threads
# at once. Harmless for every other test binary, and cheaper than giving
# one test its own rule outside this pattern.
tests/run-%: tests/test_%.c $(FIXTURES) tests/fixtures.h $(LIB) $(MBED_LIBS) $(DIST)/.stamp Makefile
	$(CC) $(ALL_CFLAGS) $(GEN_INC) -Itests -pthread $< $(FIXTURES) $(LIB) $(DIST)/*.o $(MBED_LIBS) -o $@
	@# On Darwin, a -g link auto-generates a companion run-%.dSYM directory.
	@# tests/run-tests globs "run-*", so that bundle would be picked up and
	@# "run" as if it were a test binary. Drop it: it is a build byproduct,
	@# not a test.
	@rm -rf $@.dSYM

check: $(TESTS)
	./tests/run-tests

# tools/bpp-dump builds a Bound Profile Package and prints its structure, so
# a person can look at the artifact the suite only proves correct. It is a
# demonstration and stays out of the way: "all" does not build it and "check"
# does not run it, so it can never be why a build or a test run fails.
#
# It compiles to an object through the %.o rule and links as a second step,
# rather than doing both in one $(CC) call the way tests/run-% does. The build
# is identical either way; the difference is that an IDE which learns a file's
# include paths by watching the build only records "-c" compilations. A
# combined compile-and-link command is invisible to it, so bpp-dump.c would be
# a file with no known flags -- #include "rsp.h" unresolvable in the editor --
# for as long as it stayed out of "all".
tools/bpp-dump: tools/bpp-dump.o $(LIB) $(MBED_LIBS) $(DIST)/.stamp
	$(CC) $(ALL_CFLAGS) $(GEN_INC) $< $(LIB) $(DIST)/*.o $(MBED_LIBS) -o $@
	@rm -rf $@.dSYM

# tools/session-fixtures writes one whole RSP session to disk so a consumer
# outside this repository -- euicc-smdp, in Rust -- can replay it without a
# card. It links the shared fixture builders for the eUICC side, and follows
# bpp-dump's compile-then-link split for the same IDE reason given above.
tools/session-fixtures: tools/session-fixtures.o $(FIXTURES) tests/fixtures.h \
                        $(LIB) $(MBED_LIBS) $(DIST)/.stamp
	$(CC) $(ALL_CFLAGS) $(GEN_INC) -Itests $< $(FIXTURES) $(LIB) $(DIST)/*.o \
	    $(MBED_LIBS) -o $@
	@rm -rf $@.dSYM

tools/session-fixtures.o: tools/session-fixtures.c tests/fixtures.h $(DIST)/.stamp
	$(CC) $(ALL_CFLAGS) $(GEN_INC) -Itests -c $< -o $@

# Regenerating is the only supported way to change testdata/session/ --
# the files are outputs, not sources to be edited.
.PHONY: session-fixtures
session-fixtures: tools/session-fixtures
	@mkdir -p testdata/session
	./tools/session-fixtures testdata/session

clean:
	rm -f $(OBJS) $(LIB) tools/bpp-dump tools/bpp-dump.o \
	    tools/session-fixtures tools/session-fixtures.o
	@rm -rf tools/bpp-dump.dSYM tools/session-fixtures.dSYM
	@# Not "rm -f $(TESTS)": $(TESTS) is derived from the test sources that
	@# exist right now, so a binary left over from a test that was since
	@# renamed or deleted would not be in that list at all, would survive
	@# "make clean", and tests/run-tests (which globs "run-*", not
	@# $(TESTS)) would go on running and reporting it. Match run-tests'
	@# own glob here instead, with the same "run-tests" exclusion it uses
	@# on itself, so a clean tree and a stale binary cannot coexist.
	@for f in tests/run-*; do \
	    [ -e "$$f" ] || continue; \
	    [ "$$(basename "$$f")" = "run-tests" ] && continue; \
	    rm -f "$$f"; \
	done
	rm -rf $(DIST) build
	$(MAKE) -C $(MBED)/library clean 2>/dev/null || true
