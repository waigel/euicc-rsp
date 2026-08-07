# euicc-rsp

The SM-DP+ role of SGP.22, as a C library. It builds a Bound Profile Package
for one eUICC. It is not a server: no HTTPS, no ES2+, no SM-DS, no activation
code. [euicc-tools](https://github.com/waigel/euicc-tools) is the command
that uses it.

**No card accepts the BPP this library builds today.** `'87'`/`'88'` groups
go in unprotected, `transactionId` is a fixed placeholder byte, `hostId` is
the ICCID instead of the eUICC's EID, and `smdpSign` is empty -- see
[`include/rsp.h`](include/rsp.h)'s comment on `rsp_bpp_input_t` for the full
list and why each one is still open.

| Repository | Role |
| --- | --- |
| [asn1c-vn](https://github.com/waigel/asn1c-vn) | the language |
| [euicc-schema](https://github.com/waigel/euicc-schema) | the vocabulary |
| [euicc-tools](https://github.com/waigel/euicc-tools) | the command |
| `euicc-rsp` (this one) | the protocol |

## Build

```sh
git clone --recurse-submodules https://github.com/waigel/euicc-rsp.git
cd euicc-rsp
make
make check
```

`make check` needs no card reader. Every test it runs is provable on a
machine with no hardware attached, `make check-card` (below) is the one
exception, and it is not part of `check` for exactly that reason.

`make check` also generates the RSP codec with `asn1c` (see below) the first
time it runs. Install it with `brew install asn1c`, or point `ASN1C=` at a
binary you already built; `SKELDIR=` overrides the skeleton directory the
same way, if it is not next to `asn1c` on `PATH`.

**PC/SC.** [`src/rsp_pcsc.c`](src/rsp_pcsc.c) is part of every build --
`SRCS` globs `src/*.c` -- even on a machine with no reader attached, since
the transport it implements still has to compile and link. macOS ships
PC/SC as a system framework (`-framework PCSC`, already on every Mac, no
install needed); Linux has no PC/SC of its own, so `libpcsclite-dev`
(Debian/Ubuntu) or the equivalent `pcsc-lite-devel` package for your
distribution needs to be installed first, or the build fails at
`src/rsp_pcsc.c:38: fatal error: winscard.h: No such file or directory`.
See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for exactly
what CI installs.

## `make check-card`

The one target in this repository that is not provable without hardware:
it needs a real card reader with a test eUICC in it, over PC/SC, and reads
what the card actually says (see [`tests/test_card.c`](tests/test_card.c)
and [`testdata/cards/README.md`](testdata/cards/README.md) for what it
found against this project's own test card). It is not part of `make
check` and CI never runs it, for the same reason: there is no reader
attached to a CI runner, and a target that fails whenever hardware is
absent would make every ordinary contribution look broken.

```sh
make check-card
```

`rsp_pcsc_open`'s own reader-selection and protocol-negotiation logic
(`src/rsp_pcsc.c`) is what this target actually exercises; a recorded
session (`testdata/cards/omnikey-info.log`) stands in for the reader
everywhere else in the suite, which is what lets the rest of `make check`
run with no hardware at all.

**This needs asn1c 0.9.29 or later.** The codec rule passes `-D` (the
destination directory for generated files), which
[was added](https://github.com/vlm/asn1c/commit/6431b1c969785e71aadb1b1991a3c8592266e747)
in that release. Debian and Ubuntu package 0.9.28, which does not have it --
`asn1c: invalid option -- 'D'` means this is why. `brew install asn1c` on
macOS already gets 0.9.29 or newer; on Debian/Ubuntu, build from source (see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) for a working
sequence) and point `ASN1C=`/`SKELDIR=` at the result instead of installing
the packaged one.

## The RSP ASN.1 module

[`rsp-2.5.asn`](rsp-2.5.asn) is the `RSPDefinitions` module of GSMA SGP.22
(RSP Technical Specification), the wire format this library encodes and
decodes -- `BoundProfilePackage`, `StoreMetadataRequest`,
`ProfileInstallationResult`, and the rest of the ES8+/ES9+ messages. `make`
runs it through `asn1c` and writes the generated codec to `dist/`, which is
not committed.

It imports `Certificate`, `CertificateList`, `Time` and
`SubjectKeyIdentifier` from the PKIX ASN.1 modules (RFC 3280). Those are
vendored in [`third_party/pkix/`](third_party/pkix/): generated once from the
RFC text by the same `crfc2asn1.pl` extraction
[euicc-schema](https://github.com/waigel/euicc-schema) already performs, and
copied in rather than re-run here, so this repository does not depend on that
sibling or on Perl at build time.

## License and attribution

The code of this project, its Makefile and its documentation are under the
[MIT License](LICENSE). Two parts have their own origin:

- [`rsp-2.5.asn`](rsp-2.5.asn), the `RSPDefinitions` module, is
  © [GSMA](https://www.gsma.com/). It comes from the public *RSP Technical
  Specification* (SGP.22) and is not under an open source license; the
  specification carries no warranty and its own IPR disclaimer applies. This
  copy was fetched from
  [estkme-group/lpac](https://github.com/estkme-group/lpac/blob/main/docs/asn1/rsp.asn),
  one of several public projects that redistribute it, and cross-checked
  against the independent copy in
  [osmocom/pysim](https://github.com/osmocom/pysim) (`pySim/esim/asn1/rsp/rsp.asn`)
  -- the two agree on the module identifier and on every type both define.
- [`third_party/pkix/`](third_party/pkix/) is extracted from IETF RFC 3280,
  under the [IETF Trust's rules](https://www.ietf.org/about/administration/ietf-trust/),
  which permit unmodified redistribution.
- The code generator and the runtime skeletons are
  [asn1c](https://github.com/vlm/asn1c) by Lev Walkin, under a BSD license.

## Test material only

The certificates and keys in [`testdata/sgp26/`](testdata/sgp26/) are the
published GSMA SGP.26 **test** material -- the ASN.1 module above is a
format definition, not test material, and is unaffected by this note. They
work on test eUICCs and nowhere else. A production eUICC rejects them, and
a production profile must never be loaded with them. The DP certificates'
private keys are part of the published material, redistributed here
byte-identical from [osmocom/pysim](https://github.com/osmocom/pysim); the
Certificate Issuer's private key is not published and is not in this
repository -- see [`testdata/sgp26/README.md`](testdata/sgp26/README.md)
for what each file is and where it came from.
