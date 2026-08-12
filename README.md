# euicc-rsp

The SM-DP+ role of SGP.22, as a C library. It runs an RSP session's server
side -- `InitiateAuthentication`, `AuthenticateClient`,
`GetBoundProfilePackage` -- and builds the Bound Profile Package the last of
those hands back. It is not a server: no HTTPS, no ES2+, no SM-DS, no
activation code, and no Profile order database, so the caller supplies the
Profile metadata this library has nowhere to look it up from.
[euicc-tools](https://github.com/waigel/euicc-tools) is the command that
uses it.

The BPP now carries everything SGP.22 v2.6 section 2.5.4's Table 4 requires
for a card to accept it: `'87'` encrypted and MAC'd, `'88'` MAC'd, and real
`transactionId`, `hostId` and `smdpSign` where placeholders used to be. That
is a conformance claim, checked against Table 4 and against this library's
own recovery of what it built -- not a card's answer. No eUICC in this
repository accepts anything, because the card side is not in this
repository.

What is still open is narrower, and each piece is spec-conformant on its
own: the Profile Protection Keys ("random key") mode, a `'88'` too large for
one segment, and a handful of OPTIONAL metadata fields --
[`include/rsp.h`](include/rsp.h)'s comment on `rsp_bpp_input_t` has the full
list and why each one is still open.

`serverAddress` used to sit on that list and no longer does. The SM-DP+'s
own address is now a parameter of `rsp_dp_initiate_authentication`, and so
is the `smdpAddress` the LPA sent: SGP.22 section 5.6.1 has the server
compare the two case-insensitively, and a mismatch is the one thing that
function refuses. An `.invalid` placeholder used to be signed in its place.
The same call's response can now be read apart into the five fields the
ES9+ JSON binding names (section 6.5.2.6), as can `AuthenticateClient`'s
(section 6.5.2.8) -- cut out of the encoded bytes rather than decoded and
rebuilt, so what a server puts on the wire is what was signed.

The session still stops where the download does. Of ES9+'s five functions,
the three above are implemented; `HandleNotification` and `CancelSession`
are not. A `ProfileInstallationResult` that reaches this library *is*
checked against the eUICC's own signature over it
(`rsp_dp_verify_installation_result`), but nothing here receives one over
a network, and no notification the eUICC queues is collected. This library
can bind a Profile to an eUICC and judge the report it is handed; it
cannot yet go and ask for one.

| Repository | Role |
| --- | --- |
| [asn1c-vn](https://github.com/waigel/asn1c-vn) | the language |
| [euicc-schema](https://github.com/waigel/euicc-schema) | the vocabulary |
| [euicc-tools](https://github.com/waigel/euicc-tools) | the command |
| `euicc-rsp` (this one) | the protocol |

## Threads

`rsp_sign` builds its RNG per call, so signing from several threads at
once is safe and genuinely parallel -- measured at 755% CPU over 12 800
signatures on eight threads. It was not always: the RNG used to be a
file-scope singleton with an unsynchronised lazy initialisation, which
segfaulted under concurrency in five runs out of six.
[`tests/test_threads.c`](tests/test_threads.c) is what holds it, and it
crosses `MBEDTLS_CTR_DRBG_RESEED_INTERVAL` on purpose so it reaches the
second race as well as the first.

No mutex was added and `MBEDTLS_THREADING_C` is still off in the vendored
mbedTLS: the sharing was removed rather than guarded, which is why
nothing downstream has to agree on a configuration.

## Build

```sh
git clone --recurse-submodules https://github.com/waigel/euicc-rsp.git
cd euicc-rsp
make
make check
```

`make check` needs no card reader. Every test in this repository is
provable on a machine with no hardware attached -- the transport, the ES10
command layer and the read-only card commands, the parts that would need
one, live in [euicc-lpa](https://github.com/waigel/euicc-lpa) now, not here.

`make check` also generates the RSP codec with `asn1c` (see below) the first
time it runs. Install it with `brew install asn1c`, or point `ASN1C=` at a
binary you already built; `SKELDIR=` overrides the skeleton directory the
same way, if it is not next to `asn1c` on `PATH`.

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
