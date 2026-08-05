# euicc-rsp

The SM-DP+ role of SGP.22, as a C library. It builds a Bound Profile Package
for one eUICC. It is not a server: no HTTPS, no ES2+, no SM-DS, no activation
code. [euicc-tools](https://github.com/waigel/euicc-tools) is the command
that uses it.

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

Tests need no card reader. Everything in this repository is provable on a
machine with no hardware attached.

`make check` also generates the RSP codec with `asn1c` (see below) the first
time it runs. Install it with `brew install asn1c`, or point `ASN1C=` at a
binary you already built; `SKELDIR=` overrides the skeleton directory the
same way, if it is not next to `asn1c` on `PATH`.

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

The certificates and keys in this repository are the published GSMA SGP.26
**test** material -- the ASN.1 module above is a format definition, not test
material, and is unaffected by this note. The certificates and keys work on
test eUICCs and nowhere else. A production eUICC rejects them, and a
production profile must never be loaded with them. The private CI key is
public by design, so nothing here is a secret and nothing here is safe.
