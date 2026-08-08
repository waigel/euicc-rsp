# GSMA SGP.26 test material

These are the published SGP.26 test certificates and the DP secret keys
that accompany them. Together they let this library act as an SM-DP+
towards an eUICC that trusts the test Certificate Issuer below -- the
certificate chain and the key material a real SM-DP+ needs to sign with,
minus a production Certificate Issuer's actual private key, which SGP.26
never publishes.

They work on test cards only, and nowhere else. A production eUICC rejects
them; never load a production profile with them.

| File | Content |
| --- | --- |
| `ci.der` | Test Certificate Issuer certificate (no private key: SGP.26 does not publish one) |
| `dpauth.der` | Test SM-DP+ authentication (DPauth) certificate |
| `dpauth-key.pem` | The DPauth certificate's private key (SEC1 PEM, P-256) |
| `dppb.der` | Test SM-DP+ profile-binding (DPpb) certificate |
| `dppb-key.pem` | The DPpb certificate's private key (SEC1 PEM, P-256) |
| `ci-2017.der` | The *same* Test CI key, under its original 2017 SGP.26 v1.0 certificate (see below) |
| `eum.der` | Test EUM (eUICC manufacturer) certificate, issued by `ci-2017.der` |
| `euicc.der` | Test eUICC certificate, issued by `eum.der`; EID `89049032123451234512345678901235` |
| `euicc-key.pem` | The eUICC certificate's private key (SEC1 PEM, P-256) |

Both DP certificates are issued by, and chain to, `ci.der`.

Both DP certificates expire on 30 March 2030 (`ci.der` itself is valid
until 2055); from that date on, `rsp_pki_verify` will start failing on
`dpauth.der`/`dppb.der` for that reason, not because anything in this
library broke -- replace them with a current SGP.26 test issuance.

## The EUM/eUICC pair, and why a second CI certificate exists

`rsp_dp_authenticate_client`'s tests (`tests/test_es9.c`) need an EUM
certificate and an eUICC certificate to exercise CERT.EUM/CERT.EUICC chain
verification and EID extraction, neither of which SGP.26's DP-only subset
above provides. GSMA's own SGP.26 v1.0 test material
(`SGP.26_v1.0_Files.zip`, linked from
<https://euicc-manual.osmocom.org/docs/pki/ci/>, itself fetched from
<https://www.gsma.com/newsroom/wp-content/uploads/SGP.26_v1.0_Files.zip>)
publishes exactly this: `NIST/EUM-cert_NIST.der` (vendored here,
byte-identical, as `eum.der`) and `NIST/eUICC-cert_NIST.cer` +
`NIST/euiccPrivKey_NIST.pem` (see the next section for why `euicc.der` is
*not* that file byte-identical, unlike everything else in this
directory). `eUICC-cert_NIST.cer`'s subject carries
`serialNumber=89049032123451234512345678901235` -- the exact EID SGP.22
v2.6 itself uses as the illustrative example for the eUICC certificate
Subject field (section 4.5.1's own worked example: "o = ACME, serialNumber
= 89049032123451234512345678901235"), not a value this project invented.
There is still no CI *private* key in this v1.0 archive either (only
`NIST/CI-cert_NIST.der`, a certificate); the claim above about `ci.der`
holds up independently, not merely on the previous README's say-so.

`euicc-key.pem` is, like `dpauth-key.pem` and `dppb-key.pem` above, a
private key committed to this repository -- worth saying plainly, not
leaving a reader to wonder why. It carries no security value: it is
GSMA's own published SGP.26 v1.0 test material (`NIST/euiccPrivKey_NIST.pem`
in the same archive as `eum.der` above, byte-identical), meant to be
public so that any implementation can exercise the eUICC side of this
protocol against it, exactly like the DP keys already vendored here. It
signs nothing a production eUICC accepts.

### `euicc.der` is a re-issuance, not a byte-identical copy

`NIST/eUICC-cert_NIST.cer`'s own serial number is nine octets
(`02 00 00 00 00 00 00 00 01`) -- valid DER, RFC 5280 permits up to twenty
-- but this project's generated codec cannot hold it:
`dist/CertificateSerialNumber.h` (generated from
`third_party/pkix/rfc3280-PKIX1Explicit88.asn1`, `CertificateSerialNumber_t`)
is `typedef long CertificateSerialNumber_t`, a native machine `long`, and
nine octets overflows it. Confirmed directly, not inferred: decoding
`eUICC-cert_NIST.cer` unmodified through `ber_decode(&asn_DEF_Certificate,
...)` -- the exact call `rsp_dp_authenticate_client` makes on an incoming
`euiccCertificate` -- fails (`RC_FAIL`) a few bytes into `tbsCertificate`,
right at `serialNumber`. This is not specific to this one certificate or
to testing: *any* real eUICC whose manufacturer issues serial numbers
wider than a native `long` (RFC 5280 explicitly allows this) would make
`rsp_dp_authenticate_client` fail to even parse its `AuthenticateServerResponse`,
in production, not only in this test fixture -- worth flagging as a real
limitation of the generated codec, in the same register as `src/rsp_bpp.c`'s
own documented SEQUENCE-OF-tagged-element defect, not something Task 3
introduces or is in scope to fix (it would mean changing how asn1c
generates `CertificateSerialNumber_t`, or the vendored PKIX module itself).

So that this project's own tests can still exercise the real
`AuthenticateServerResponse` decode path rather than working around it,
`euicc.der` here is a *re-issuance* of `eUICC-cert_NIST.cer`, not the
original file: the same subject (same EID), the same public key (so
`euicc-key.pem` above still matches it), the same issuer and the same
extensions (`authorityKeyIdentifier`, `subjectKeyIdentifier`, `keyUsage`,
`certificatePolicies`, copied from `NIST/eUICC-ext.cnf` in the same
archive), signed by the same EUM private key (`NIST/eumPrivKey_NIST.pem`,
not vendored here -- it is not needed by anything at runtime, only for
this one re-issuance, and re-deriving it from the original archive is
one command away if this ever needs regenerating) -- with only the serial
number (`1`, not the original's nine octets) and the validity period
(freshly dated, since the CSR is regenerated) different. Reproduced with:

```sh
# from NIST/ inside the extracted SGP.26_v1.0_Files.zip
openssl req -new -sha256 -config eUICC-csr.cnf -key euiccPrivKey_NIST.pem -out eUICC-new.csr
openssl x509 -req -in eUICC-new.csr -CA EUM-cert_NIST.der -CAkey eumPrivKey_NIST.pem \
    -set_serial 1 -days 9125 -sha256 -extfile eUICC-ext.cnf -out euicc.pem
openssl x509 -in euicc.pem -outform der -out euicc.der
```

(`openssl x509 -req`'s `-CA` wants PEM, so convert `EUM-cert_NIST.der`
first: `openssl x509 -inform der -in EUM-cert_NIST.der -out EUM-cert_NIST.pem`.)
Verified afterward, independently of this library, exactly the same way
the "verify a certificate is what it claims to be" section below checks
the other files: chains to `eum.der` (`openssl verify -CAfile eum.pem
euicc.pem` once both are PEM, `-CAfile` given `eum.pem` alone since
Name Constraints below makes `openssl verify`'s own stricter policy engine
reject the full three-certificate chain even though the signature itself
is fine -- see the mbedTLS note below), and the private key still matches
(`openssl ec -in euicc-key.pem -pubout` equals `openssl x509 -in euicc.der
-noout -pubkey`).

The catch: `EUM-cert_NIST.der`'s issuer is `CN=GSMA Test CI, ...`, but this
directory's `ci.der` (vendored from a later SGP.26 reissue via pySim, see
below) has subject `CN=Test CI, ...` -- same key
(`openssl x509 -in ci.der -noout -pubkey` and `... -in ci-2017.der -noout
-pubkey` are byte-identical), different certificate text, because GSMA
reissued the Test CI's certificate at least once between 2017 and 2020
while keeping its key. X.509 chain building matches by issuer/subject
*name*, not by public key, so `mbedtls_x509_crt_verify(eum, ci, ...)`
needs the 2017-vintage certificate object specifically -- `ci-2017.der` is
vendored for exactly that, and `rsp_dp_authenticate_client` trusts both
`ci.der` and `ci-2017.der` as CERT.EUM anchors for this reason (one
cryptographic entity, two historical certificate issuances of the same
key -- not two different trusted roots).

`eum.der` also carries a critical Name Constraints extension restricting
the EIDs it may issue for; see
`rsp_accept_certificate_policies_and_name_constraints` in
`src/rsp_internal.h` for why parsing it needs a second accept-callback and
what mbedTLS does (nothing) with its content.

## Provenance

Fetched byte-identical from the
[Osmocom pySim](https://github.com/osmocom/pysim) repository's
`smdpp-data/certs/` tree (the same material `osmo-smdpp` uses), NIST
P-256 variants -- this project's spec commits to P-256, so the Brainpool
variants pySim also carries are not vendored here:

- `ci.der` from `smdpp-data/certs/CertificateIssuer/CERT_CI_ECDSA_NIST.der`
- `dpauth.der` from `smdpp-data/certs/DPauth/CERT_S_SM_DPauth_ECDSA_NIST.der`
- `dpauth-key.pem` from `smdpp-data/certs/DPauth/SK_S_SM_DPauth_ECDSA_NIST.pem`
- `dppb.der` from `smdpp-data/certs/DPpb/CERT_S_SM_DPpb_ECDSA_NIST.der`
- `dppb-key.pem` from `smdpp-data/certs/DPpb/SK_S_SM_DPpb_ECDSA_NIST.pem`

Verify a certificate is what it claims to be, independently of this
library:

```sh
openssl x509 -inform der -in ci.der -noout -subject -issuer
openssl x509 -inform der -in dpauth.der -noout -subject -issuer
```

The CI certificate is self-signed: its subject and issuer are identical.
The DP certificates' issuer matches the CI's subject.
