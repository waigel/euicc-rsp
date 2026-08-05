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

Both DP certificates are issued by, and chain to, `ci.der`.

Both DP certificates expire on 30 March 2030 (`ci.der` itself is valid
until 2055); from that date on, `rsp_pki_verify` will start failing on
`dpauth.der`/`dppb.der` for that reason, not because anything in this
library broke -- replace them with a current SGP.26 test issuance.

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
