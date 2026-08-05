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

## Test material only

The certificates and keys in this repository are the published GSMA SGP.26
**test** material. They work on test eUICCs and nowhere else. A production
eUICC rejects them, and a production profile must never be loaded with them.
The private CI key is public by design, so nothing here is a secret and
nothing here is safe.

## Build

```sh
git clone --recurse-submodules https://github.com/waigel/euicc-rsp.git
cd euicc-rsp
make
make check
```

Tests need no card reader. Everything in this repository is provable on a
machine with no hardware attached.
