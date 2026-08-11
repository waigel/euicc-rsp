# One RSP session, written down

These files are one complete SM-DP+ session — the three ES9+ steps of a
Profile download — recorded so that something outside this repository can
replay it without a card and without `asn1c`.

They are **outputs, not sources**. Regenerate them with:

```sh
make session-fixtures
```

Do not edit them by hand. If one needs to change, change
[`tools/session-fixtures.c`](../../tools/session-fixtures.c) and
regenerate.

## Why this is possible at all

Every input to the session is fixed: the eUICC challenge, the
transactionId, the serverChallenge and `otsk_dp` are all constants in the
tool, and `rsp_sign` signs deterministically. Nothing on this path draws
entropy any more, so `make session-fixtures` twice produces byte-identical
files. That is what makes these a fixture rather than a recording of one
particular run — and it is the whole reason the serverChallenge became a
caller-supplied parameter of `rsp_dp_initiate_authentication` rather than
something the function drew for itself.

## What each file is

The eUICC side and the caller-supplied inputs — what a server receives or
must be told:

| File | What it is |
| --- | --- |
| `euicc-challenge.bin` | the 16-byte challenge from `ES10b.GetEUICCChallenge` |
| `transaction-id.bin` | the 16-byte transactionId the SM-DP+ was told to use |
| `server-challenge.bin` | the 16-byte serverChallenge the SM-DP+ was told to use |
| `otsk-dp.bin` | the 32-byte one-time SM-DP+ private key for the key agreement |
| `euicc-info1.der` | `EUICCInfo1`, from `ES10b.GetEUICCInfo` |
| `auth-server-response.der` | `AuthenticateServerResponse`, from `ES10b.AuthenticateServer` |
| `store-metadata.der` | `StoreMetadataRequest` — the Profile metadata this library has no database to look up, so a caller supplies it |
| `prepare-download-response.der` | `PrepareDownloadResponse`, from `ES10b.PrepareDownload` |
| `upp.der` | the Unprotected Profile Package that gets bound |

What this library made of them:

| File | What it is |
| --- | --- |
| `initiate-response.der` | `InitiateAuthenticationOkEs9` (SGP.22 v2.6 section 5.6.1) |
| `authenticate-response.der` | `AuthenticateClientResponseEs9` (section 5.6.3) |
| `bound-profile-package.der` | the `BoundProfilePackage` (section 5.6.2) |

The three outputs are recorded on purpose. A consumer replaying this
session can compare what it produced against them byte for byte, which is
a far stronger statement than "the call returned 0".

## Test material only

The eUICC-side answers here are signed with the published GSMA SGP.26
**test** credentials, the same ones
[`testdata/sgp26/`](../sgp26/README.md) describes. They work on test
eUICCs and nowhere else. A production eUICC rejects them, and a production
Profile must never be loaded with them.

The session's own address is `smdp.example.com`, from RFC 2606's reserved
`example.com`. Nothing here resolves and nothing here is meant to.
