# P-256 ECDH test vector

`ecdh-p256.txt` pins `rsp_ecdh_p256` to a single published key-agreement
case, one hex string per line:

1. the private scalar of party A
2. `04` followed by the uncompressed public point of party B (65 bytes)
3. the expected shared x coordinate

## Provenance

The brief asked for a case from the NIST CAVP key-agreement vectors for
P-256, or from any other published P-256 ECDH test case that gives all
three values. The CAVP vector archive is a zip on NIST's CSRC site with
no stable per-case URL, so this instead uses a case from a small,
directly readable RFC text that gives the same three values:

**RFC 5903, "Elliptic Curve Groups modulo a Prime (ECP Groups) for IKE
and IKEv2", Section 8.1, "256-Bit Random ECP Group"**
(<https://www.rfc-editor.org/rfc/rfc5903.txt>).

That section runs one complete ECDH exchange over the NIST P-256 curve
(IANA DH group 19) between an "initiator" and a "responder". This
project's three-line vector maps onto it as:

- line 1 (A's private scalar) = the initiator's private key, labeled `i`
- line 2 (B's public point) = `04` + the responder's public key
  `(grx, gry)`
- line 3 (expected shared x) = `girx`, the x coordinate of the shared
  point `(girx, giry)` -- RFC 5903 states plainly: "The Diffie-Hellman
  shared secret value is girx."

No value was renamed, reordered, or recomputed; each line is the exact
hex digits from the labeled field in the RFC, concatenated without the
RFC's line-wrapping spaces.

Verify against the RFC text directly:

```sh
curl -s https://www.rfc-editor.org/rfc/rfc5903.txt | grep -A1 '^i:'
curl -s https://www.rfc-editor.org/rfc/rfc5903.txt | grep -A1 '^grx:\|^gry:\|^girx:'
```
