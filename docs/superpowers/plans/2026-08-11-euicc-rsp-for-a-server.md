# euicc-rsp: what a server needs from the library — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `euicc-rsp` the two things an ES9+ HTTP server needs and it does not have: a real SM-DP+ address (given, signed, and checked against the one the LPA sent), and a way to read the individual fields of its two response blobs without re-encoding them.

**Architecture:** Both changes are additive to `src/rsp_es9.c` and `include/rsp.h`. The first extends `rsp_dp_initiate_authentication`'s parameter list and moves it into the header's `-1`/`-2` failure group, because it now has something real to refuse. The second adds two pure functions that slice an existing response buffer into borrowed views — no allocation, no ownership crossing a language boundary later, and byte-identical to what the library encoded.

**Tech Stack:** C99, mbedTLS, asn1c-generated codec in `dist/`, the repository's own `tests/run-*` harness driven by `make check`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-11-euicc-smdp-server-design.md`.
- Target specification: GSMA SGP.22 v2.6. Cite section numbers in comments the way the surrounding code already does.
- Failure convention (`include/rsp.h`, top comment): `0` success, `-1` the question was asked and the answer is no, `-2` the question was never reached. Functions with only one way to fail use plain `-1`.
- No new dependencies. No new build steps. `make check` must stay runnable with no card reader attached.
- Doc comments in `include/rsp.h` carry the reasoning, not just the signature — match the density already there.
- This plan touches `euicc-rsp` only. It **will** break `euicc-lpa`'s `src/lpa_install.c:272`, which calls `rsp_dp_initiate_authentication` with the old signature. That break does not surface until `euicc-lpa` bumps its `vendor/euicc-rsp` submodule, which is a separate change in a separate repository and is not part of this plan.

---

### Task 1: The SM-DP+ address, given and checked

`src/rsp_es9.c:191` signs a fixed placeholder, `"smdp-address-placeholder.invalid"`, because the function has no address parameter. The file's own top comment says what to do about it: "Whichever task first wires up server configuration should replace it with one, not extend it."

Reading SGP.22 v2.6 section 5.6.1 shows this is two values, not one. The SM-DP+ SHALL "[c]heck if the received address matches its own SM-DP+ address, where the comparison SHALL be case-insensitive", and `InitiateAuthenticationRequest` carries `smdpAddress [3] UTF8String` for exactly that purpose. So the function takes its own address — which goes into `ServerSigned1.serverAddress` — and the address the LPA sent, which is compared against it.

That comparison is the function's first genuine refusal (`InitiateAuthenticationError.invalidDpAddress(1)`), so it stops being a plain-`-1` function.

The comparison folds ASCII case only, with no `strcasecmp`: that function's behaviour depends on the locale, and a host name is not locale-dependent text.

**Files:**
- Modify: `include/rsp.h` (declaration and doc comment of `rsp_dp_initiate_authentication`, around line 448)
- Modify: `src/rsp_es9.c` (the placeholder constant at line ~191, the top comment's judgement-call note at line ~131, and the function body)
- Modify: `tests/test_es9.c` (existing call sites at lines ~489, ~799, ~861; new tests)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  ```c
  int rsp_dp_initiate_authentication(
          const uint8_t *euicc_challenge, size_t challenge_len,
          const uint8_t *euicc_info1, size_t info1_len,
          const uint8_t transaction_id[16],
          const char *server_address,
          const char *requested_address,
          rsp_dp_session_t **out,
          uint8_t **resp, size_t *resp_len);
  ```
  `server_address` is the SM-DP+'s own FQDN, NUL-terminated, required. `requested_address` is the `smdpAddress` the LPA sent, NUL-terminated; `NULL` means the caller has none to check and skips the comparison. Returns `0`; `-1` when `requested_address` is non-NULL and does not ASCII-case-insensitively equal `server_address`; `-2` for a null/malformed argument or an internal failure.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_es9.c`. Put the first two helpers just above `int main(void)`:

```c
/* SGP.22 v2.6 section 5.6.1 has the SM-DP+ compare the address the LPA
   sent against its own "case-insensitive[ly]". A host name is ASCII, and
   strcasecmp folds according to the locale, so this test states the
   property in the only terms that hold everywhere. */
static const char SMDP_ADDR[]  = "smdp.example.com";
static const char SMDP_UPPER[] = "SMDP.EXAMPLE.COM";
static const char SMDP_OTHER[] = "other.example.com";

/* Decode a response from rsp_dp_initiate_authentication and copy out
   ServerSigned1.serverAddress. Returns 0 on success. */
static int
server_address_of(const uint8_t *resp, size_t resp_len,
                  char *out, size_t out_cap) {
    InitiateAuthenticationOkEs9_t *ok = NULL;
    asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_InitiateAuthenticationOkEs9,
                                   (void **)&ok, resp, resp_len);
    int rc = -1;
    if (dr.code == RC_OK && ok) {
        const OCTET_STRING_t *a = &ok->serverSigned1.serverAddress;
        if ((size_t)a->size < out_cap) {
            memcpy(out, a->buf, (size_t)a->size);
            out[a->size] = '\0';
            rc = 0;
        }
    }
    ASN_STRUCT_FREE(asn_DEF_InitiateAuthenticationOkEs9, ok);
    return rc;
}
```

Then, inside `main`, immediately after the existing block that asserts `rsp_dp_initiate_authentication succeeds`:

```c
    {
        char addr[128] = { 0 };
        ok("serverSigned1 carries the address it was given",
           server_address_of(resp, resp_len, addr, sizeof addr) == 0
           && strcmp(addr, SMDP_ADDR) == 0);
        ok("no placeholder address survives",
           strstr(addr, ".invalid") == NULL);
    }

    {
        /* A case-only difference is not a mismatch (section 5.6.1). */
        rsp_dp_session_t *s2 = NULL;
        uint8_t *r2 = NULL;
        size_t r2_len = 0;
        int rc2 = rsp_dp_initiate_authentication(
                euicc_challenge, sizeof euicc_challenge,
                info1_buf, info1_len, transaction_id,
                SMDP_ADDR, SMDP_UPPER, &s2, &r2, &r2_len);
        ok("a case-only difference is accepted", rc2 == 0);
        free(r2);
        rsp_dp_session_free(s2);
    }

    {
        /* A real mismatch is a refusal, not an internal failure. */
        rsp_dp_session_t *s3 = NULL;
        uint8_t *r3 = NULL;
        size_t r3_len = 0;
        int rc3 = rsp_dp_initiate_authentication(
                euicc_challenge, sizeof euicc_challenge,
                info1_buf, info1_len, transaction_id,
                SMDP_ADDR, SMDP_OTHER, &s3, &r3, &r3_len);
        ok("a different address is refused with -1", rc3 == -1);
        ok("a refusal returns no session", s3 == NULL);
        ok("a refusal returns no response", r3 == NULL);
    }

    {
        /* A missing own-address is a question never reached, not a no. */
        rsp_dp_session_t *s4 = NULL;
        uint8_t *r4 = NULL;
        size_t r4_len = 0;
        int rc4 = rsp_dp_initiate_authentication(
                euicc_challenge, sizeof euicc_challenge,
                info1_buf, info1_len, transaction_id,
                NULL, SMDP_ADDR, &s4, &r4, &r4_len);
        ok("a null server address is -2, not -1", rc4 == -2);
    }

    {
        /* No address to check against is legitimate: the comparison is
           skipped, the signing is not. */
        rsp_dp_session_t *s5 = NULL;
        uint8_t *r5 = NULL;
        size_t r5_len = 0;
        char addr5[128] = { 0 };
        int rc5 = rsp_dp_initiate_authentication(
                euicc_challenge, sizeof euicc_challenge,
                info1_buf, info1_len, transaction_id,
                SMDP_ADDR, NULL, &s5, &r5, &r5_len);
        ok("a null requested address skips the check", rc5 == 0);
        ok("and still signs the real address",
           rc5 == 0 && server_address_of(r5, r5_len, addr5, sizeof addr5) == 0
           && strcmp(addr5, SMDP_ADDR) == 0);
        free(r5);
        rsp_dp_session_free(s5);
    }
```

Update the three existing call sites (lines ~489, ~799, ~861) to pass `SMDP_ADDR, SMDP_ADDR` between `transaction_id` and `&sess`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
make check
```

Expected: `tests/run-es9` fails to compile — "too many arguments to function `rsp_dp_initiate_authentication`". That is the failure; the signature does not exist yet.

- [ ] **Step 3: Change the declaration in `include/rsp.h`**

Replace the declaration around line 448 and rewrite its doc comment. Keep everything the existing comment says about `euicc_challenge`, `euicc_info1` and `transaction_id`; replace only the final paragraph about the failure convention, and add the two new parameters:

```c
/* … existing prose about euicc_challenge, euicc_info1, transaction_id …
 *
 * server_address is this SM-DP+'s own FQDN, NUL-terminated. It is what
 * ServerSigned1.serverAddress carries and what the eUICC will see
 * signed (section 5.7.13). It is required: there is no placeholder any
 * more, because a server that does not know its own address cannot
 * answer this function honestly.
 *
 * requested_address is the smdpAddress the LPA sent in
 * InitiateAuthenticationRequest (Table 35), NUL-terminated, or NULL.
 * Section 5.6.1 has the SM-DP+ "[c]heck if the received address matches
 * its own SM-DP+ address, where the comparison SHALL be
 * case-insensitive" -- so when it is not NULL it is compared against
 * server_address, folding ASCII case only. Not strcasecmp: that folds
 * according to the locale, and a host name is not locale-dependent
 * text. NULL means the caller has no such address to check -- a local
 * caller that never received one -- and the comparison is skipped. The
 * signing is not.
 *
 * On success (0), *out receives a new session … (unchanged) …
 *
 * -1 means the question was asked and the answer is no: requested_address
 * is not this server's address. That is
 * InitiateAuthenticationError.invalidDpAddress(1) on the wire, and it is
 * the only thing this function can refuse. -2 means the question was
 * never reached: a null or malformed argument (server_address included),
 * or an internal failure -- allocation, RNG seeding, credential loading,
 * signing. On any failure *out / *resp / *resp_len are untouched. */
int rsp_dp_initiate_authentication(
        const uint8_t *euicc_challenge, size_t challenge_len,
        const uint8_t *euicc_info1, size_t info1_len,
        const uint8_t transaction_id[16],
        const char *server_address,
        const char *requested_address,
        rsp_dp_session_t **out,
        uint8_t **resp, size_t *resp_len);
```

Also add `rsp_dp_initiate_authentication` to the list of functions named in the header's top failure-convention comment (it currently names four: `rsp_pki_verify`, `rsp_sign_verify`, `rsp_unprotect`, `rsp_bpp_recover`). Change "Four functions are different" to "Five functions are different" and add this one, noting that its question is put to a comparison rather than to a cryptographic primitive.

- [ ] **Step 4: Implement in `src/rsp_es9.c`**

Delete the placeholder constant at line ~191 entirely. Add the ASCII fold near the top of the file, with the other static helpers:

```c
/* Fold ASCII case only, for the section 5.6.1 address comparison.
   Deliberately not strcasecmp: that folds according to the locale, and
   a host name is not locale-dependent text -- a Turkish locale maps 'I'
   to a dotless lowercase and would make two equal FQDNs compare
   unequal. Returns 1 when equal. */
static int
ascii_ieq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        unsigned char ca = (unsigned char)*a, cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return *a == '\0' && *b == '\0';
}
```

In the function body, before any allocation or signing:

```c
    if (!server_address) return -2;
    if (requested_address && !ascii_ieq(server_address, requested_address))
        return -1;
```

Keep the existing null checks on the other arguments, changing their `return -1` to `return -2`. Then replace the placeholder use with the parameter:

```c
        OCTET_STRING_fromBuf(&ok.serverSigned1.serverAddress,
                             server_address, (int)strlen(server_address)) != 0
```

Finally, update the file's top comment: the first of the "[t]wo judgement calls" (around line 131) no longer applies. Replace that bullet with what is now true — the address is supplied by the caller, and the received one is checked against it per section 5.6.1.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
make check
```

Expected: every test binary passes, `tests/run-es9` included, with the eight new `ok` lines present and no `FAIL`.

- [ ] **Step 6: Verify the placeholder is genuinely gone**

```bash
grep -rn "invalid\"" src/ include/ | grep -i smdp
```

Expected: no output. If anything matches, a second copy of the placeholder survived and must be removed — the point of the change is that the library can no longer sign a fake address by accident.

- [ ] **Step 7: Commit**

```bash
git add include/rsp.h src/rsp_es9.c tests/test_es9.c
git commit -m "feat: the SM-DP+ knows its own address, and checks the one it was sent"
```

---

### Task 2: Field slices for the JSON binding

The ES9+ JSON binding (SGP.22 v2.6 sections 6.5.2.6 and 6.5.2.8) carries five separately named, separately base64-encoded fields per response. The library hands back one DER blob. Something has to open it.

It is done here rather than in the server for the reason commit `8928231` already established in this repository: the bytes that go on the wire must be the bytes that were produced, not a re-encoding of a decode. Slicing gives exactly that — each field is a borrowed view into the response buffer, byte-identical to what was signed and encoded. It also keeps the structure known in one place instead of two.

Both accessors must walk their SEQUENCE **positionally**, not by tag. In `InitiateAuthenticationOkEs9`, `serverSigned1` and `serverCertificate` are both untagged SEQUENCEs and both encode with tag `30`; in `AuthenticateClientOk`, `smdpSigned2` and `smdpCertificate` are the same. A tag search would find the wrong one.

The two functions take blobs at different levels, and that is deliberate: `rsp_dp_initiate_authentication` returns `InitiateAuthenticationOkEs9` (the inner SEQUENCE) and `rsp_dp_authenticate_client` returns `AuthenticateClientResponseEs9` (the CHOICE, tag `BF3B`). The spec document called for straightening that out; doing so would change bytes `euicc-lpa`'s `PrepareDownload` repacking already depends on, for no gain that this plan needs. The difference is absorbed here and documented instead.

**Files:**
- Modify: `include/rsp.h` (two structs and two declarations, after `rsp_dp_verify_installation_result`)
- Modify: `src/rsp_es9.c` (implementation; reuses the existing `find_tlv` at line ~1204)
- Modify: `tests/test_es9.c` (new tests)

**Interfaces:**
- Consumes: `rsp_dp_initiate_authentication` from Task 1 (new signature), and the existing `rsp_dp_authenticate_client`.
- Produces:
  ```c
  typedef struct {
      const uint8_t *transaction_id;     size_t transaction_id_len;
      const uint8_t *server_signed1;     size_t server_signed1_len;
      const uint8_t *server_signature1;  size_t server_signature1_len;
      const uint8_t *euicc_ci_pkid;      size_t euicc_ci_pkid_len;
      const uint8_t *server_certificate; size_t server_certificate_len;
  } rsp_dp_initiate_fields_t;

  typedef struct {
      const uint8_t *transaction_id;    size_t transaction_id_len;
      const uint8_t *profile_metadata;  size_t profile_metadata_len;
      const uint8_t *smdp_signed2;      size_t smdp_signed2_len;
      const uint8_t *smdp_signature2;   size_t smdp_signature2_len;
      const uint8_t *smdp_certificate;  size_t smdp_certificate_len;
  } rsp_dp_authenticate_fields_t;

  int rsp_dp_initiate_fields(const uint8_t *resp, size_t resp_len,
                             rsp_dp_initiate_fields_t *out);
  int rsp_dp_authenticate_fields(const uint8_t *resp, size_t resp_len,
                                 rsp_dp_authenticate_fields_t *out);
  ```
  Each pointer borrows from `resp` and is valid only as long as it is. Each slice is the **complete** TLV of its field — tag and length included — because that is what the JSON binding base64-encodes and what the eUICC expects to receive back. Returns `0`, or `-1` when the buffer does not have the expected shape, or `-2` for a null argument.

- [ ] **Step 1: Write the failing tests**

Add inside `main` in `tests/test_es9.c`, after the response from `rsp_dp_initiate_authentication` exists:

```c
    {
        rsp_dp_initiate_fields_t f;
        memset(&f, 0, sizeof f);
        ok("initiate fields slice out", rsp_dp_initiate_fields(resp, resp_len, &f) == 0);
        ok("every initiate field is non-empty",
           f.transaction_id_len && f.server_signed1_len && f.server_signature1_len
           && f.euicc_ci_pkid_len && f.server_certificate_len);
        /* Borrowed, not copied: each slice points inside resp. */
        ok("initiate fields borrow from the response",
           f.transaction_id >= resp && f.server_certificate + f.server_certificate_len
                                        <= resp + resp_len);
        /* The two untagged SEQUENCEs must not be confused for each other:
           serverSigned1 comes before serverSignature1, the certificate
           after it. Positional, not by tag. */
        ok("serverSigned1 precedes serverSignature1",
           f.server_signed1 < f.server_signature1);
        ok("serverCertificate follows serverSignature1",
           f.server_certificate > f.server_signature1);
        /* serverSignature1 is [APPLICATION 55], tag 5F37. */
        ok("serverSignature1 carries its own tag",
           f.server_signature1_len > 2 && f.server_signature1[0] == 0x5f
           && f.server_signature1[1] == 0x37);
        /* transactionId is [0], tag A0. */
        ok("transactionId carries its own tag",
           f.transaction_id_len > 2 && f.transaction_id[0] == 0xa0);

        ok("a truncated response is refused, not misread",
           rsp_dp_initiate_fields(resp, resp_len / 2, &f) == -1);
        ok("a null response is -2", rsp_dp_initiate_fields(NULL, resp_len, &f) == -2);
        ok("a null out is -2", rsp_dp_initiate_fields(resp, resp_len, NULL) == -2);
    }
```

And, in the existing block that already holds a successful `rsp_dp_authenticate_client` response — its buffer is `ac_out` / `ac_out_len`, filled at `tests/test_es9.c:641` — add after the `a response was returned` assertion:

```c
    {
        rsp_dp_authenticate_fields_t g;
        memset(&g, 0, sizeof g);
        ok("authenticate fields slice out",
           rsp_dp_authenticate_fields(ac_out, ac_out_len, &g) == 0);
        ok("every authenticate field is non-empty",
           g.transaction_id_len && g.profile_metadata_len && g.smdp_signed2_len
           && g.smdp_signature2_len && g.smdp_certificate_len);
        /* profileMetaData is [37], tag BF25. */
        ok("profileMetadata carries its own tag",
           g.profile_metadata_len > 2 && g.profile_metadata[0] == 0xbf
           && g.profile_metadata[1] == 0x25);
        /* smdpSignature2 is [APPLICATION 55], tag 5F37. */
        ok("smdpSignature2 carries its own tag",
           g.smdp_signature2_len > 2 && g.smdp_signature2[0] == 0x5f
           && g.smdp_signature2[1] == 0x37);
        ok("smdpCertificate follows smdpSignature2",
           g.smdp_certificate > g.smdp_signature2);
        ok("a truncated response is refused",
           rsp_dp_authenticate_fields(ac_out, ac_out_len / 2, &g) == -1);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
make check
```

Expected: `tests/run-es9` fails to compile — `rsp_dp_initiate_fields_t` and both functions are undeclared.

- [ ] **Step 3: Declare the structs and functions in `include/rsp.h`**

Append after `rsp_dp_verify_installation_result`, with a doc comment that states the three things a caller must know: the slices borrow, each slice is a whole TLV, and the two functions take blobs at different levels because their producers do.

```c
/* The ES9+ JSON binding (SGP.22 v2.6 sections 6.5.2.6 and 6.5.2.8) sends
 * five separately named, separately base64-encoded fields per response.
 * These two functions cut them out of the single DER blob the two
 * functions above return.
 *
 * Cut, not decoded and re-encoded. The bytes a server puts on the wire
 * are then the bytes this library produced and signed -- the same reason
 * rsp_dp_verify_installation_result verifies the received
 * ProfileInstallationResultData rather than a reconstruction of it.
 *
 * Every pointer borrows from resp and is valid exactly as long as resp
 * is. Nothing is allocated and there is nothing to free. Each slice is
 * the complete TLV of its field, tag and length included: that is what
 * the binding base64-encodes, and what the eUICC expects back.
 *
 * The two take blobs at different levels, because their producers
 * return different levels: rsp_dp_initiate_authentication returns an
 * InitiateAuthenticationOkEs9 (the inner SEQUENCE), while
 * rsp_dp_authenticate_client returns an AuthenticateClientResponseEs9
 * (the CHOICE, tag 'BF3B'), so this one steps through the CHOICE first.
 *
 * Both walk their SEQUENCE positionally rather than searching by tag,
 * and must: InitiateAuthenticationOkEs9's serverSigned1 and
 * serverCertificate are both untagged SEQUENCEs encoding with tag '30',
 * as are AuthenticateClientOk's smdpSigned2 and smdpCertificate. A tag
 * search would find the first and call it the second.
 *
 * Returns 0. -1 means the question was asked and the answer is no: the
 * buffer is not the shape this function expects -- truncated, or some
 * other DER object. -2 means the question was never reached: a null
 * argument. */
typedef struct {
    const uint8_t *transaction_id;     size_t transaction_id_len;
    const uint8_t *server_signed1;     size_t server_signed1_len;
    const uint8_t *server_signature1;  size_t server_signature1_len;
    const uint8_t *euicc_ci_pkid;      size_t euicc_ci_pkid_len;
    const uint8_t *server_certificate; size_t server_certificate_len;
} rsp_dp_initiate_fields_t;

typedef struct {
    const uint8_t *transaction_id;    size_t transaction_id_len;
    const uint8_t *profile_metadata;  size_t profile_metadata_len;
    const uint8_t *smdp_signed2;      size_t smdp_signed2_len;
    const uint8_t *smdp_signature2;   size_t smdp_signature2_len;
    const uint8_t *smdp_certificate;  size_t smdp_certificate_len;
} rsp_dp_authenticate_fields_t;

int rsp_dp_initiate_fields(const uint8_t *resp, size_t resp_len,
                           rsp_dp_initiate_fields_t *out);
int rsp_dp_authenticate_fields(const uint8_t *resp, size_t resp_len,
                               rsp_dp_authenticate_fields_t *out);
```

Add both to the header's top failure-convention comment alongside Task 1's addition.

- [ ] **Step 4: Implement in `src/rsp_es9.c`**

Add one TLV primitive and one field-taker near `find_tlv` (line ~1204), then the two functions:

```c
/* Parse the TLV at off. *val_off / *val_len become its value, and
   *next_off where the next TLV begins. Multi-byte tags and long-form
   lengths both occur here -- 'BF25', and certificates longer than 127
   bytes -- so neither may be assumed away. Returns 0, or -1 when the
   buffer runs out, when the length is the indefinite form (which DER
   forbids), or when it is wider than a size_t. */
static int
parse_tlv(const uint8_t *buf, size_t end, size_t off,
          size_t *val_off, size_t *val_len, size_t *next_off) {
    size_t p = off, len = 0;
    if (p >= end) return -1;
    /* Tag: low five bits all set means it continues into further bytes,
       each with its high bit set while more follow. */
    if ((buf[p] & 0x1f) == 0x1f) {
        p++;
        while (p < end && (buf[p] & 0x80)) p++;
        if (p >= end) return -1;
    }
    p++;
    if (p >= end) return -1;
    /* Length: short form is the byte itself. Long form has the low
       seven bits give how many bytes follow; 0x80 alone is the
       indefinite form and is refused. */
    if (buf[p] < 0x80) {
        len = buf[p];
        p++;
    } else {
        size_t n = (size_t)(buf[p] & 0x7f), i;
        p++;
        if (n == 0 || n > sizeof(size_t) || n > end - p) return -1;
        for (i = 0; i < n; i++) len = (len << 8) | buf[p + i];
        p += n;
    }
    if (len > end - p) return -1;
    *val_off  = p;
    *val_len  = len;
    *next_off = p + len;
    return 0;
}

/* Cut the field at *off out whole -- tag and length included, which is
   what the JSON binding base64-encodes -- and move *off past it. */
static int
take_field(const uint8_t *buf, size_t end, size_t *off,
           const uint8_t **tlv, size_t *tlv_len) {
    size_t v_off, v_len, next;
    if (parse_tlv(buf, end, *off, &v_off, &v_len, &next) != 0) return -1;
    *tlv     = buf + *off;
    *tlv_len = next - *off;
    *off     = next;
    return 0;
}

int
rsp_dp_initiate_fields(const uint8_t *resp, size_t resp_len,
                       rsp_dp_initiate_fields_t *out) {
    size_t v_off, v_len, next, off, end;
    if (!resp || !out) return -2;
    /* resp is the InitiateAuthenticationOkEs9 SEQUENCE itself; step
       inside it and walk its five members in order. */
    if (parse_tlv(resp, resp_len, 0, &v_off, &v_len, &next) != 0) return -1;
    off = v_off;
    end = v_off + v_len;
    if (take_field(resp, end, &off, &out->transaction_id,
                   &out->transaction_id_len) != 0) return -1;
    if (take_field(resp, end, &off, &out->server_signed1,
                   &out->server_signed1_len) != 0) return -1;
    if (take_field(resp, end, &off, &out->server_signature1,
                   &out->server_signature1_len) != 0) return -1;
    if (take_field(resp, end, &off, &out->euicc_ci_pkid,
                   &out->euicc_ci_pkid_len) != 0) return -1;
    if (take_field(resp, end, &off, &out->server_certificate,
                   &out->server_certificate_len) != 0) return -1;
    return 0;
}

int
rsp_dp_authenticate_fields(const uint8_t *resp, size_t resp_len,
                           rsp_dp_authenticate_fields_t *out) {
    size_t v_off, v_len, next, off, end;
    if (!resp || !out) return -2;
    /* resp is the AuthenticateClientResponseEs9 CHOICE (tag 'BF3B').
       Step inside it to reach the authenticateClientOk SEQUENCE, then
       inside that to reach its five members. */
    if (parse_tlv(resp, resp_len, 0, &v_off, &v_len, &next) != 0) return -1;
    if (parse_tlv(resp, v_off + v_len, v_off, &v_off, &v_len, &next) != 0)
        return -1;
    off = v_off;
    end = v_off + v_len;
    if (take_field(resp, end, &off, &out->transaction_id,
                   &out->transaction_id_len) != 0) return -1;
    if (take_field(resp, end, &off, &out->profile_metadata,
                   &out->profile_metadata_len) != 0) return -1;
    if (take_field(resp, end, &off, &out->smdp_signed2,
                   &out->smdp_signed2_len) != 0) return -1;
    if (take_field(resp, end, &off, &out->smdp_signature2,
                   &out->smdp_signature2_len) != 0) return -1;
    if (take_field(resp, end, &off, &out->smdp_certificate,
                   &out->smdp_certificate_len) != 0) return -1;
    return 0;
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
make check
```

Expected: all binaries pass, with the sixteen new `ok` lines and no `FAIL`. If the `authenticateClientOk` walk returns `-1`, check whether `rsp_dp_authenticate_client` really encodes the CHOICE — `src/rsp_es9.c:825` sets `ok_resp.present = AuthenticateClientResponseEs9_PR_authenticateClientOk` before `der_encode_alloc(&asn_DEF_AuthenticateClientResponseEs9, …)`, so it does — and then whether one `enter_tlv` too many or too few is being applied.

- [ ] **Step 6: Prove the slices are the encoded bytes, not a reconstruction**

Add one test that closes the loop against a field the repository already knows how to build independently. In `tests/test_es9.c`, after the initiate-fields block:

```c
    {
        /* The whole point of slicing: what comes out is what went in.
           Re-encode ServerSigned1 from a decode of the response and
           require the bytes to be identical to the slice. If they ever
           differ, this function has started reconstructing rather than
           cutting, and a BER response would silently change on the
           wire -- the failure commit 8928231 removed elsewhere. */
        rsp_dp_initiate_fields_t f;
        InitiateAuthenticationOkEs9_t *okp = NULL;
        unsigned char again[512];
        struct sink sk = { again, 0, sizeof again };
        asn_dec_rval_t dr;

        memset(&f, 0, sizeof f);
        ok("fields for the round trip", rsp_dp_initiate_fields(resp, resp_len, &f) == 0);
        dr = ber_decode(NULL, &asn_DEF_InitiateAuthenticationOkEs9,
                        (void **)&okp, resp, resp_len);
        ok("the response decodes", dr.code == RC_OK && okp != NULL);
        if (okp) {
            asn_enc_rval_t er = der_encode(&asn_DEF_ServerSigned1,
                                           &okp->serverSigned1, collect, &sk);
            ok("serverSigned1 re-encodes", er.encoded > 0);
            ok("and the slice is byte-identical",
               sk.len == f.server_signed1_len
               && memcmp(again, f.server_signed1, f.server_signed1_len) == 0);
        }
        ASN_STRUCT_FREE(asn_DEF_InitiateAuthenticationOkEs9, okp);
    }
```

`struct sink` is declared at `tests/test_es9.c:69` as `{ unsigned char *p; size_t len; size_t cap; }` and its `der_encode` callback is `collect` — hence the `{ again, 0, sizeof again }` initialiser order.

Run `make check` again. Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add include/rsp.h src/rsp_es9.c tests/test_es9.c
git commit -m "feat: hand back the response fields the JSON binding names"
```

---

### Task 3: Say what changed, in the README

The README's own account of this library is now wrong in one place and incomplete in another. It says `serverAddress` "has no parameter that could carry a real value yet, so an `.invalid` placeholder is genuinely signed in its place" — no longer true after Task 1.

**Files:**
- Modify: `README.md` (the paragraph beginning "One more sits a level up, in ES9+")

**Interfaces:**
- Consumes: Tasks 1 and 2.
- Produces: nothing code depends on.

- [ ] **Step 1: Replace the `serverAddress` paragraph**

Replace it with what is now true: the address is supplied by the caller and signed, and the address the LPA sent is checked against it case-insensitively per section 5.6.1. Note that the list of what remains open in the BPP (Profile Protection Keys, multi-segment `'88'`, the OPTIONAL metadata fields) is unchanged.

- [ ] **Step 2: Add a sentence about the field accessors**

In the same area, one sentence: the library now hands back the individual response fields the ES9+ JSON binding names, so a server can encode them without re-encoding what was signed.

- [ ] **Step 3: Verify the README makes no claim the tests do not**

```bash
make check
```

Expected: pass. Read the changed paragraphs once against the test output and confirm every claim is one a test covers.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: the address is real now, and the fields come apart"
```

---

## What this plan does not cover

The spec spans three repositories. This plan is the first of three, and it is the one that has to land first because everything else links against it.

- **`euicc-smdp`** — the Rust workspace, `rsp-sys` and bindgen, the safe wrapper, the store, the CLI, the three endpoints. Gets its own plan once this one lands and the C API it binds to is fixed. Writing it before that would be writing against a signature that is still moving.
- **`euicc-tools`** — `euicc card install --server URL` and the certificate-trust flag, then the download onto real hardware. Gets its own plan, after `euicc-smdp` has something to talk to.

`euicc-lpa` needs a small change too, but not a plan: bumping `vendor/euicc-rsp` past Task 1 breaks `src/lpa_install.c:272`, and the fix is to pass an address through — one parameter, following whatever `rsp_lpa_install`'s own caller supplies.
