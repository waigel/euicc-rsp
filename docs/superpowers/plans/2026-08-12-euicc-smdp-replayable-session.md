# euicc-smdp, part one: a replayable RSP session in Rust — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a whole SM-DP+ session reproducible from fixed inputs, capture one as fixtures, and stand up the `euicc-smdp` Rust workspace far enough that a Rust test drives `InitiateAuthentication` → `AuthenticateClient` → `GetBoundProfilePackage` through the C library and gets a Bound Profile Package back — with no card attached.

**Architecture:** Three of five tasks are in `euicc-rsp` (C) and land first: `serverChallenge` stops being generated internally, and a tool dumps one session's eUICC-side bytes so anything can replay it. The other two create `euicc-smdp` — a Cargo workspace whose `rsp-sys` crate builds and links the C library, and whose safe wrapper preserves the library's `-1`/`-2` distinction instead of flattening it.

**Tech Stack:** C99 + the existing Makefile and `tests/run-*` harness; Rust 1.95 (verified present), `bindgen` in a `build.rs`, `libclang` from the macOS Command Line Tools (verified present at `/Library/Developer/CommandLineTools/usr/lib/libclang.dylib`).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-11-euicc-smdp-server-design.md`.
- Target specification: GSMA SGP.22 v2.6. Cite section numbers in comments the way the surrounding code already does.
- `euicc-rsp` failure convention: `0` success, `-1` question asked and answered no, `-2` question never reached. The Rust wrapper must keep the two apart.
- Everything in this plan must be provable with no card reader attached. `make check` in `euicc-rsp` and `cargo test` in `euicc-smdp` are the two gates.
- The new repository lives at `~/git/waigel/euicc-smdp`, beside its four siblings, and vendors `euicc-rsp` as a submodule the way `euicc-tools` vendors `euicc-lpa`.
- Tasks 1 and 2 change `euicc-rsp`'s public API again. That breaks `euicc-lpa`'s `src/lpa_install.c:272` on its next submodule bump — already true from the previous plan, and not fixed here.
- No new C dependencies. The Rust side pulls only `bindgen` (build) in this plan.

---

### Task 1: `serverChallenge` comes from the caller

`rsp_dp_initiate_authentication` generates its own `serverChallenge` from real entropy. That single value is what makes a session unreproducible: `AuthenticateClient` needs an `AuthenticateServerResponse` the eUICC signed over *that* challenge, so no recorded fixture can ever satisfy it.

The library already solved this twice, and `include/rsp.h` states the rule: `transaction_id` and `otsk_dp` are caller-supplied because "production passes fresh random, a test passes a fixed value, and that difference is the entire reason a recorded session can be replayed -- there is no fallback that generates one internally, so there is no test path that ships that way by accident." `serverChallenge` is the last value in this function that escapes it.

The RNG in this function serves nothing else — `rsp_sign` signs deterministically (commit `bec7a8e`) — so the entropy context, the DRBG, `have_rng` and their cleanup all leave with it. The function becomes a pure function of its inputs.

**Files:**
- Modify: `include/rsp.h` (declaration and doc comment, around line 457)
- Modify: `src/rsp_es9.c` (the function's locals, the RNG block, the cleanup)
- Modify: `tests/test_es9.c` (four call sites, one new assertion)

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```c
  int rsp_dp_initiate_authentication(
          const uint8_t *euicc_challenge, size_t challenge_len,
          const uint8_t *euicc_info1, size_t info1_len,
          const uint8_t transaction_id[16],
          const uint8_t server_challenge[16],
          const char *server_address,
          const char *requested_address,
          rsp_dp_session_t **out,
          uint8_t **resp, size_t *resp_len);
  ```
  `server_challenge` is 16 bytes the caller supplies. No internal fallback. Return values are unchanged from the previous plan: `0`, `-1` only for an address mismatch, `-2` for a null/malformed argument or internal failure.

- [ ] **Step 1: Write the failing test**

In `tests/test_es9.c`, add a fixed challenge beside the existing fixed `transaction_id` at the top of `main`:

```c
    static const uint8_t server_challenge_in[16] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f
    };
```

Add `server_challenge_in,` after `transaction_id,` at all four call sites (the main one, and the three inside the address-check and negative blocks). Then, next to the existing `serverSigned1.euiccChallenge` assertion, add:

```c
    ok("serverSigned1.serverChallenge is the one that was passed in",
       decoded->serverSigned1.serverChallenge.size == 16 &&
       memcmp(decoded->serverSigned1.serverChallenge.buf,
              server_challenge_in, 16) == 0);
```

And, immediately after it, the assertion that gives the whole task its point:

```c
    /* The function is now a pure function of its inputs: same inputs,
       byte-identical output. This is what lets a session be recorded
       once and replayed anywhere -- see tools/session-fixtures. */
    {
        rsp_dp_session_t *sr = NULL;
        uint8_t *rr = NULL;
        size_t rr_len = 0;
        int rcr = rsp_dp_initiate_authentication(
                euicc_challenge, sizeof euicc_challenge,
                info1_buf, info1_len, transaction_id, server_challenge_in,
                SMDP_ADDR, SMDP_ADDR, &sr, &rr, &rr_len);
        ok("the same inputs open a session again", rcr == 0);
        ok("and produce a byte-identical response",
           rcr == 0 && rr_len == resp_len &&
           memcmp(rr, resp, resp_len) == 0);
        free(rr);
        rsp_dp_session_free(sr);
    }
```

The existing capture of `server_challenge` out of the decoded response (the comment at `tests/test_es9.c` explaining that it must be read back because it is generated internally) is now redundant but still correct — leave it, and let the new assertion prove it equals the input.

- [ ] **Step 2: Run the test to verify it fails**

```bash
make check
```

Expected: `tests/run-es9` fails to compile with "too many arguments to function call, expected 10, have 11".

- [ ] **Step 3: Change the declaration in `include/rsp.h`**

Add the parameter, and extend the paragraph that already explains `transaction_id` so the two are argued for together rather than separately:

```c
 * transaction_id and server_challenge are 16 bytes each, both supplied
 * by the caller and neither generated inside: production passes fresh
 * random, a test passes a fixed value, and that difference is the entire
 * reason a recorded session can be replayed -- there is no fallback that
 * generates either one internally, so there is no test path that ships
 * that way by accident. With both fixed, and rsp_sign signing
 * deterministically, this function is a pure function of its inputs.
```

Delete the older sentence that made this claim about `transaction_id` alone, so the file does not say it twice.

- [ ] **Step 4: Implement in `src/rsp_es9.c`**

Add `const uint8_t server_challenge[16],` to the definition, after `transaction_id`. Then delete, from the function body:

- the locals `mbedtls_entropy_context ent;`, `mbedtls_ctr_drbg_context drbg;`, `int have_rng = 0;`, and the local array `uint8_t server_challenge[16];` (now the parameter);
- the whole `have_rng = rsp_rng_init(...)` block and its `goto out`;
- the `if (have_rng) { mbedtls_ctr_drbg_free(&drbg); ... }` cleanup at `out:`.

Add a null check for the new parameter to the existing guard:

```c
    if (!euicc_challenge || challenge_len != 16 || !euicc_info1 ||
        info1_len == 0 || !transaction_id || !server_challenge ||
        !server_address || !out || !resp || !resp_len) {
        goto out;
    }
```

`sizeof server_challenge` no longer means 16 — it is a pointer now. Replace both uses (the `OCTET_STRING_fromBuf` for `serverSigned1.serverChallenge`, and the `memcpy` into the session) with the literal `16`, matching how `transaction_id` is already handled two lines above each.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
make check
```

Expected: all binaries pass. If "the same inputs produce a byte-identical response" fails, something else in the path is still non-deterministic — find it before continuing, because Task 2 depends on this property.

- [ ] **Step 6: Verify the RNG really left this function**

```bash
sed -n '/^int rsp_dp_initiate_authentication/,/^}/p' src/rsp_es9.c | grep -c "drbg\|rsp_rng_init"
```

Expected: `0`.

- [ ] **Step 7: Commit**

```bash
git add include/rsp.h src/rsp_es9.c tests/test_es9.c
git commit -m "feat: the server challenge comes from the caller, so a session can be replayed"
```

---

### Task 2: One session's eUICC-side bytes, on disk

A Rust test cannot build an `AuthenticateServerResponse`: doing so means signing with the SGP.26 test eUICC key over a structure the C test suite already knows how to assemble. Rather than reimplement eight fixture builders in Rust, `euicc-rsp` writes them out once.

The eight builders live in `tests/test_es9.c` as `static` functions (`build_euicc_info1`, `build_euicc_info2`, `build_device_info`, `build_ctx_params1`, `build_auth_server_response`, `build_store_metadata`, `build_installation_result`, `build_prepare_download_response`). They move to a shared translation unit so the tool and the test use one copy — two copies of a fixture builder is exactly the drift this repository keeps designing against.

**Files:**
- Create: `tests/fixtures.h`, `tests/fixtures.c` (the eight builders, moved verbatim, `static` dropped)
- Modify: `tests/test_es9.c` (delete the eight definitions, `#include "fixtures.h"`)
- Modify: `Makefile` (compile `tests/fixtures.c` into every test binary; add a `tools/session-fixtures` rule)
- Create: `tools/session-fixtures.c`
- Create: `testdata/session/README.md`

**Interfaces:**
- Consumes: Task 1's signature.
- Produces: `testdata/session/` holding six files, each raw DER or raw bytes, written by `make session-fixtures`:

  | File | What it is |
  | --- | --- |
  | `euicc-challenge.bin` | the fixed 16-byte eUICC challenge |
  | `transaction-id.bin` | the fixed 16-byte transactionId |
  | `server-challenge.bin` | the fixed 16-byte serverChallenge |
  | `euicc-info1.der` | `EUICCInfo1`, the input to InitiateAuthentication |
  | `auth-server-response.der` | `AuthenticateServerResponse`, the input to AuthenticateClient |
  | `prepare-download-response.der` | `PrepareDownloadResponse`, the input to GetBoundProfilePackage |
  | `store-metadata.der` | `StoreMetadataRequest`, which `AuthenticateClient` requires the caller to supply |
  | `upp.der` | the Unprotected Profile Package that gets bound |

  The tool's own `otsk_dp` is the fixed 32-byte value `0x11` repeated, for the same reason every other input here is fixed. Task 5's Rust test passes the same value.

- [ ] **Step 1: Move the builders, and prove nothing changed**

Create `tests/fixtures.h` declaring the eight functions with exactly the signatures they have today (copy each `static int build_...(...)` line, drop `static`, add `;`). Create `tests/fixtures.c` with `#include "fixtures.h"` plus the includes `tests/test_es9.c` currently uses for them, and move the eight bodies across unchanged, dropping `static`.

In `tests/test_es9.c`, delete the eight definitions and add `#include "fixtures.h"`. The `struct sink` and `collect` helpers are used by the builders, so they move to `fixtures.c` too and get declared in `fixtures.h`.

Change the Makefile's generic test rule to compile the shared unit alongside each test:

```make
FIXTURES := tests/fixtures.c

tests/run-%: tests/test_%.c $(FIXTURES) $(LIB) $(MBED_LIBS) $(DIST)/.stamp Makefile
	$(CC) $(ALL_CFLAGS) $(GEN_INC) $< $(FIXTURES) $(LIB) $(DIST)/*.o $(MBED_LIBS) -o $@
	@rm -rf $@.dSYM
```

- [ ] **Step 2: Run the tests — the move must change nothing**

```bash
make check
```

Expected: the same count as before the move, all passing. A pure move that changes a number means it was not a pure move.

- [ ] **Step 3: Commit the move on its own**

Keeping the refactor and the new tool in separate commits is what makes either one reviewable.

```bash
git add tests/fixtures.h tests/fixtures.c tests/test_es9.c Makefile
git commit -m "refactor: the fixture builders get their own translation unit"
```

- [ ] **Step 4: Write the tool**

Create `tools/session-fixtures.c`. It runs the three DP steps with the fixed inputs, calling the moved builders for each eUICC-side answer, and writes every blob it used or produced:

```c
/*
 * session-fixtures -- write one whole RSP session's bytes to disk, so
 * something that is not this repository can replay it.
 *
 * Every input here is fixed, and rsp_dp_initiate_authentication is a
 * pure function of its inputs since the serverChallenge stopped being
 * generated internally. Running this twice produces identical files;
 * that is the property that makes the output a fixture rather than a
 * recording of one particular afternoon.
 *
 * The eUICC-side answers are built with the SGP.26 test material by the
 * same builders tests/test_es9.c uses (tests/fixtures.h) -- one copy,
 * so a fixture and the test that pins it cannot drift apart.
 */
```

It must, in order: build `EUICCInfo1`; call `rsp_dp_initiate_authentication` with the fixed challenge, transactionId and server challenge; read the serverChallenge back out of the response (it equals the input, and reading it back is what a real LPA does); build the `AuthenticateServerResponse` over that; build the `StoreMetadataRequest`; call `rsp_dp_authenticate_client`; build the `PrepareDownloadResponse` over the resulting `smdpSigned2`/`smdpSignature2`; call `rsp_dp_get_bound_profile_package` with a fixed `otsk_dp`; and write the seven files. It exits non-zero with a message naming the step if any call does not return 0.

Add the Makefile rule beside the existing `tools/bpp-dump` one, following its shape, and a phony target:

```make
session-fixtures: tools/session-fixtures
	./tools/session-fixtures testdata/session
```

- [ ] **Step 5: Run it, and check the property that matters**

```bash
make session-fixtures
ls -l testdata/session/
shasum testdata/session/*.der > /tmp/first.txt
make session-fixtures
shasum testdata/session/*.der | diff - /tmp/first.txt && echo "reproducible"
```

Expected: seven files, non-empty, and `reproducible` printed. If the second run differs, Task 1 is incomplete — something on the path still draws entropy.

- [ ] **Step 6: Say what the fixtures are**

Write `testdata/session/README.md`: what each file is, that they are regenerated with `make session-fixtures` rather than edited, that every value in them is fixed on purpose, and that they are SGP.26 **test** material and work on test eUICCs and nowhere else — the same warning `testdata/sgp26/README.md` already carries.

- [ ] **Step 7: Commit**

```bash
git add tools/session-fixtures.c Makefile testdata/session
git commit -m "feat: write one session's bytes down, so it can be replayed elsewhere"
```

---

### Task 3: The workspace, and proof that Rust can reach the C

This is the riskiest task in the plan and it is deliberately small: it ends the moment a Rust test calls one C function and gets a sane answer back. Everything after it is ordinary work; this is the part that either links or does not.

Two things are already verified on this machine and should not be re-litigated: `cargo`/`rustc` 1.95.0 are installed, and `libclang.dylib` is present in the Command Line Tools, so `bindgen` can run.

Two facts about `euicc-rsp`'s build shape drive the `build.rs`: linking needs `librsp.a` **and** `dist/*.o` **and** the two mbedTLS archives (that is the test rule's own link line), and `dist/` holds over three hundred object files — so they get bundled into one archive rather than emitted as three hundred link arguments.

**Files:**
- Create: `~/git/waigel/euicc-smdp/` — `Cargo.toml`, `.gitignore`, `README.md`
- Create: `crates/rsp-sys/Cargo.toml`, `crates/rsp-sys/build.rs`, `crates/rsp-sys/src/lib.rs`
- Create: `crates/rsp-sys/tests/link.rs`
- Add: `vendor/euicc-rsp` as a submodule

**Interfaces:**
- Consumes: Tasks 1 and 2 (committed and pushed in `euicc-rsp`, so the submodule can point at them).
- Produces: the crate `rsp_sys`, re-exporting every `rsp_*` function and type from `include/rsp.h` as raw FFI.

- [ ] **Step 1: Create the repository and the workspace**

```bash
mkdir -p ~/git/waigel/euicc-smdp && cd ~/git/waigel/euicc-smdp
git init
git submodule add --depth 1 git@github.com:waigel/euicc-rsp.git vendor/euicc-rsp
git -C vendor/euicc-rsp submodule update --init --recursive
```

`Cargo.toml`:

```toml
[workspace]
members = ["crates/rsp-sys"]
resolver = "3"
```

`.gitignore`:

```
/target
```

- [ ] **Step 2: Write the failing test**

`crates/rsp-sys/tests/link.rs`:

```rust
use std::ffi::CStr;

/// The whole point of this crate: that the C library builds, links, and
/// answers. rsp_version is the cheapest question it can be asked.
#[test]
fn the_library_links_and_answers() {
    let raw = unsafe { rsp_sys::rsp_version() };
    assert!(!raw.is_null(), "rsp_version returned NULL");
    let v = unsafe { CStr::from_ptr(raw) }
        .to_str()
        .expect("the version is UTF-8");
    assert!(!v.is_empty(), "rsp_version returned an empty string");
}
```

- [ ] **Step 3: Run it to verify it fails**

```bash
cd ~/git/waigel/euicc-smdp && cargo test -p rsp-sys
```

Expected: failure — there is no `crates/rsp-sys/Cargo.toml` yet, so cargo reports the workspace member is missing.

- [ ] **Step 4: Write the crate**

```bash
cd ~/git/waigel/euicc-smdp/crates/rsp-sys && cargo add --build bindgen
```

Use whatever version that resolves to rather than pinning one from memory.

`crates/rsp-sys/Cargo.toml` — add `links = "rsp"` under `[package]`, which is how a `-sys` crate declares that it owns the native library and stops two copies being linked.

`crates/rsp-sys/src/lib.rs`:

```rust
//! Raw FFI for euicc-rsp. Generated from vendor/euicc-rsp/include/rsp.h
//! at build time -- the header is still changing, and a hand-maintained
//! copy would drift silently.
//!
//! Nothing here is safe to call. The wrapper in the `smdp` crate is what
//! turns these into something with lifetimes and a Result.
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
```

`crates/rsp-sys/build.rs`:

```rust
use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor = manifest
        .join("../../vendor/euicc-rsp")
        .canonicalize()
        .expect("vendor/euicc-rsp -- did the submodule get checked out?");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    // euicc-rsp's own Makefile builds librsp.a, generates the asn1c
    // codec into dist/, and builds the vendored mbedTLS. Driving it is
    // far better than reimplementing it: the codec generation alone has
    // an asn1c version floor and a skeleton-directory dance.
    let st = Command::new("make")
        .current_dir(&vendor)
        .status()
        .expect("could not run make");
    assert!(st.success(), "euicc-rsp's make failed");

    // dist/ holds hundreds of object files -- one per generated ASN.1
    // type. Bundle them into a single archive instead of emitting a
    // link argument each.
    let mut objs: Vec<PathBuf> = fs::read_dir(vendor.join("dist"))
        .expect("dist/ is missing -- did asn1c run?")
        .filter_map(|e| {
            let p = e.ok()?.path();
            (p.extension().and_then(|x| x.to_str()) == Some("o")).then_some(p)
        })
        .collect();
    assert!(!objs.is_empty(), "no dist/*.o to bundle");
    objs.sort(); // so the archive is reproducible

    let dist_a = out.join("libdist.a");
    let _ = fs::remove_file(&dist_a);
    let st = Command::new("ar")
        .arg("rcs")
        .arg(&dist_a)
        .args(&objs)
        .status()
        .expect("could not run ar");
    assert!(st.success(), "ar failed to build libdist.a");

    // Order matters: rsp refers to the codec and to mbedTLS, so it is
    // named first.
    println!("cargo:rustc-link-search=native={}", vendor.display());
    println!("cargo:rustc-link-search=native={}", out.display());
    println!(
        "cargo:rustc-link-search=native={}",
        vendor.join("vendor/mbedtls/library").display()
    );
    println!("cargo:rustc-link-lib=static=rsp");
    println!("cargo:rustc-link-lib=static=dist");
    println!("cargo:rustc-link-lib=static=mbedx509");
    println!("cargo:rustc-link-lib=static=mbedcrypto");

    let header = vendor.join("include/rsp.h");
    println!("cargo:rerun-if-changed={}", header.display());
    bindgen::Builder::default()
        .header(header.to_str().unwrap())
        .allowlist_function("rsp_.*")
        .allowlist_type("rsp_.*")
        .generate()
        .expect("bindgen failed")
        .write_to_file(out.join("bindings.rs"))
        .expect("could not write bindings.rs");
}
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
cd ~/git/waigel/euicc-smdp && cargo test -p rsp-sys
```

Expected: `the_library_links_and_answers ... ok`.

If bindgen cannot find `libclang`, set `LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib` and note in the README that it was needed. If the link fails with undefined symbols from `dist/`, the archive did not pick up every object — check the count in `OUT_DIR` against `ls vendor/euicc-rsp/dist/*.o | wc -l`.

- [ ] **Step 6: Write the README and commit**

`README.md`: what this repository is (the SM-DP+ server of SGP.22, standing on `euicc-rsp`), the four sibling repositories and their roles, how to clone with submodules, and that `cargo test` needs no card reader. Follow the tone of `euicc-rsp`'s own README — state what is true and what is not yet built.

```bash
cd ~/git/waigel/euicc-smdp
git add -A
git commit -m "feat: a workspace that reaches the C library and gets an answer"
```

---

### Task 4: The error type, and `InitiateAuthentication` in Rust

**Files:**
- Create: `crates/smdp/Cargo.toml`, `crates/smdp/src/lib.rs`
- Create: `crates/smdp/src/rsp/mod.rs`, `crates/smdp/src/rsp/error.rs`, `crates/smdp/src/rsp/owned.rs`
- Create: `crates/smdp/tests/session.rs`
- Create: `fixtures/` (copied from `vendor/euicc-rsp/testdata/session/`)
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Consumes: `rsp_sys` from Task 3; the fixture files from Task 2.
- Produces:
  ```rust
  pub enum RspError { Refused(&'static str), NotReached(&'static str) }
  pub type Result<T> = std::result::Result<T, RspError>;

  pub struct OwnedDer;              // a malloc'd buffer the C library gave us
  impl OwnedDer { pub fn as_slice(&self) -> &[u8]; }

  pub struct DpSession;             // owns *mut rsp_dp_session_t
  impl DpSession {
      pub fn initiate(
          euicc_challenge: &[u8; 16],
          euicc_info1: &[u8],
          transaction_id: &[u8; 16],
          server_challenge: &[u8; 16],
          server_address: &str,
          requested_address: Option<&str>,
      ) -> Result<(DpSession, OwnedDer)>;
  }
  ```

- [ ] **Step 1: Write the failing tests**

Copy the fixtures in first:

```bash
cd ~/git/waigel/euicc-smdp
mkdir -p fixtures && cp vendor/euicc-rsp/testdata/session/* fixtures/
```

`crates/smdp/tests/session.rs`:

```rust
use smdp::rsp::{DpSession, RspError};

fn fixture(name: &str) -> Vec<u8> {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/");
    std::fs::read(format!("{p}{name}")).expect("fixture is missing -- copy testdata/session/")
}

fn arr16(name: &str) -> [u8; 16] {
    fixture(name).try_into().expect("expected exactly 16 bytes")
}

#[test]
fn a_session_opens_from_the_recorded_bytes() {
    let (_s, resp) = DpSession::initiate(
        &arr16("euicc-challenge.bin"),
        &fixture("euicc-info1.der"),
        &arr16("transaction-id.bin"),
        &arr16("server-challenge.bin"),
        "smdp.example.com",
        Some("smdp.example.com"),
    )
    .expect("the recorded session opens");
    assert!(!resp.as_slice().is_empty());
}

#[test]
fn a_mismatched_address_is_refused_not_broken() {
    let err = DpSession::initiate(
        &arr16("euicc-challenge.bin"),
        &fixture("euicc-info1.der"),
        &arr16("transaction-id.bin"),
        &arr16("server-challenge.bin"),
        "smdp.example.com",
        Some("other.example.com"),
    )
    .expect_err("a different address must be refused");
    assert!(
        matches!(err, RspError::Refused(_)),
        "an address mismatch is the library saying no, not failing to ask: {err:?}"
    );
}

#[test]
fn a_malformed_euicc_info1_never_reaches_the_question() {
    let err = DpSession::initiate(
        &arr16("euicc-challenge.bin"),
        b"not an EUICCInfo1",
        &arr16("transaction-id.bin"),
        &arr16("server-challenge.bin"),
        "smdp.example.com",
        None,
    )
    .expect_err("garbage input must not open a session");
    assert!(
        matches!(err, RspError::NotReached(_)),
        "malformed input is a question never reached: {err:?}"
    );
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cargo test -p smdp
```

Expected: the `smdp` crate does not exist yet — cargo reports no such package.

- [ ] **Step 3: Write the crate**

Add `"crates/smdp"` to the workspace members. `crates/smdp/Cargo.toml` depends on `rsp-sys` by path.

`crates/smdp/src/rsp/error.rs`:

```rust
/// euicc-rsp's failure convention, kept apart rather than flattened.
///
/// include/rsp.h argues for this split at every declaration that has it:
/// -1 means the question was asked and the answer is no, -2 means the
/// question was never reached. They call for different responses --
/// reject-and-move-on versus report-and-stop -- and the ES9+ JSON
/// binding needs the difference too, since a refusal and an internal
/// failure produce different function execution statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RspError {
    /// -1: asked, answered no.
    Refused(&'static str),
    /// -2: never reached.
    NotReached(&'static str),
}

impl std::fmt::Display for RspError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RspError::Refused(w) => write!(f, "{w}: refused"),
            RspError::NotReached(w) => write!(f, "{w}: could not be attempted"),
        }
    }
}
impl std::error::Error for RspError {}

impl RspError {
    /// Anything that is not -1 is treated as -2. The library returns only
    /// 0, -1 and -2; mapping an unexpected code to the more cautious of
    /// the two is safer than asserting.
    pub(crate) fn from_code(code: i32, what: &'static str) -> Self {
        if code == -1 { RspError::Refused(what) } else { RspError::NotReached(what) }
    }
}

pub type Result<T> = std::result::Result<T, RspError>;
```

`crates/smdp/src/rsp/owned.rs`:

```rust
/// A buffer euicc-rsp malloc'd and handed over. Freed here, once.
pub struct OwnedDer {
    ptr: *mut u8,
    len: usize,
}

impl OwnedDer {
    /// # Safety
    /// `ptr` must come from a euicc-rsp out-parameter and not be freed
    /// elsewhere.
    pub(crate) unsafe fn from_raw(ptr: *mut u8, len: usize) -> Self {
        OwnedDer { ptr, len }
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for OwnedDer {
    fn drop(&mut self) {
        unsafe { libc_free(self.ptr as *mut core::ffi::c_void) }
    }
}

unsafe extern "C" {
    #[link_name = "free"]
    fn libc_free(p: *mut core::ffi::c_void);
}
```

`crates/smdp/src/rsp/mod.rs` — this is the shape every later method copies:

```rust
mod error;
mod owned;
pub use error::{Result, RspError};
pub use owned::OwnedDer;

use std::ffi::CString;
use std::ptr;

/// One RSP session's server-side state. Owns the C session and wipes it
/// on drop -- rsp_dp_session_free zeroizes rather than merely freeing,
/// because the SCP03t keys land in here.
pub struct DpSession {
    raw: *mut rsp_sys::rsp_dp_session_t,
}

impl Drop for DpSession {
    fn drop(&mut self) {
        unsafe { rsp_sys::rsp_dp_session_free(self.raw) }
    }
}

impl DpSession {
    pub fn initiate(
        euicc_challenge: &[u8; 16],
        euicc_info1: &[u8],
        transaction_id: &[u8; 16],
        server_challenge: &[u8; 16],
        server_address: &str,
        requested_address: Option<&str>,
    ) -> Result<(DpSession, OwnedDer)> {
        const WHAT: &str = "InitiateAuthentication";

        // A NUL inside an address means the question was never asked,
        // not that the library said no.
        let own = CString::new(server_address)
            .map_err(|_| RspError::NotReached(WHAT))?;
        let req = match requested_address {
            Some(a) => Some(CString::new(a).map_err(|_| RspError::NotReached(WHAT))?),
            None => None,
        };

        let mut sess: *mut rsp_sys::rsp_dp_session_t = ptr::null_mut();
        let mut resp: *mut u8 = ptr::null_mut();
        let mut resp_len: usize = 0;

        let rc = unsafe {
            rsp_sys::rsp_dp_initiate_authentication(
                euicc_challenge.as_ptr(),
                euicc_challenge.len(),
                euicc_info1.as_ptr(),
                euicc_info1.len(),
                transaction_id.as_ptr(),
                server_challenge.as_ptr(),
                own.as_ptr(),
                req.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                &mut sess,
                &mut resp,
                &mut resp_len,
            )
        };
        if rc != 0 {
            // The library leaves both out-parameters untouched on
            // failure, so there is nothing to free here.
            return Err(RspError::from_code(rc, WHAT));
        }
        Ok((
            DpSession { raw: sess },
            unsafe { OwnedDer::from_raw(resp, resp_len) },
        ))
    }
}
```

`crates/smdp/src/lib.rs` is `pub mod rsp;`.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p smdp
```

Expected: three tests pass.

- [ ] **Step 5: Check for leaks the type system cannot**

```bash
cargo test -p smdp 2>&1 | tail -5
leaks --atExit -- ./target/debug/deps/session-* 2>&1 | tail -5 || echo "leaks unavailable, skipped"
```

Expected: no leaks reported from `OwnedDer` or the session. `leaks` is a macOS tool; if it is unavailable the step is informational, not a gate.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: a session, opened from Rust, with the library's two failure kinds intact"
```

---

### Task 5: The rest of the session, and a Bound Profile Package in Rust

**Files:**
- Modify: `crates/smdp/src/rsp/mod.rs` (two more methods, two field structs)
- Modify: `crates/smdp/tests/session.rs`

**Interfaces:**
- Consumes: Task 4.
- Produces:
  ```rust
  impl DpSession {
      pub fn authenticate_client(&mut self, auth_server_resp: &[u8], metadata: &[u8])
          -> Result<OwnedDer>;
      pub fn get_bound_profile_package(
          &mut self, prepare_download_resp: &[u8], upp: &[u8], otsk_dp: &[u8; 32],
      ) -> Result<OwnedDer>;
      pub fn eid(&self) -> Result<String>;
  }

  pub struct InitiateFields<'a> {
      pub transaction_id: &'a [u8], pub server_signed1: &'a [u8],
      pub server_signature1: &'a [u8], pub euicc_ci_pkid: &'a [u8],
      pub server_certificate: &'a [u8],
  }
  pub struct AuthenticateFields<'a> {
      pub transaction_id: &'a [u8], pub profile_metadata: &'a [u8],
      pub smdp_signed2: &'a [u8], pub smdp_signature2: &'a [u8],
      pub smdp_certificate: &'a [u8],
  }
  pub fn initiate_fields(resp: &[u8]) -> Result<InitiateFields<'_>>;
  pub fn authenticate_fields(resp: &[u8]) -> Result<AuthenticateFields<'_>>;
  ```
  The two field structs borrow from the response slice — the C accessors return borrowed views, and the lifetime here is what makes that contract checkable rather than merely documented.

- [ ] **Step 1: Write the failing test**

Append to `crates/smdp/tests/session.rs`:

```rust
#[test]
fn the_whole_session_runs_and_yields_a_bound_profile_package() {
    let (mut s, init_resp) = DpSession::initiate(
        &arr16("euicc-challenge.bin"),
        &fixture("euicc-info1.der"),
        &arr16("transaction-id.bin"),
        &arr16("server-challenge.bin"),
        "smdp.example.com",
        Some("smdp.example.com"),
    )
    .expect("the session opens");

    // The five fields the ES9+ JSON binding names, borrowed from the
    // response rather than rebuilt from a decode.
    let f = smdp::rsp::initiate_fields(init_resp.as_slice()).expect("fields slice out");
    assert_eq!(f.transaction_id[0], 0x80, "[0] implicit, per AUTOMATIC TAGS");
    assert!(f.server_signed1.as_ptr() >= init_resp.as_slice().as_ptr());

    let ac = s
        .authenticate_client(
            &fixture("auth-server-response.der"),
            &fixture("store-metadata.der"),
        )
        .expect("the recorded eUICC authenticates");
    let g = smdp::rsp::authenticate_fields(ac.as_slice()).expect("fields slice out");
    assert_eq!(&g.profile_metadata[..2], &[0xbf, 0x25], "profileMetaData is [37]");

    let eid = s.eid().expect("the session learned an EID");
    assert!(eid.chars().all(|c| c.is_ascii_digit()), "an EID is decimal: {eid}");

    let otsk_dp = [0x11u8; 32];
    let bpp = s
        .get_bound_profile_package(
            &fixture("prepare-download-response.der"),
            &fixture("upp.der"),
            &otsk_dp,
        )
        .expect("a Bound Profile Package comes back");
    assert!(bpp.as_slice().len() > 64, "a BPP is not a stub");
}
```

`upp.der` and the `0x11`-repeated `otsk_dp` both come from Task 2's fixture table — nothing new is needed here.

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo test -p smdp the_whole_session_runs
```

Expected: `authenticate_client` is not a method on `DpSession`.

- [ ] **Step 3: Implement the three methods and the two accessors**

Two of them are shown here; `get_bound_profile_package` follows `authenticate_client` exactly (three input slices plus a `&[u8; 32]`, one `OwnedDer` out), and `authenticate_fields` follows `initiate_fields` exactly with its own five field names.

```rust
impl DpSession {
    pub fn authenticate_client(
        &mut self,
        auth_server_resp: &[u8],
        metadata: &[u8],
    ) -> Result<OwnedDer> {
        const WHAT: &str = "AuthenticateClient";
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            rsp_sys::rsp_dp_authenticate_client(
                self.raw,
                auth_server_resp.as_ptr(),
                auth_server_resp.len(),
                metadata.as_ptr(),
                metadata.len(),
                &mut out,
                &mut out_len,
            )
        };
        if rc != 0 {
            return Err(RspError::from_code(rc, WHAT));
        }
        Ok(unsafe { OwnedDer::from_raw(out, out_len) })
    }

    /// The EID rsp_dp_authenticate_client learned from
    /// CERT.EUICC.ECDSA's Subject serialNumber -- decimal digits, never
    /// NUL-terminated by the C side.
    pub fn eid(&self) -> Result<String> {
        const WHAT: &str = "session EID";
        let mut buf = [0u8; 32];
        let mut len: usize = 0;
        let rc = unsafe {
            rsp_sys::rsp_dp_session_eid(self.raw, buf.as_mut_ptr(), buf.len(), &mut len)
        };
        if rc != 0 {
            return Err(RspError::from_code(rc, WHAT));
        }
        String::from_utf8(buf[..len].to_vec()).map_err(|_| RspError::NotReached(WHAT))
    }
}

pub struct InitiateFields<'a> {
    pub transaction_id: &'a [u8],
    pub server_signed1: &'a [u8],
    pub server_signature1: &'a [u8],
    pub euicc_ci_pkid: &'a [u8],
    pub server_certificate: &'a [u8],
}

/// The C accessor hands back borrowed views into `resp`. Tying the
/// returned lifetime to `resp` is what turns that from a documented
/// promise into a checked one.
pub fn initiate_fields(resp: &[u8]) -> Result<InitiateFields<'_>> {
    const WHAT: &str = "InitiateAuthentication fields";
    let mut f = std::mem::MaybeUninit::<rsp_sys::rsp_dp_initiate_fields_t>::zeroed();
    let rc = unsafe {
        rsp_sys::rsp_dp_initiate_fields(resp.as_ptr(), resp.len(), f.as_mut_ptr())
    };
    if rc != 0 {
        return Err(RspError::from_code(rc, WHAT));
    }
    let f = unsafe { f.assume_init() };
    // Safety: on a 0 return every pair points inside resp, which
    // outlives the returned struct by the signature above.
    unsafe {
        Ok(InitiateFields {
            transaction_id: std::slice::from_raw_parts(f.transaction_id, f.transaction_id_len),
            server_signed1: std::slice::from_raw_parts(f.server_signed1, f.server_signed1_len),
            server_signature1: std::slice::from_raw_parts(
                f.server_signature1,
                f.server_signature1_len,
            ),
            euicc_ci_pkid: std::slice::from_raw_parts(f.euicc_ci_pkid, f.euicc_ci_pkid_len),
            server_certificate: std::slice::from_raw_parts(
                f.server_certificate,
                f.server_certificate_len,
            ),
        })
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p smdp
```

Expected: four tests pass. A full SM-DP+ session now runs in Rust against recorded eUICC bytes, with no card attached.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: a whole session in Rust, and a Bound Profile Package at the end of it"
```

---

## What part two covers

This plan stops where the protocol work stops. Everything left is server construction on top of an API that now exists and is tested:

- The `Store` trait, the SQLite provider, and the schema — orders, ICCID, EID, `CERT.EUICC.ECDSA`, state.
- The service module the CLI and a later admin API both call.
- `smdp order add` / `smdp order list`, printing a MatchingID and an activation code.
- The three ES9+ endpoints and `smdp serve` — `axum`, `rustls`, the JSON binding as recorded in the spec (no request header on ES9+, HTTP 200 regardless of function outcome, `transactionId` as uppercase hex).
- An end-to-end test that drives the running server over HTTP with these same fixtures.

It gets its own plan once Task 5 lands, for the same reason this one was split off: writing HTTP handlers against Rust types that do not exist yet means writing them twice.
