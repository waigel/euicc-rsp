# euicc-smdp: an SM-DP+ that answers over the network

Design, 2026-08-11.

This document is written in `euicc-rsp` because that is where the
conversation happened and where one of the three changes lands. It moves
into `euicc-smdp` once that repository exists.

## Where this starts

`euicc-rsp` runs the SM-DP+ role of SGP.22 as a library, and it runs it
well enough that a real eUICC accepts what it builds: a profile has been
installed, enabled, disabled and deleted on a physical card, and the
`ProfileInstallationResult` that came back was checked against the eUICC's
own signature rather than believed.

What it is not, and says so in its own README, is a server. No HTTPS, no
ES2+, no SM-DS, no activation code, no Profile order database. Every
session so far has lived inside a single `euicc-tools` process that held
both roles at once: it asked the card questions and answered them itself.

That arrangement has now hit its limit in a specific, diagnosable way.
Notifications were the intended next step, and working through them
surfaced the reason they cannot be done well from where we stand:

- A real LPA never verifies a notification. It has no key to verify with
  and no reason to. It reads `notificationAddress` out of the metadata,
  POSTs the `PendingNotification` to that address unchanged, and deletes
  it from the card only once the server has confirmed. The signature
  exists for the SM-DP+.
- The SM-DP+ receives that notification with no session behind it.
  `NotificationMetadata` carries `seqNumber`, the operation, the address
  and an OPTIONAL ICCID -- and **no EID**. To know whose signature to
  check, the server must have remembered, at download time, which eUICC
  received which ICCID, and kept `CERT.EUICC.ECDSA` from back then.

That memory is the Profile order database the library deliberately does
not have. It does not belong in the library. It belongs in a server that
uses it.

So notifications are deferred, and this design builds the thing they were
waiting on.

## Goal

A standalone SM-DP+ binary that speaks ES9+ over HTTPS, persists what has
to outlive a process, and can complete a real profile download onto a
physical eUICC across a network socket.

## Non-goals

Named so they are decisions rather than omissions:

- **Notifications.** `HandleNotification`, the three ES10b commands, and
  the delivery cycle. This design puts the schema and the stored
  certificate in place for them; it does not implement them.
- **`CancelSession`.** The fifth ES9+ function.
- **ES2+.** The operator-facing interface. Orders are seeded by CLI.
- **An admin API.** Deliberately deferred, but the code is shaped so that
  adding it later is not a restructuring -- see "The service seam".
- **SM-DS, activation-code redemption.** `order add` prints an activation
  code because it costs nothing; nothing consumes one yet.
- **Production credentials.** SGP.26 test material only. A production
  eUICC rejects it, by design.

## Architecture

Five repositories, each with one role:

| Repository | Role |
| --- | --- |
| `euicc-schema` | the vocabulary |
| `euicc-rsp` | the protocol (SM-DP+ role, as a C library) |
| `euicc-lpa` | the card side (LPA role, as a C library) |
| `euicc-tools` | the command |
| `euicc-smdp` | **the server** (new) |

`euicc-smdp` is a Rust workspace that vendors `euicc-rsp` as a submodule,
the same way `euicc-tools` vendors `euicc-lpa`.

```
euicc-smdp/
  Cargo.toml              workspace
  crates/
    rsp-sys/              raw FFI; build.rs runs euicc-rsp's make, bindgen over include/rsp.h
    smdp/                 safe wrapper, store, service, server, CLI
  vendor/euicc-rsp/       submodule
```

Two crates, not four. The `-sys` split is real -- generated bindings and
hand-written safety belong apart -- but the store does not need its own
crate until a second provider exists.

### The FFI layer

`rsp-sys` generates bindings with `bindgen` in `build.rs` rather than
carrying them by hand: `include/rsp.h` is still changing, and a
hand-maintained copy would drift silently. The header includes only
`stddef.h` and `stdint.h`, so nothing generated has to exist first.
`build.rs` invokes the existing Makefile, then links `librsp.a` and the
generated codec objects.

The safe wrapper in `smdp` preserves the library's own failure
distinction rather than flattening it:

```rust
enum RspError {
    /// -1: the question was asked and the answer is no.
    Refused(Refusal),
    /// -2: the question was never reached.
    NotReached(&'static str),
}
```

This is not a style preference. `include/rsp.h` argues for that split at
every declaration that has it, and the CLI's exit-code contract (0 done,
1 a real negative answer, 2 could not answer) is built on it. A `Result`
that collapses both into one error throws away exactly what the library
was careful to provide -- and the HTTP layer needs it too: a refusal is a
4xx with a meaningful ES9+ status, an unreached question is a 5xx.

Every `malloc`'d buffer the library hands back gets a Rust owner that
frees it.

### The store

```rust
trait Store {
    fn order_by_matching_id(&self, id: &str) -> Result<Option<Order>>;
    fn order_by_iccid(&self, iccid: &[u8; 10]) -> Result<Option<Order>>;
    fn bind_euicc(&self, order: OrderId, eid: &str, cert_euicc: &[u8]) -> Result<()>;
    fn set_state(&self, order: OrderId, state: OrderState) -> Result<()>;
    fn add_order(&self, new: NewOrder) -> Result<Order>;
    fn list_orders(&self) -> Result<Vec<Order>>;
}
```

An `Order` holds its MatchingID, ICCID, the UPP bytes, the
`StoreMetadataRequest` DER, and a state: `Available`, `Bound`,
`Downloaded`, `Failed`.

SQLite via `rusqlite` is the default and, for now, only provider. The
trait exists because a second one is expected, not because one is being
written.

`bind_euicc` is the row notifications will later stand on: it is where
the EID and `CERT.EUICC.ECDSA` learned during `AuthenticateClient` are
stored, so that a future `HandleNotification` can verify a signature
without a session. Storing them now costs one column each and removes
the reason notifications were blocked.

### Sessions

`rsp_dp_session_t` offers no serialization, so sessions are **not**
persisted. They live in a `HashMap<TransactionId, DpSession>` in the
process, with a TTL and periodic eviction.

Stated as a consequence, not hidden as an implementation detail: one
process, no horizontal scaling, and a restart aborts every download in
flight. For what this server is for, that is the right trade -- but it
is a trade.

### The service seam

CLI handlers contain no logic. `order add` and `order list` call
functions in a service module that takes `&dyn Store`; the CLI is a thin
argument parser over it. When the admin API arrives, its HTTP handlers
call the same functions.

This is the one place where the design builds ahead of what is being
built, and it is justified by the next step already being named rather
than imagined. It stops there: no client crate, no transport
abstraction, no trait for something that has one implementation.

### The ES9+ endpoints

`axum`, with TLS terminated in-process by `rustls`. Three routes under
`/gsma/rsp2/es9plus/`: `initiateAuthentication`, `authenticateClient`,
`getBoundProfilePackage`. Each is a thin adapter -- decode the request,
find or create the session, call one `euicc-rsp` function, encode the
answer.

**The exact binding must be read out of SGP.22 section 6.5 before
implementation, not recalled.** The working assumption is JSON over
HTTPS with base64-encoded DER in the payload fields and an
`X-Admin-Protocol` header, but field names and the precise request and
response shapes are to be confirmed against the specification text.
Verifying this is the first step of the implementation plan, and its
outcome may adjust the adapter layer.

On TLS: SGP.22 requires a production SM-DP+'s TLS certificate to chain
to the GSMA CI. The only client here is our own `euicc-tools`, so the
server runs with a certificate the client is told to trust explicitly.
The DP signing credentials remain SGP.26 test material, unchanged.

### The CLI

One binary, subcommands, `serve` among them -- the shape Ory Hydra uses.

```
smdp serve       --db smdp.db --addr 0.0.0.0:8443 --tls-cert FILE --tls-key FILE
smdp order add   --upp FILE --iccid 89… --profile-name NAME --sp-name NAME [--class C]
smdp order list
```

`order add` prints the MatchingID and an activation code
(`LPA:1$host$MATCHINGID`). Nothing redeems one yet; it names where this
leads and costs nothing to emit.

## Changes in the other two repositories

This project spans three repositories. Both changes outside `euicc-smdp`
are small and neither can be made from inside it.

### `euicc-rsp`: a real `serverAddress`

`src/rsp_es9.c` signs an `.invalid` placeholder because no parameter can
carry a real value -- the README lists this as open. With a server at a
real address, it stops being a placeholder.
`rsp_dp_initiate_authentication` gains a server-address parameter -- it
is the call that creates the session and the one whose `serverSigned1`
carries the value -- and the placeholder path is removed.

### `euicc-tools`: `euicc card install --server URL`

A minimal HTTPS client so the download actually crosses a socket.

Its purpose is evidence. Without it the server is exercisable only by
`curl` and replay fixtures, and this project's standard is that the card
answered -- not that the code looks plausible. `--server` is what makes a
real download onto real hardware the proof that this design works.

A flag for the certificate to trust (`--server-ca`, or an explicit
pinned certificate) comes with it, since the server's certificate does
not chain to a public root.

## Testing

- **Store**: unit tests against an in-memory SQLite.
- **FFI**: tests that each wrapper maps `-1` to `Refused` and `-2` to
  `NotReached`, driven by inputs that produce each -- a signature that
  does not verify versus a null argument.
- **End to end, no hardware**: the server started in-process, driven by
  the card recordings already in the repositories. This keeps the
  existing property that everything is provable with nothing attached.
- **On hardware**: a real download over HTTPS onto the physical eUICC,
  recorded as a fixture so the run is replayable afterwards.

## Order of work

1. Read SGP.22 section 6.5 and write down the ES9+ HTTP binding as it
   actually is. Everything downstream depends on this being right.
2. `euicc-rsp`: the `serverAddress` parameter.
3. `euicc-smdp` skeleton: workspace, `rsp-sys` with bindgen and a
   working link against `librsp.a`.
4. The safe wrapper and its error type.
5. Store trait, SQLite provider, schema, service module.
6. CLI: `order add`, `order list`.
7. The three ES9+ endpoints and `serve`.
8. `euicc-tools`: `--server`.
9. The hardware download.

Steps 1 and 3 carry the most risk -- an unfamiliar binding and a build
that has to reach across a language boundary into an existing Makefile.
Both are early on purpose.
