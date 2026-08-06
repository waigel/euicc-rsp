# Card recordings

A recording is a text log of one session with a physical eUICC in a card
reader: every command APDU sent and every response APDU received, in the
exact order they crossed the wire. `rsp_record_open` (see `include/rsp.h`
and `src/rsp_transport.c`) writes one while talking to real hardware;
`rsp_replay_open` reads one back and answers the command layer exactly as
the card did, so the same code path runs in CI with no reader attached.

The format is plain text on purpose, not a binary capture:

- a line beginning `> ` is a command APDU, in hex
- a line beginning `< ` is the response, in hex, including its two
  trailing status bytes
- `#` and blank lines are comments
- whitespace inside a hex line is insignificant

That is what lets a recording be read directly in a code review, diffed
meaningfully when it changes, and hand-edited into the failure cases a
healthy card will not itself produce -- a wrong status word, a truncated
response, a segment out of order. `tests/test_recording.c` is itself an
example of a hand-written recording used this way.

Replay expects the recorded sequence strictly: a command that does not
match what comes next, or a command sent after the recording is
exhausted, is refused. A committed recording is a pin on the bytes that
crossed the wire, not a lenient stub that answers whatever it is asked.

## What is safe to commit

This round only reads a card: selecting applets, listing profiles,
fetching public identifiers such as the EID. None of that is secret, and
a recording of it is public data, safe to commit and safe to paste into
an issue or a review comment.

That stops being true the moment a recording covers a *write* session --
loading a profile, or any exchange that carries SCP03t-protected
segments, session keys, or profile content. Those recordings carry
protected material by construction, the same material `rsp_session_t`
and `rsp_credential_t` elsewhere in this library exist to keep off
`stdout`/`stderr`/logs. A recording like that must not be pasted into an
issue, a chat message, or a bug report unexamined -- read what it
actually contains first, the same as you would before sharing a core
dump.
