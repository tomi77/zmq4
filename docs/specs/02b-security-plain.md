# 02b — PLAIN security mechanism (Phase 2b)

> **Status:** draft, awaiting approval before implementation.
> **Author:** Tomasz Rup
> **Date:** 2026-05-03
> **Layer:** L2 — `internal/security/plain`
> **Depends on:** F1 (`internal/wire`), with one additive change (see §2.1).
> **Consumed by:** F4 (connection layer); F6 may later replace the
> `Authenticator` callback with a ZAP-backed implementation.

## 1. Summary

This phase delivers `internal/security/plain`: a pure, I/O-free pair of state
machines that drive the ZMTP 3.1 **PLAIN** security handshake. PLAIN
authenticates a peer with a clear-text username/password pair. It provides
**no confidentiality** — credentials and traffic are sent in the clear. PLAIN
is appropriate only over already-secured transports (e.g. a TLS-tunnelled
TCP, a trusted IPC socket, an authenticated VPN) or in development.

The handshake is **asymmetric**: the client speaks first. F2b therefore
ships two state machines in the same package — `ClientState` and
`ServerState` — instead of the single symmetric `null.State`. The shared
`Mechanism` interface remains deferred: it will be extracted in F2c once
CURVE adds a third concrete implementation to compare against.

The state machines:

- Do not touch sockets, files, timers, or goroutines.
- Do not do framing — that is L1's job (F1).
- Do not invoke ZAP — server-side authentication is delegated to a caller-
  supplied `Authenticator` callback. F6 will provide a ZAP-backed
  authenticator.
- Do not interpret metadata semantics (e.g. Socket-Type compatibility) —
  that is the socket layer's job (F5).

After the four-step exchange completes (HELLO → WELCOME → INITIATE → READY),
both sides have learned the peer's metadata and the connection transitions
to traffic.

## 2. Mapping to RFC 37/ZMTP 3.1

| RFC section | F2b covers |
|-------------|------------|
| §3 Security mechanisms — generic | **Yes** (handshake driver shape, `READY` / `ERROR` command handling, peer-initiated abort). |
| §3.1 NULL mechanism | **F2a** (already shipped). |
| §3.2 PLAIN mechanism | **Yes** (HELLO ↔ WELCOME ↔ INITIATE ↔ READY). |
| §3.3 CURVE mechanism | **F2c**. |
| §2.4 Metadata properties (Socket-Type, Identity, Resource, ...) | **Pass-through only.** Security ferries metadata; semantic validation lives in F5. |
| ZAP (RFC 27) authentication hook for PLAIN | **Out of scope.** Replaced by a caller-supplied `Authenticator` callback. F6 will provide a ZAP-backed authenticator that satisfies the same callback. |

### 2.1 L1 additive change

PLAIN's `INITIATE` command body is metadata in the same format as `READY`
(RFC 37 §3.2). F1 already has internal `parseMetadata` / `encodeMetadata`
helpers consumed by `ReadyCommand`. F2b promotes them to L1's public API:

```go
// internal/wire (new exports; existing callers unchanged)
func ParseMetadata(data []byte) (Metadata, error)
func EncodeMetadata(md Metadata) []byte
```

This is **additive**: no existing F1 type or function changes, and F1's
frozen public surface keeps the same semantics. The change is recorded in
the F1 spec as a note ("metadata helpers exported for F2b/F2c").

HELLO's and WELCOME's bodies are PLAIN-specific and stay inside
`internal/security/plain` (see §5.1). L1 does **not** grow new command-
name constants for HELLO/WELCOME/INITIATE — those are mechanism-private
strings, owned by the mechanism.

## 3. ABNF reference

PLAIN handshake commands per RFC 37 §3.2:

```abnf
hello       = command-size %d5 "HELLO" username password
username    = OCTET 0*255OCTET            ; 1-byte length prefix
password    = OCTET 0*255OCTET            ; 1-byte length prefix

welcome     = command-size %d7 "WELCOME"  ; no body

initiate    = command-size %d8 "INITIATE" metadata
metadata    = *property                   ; same as ready (§3 of 01-spec)

ready       = command-size %d5 "READY" metadata
error       = command-size %d5 "ERROR" reason
```

Step-by-step exchange:

```
client → server : HELLO    (username, password)
client ← server : WELCOME                     | ERROR
client → server : INITIATE (metadata)
client ← server : READY    (metadata)         | ERROR
```

Either party MAY abort at any point by sending `ERROR` with a reason. After
`ERROR`, the connection is terminated; no further commands are exchanged.

A peer that stops responding mid-handshake (e.g. never replies to
`HELLO`) leaves the state machine waiting indefinitely.  This state machine
has no timer; **detecting and aborting a stalled handshake is F4's
responsibility** (connection layer).  F4 MUST set a deadline on the
underlying connection before driving the PLAIN state machine in a read loop.

Ordering is **strict**: PLAIN is a request/response chain, unlike NULL's
full-duplex `READY`. Each side waits for the previous step before sending
the next one.

## 4. Public interface

All public API lives in `internal/security/plain`. `ClientState` and
`ServerState` are independent — neither is an alias for the other and there
is (yet) no shared interface.

```go
package plain

import "github.com/tomi77/zmq4/internal/wire"

// Authenticator decides whether to accept a (username, password) pair on
// the server side. Returning nil ⇒ server replies WELCOME and continues.
// Returning a non-nil error ⇒ server replies ERROR with the error's
// message as reason (truncated to 255 bytes per RFC 37 §3 ABNF).
//
// The callback runs synchronously inside ServerState.Receive. It MUST
// NOT do I/O, take locks held elsewhere, or call back into the State.
// F6 will provide a ZAP-backed authenticator that satisfies this shape.
//
// username and password slices alias an internal buffer that is valid
// only for the duration of the call; if the implementation needs to
// keep them, it must copy.
type Authenticator func(username, password []byte) error
```

### 4.1 ClientState

```go
// ClientState drives the client side of a PLAIN handshake. Single-shot;
// once Done() returns true (or any method returns an error), the state
// must not be reused.
type ClientState struct { /* unexported */ }

// NewClient constructs a client. username and password are referenced,
// not copied; callers must not mutate them after passing them in. Each
// must be ≤255 bytes (RFC 37 §3.2 ABNF); otherwise NewClient returns
// ErrCredentialsTooLong.
//
// localMetadata is sent in INITIATE (step 3). Same lifetime rules as
// null.New: referenced, not copied; standard properties are passed
// through verbatim, no validation.
func NewClient(username, password []byte, localMetadata wire.Metadata) (*ClientState, error)

// Start emits HELLO. Must be called exactly once before Receive.
// Returns ErrAlreadyStarted on second call, ErrAlreadyFailed if a
// previous call has put the state into the failed state.
func (c *ClientState) Start() (wire.Command, error)

// Receive consumes one peer command and advances the state machine.
//
//   step 2: cmd=WELCOME ⇒ out=INITIATE, done=false, err=nil
//   step 4: cmd=READY   ⇒ out=nil,      done=true,  err=nil
//   any:    cmd=ERROR   ⇒ out=nil, done=false, err=ErrPeerError(reason)
//
// Lifecycle errors (ErrNotStarted, ErrAlreadyDone, ErrAlreadyFailed,
// ErrUnexpectedCommand, ErrMalformedWelcome, ErrMalformedReady) follow
// the same wrapping convention as null.State (§6).
func (c *ClientState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error)

// PeerMetadata returns the metadata the server sent in its READY
// command. Valid only after Receive returned done=true. The slice
// aliases an internal buffer; callers must NOT mutate it.
func (c *ClientState) PeerMetadata() wire.Metadata

// Done reports whether the handshake has completed successfully.
func (c *ClientState) Done() bool
```

### 4.2 ServerState

```go
// ServerState drives the server side of a PLAIN handshake. Single-shot.
type ServerState struct { /* unexported */ }

// NewServer constructs a server. auth is required and must not be nil
// (use func(_, _ []byte) error { return nil } to accept everyone in
// tests). localMetadata is sent in READY (step 4); same lifetime rules
// as NewClient.
//
// NewServer panics if auth is nil — calling it without an authenticator
// is always a programming error.
func NewServer(auth Authenticator, localMetadata wire.Metadata) *ServerState

// Receive consumes one peer command and advances the state machine.
// Server has no Start — it is purely reactive.
//
//   step 1: cmd=HELLO, auth(...)==nil ⇒ out=WELCOME, done=false, err=nil
//   step 1: cmd=HELLO, auth(...)!=nil ⇒ out=ERROR(reason), done=false,
//                                        err=ErrAuthRejected (caller MUST
//                                        send out, then close).
//   step 3: cmd=INITIATE              ⇒ out=READY, done=true, err=nil
//   any:    cmd=ERROR                 ⇒ out=nil, done=false,
//                                        err=ErrPeerError(reason)
//
// Lifecycle and malformed-* errors follow §6.
func (s *ServerState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error)

// PeerMetadata returns the metadata the client sent in INITIATE. Valid
// only after Receive returned done=true.
func (s *ServerState) PeerMetadata() wire.Metadata

// Done reports whether the handshake has completed successfully.
func (s *ServerState) Done() bool
```

### 4.3 Why this shape

- **Two types instead of one.** PLAIN client and server have distinct
  state graphs (4 states vs 3 states) and distinct entry points (`Start`
  exists only on the client). Shoehorning both into one type with a
  `Role` enum would put illegal transitions one if-statement away from
  legal ones. Two types make every reachable state a compilable
  configuration.
- **Authenticator is a `func`, not an interface.** F2b has exactly two
  call sites: tests, and (eventually) F6's ZAP-backed adapter. A single-
  method interface is premature abstraction; promote later if a third
  caller appears. The shape `func(u, p []byte) error` is identical to
  what an interface would have, so promoting is mechanical.
- **`out, err` both non-nil on auth-reject.** Server's `Receive(HELLO)`
  with a failing authenticator returns `(out=ERROR_cmd, err=ErrAuthRejected)`.
  Caller contract: if `out != nil`, send it on the wire. If `err != nil`,
  close the connection after the send. If sending `out` fails, the
  connection MUST be closed; the state machine MUST NOT be reused.
  This single rule covers auth reject and any future "abort with
  notification" path without adding a second return slot.
- **Server has no `Start`.** PLAIN server is passive; introducing a
  no-op `Start()` would suggest symmetry that doesn't exist. F4 calls
  `Start` only on the active side (driven by `greeting.AsServer`).
- **Username/password length validated in `NewClient`.** RFC 37's ABNF
  caps each at 255 bytes (1-byte length prefix). Catching it at
  construction beats failing inside `Start`'s encoder, where the error
  is harder to attribute.

### 4.4 Symmetry with `null.State`

| Aspect | `null.State` | `plain.ClientState` | `plain.ServerState` |
|--------|--------------|---------------------|---------------------|
| `Start` | yes | yes | **no** |
| `Receive` | one call | two calls (WELCOME, READY) | two calls (HELLO, INITIATE) |
| `out` non-nil | never | once (INITIATE) | once or twice (WELCOME, READY; or ERROR on reject) |
| `Done()` | after one Receive | after two Receives | after two Receives |
| `PeerMetadata()` | from peer's READY | from server's READY | from client's INITIATE |

## 5. Internal data structures

### 5.1 Codec for HELLO / WELCOME

`internal/security/plain/codec.go`:

```go
package plain

const (
    helloCommandName    = "HELLO"
    welcomeCommandName  = "WELCOME"
    initiateCommandName = "INITIATE"
    // ReadyCommandName + ErrorCommandName come from internal/wire.
)

type helloBody struct {
    Username []byte
    Password []byte
}

func encodeHello(b helloBody) (wire.Command, error)
func parseHello(cmd wire.Command) (helloBody, error)

func encodeWelcome() wire.Command  // body is empty; no parse needed
func parseWelcome(cmd wire.Command) error  // verifies name + empty body
```

`INITIATE` body is metadata, encoded/decoded via `wire.EncodeMetadata` /
`wire.ParseMetadata` (the new exports from §2.1). `INITIATE` therefore does
not need its own type — `client.go` and `server.go` build the
`wire.Command` directly.

`ERROR` is encoded/decoded via the existing `wire.ErrorCommand`. Reasons
returned by the `Authenticator` are truncated (and stripped of non-VCHAR
bytes) before encoding to satisfy `error-reason = OCTET 0*255VCHAR`; the
truncation rule lives in `codec.go` next to a small helper:

```go
// sanitizeReason makes s safe to put inside an ERROR command: replaces
// any non-VCHAR byte with '?', then truncates to 255 bytes.
func sanitizeReason(s string) string
```

### 5.2 ClientState

```go
type ClientState struct {
    username, password wire.Metadata // referenced; ≤255 bytes each (validated in NewClient)
    local              wire.Metadata // metadata for INITIATE
    peer               wire.Metadata // metadata from peer READY
    started            bool
    welcomeReceived    bool          // step 2 done
    done               bool          // step 4 done
    failed             bool
}
```

(Pseudo-code: `username`/`password` are `[]byte`, not `wire.Metadata` —
shown for layout only.)

### 5.3 ServerState

```go
type ServerState struct {
    auth             Authenticator
    local            wire.Metadata // metadata for READY
    peer             wire.Metadata // metadata from peer INITIATE
    helloProcessed   bool          // step 1 done (auth ran successfully)
    done             bool          // step 3 done
    failed           bool
}
```

Each state's footprint is ~80–120 bytes including slice headers. As with
`null.State`, allocation is single-shot in the constructor; per-handshake
allocations are limited to the defensive copies of peer metadata
(see §5.4).

### 5.4 Defensive copy of peer metadata

Same contract as `null.State`: peer metadata returned from `PeerMetadata()`
is independent of the input frame buffer. Implementation reuses the
`copyMetadata` helper from `null` — which means **promoting it** to a
shared internal helper. Two reasonable homes:

- `internal/security/internal/metaclone` — small package, shared by
  `null` and `plain`. Pure function, no state. Recommended.
- Duplicate inside `plain`. Avoids a new package but invites drift.

The plan goes with the small shared package; F2c CURVE will reuse it too.

## 6. Error model

Sentinel errors live in `internal/security/plain/errors.go` and are
wrapped via `fmt.Errorf("%w: ...", ErrXxx)` so callers can use
`errors.Is`. Same convention as `null`.

| Sentinel | Returned when |
|----------|---------------|
| `ErrCredentialsTooLong` | `NewClient` called with username or password >255 bytes. |
| `ErrAlreadyStarted` | Client's `Start` called more than once. |
| `ErrNotStarted` | Client's `Receive` called before `Start`. |
| `ErrAlreadyDone` | Any method called after a previous successful completion. |
| `ErrAlreadyFailed` | Any method called after a previous error. |
| `ErrUnexpectedCommand` | Peer sent a command whose name is not the one expected in the current state (and is not `ERROR`). |
| `ErrPeerError` | Peer sent an `ERROR` command. The wrapped string includes the peer's reason. |
| `ErrAuthRejected` | (Server only.) Authenticator returned a non-nil error for HELLO. The wrapped string includes the authenticator's reason. Returned alongside a non-nil `out` containing the ERROR command to send. |
| `ErrMalformedHello` | Server: HELLO body fails to parse as `username password` per §3 ABNF. |
| `ErrMalformedWelcome` | Client: WELCOME has a non-empty body. |
| `ErrMalformedInitiate` | Server: INITIATE body fails `wire.ParseMetadata`. |
| `ErrMalformedReady` | Client: READY body fails `wire.ParseMetadata`. |

**Server abort with notification.** When the server returns
`ErrAuthRejected`, the corresponding `out *wire.Command` contains the
ERROR command to send. The same convention applies if a future malformed-
* path on the server wants to notify the client — though F2b does **not**
emit ERROR for malformed inputs (the spec is silent on this; we treat
malformed input as a fatal local error and let F4 close the connection
without sending anything). If field experience shows otherwise, this is
an additive change behind the same `(out, err)` contract.

**Not in scope:** ZAP rejection paths other than via the `Authenticator`
callback (F6), Socket-Type compatibility checks (F5), I/O errors / partial
reads (F4), TLS or other transport-layer security.

**No panics.** Any internal invariant violation is converted to an error.
The single exception is `NewServer(nil, ...)` — passing a nil
authenticator is a programming error caught at construction.

## 7. State machines

### 7.1 ClientState

```
                    ┌──────────────────────────────────┐
                    │              INIT                │
                    │ Start ⇒ emit HELLO,              │
                    │         transition to AWAIT_W    │
                    └────────────────┬─────────────────┘
                                     │
                                     ▼
                    ┌──────────────────────────────────┐
                    │           AWAIT_WELCOME          │
                    │ Receive(WELCOME) ⇒ emit INITIATE,│
                    │                    AWAIT_READY   │
                    │ Receive(ERROR)   ⇒ FAILED        │
                    │ Receive(other/malformed) ⇒ FAILED│
                    └────────────────┬─────────────────┘
                                     │
                                     ▼
                    ┌──────────────────────────────────┐
                    │           AWAIT_READY            │
                    │ Receive(READY)  ⇒ DONE           │
                    │ Receive(ERROR)  ⇒ FAILED         │
                    │ Receive(other/malformed)⇒ FAILED │
                    └─────┬──────────────────┬─────────┘
                          ▼                  ▼
                      ┌────────┐         ┌──────────┐
                      │  DONE  │         │  FAILED  │
                      └────────┘         └──────────┘
```

States are derived from the `started` / `welcomeReceived` / `done` /
`failed` flags; the machine has five reachable configurations (INIT,
AWAIT_WELCOME, AWAIT_READY, DONE, FAILED).

### 7.2 ServerState

```
                    ┌──────────────────────────────────┐
                    │           AWAIT_HELLO            │
                    │ Receive(HELLO):                  │
                    │   auth ok    ⇒ emit WELCOME,     │
                    │                AWAIT_INITIATE    │
                    │   auth fails ⇒ emit ERROR,       │
                    │                FAILED            │
                    │ Receive(ERROR)  ⇒ FAILED         │
                    │ Receive(other/malformed) ⇒ FAILED│
                    └────────────────┬─────────────────┘
                                     │
                                     ▼
                    ┌──────────────────────────────────┐
                    │          AWAIT_INITIATE          │
                    │ Receive(INITIATE) ⇒ emit READY,  │
                    │                     DONE         │
                    │ Receive(ERROR)    ⇒ FAILED       │
                    │ Receive(other/malformed)⇒ FAILED │
                    └─────┬──────────────────┬─────────┘
                          ▼                  ▼
                      ┌────────┐         ┌──────────┐
                      │  DONE  │         │  FAILED  │
                      └────────┘         └──────────┘
```

Four reachable configurations (AWAIT_HELLO, AWAIT_INITIATE, DONE,
FAILED). The auth-rejection edge is the only place where the server
emits `out` and `err` simultaneously.

## 8. Test plan

### 8.1 Unit tests

`internal/security/plain/client_test.go`:

- `NewClient` rejects username >255 bytes → `ErrCredentialsTooLong`.
- `NewClient` rejects password >255 bytes → `ErrCredentialsTooLong`.
- `Start` from INIT → emits HELLO with our username+password, transitions
  to AWAIT_WELCOME.
- `Start` from AWAIT_WELCOME → `ErrAlreadyStarted`.
- `Receive` from INIT → `ErrNotStarted`.
- `Receive(WELCOME)` from AWAIT_WELCOME → `out=INITIATE` with our
  metadata, `done=false`.
- `Receive(READY)` from AWAIT_READY → `done=true`, `PeerMetadata()` matches.
- `Receive(ERROR)` from AWAIT_WELCOME → `ErrPeerError`, wrapped reason.
- `Receive(ERROR)` from AWAIT_READY → `ErrPeerError`, wrapped reason.
- `Receive(HELLO)` from AWAIT_WELCOME → `ErrUnexpectedCommand`.
- `Receive(WELCOME with non-empty body)` → `ErrMalformedWelcome`.
- `Receive(malformed READY)` from AWAIT_READY → `ErrMalformedReady`.
- `Receive(*)` from DONE → `ErrAlreadyDone`.
- `Receive(*)` from FAILED → `ErrAlreadyFailed`.
- `PeerMetadata()` is independent of the input frame buffer (clobber test).

`internal/security/plain/server_test.go`:

- `NewServer(nil, ...)` panics.
- `Receive(HELLO)` with auth-accepts-all → `out=WELCOME`, `done=false`.
- `Receive(HELLO)` with auth that returns `errors.New("nope")` →
  `out=ERROR("nope")`, `done=false`, `err=ErrAuthRejected`. The reason
  in the encoded ERROR equals `"nope"`.
- `Receive(HELLO)` with auth returning a long error (>255 bytes) → reason
  in encoded ERROR is sanitized + truncated to 255 bytes.
- `Receive(HELLO)` with auth returning a reason containing non-VCHAR
  (`\n`, `\x00`) → reason in encoded ERROR has those bytes replaced with
  `'?'`.
- `Receive(INITIATE)` from AWAIT_INITIATE → `out=READY` with our
  metadata, `done=true`.
- `Receive(INITIATE)` from AWAIT_HELLO → `ErrUnexpectedCommand`.
- `Receive(malformed HELLO)` → `ErrMalformedHello`.
- `Receive(malformed INITIATE)` from AWAIT_INITIATE → `ErrMalformedInitiate`.
- `Receive(ERROR)` from any state → `ErrPeerError`, wrapped reason.
- `Receive(*)` after DONE → `ErrAlreadyDone`.
- `Receive(*)` after auth-reject → `ErrAlreadyFailed`.
- `PeerMetadata()` independent of input buffer (clobber test).

### 8.2 Property test (`testing/quick`)

`internal/security/plain/handshake_property_test.go`:

```
TestPlainHappyPathProperty(seed) :
    rng = rand.New(rand.NewSource(seed))
    user, pass = randCreds(rng)         // each 0..255 bytes
    mdC, mdS   = randMetadata(rng), randMetadata(rng)

    client, _ = NewClient(user, pass, mdC)
    server    = NewServer(acceptingAuth, mdS)

    hello, _   = client.Start()
    welcome, _, _ = server.Receive(hello)
    initiate, _, _ = client.Receive(*welcome)
    ready, done, _ = server.Receive(*initiate)
    require done == true
    out, done, _   = client.Receive(*ready)
    require done == true && out == nil

    require client.PeerMetadata() ≡ mdS
    require server.PeerMetadata() ≡ mdC
```

`TestPlainAuthRejectProperty(seed)`: same as above, but server uses
`func(u,p) error { return errors.New("denied") }`. Verifies:

- `server.Receive(HELLO)` returns `(out=ERROR_cmd, err=ErrAuthRejected)`.
- The encoded ERROR's reason equals `"denied"`.
- A subsequent `client.Receive(ERROR_cmd)` returns
  `err=ErrPeerError` whose `.Error()` contains `"denied"`.
- Both states are now FAILED; further Receive calls return
  `ErrAlreadyFailed` / `ErrAlreadyDone` as appropriate.

Both properties run with `quick.Config{MaxCount: 1000}`.

### 8.3 Vector tests (`testdata/*.bin`)

Hand-crafted from RFC 37 §3.2 using F1's encoder + F2b's HELLO codec.
Each vector holds the **command body** (command-name + command-data),
the same format as F2a's vectors. Cross-validation against libzmq is
deferred to F4 interop, per `00-meta-overview.md` §6.

| File | Contents |
|------|----------|
| `plain-hello-empty.bin` | `HELLO` with empty username and password. |
| `plain-hello-creds.bin` | `HELLO` with `username="admin"`, `password="secret"`. |
| `plain-welcome.bin` | `WELCOME` with empty body. |
| `plain-initiate-empty.bin` | `INITIATE` with no metadata. |
| `plain-initiate-with-socket-type.bin` | `INITIATE` with `Socket-Type=DEALER`. |
| `plain-ready-with-identity.bin` | `READY` with `Socket-Type=ROUTER` + 8-byte `Identity`. (Reused-shape, but encoded in this package's testdata for completeness of the PLAIN handshake.) |
| `plain-error-auth-failed.bin` | `ERROR` with reason `"Authentication failed"`. |

Each vector is decoded via the appropriate `parse*` function (or
`ServerState.Receive` / `ClientState.Receive` for end-to-end coverage)
and re-encoded to verify byte equality.

### 8.4 Bench

`bench_test.go` mirrors F2a:

- `BenchmarkClientHandshake` — full client round trip (`Start` →
  `Receive(WELCOME)` → `Receive(READY)`).
- `BenchmarkServerHandshake` — full server round trip
  (`Receive(HELLO)` → `Receive(INITIATE)`).

Both report `b.ReportAllocs()` and use `b.Loop()` (per the project's
modernize convention). The numbers are informational and bound the
budget for F2c regression checks.

### 8.5 What is **not** tested in F2b

- ZAP authentication paths (F6) — only the `Authenticator` callback shape
  is exercised.
- Socket-Type compatibility (F5).
- I/O errors / partial reads (F4).
- TLS or other transport-layer concerns.
- Concurrent use (single-threaded by contract; race detector enforces).

### 8.6 Done criteria

- [ ] All unit tests pass.
- [ ] Both property tests pass 1000 iterations each.
- [ ] All 7 vector tests pass.
- [ ] `go vet ./...` clean.
- [ ] `staticcheck ./...` clean.
- [ ] `modernize -fix ./...` clean (no diff).
- [ ] `go test -race ./internal/security/plain/...` clean.
- [ ] Benchmark allocs/op pinned via `testing.AllocsPerRun` for the
      client-side and server-side happy paths, with the same defensive-
      copy budget as F2a (one slice header + one `Name` and one `Value`
      buffer per peer property in the metadata-bearing step).

## 9. Open questions

None at draft time. Will be revisited if any surface during implementation.
Candidates worth flagging if they appear:

- Whether server should send ERROR on malformed HELLO/INITIATE before
  closing (currently: no, treat as local fatal). Decision is reversible
  under the existing `(out, err)` contract.
- Whether `Authenticator` should receive a third parameter (e.g. peer
  identity, transport context). Deferred until F6 says it needs one.

## 10. References

- [RFC 37/ZMTP 3.1](https://rfc.zeromq.org/spec/37/) §3 (Security
  mechanisms), §3.2 (PLAIN mechanism), §2.4 (Metadata).
- [RFC 24/PLAIN](https://rfc.zeromq.org/spec/24/) — original PLAIN
  specification (subsumed by RFC 37 §3.2 for ZMTP 3.1).
- [RFC 27/ZAP](https://rfc.zeromq.org/spec/27/) — referenced for context;
  not implemented here. F6 will replace `Authenticator` with a ZAP-backed
  implementation.
- `docs/specs/01-zmtp-wire-protocol.md` — `READY` / `ERROR` wire format,
  `Metadata` codec.
- `docs/specs/02a-security-null.md` — sibling spec, source of the
  `Authenticator`-less symmetric pattern PLAIN diverges from.
- `docs/specs/00-meta-overview.md` — phase plan, layering rules, testing
  strategy.
