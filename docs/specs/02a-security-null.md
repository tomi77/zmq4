# 02a — NULL security mechanism (Phase 2a)

> **Status:** implemented, frozen for F2b+.
> **Author:** Tomasz Rup
> **Date:** 2026-05-03
> **Layer:** L2 — `internal/security/null`
> **Depends on:** F1 (`internal/wire`).
> **Consumed by:** F4 (connection layer).

## 1. Summary

This phase delivers `internal/security/null`: a pure, I/O-free state machine
that drives the ZMTP 3.1 **NULL** security handshake. It does not authenticate
peers — NULL is the "no security" mechanism, used when the underlying
transport is trusted or testing is in progress.

The state machine consumes and produces `wire.Command` values:

- It does not touch sockets, files, timers, or goroutines.
- It does not do framing — that is L1's job (F1).
- It does not invoke ZAP — NULL with ZAP support is deferred to F6.
- It does not interpret metadata semantics (e.g. Socket-Type compatibility) —
  that is the socket layer's job (F5).

After both peers have exchanged `READY` commands, the handshake is complete
and the connection transitions to traffic. Either peer may also receive an
`ERROR` command, which causes the handshake to fail with the error reason
preserved.

This is the first of three security-mechanism phases. F2b (PLAIN) and F2c
(CURVE) will follow with their own specs. There is **no shared `Mechanism`
interface** at this stage — abstractions will be extracted once we have all
three concrete implementations to compare.

## 2. Mapping to RFC 37/ZMTP 3.1

| RFC section | F2a covers |
|-------------|------------|
| §3 Security mechanisms — generic | **Yes** (handshake driver shape, `READY` / `ERROR` command handling). |
| §3.1 NULL mechanism | **Yes** (READY ↔ READY exchange with metadata). |
| §3.2 PLAIN mechanism | **F2b**. |
| §3.3 CURVE mechanism | **F2c**. |
| §2.4 Metadata properties (Socket-Type, Identity, Resource, ...) | **Pass-through only.** Security ferries metadata; semantic validation lives in F5. |
| ZAP (RFC 27) authentication hook for NULL | **Out of scope.** RFC 37 §3.1 says NULL servers MAY invoke ZAP. Deferred to F6 alongside ZAP itself. |

## 3. ABNF reference

NULL handshake commands are already defined as L1 commands in §3 of spec
`01-zmtp-wire-protocol.md`. F2a only sequences them — it does not redefine the
wire format.

The relevant L1 commands are:

```abnf
ready    = command-size %d5 "READY" metadata
metadata = *property
property = name value
error    = command-size %d5 "ERROR" reason
reason   = OCTET 0*255VCHAR
```

After the greeting completes with `mechanism = "NULL"`, the handshake consists
of exactly:

```
client → server : READY (metadata)
client ← server : READY (metadata)
```

Order is full-duplex: each peer SHOULD send its `READY` immediately after the
greeting completes, without waiting for the peer's `READY`. Implementations
MUST also accept lock-step ordering (one peer sends first, the other replies)
to interoperate with libzmq.

Either peer MAY abort the handshake by sending `ERROR` instead of `READY`.

## 4. Public interface

All public API lives in `internal/security/null`. It has no exported
constructors or types beyond what is listed here.

```go
package null

import "github.com/tomi77/zmq4/internal/wire"

// State drives one side of a ZMTP 3.1 NULL handshake. It is single-shot:
// once Done() returns true (or any method returns an error), the State
// must not be reused.
//
// The State is symmetric — client and server use the same type with the
// same calls. The greeting's as-server byte does not affect NULL; it is
// only relevant for CURVE (F2c).
type State struct { /* unexported */ }

// New constructs a State that will advertise localMetadata in our outbound
// READY command. localMetadata is referenced, not copied; callers must not
// mutate it after passing it in.
//
// Standard properties (per RFC 37 §2.4.1) — Socket-Type, Identity,
// Resource — are passed through verbatim. NULL does not validate them.
func New(localMetadata wire.Metadata) *State

// Start produces the initial READY command. It must be called exactly
// once, before any Receive call. Returns ErrAlreadyStarted on second call.
//
// In a typical full-duplex flow, the caller sends the returned command on
// the wire as soon as the greeting completes, without waiting for any
// peer input.
func (s *State) Start() (wire.Command, error)

// Receive consumes one command from the peer and advances the state
// machine. Returns:
//   - out: optional response command. For NULL this is always nil — the
//          peer's READY needs no reply. The slot exists so the API shape
//          matches PLAIN/CURVE state machines that will be defined in
//          later phases.
//   - done: true once the handshake has succeeded. After done==true the
//           caller transitions to traffic (F4).
//   - err:  non-nil if the peer sent an ERROR command, an unexpected
//           command, malformed metadata, or a duplicate READY. The
//           returned error wraps a sentinel from this package (see §6).
//
// Receive must not be called before Start, and must not be called again
// after done==true or after err != nil. Calling Receive out of order is
// always a caller bug, never an expected interleaving — F4 must buffer
// any peer command that arrives before our Start has been called and the
// resulting outbound READY has been written.
func (s *State) Receive(cmd wire.Command) (out *wire.Command, done bool, err error)

// PeerMetadata returns the metadata the peer sent in its READY command.
// Valid only after Receive has returned done==true. The slice aliases an
// internal buffer; callers MUST NOT mutate it.
func (s *State) PeerMetadata() wire.Metadata

// Done reports whether the handshake has completed successfully. It
// becomes true after the corresponding Receive call returns done==true.
func (s *State) Done() bool
```

### Why this shape

- **`Start` separate from `Receive`.** NULL is full-duplex: our READY is
  produced unconditionally, not as a reply. Folding "first call produces
  output" into `Receive(nil)` would conflate two distinct operations.
- **`out *wire.Command` always nil for NULL.** Kept in the signature for
  forward compatibility — PLAIN's HELLO/WELCOME/INITIATE/READY chain produces
  one outbound command per inbound command. F2b can reuse this shape.
- **No `Reset` / `Restart`.** A single `State` corresponds to a single
  connection. If the connection is recycled, F4 constructs a new `State`.

## 5. Internal data structures

```go
type State struct {
    local       wire.Metadata
    peer        wire.Metadata // populated after peer's READY
    started     bool          // Start() has been called
    received    bool          // peer's READY has been processed
    failed      bool          // any error has been returned
}
```

Total size: ~80 bytes including slice headers. Allocation is single-shot in
`New`; no further allocations during the handshake.

## 6. Error model

Sentinel errors live in `internal/security/null/errors.go` and are wrapped
via `fmt.Errorf("%w: ...", ErrXxx)` so callers can use `errors.Is`.

| Sentinel | Returned when |
|----------|---------------|
| `ErrAlreadyStarted` | `Start` called more than once. |
| `ErrNotStarted` | `Receive` called before `Start`. |
| `ErrAlreadyDone` | `Receive` called after a previous successful completion. |
| `ErrAlreadyFailed` | Any method called after a previous error. |
| `ErrUnexpectedCommand` | Peer sent a command whose name is neither `READY` nor `ERROR` during the handshake. |
| `ErrPeerError` | Peer sent an `ERROR` command. The wrapped string includes the peer's reason. |
| `ErrMalformedReady` | Peer's `READY` command-data fails to parse as metadata (delegates to `wire.ParseReady`). |

**Not in scope:** ZAP rejection paths (F6), Socket-Type compatibility checks
(F5), I/O errors (F4 layer above us).

**No panics.** Any internal invariant violation is converted to an error.

## 7. State machine

```
                     ┌──────────────────────────────┐
                     │         INIT                  │
                     │ Start ⇒ emit READY,          │
                     │         transition to AWAIT  │
                     └──────────────┬───────────────┘
                                    │
                                    ▼
                     ┌──────────────────────────────┐
                     │         AWAIT                 │
                     │ Receive(READY)  ⇒ DONE       │
                     │ Receive(ERROR)  ⇒ FAILED     │
                     │ Receive(other)  ⇒ FAILED     │
                     │ Receive(malformed) ⇒ FAILED  │
                     └─────┬─────────────┬──────────┘
                           │             │
                           ▼             ▼
                       ┌────────┐   ┌──────────┐
                       │  DONE  │   │  FAILED  │
                       └────────┘   └──────────┘
```

States are derived from the `started` / `received` / `failed` flags; the
machine has four reachable configurations (INIT, AWAIT, DONE, FAILED).

There is no peer-initiated "you go first" state — `Start` is always called
before `Receive`, even if the peer's `READY` arrives first on the wire (F4
will buffer it).

## 8. Test plan

### Unit tests (`internal/security/null/*_test.go`)

State-table coverage:

- `Start` from INIT → emits `READY` with our metadata, transitions to AWAIT.
- `Start` from AWAIT → `ErrAlreadyStarted`.
- `Receive` from INIT → `ErrNotStarted`.
- `Receive(valid READY)` from AWAIT → `done=true`, peer metadata available.
- `Receive(ERROR with reason)` from AWAIT → `ErrPeerError`, wrapped reason.
- `Receive(malformed READY)` from AWAIT → `ErrMalformedReady`.
- `Receive(unexpected command name)` from AWAIT → `ErrUnexpectedCommand`.
- `Receive(*)` from DONE → `ErrAlreadyDone`.
- `Receive(*)` from FAILED → `ErrAlreadyFailed`.

Metadata pass-through:

- Round-trip: `New(metadata).Start()` → parse output → equals input metadata.
- Empty metadata: `New(nil).Start()` succeeds and emits `READY` with empty
  metadata.
- Identity property (8 random bytes) survives round-trip.

### Property test (`testing/quick`)

`TestNullHandshakeProperty`: random metadata round-trip via two `State`
instances handing commands to each other:

```
peer A: New(mdA), Start() → cmdA
peer B: New(mdB), Start() → cmdB
peer A: Receive(cmdB) → done, PeerMetadata() == mdB
peer B: Receive(cmdA) → done, PeerMetadata() == mdA
```

Implements both lock-step (A starts → B starts after seeing A's command) and
full-duplex orderings.

### Vector tests (`testdata/null/*.bin`)

Hand-crafted from RFC 37 §3.1, analogous to F1's vector strategy:

| File | Contents |
|------|----------|
| `null-ready-empty.bin` | `READY` with no metadata. |
| `null-ready-socket-type-req.bin` | `READY` with `Socket-Type=REQ`. |
| `null-ready-with-identity.bin` | `READY` with `Socket-Type=ROUTER` + `Identity=8 random bytes`. |
| `null-error.bin` | `ERROR` with reason `"Invalid client"` (RFC 37 §3.1 example). |

Each vector is decoded via `null.State` and re-encoded to verify byte
equality. Cross-validation against libzmq is deferred to F4 interop.

### What is **not** tested in F2a

- ZAP authentication paths (F6).
- Socket-Type compatibility (F5).
- I/O errors / partial reads (F4).
- Concurrent use (single-threaded by contract; race detector enforces).

### Done criteria

- [x] All unit tests pass.
- [x] Property test passes 1000 iterations.
- [x] All 4 vector tests pass.
- [x] `go vet ./...` clean.
- [x] `staticcheck ./...` clean.
- [x] `go test -race ./internal/security/null/...` clean.
- [ ] Zero allocations in `Start` and `Receive` happy paths beyond what
      the underlying `wire` codec already allocates (verified via
      `testing.AllocsPerRun`). `null.State` itself adds nothing on top.
      <!-- NOT TICKED: BenchmarkHandshake reports 5 allocs/op, 136 B/op,
      but that figure includes both wire codec allocations and null.State's
      own copyMetadata call. No separate AllocsPerRun test isolates the
      wire codec's per-handshake baseline, so the claim "null.State adds
      nothing on top" cannot be verified without that baseline. The
      benchmark documents the total budget; a targeted AllocsPerRun test
      is deferred to F2b/F2c regression work. -->

## 9. Open questions

None at draft time. Will be revisited if any surface during implementation.

## 10. References

- [RFC 37/ZMTP 3.1](https://rfc.zeromq.org/spec/37/) §3 (Security
  mechanisms), §3.1 (NULL mechanism), §2.4 (Metadata).
- [RFC 27/ZAP](https://rfc.zeromq.org/spec/27/) — referenced for context;
  not implemented here.
- `docs/specs/01-zmtp-wire-protocol.md` — `READY` / `ERROR` wire format.
- `docs/specs/00-meta-overview.md` — phase plan, layering rules.
