# 05c — Socket layer: PUSH / PULL / PAIR (Phase 5c)

> **Status:** design approved, implementation pending.
> **Author:** Tomasz Rup
> **Date:** 2026-05-09
> **Layer:** L5 — `zmq4` (root package)
> **Depends on:** F1 (`internal/wire`), F2a/F2b/F2c (`internal/security`),
> F3 (`internal/transport`), F4 (`internal/conn`), F5a (socketBase, pipe, pipeSet, options).
> **Consumed by:** application code (public API surface).

## 1. Summary

This phase delivers three public socket types in the root `zmq4` package: `PUSH`,
`PULL`, and `PAIR`. Together they implement two patterns:

- **Pipeline** (RFC 30/PIPELINE) — `PUSH` → `PULL` unidirectional fan-out.
- **Exclusive pair** (RFC 31/EXPAIR) — `PAIR` ↔ `PAIR` single-peer bidirectional.

All three reuse `socketBase`, `pipeSet`, and the existing options API from F5a.
No new internal data structures are needed: PUSH and PULL are pure delegations;
PAIR uses the existing `postHandshake` hook to enforce the one-peer invariant.

The public surface:

```go
func NewPUSH(opts ...Option) *PUSH
func NewPULL(opts ...Option) *PULL
func NewPAIR(opts ...Option) *PAIR
```

What F5c explicitly does **not** do:

- **No XPUSH/XPULL.** These socket types do not exist in the ZMQ specification.
- **No ZAP.** ZAP-backed authenticators are F6.
- **No HWM tuning.** Per-pipe queue limits remain at 64 (same as F5a/F5b).
- **No heartbeat.** PING/PONG is F6.
- **No auto-reconnect.** Pipe death is handled identically to prior phases.
- **No monitoring events.** F6.

Forbidden dependencies: none — L5 is the top layer. No `cgo`.

## 2. Mapping to RFCs

### RFC 30/PIPELINE

| RFC 30 § | F5c covers |
|----------|-----------|
| §2 PUSH — send only, round-robin across peers | **Yes** — `sendWaitPipe` round-robin; no `Recv`. |
| §2 PULL — receive only, fair-queue across peers | **Yes** — `recvAny` fair-queue; no `Send`. |
| §2 Compatible pair: PUSH↔PULL only | **Yes** — `compatiblePeers` table. |
| §2 PUSH blocks when no peers (no drop) | **Yes** — `sendWaitPipe` blocks until a pipe is available. |

### RFC 31/EXPAIR

| RFC 31 § | F5c covers |
|----------|-----------|
| §2 PAIR — bidirectional, single peer | **Yes** — `postHandshake` rejects second peer. |
| §2 Compatible pair: PAIR↔PAIR only | **Yes** — `compatiblePeers` table. |
| §2 Peer death allows reconnection | **Yes** — pipeSet removes dead pipes; `postHandshake` check passes once empty. |

## 3. Public interface

All public API lives in the root `zmq4` package.

### 3.1 PUSH

```go
// PUSH is a pipeline push socket. It pairs only with PULL peers.
//
// Send distributes messages round-robin across connected peers. If no peers
// are connected, Send blocks until one becomes available or ctx is done.
// PUSH has no Recv — calling code that needs both directions should use DEALER.
type PUSH struct{ /* opaque */ }

func NewPUSH(opts ...Option) *PUSH

func (s *PUSH) Bind(ctx context.Context, endpoint string) error
func (s *PUSH) Connect(ctx context.Context, endpoint string) error

// Send selects the next available pipe (round-robin) and sends msg.
// Blocks until a pipe is ready or ctx is done.
// Returns ErrClosed after Close.
func (s *PUSH) Send(ctx context.Context, msg Message) error

func (s *PUSH) Close() error
```

### 3.2 PULL

```go
// PULL is a pipeline pull socket. It pairs only with PUSH peers.
//
// Recv fair-queues across all connected peers. PULL has no Send.
type PULL struct{ /* opaque */ }

func NewPULL(opts ...Option) *PULL

func (s *PULL) Bind(ctx context.Context, endpoint string) error
func (s *PULL) Connect(ctx context.Context, endpoint string) error

// Recv fair-queues across all connected pipes. Blocks until a message
// arrives, ctx is done, or the socket is closed.
// Returns ErrClosed after Close.
func (s *PULL) Recv(ctx context.Context) (Message, error)

func (s *PULL) Close() error
```

### 3.3 PAIR

```go
// PAIR is an exclusive-pair socket. It pairs only with another PAIR peer.
//
// Exactly one peer is allowed at a time. If a second peer attempts to connect
// while one is already active, the handshake is rejected with
// ErrPairAlreadyConnected. When the current peer disconnects, PAIR
// accepts a new connection.
//
// Send blocks until the peer is connected or ctx is done.
// Recv blocks until a message arrives or ctx is done.
// Both operations are unrestricted (no alternating-sequence constraint).
type PAIR struct{ /* opaque */ }

func NewPAIR(opts ...Option) *PAIR

func (s *PAIR) Bind(ctx context.Context, endpoint string) error
func (s *PAIR) Connect(ctx context.Context, endpoint string) error

// Send waits for the peer to be connected, then sends msg.
// Returns ErrClosed after Close.
func (s *PAIR) Send(ctx context.Context, msg Message) error

// Recv waits for a message from the peer.
// Returns ErrClosed after Close.
func (s *PAIR) Recv(ctx context.Context) (Message, error)

func (s *PAIR) Close() error
```

### 3.4 Why this shape

- **PUSH has no Recv; PULL has no Send.** Type-safe at compile time. Pipeline is
  strictly unidirectional; callers that need bidirectionality should use
  DEALER/ROUTER.
- **PUSH blocks on no peers (no drop).** RFC 30 requires PUSH not to lose
  messages. This matches libzmq behaviour with the default HWM.
- **PAIR rejects the second peer, not the first `Connect`/`Bind`.** The
  connection attempt is visible only at handshake time; returning an error from
  `addConn` cleanly closes the connection from the server side without
  disrupting the already-connected peer or the listener.

## 4. Internal data structures

### 4.1 PUSH and PULL — no new structures

Both types embed `socketBase` directly and delegate to existing helpers:

```go
type PUSH struct{ base socketBase }
type PULL struct{ base socketBase }
```

`PUSH.Send` calls `sendWaitPipe` (same as `DEALER.Send`).
`PULL.Recv` calls `recvAny` (same as `REP.Recv` and `DEALER.Recv`).
No goroutines beyond the standard acceptor and pipe reader started by
`socketBase`.

### 4.2 PAIR — postHandshake exclusivity hook

```go
type PAIR struct{ base socketBase }

func NewPAIR(opts ...Option) *PAIR {
    s := &PAIR{base: newSocketBase(newSocketConfig(opts))}
    s.base.postHandshake = s.exclusivePeer
    return s
}

func (s *PAIR) exclusivePeer(c *conn.Conn) error {
    if len(s.base.pipes.all()) > 0 {
        return ErrPairAlreadyConnected
    }
    identity := peerIdentity(c.PeerMetadata())
    p := newPipe(c, identity)
    s.base.pipes.add(p)
    p.start(s.base.pipes, s.base.closeCh)
    return nil
}
```

When `addConn` receives a non-nil error from `postHandshake`, it closes `c` and
returns the error. The already-connected peer is unaffected. After the connected
peer's pipe dies (its `readLoop` removes it from `pipeSet`), the next call to
`exclusivePeer` will see `len(pipes) == 0` and accept the new peer.

`PAIR.Send` uses `sendWaitPipe`; `PAIR.Recv` uses `recvAny` — identical to
DEALER. No additional state.

### 4.3 Socket-Type compatibility table (additions to `base.go`)

```go
"PUSH": {"PULL": true},
"PULL": {"PUSH": true},
"PAIR": {"PAIR": true},
```

## 5. State machines

All three socket types have **no sequencing constraints**:

| Type | Send | Recv |
|------|------|------|
| PUSH | always allowed | — (method does not exist) |
| PULL | — (method does not exist) | always allowed |
| PAIR | always allowed | always allowed |

PAIR does not enforce alternating Send/Recv. Callers may call either in any
order and from concurrent goroutines.

## 6. Error model

### 6.1 New sentinel (`errors.go`, additive)

```go
var (
    ErrPairAlreadyConnected = errors.New("zmq4: PAIR socket already has a peer")
)
```

All other errors are inherited from F5a/F5b: `ErrClosed`, `ErrIncompatiblePeer`,
`ErrSecurityMismatch`, `context.Canceled`, `context.DeadlineExceeded`.

### 6.2 Errors from lower layers

Same forwarding rules as F5a §6.2. No additions specific to F5c.

## 7. Test plan

### 7.1 Unit — pipeline and pair (`push_pull_pair_test.go`)

- **TestPUSHPULLRoundTrip** — PUSH.Send one message; PULL.Recv returns it.
- **TestPUSHPULLMultiPeer** — 1 PUSH, 3 PULL peers; send 9 messages; each PULL
  receives exactly 3 (round-robin distribution).
- **TestPAIRRoundTrip** — PAIR↔PAIR bidirectional: A sends "ping", B receives
  "ping", B sends "pong", A receives "pong".
- **TestPAIRAlreadyConnected** — two peers attempt to connect to a bound PAIR;
  assert the second returns `ErrPairAlreadyConnected` (or connection is rejected
  at handshake).
- **TestPAIRReconnect** — connect one peer, close it, connect a second peer;
  assert second peer succeeds and round-trip works.
- **TestPUSHCtxCancelSend** — no peers; pre-cancelled ctx; Send returns
  `context.Canceled` immediately.
- **TestPULLCtxCancelRecv** — no peers; pre-cancelled ctx; Recv returns
  `context.Canceled` immediately.
- **TestPAIRCtxCancelSend** and **TestPAIRCtxCancelRecv** — same pattern.

### 7.2 Lifecycle (`lifecycle_test.go`, new cases)

- **TestPUSHCloseUnblocksSend** — PUSH blocked in Send (no peers); Close
  unblocks it with `ErrClosed`.
- **TestPULLCloseUnblocksRecv** — PULL blocked in Recv; Close unblocks it with
  `ErrClosed`.
- **TestPAIRCloseUnblocks** — PAIR blocked in Send and Recv; Close unblocks both
  with `ErrClosed`.

### 7.3 Integration (`integration_test.go`, new rows)

9 rows for PUSH/PULL and 9 rows for PAIR — 3 transports (inproc, ipc, tcp) ×
3 security mechanisms (NULL, PLAIN, CURVE) = 18 new rows total. Each row:
PUSH.Send("hello") → PULL.Recv() asserts "hello", and symmetrically for PAIR.

### 7.4 Interop (`interop/interop_test.go`, new rows)

Matrix analogous to F5a/F5b interop tests:

- PUSH (Go) → PULL (libzmq)
- PULL (Go) ← PUSH (libzmq)
- PAIR (Go) ↔ PAIR (libzmq)

Security mechanisms: NULL only (consistent with F5a/F5b interop scope).

## 8. Files changed

| File | Change |
|------|--------|
| `push.go` | new — PUSH socket (~35 lines) |
| `pull.go` | new — PULL socket (~35 lines) |
| `pair.go` | new — PAIR socket (~50 lines) |
| `errors.go` | add `ErrPairAlreadyConnected` |
| `base.go` | extend `compatiblePeers` with PUSH/PULL/PAIR entries |
| `doc.go` | add PUSH/PULL/PAIR to package godoc |
| `push_pull_pair_test.go` | new — unit + lifecycle tests |
| `lifecycle_test.go` | new cases for PUSH/PULL/PAIR |
| `integration_test.go` | 18 new rows |
| `interop/interop_test.go` | new rows |
| `docs/specs/05c-sockets-pipeline-pair.md` | this file |
| `docs/plans/05c-sockets-pipeline-pair-implementation.md` | implementation plan (F5c) |

## 9. Open questions

| # | Question | Default if not resolved |
|---|----------|------------------------|
| 9.1 | Should `PUSH.Send` with peers present but all pipes temporarily full block indefinitely or use a configurable timeout? | Block indefinitely (same as `sendWaitPipe`). HWM is F6. |
| 9.2 | Should `ErrPairAlreadyConnected` be propagated to the connecting side (via ERROR command) or just close the raw connection? | Close without ERROR command — simpler; libzmq does the same. |
