# 05b — Socket layer: PUB / SUB / XPUB / XSUB (Phase 5b)

> **Status:** design approved, implementation pending.
> **Author:** Tomasz Rup
> **Date:** 2026-05-09
> **Layer:** L5 — `zmq4` (root package)
> **Depends on:** F1 (`internal/wire`), F2a/F2b/F2c (`internal/security`),
> F3 (`internal/transport`), F4 (`internal/conn`), F5a (socketBase, pipe, pipeSet, options).
> **Consumed by:** application code (public API surface).

## 1. Summary

This phase delivers four public socket types in the root `zmq4` package: `PUB`,
`SUB`, `XPUB`, and `XSUB`. Together they implement the **publish-subscribe
pattern** defined in RFC 29/PUBSUB.

The central mechanism is **publisher-side topic filtering**: PUB and XPUB
maintain a per-pipe subscription list and deliver a message only to peers whose
subscription set contains a prefix that matches the message topic (first frame).
This matches libzmq ≥ 4.x behaviour and is the only option compatible with
interop testing.

The public surface is four socket types reusing the existing options API from
F5a:

```go
func NewPUB(opts ...Option) *PUB
func NewSUB(opts ...Option) *SUB
func NewXPUB(opts ...Option) *XPUB
func NewXSUB(opts ...Option) *XSUB
```

What F5b explicitly does **not** do:

- **No PUSH/PULL/PAIR.** Pipeline and exclusive-pair semantics are F5c.
- **No ZAP.** ZAP-backed authenticators are F6.
- **No HWM tuning.** Per-pipe queue size limits remain at 64 (same as F5a).
  `WithInboundHWM` is deferred to F6.
- **No subscription trie.** Topic matching uses linear prefix scan. A trie
  optimisation is deferred to F6 pending profiling evidence.
- **No auto-reconnect.** Pipe death is handled identically to F5a.
- **No monitoring events.** F6.
- **No XPUB verbose mode.** libzmq supports forwarding duplicate subscription
  frames in verbose mode (`ZMQ_XPUB_VERBOSE`). Deferred to F6.

Forbidden dependencies: none — L5 is the top layer. No `cgo`.

## 2. Mapping to RFC 29/PUBSUB

| RFC 29 § | F5b covers |
|----------|-----------|
| §2 PUB socket — fan-out, topic-prefix filter | **Yes** — publisher-side filter, drop for slow peers. |
| §2 SUB socket — subscribe/unsubscribe, prefix filter | **Yes** — `Subscribe`/`Unsubscribe` methods; empty prefix = subscribe-all. |
| §2 XPUB socket — PUB semantics + subscription frame exposure | **Yes** — `Recv` returns raw `\x01`/`\x00`-prefixed subscription frames. |
| §2 XSUB socket — SUB semantics + raw subscription frame send | **Yes** — `Subscribe`/`Unsubscribe` helpers + raw `Send` for forwarding. |
| §2.1 Subscription frame format (`\x01`+topic, `\x00`+topic) | **Yes** — exact wire format. |
| §2 Compatible pairs: PUB↔SUB, PUB↔XSUB, XPUB↔SUB, XPUB↔XSUB | **Yes** — enforced at handshake via Socket-Type metadata. |
| §2 New peer: SUB sends full subscription list on connect | **Yes** — subState snapshot sent immediately after handshake. |
| Subscription reference counting (multi-subscribe) | **Yes** — `map[string]int` ref counts in `subState`. |
| ZAP integration for PLAIN/CURVE authentication | **No** — F6. |
| Monitoring events, HWM, polling | **No** — F6. |
| XPUB verbose mode | **No** — F6. |

## 3. Public interface

All public API lives in the root `zmq4` package.

### 3.1 Options

F5b reuses all options from F5a (`WithNULL`, `WithPLAIN`, `WithPLAINServer`,
`WithCURVE`, `WithCURVEServer`, `WithIdentity`, `WithHandshakeTimeout`) without
modification. No new options are added in F5b.

### 3.2 PUB

```go
// PUB is a publish socket. It fans out messages to all subscribers whose
// topic subscription matches the message topic (first frame prefix).
//
// Send is the only meaningful operation. PUB.Send never blocks waiting for
// a slow peer — messages are dropped per pipe if the outbound path is
// unavailable. Send returns ErrNoTopic if msg is empty (no topic frame).
// Send returns ErrClosed after Close.
//
// PUB silently reads and discards all non-subscription frames received from
// peers. Subscription frames (\x01/\x00-prefixed) update the per-pipe filter.
type PUB struct{ /* opaque */ }

func NewPUB(opts ...Option) *PUB

func (s *PUB) Bind(ctx context.Context, endpoint string) error
func (s *PUB) Connect(ctx context.Context, endpoint string) error

// Send broadcasts msg to all peers whose subscription list contains a prefix
// that matches msg[0] (the topic frame). Non-matching or full-buffer peers
// are silently skipped. Never blocks on individual peers.
// Returns ErrNoTopic if len(msg) == 0.
// Returns ErrClosed after Close.
func (s *PUB) Send(ctx context.Context, msg Message) error

func (s *PUB) Close() error
```

### 3.3 SUB

```go
// SUB is a subscribe socket. It receives messages whose topic (first frame)
// matches at least one active subscription prefix.
//
// A SUB with no active subscriptions receives no messages.
// Subscribe(nil) or Subscribe([]byte{}) subscribes to all messages (empty
// prefix matches every topic). Subscriptions are reference-counted:
// Subscribe("foo") twice, Unsubscribe("foo") once — still subscribed.
//
// Subscribe and Unsubscribe are goroutine-safe and may be called at any
// time, including while Recv is in progress.
type SUB struct{ /* opaque */ }

func NewSUB(opts ...Option) *SUB

func (s *SUB) Bind(ctx context.Context, endpoint string) error
func (s *SUB) Connect(ctx context.Context, endpoint string) error

// Subscribe adds topic to the subscription list (or increments its reference
// count if already subscribed). If this is the first subscription for the
// topic, a \x01-prefixed subscription frame is sent to all connected peers.
// Returns ErrClosed after Close.
func (s *SUB) Subscribe(topic []byte) error

// Unsubscribe decrements the reference count for topic. When it reaches zero,
// removes the subscription and sends a \x00-prefixed unsubscription frame to
// all connected peers. No-op if topic was never subscribed.
// Returns ErrClosed after Close.
func (s *SUB) Unsubscribe(topic []byte) error

// Recv fair-queues across all connected pipes. Returns the next message whose
// topic matches an active subscription. Blocks until a matching message
// arrives, ctx is done, or the socket is closed.
func (s *SUB) Recv(ctx context.Context) (Message, error)

func (s *SUB) Close() error
```

### 3.4 XPUB

```go
// XPUB is an extended publish socket. It behaves like PUB for sending but
// exposes subscription management frames to the application via Recv.
//
// Recv returns subscription frames as they arrive from peers:
//   msg[0][0] == 0x01 — subscribe; msg[0][1:] is the topic prefix.
//   msg[0][0] == 0x00 — unsubscribe; msg[0][1:] is the topic prefix.
//
// A typical proxy loop: read subscription frames from XPUB, forward them
// to an XSUB via XSUB.Send; read data from XSUB.Recv, forward via XPUB.Send.
type XPUB struct{ /* opaque */ }

func NewXPUB(opts ...Option) *XPUB

func (s *XPUB) Bind(ctx context.Context, endpoint string) error
func (s *XPUB) Connect(ctx context.Context, endpoint string) error

// Send broadcasts msg to all peers whose subscription list matches msg[0].
// Semantics identical to PUB.Send (drop on slow peer, ErrNoTopic if no frames).
func (s *XPUB) Send(ctx context.Context, msg Message) error

// Recv blocks until a subscription or unsubscription frame arrives from any
// connected peer, ctx is done, or the socket is closed. The returned message
// is a single-frame message whose first byte is 0x01 (subscribe) or 0x00
// (unsubscribe) and whose remaining bytes are the topic prefix.
func (s *XPUB) Recv(ctx context.Context) (Message, error)

func (s *XPUB) Close() error
```

### 3.5 XSUB

```go
// XSUB is an extended subscribe socket. It behaves like SUB for receiving
// but also allows the application to send raw subscription frames upstream
// (e.g. when implementing a proxy that forwards XPUB subscription events).
//
// Subscribe and Unsubscribe are convenience wrappers that generate and send
// the appropriate \x01/\x00-prefixed frames. Send allows the application to
// send an arbitrary raw subscription frame directly (for proxy use).
//
// Recv returns data messages (filtered by active subscriptions, like SUB).
type XSUB struct{ /* opaque */ }

func NewXSUB(opts ...Option) *XSUB

func (s *XSUB) Bind(ctx context.Context, endpoint string) error
func (s *XSUB) Connect(ctx context.Context, endpoint string) error

// Subscribe adds topic and sends a \x01-prefixed frame upstream (reference-counted).
func (s *XSUB) Subscribe(topic []byte) error

// Unsubscribe decrements ref count and sends a \x00-prefixed frame upstream when zero.
func (s *XSUB) Unsubscribe(topic []byte) error

// Send sends a raw subscription frame upstream (e.g. forwarding from XPUB.Recv).
// msg must be a single-frame message starting with 0x01 or 0x00.
// Returns ErrClosed after Close.
func (s *XSUB) Send(ctx context.Context, msg Message) error

// Recv fair-queues data messages from all connected peers (filtered by subscriptions).
func (s *XSUB) Recv(ctx context.Context) (Message, error)

func (s *XSUB) Close() error
```

### 3.6 Why this shape

- **PUB.Send never blocks on peers.** A single slow subscriber must not stall
  all others or the publisher. Drop-on-full is the correct pub/sub semantic.
- **Subscribe/Unsubscribe on SUB and XSUB are goroutine-safe methods, not
  options.** Dynamic subscription changes during operation are first-class.
  Reference counting prevents premature unsubscription from shared-topic callers.
- **XPUB/XSUB use raw frames, not typed events.** This makes the standard proxy
  pattern (`for { xpub.Recv() → xsub.Send(); xsub.Recv() → xpub.Send() }`)
  expressible without conversion. Typed wrappers can be built by the caller.
- **Empty subscription (`nil`/`[]byte{}`) = subscribe-all.** Consistent with
  libzmq. A SUB with zero subscriptions receives nothing; callers must subscribe
  explicitly.

## 4. Internal data structures

### 4.1 pubPipe (`pub.go`)

```go
// pubPipe wraps a pipe with a per-peer subscription list.
// Used by PUB and XPUB.
type pubPipe struct {
    *pipe
    mu   sync.RWMutex
    subs [][]byte  // sorted; nil entry means subscribe-all (empty prefix)
}

// matches reports whether topic matches any subscription prefix.
// An empty-prefix entry matches everything.
func (pp *pubPipe) matches(topic []byte) bool

// addSub inserts prefix into subs (if not already present).
func (pp *pubPipe) addSub(prefix []byte)

// removeSub removes prefix from subs (if present).
func (pp *pubPipe) removeSub(prefix []byte)
```

`matches` iterates `subs` and returns true if `bytes.HasPrefix(topic, sub)` for
any entry. An entry with `len(sub) == 0` always returns true (subscribe-all).
A `pubPipe` with empty `subs` matches nothing.

Linear scan is sufficient for F5b — pipe counts and subscription list lengths
are both small in practice. A prefix trie may be added in F6 if profiling
shows it is necessary.

### 4.2 pubPipeSet (`pub.go`)

```go
type pubPipeSet struct {
    mu    sync.RWMutex
    pipes []*pubPipe
}

func (ps *pubPipeSet) add(pp *pubPipe)
func (ps *pubPipeSet) remove(pp *pubPipe)
func (ps *pubPipeSet) all() []*pubPipe  // snapshot for Send iteration
func (ps *pubPipeSet) len() int
```

`pubPipeSet` does not carry a `pipeAdded` channel — PUB/XPUB.Send never waits
for peers (drop semantics). The `all()` snapshot is taken under `mu.RLock()`;
Send iterates the snapshot outside the lock.

### 4.3 subState (`sub.go`)

```go
// subState tracks active subscriptions with reference counts.
// Used by SUB and XSUB.
type subState struct {
    mu   sync.Mutex
    subs map[string]int  // topic string → reference count
}

// add increments the ref count for topic.
// Returns true if this is the first reference (new subscription).
func (ss *subState) add(topic []byte) (isNew bool)

// remove decrements the ref count for topic.
// Returns true if the count reached zero (subscription removed).
func (ss *subState) remove(topic []byte) (wasLast bool)

// all returns a snapshot of currently active subscription prefixes.
func (ss *subState) all() [][]byte
```

The map key is `string(topic)` — a zero-allocation conversion is possible via
`unsafe` but unnecessary at this scale. Empty string key (`""`) represents the
subscribe-all prefix.

### 4.4 socketBase reuse

PUB and XPUB embed `socketBase` (from F5a's `base.go`) for bind/connect/close
lifecycle but use `pubPipeSet` instead of `pipeSet`. `socketBase.bind` and
`socketBase.connect` are extended with a factory parameter that constructs the
appropriate pipe wrapper (`*pipe` for SUB/XSUB, `*pubPipe` for PUB/XPUB).

SUB and XSUB embed `socketBase` directly and reuse `pipeSet` unchanged.

### 4.5 Socket-Type compatibility check

Extended from F5a §4.5:

| Local | Allowed peer Socket-Types |
|-------|--------------------------|
| PUB   | `"SUB"`, `"XSUB"` |
| SUB   | `"PUB"`, `"XPUB"` |
| XPUB  | `"SUB"`, `"XSUB"` |
| XSUB  | `"PUB"`, `"XPUB"` |

Same rejection logic as F5a (close on incompatible; `ErrIncompatiblePeer` on
Connect; silent drop on Bind/Accept).

### 4.6 subReader goroutine (PUB and XPUB)

Each `pubPipe` launches a `subReader` goroutine alongside the standard reader:

```
loop:
  frame = conn.ReadFrame()
  if error: remove pubPipe from pubPipeSet; close conn; exit
  if frame is not a message frame: continue (skip commands)
  if len(frame.Body) == 0: continue (malformed; ignore)
  op, prefix = frame.Body[0], frame.Body[1:]
  switch op:
    case 0x01: pubPipe.addSub(prefix)
               if XPUB: enqueue Message{frame} to subCh
    case 0x00: pubPipe.removeSub(prefix)
               if XPUB: enqueue Message{frame} to subCh
    default:   // not a subscription frame; ignore (PUB silently discards all data from peers)
```

For PUB, subscription events update the filter only. For XPUB, they are also
enqueued to `subCh` (capacity 64) so `XPUB.Recv` can return them to the
application.

### 4.7 Subscription propagation on new connection

After a successful handshake in SUB or XSUB, before the pipe is added to
`pipeSet`, the full current subscription list is sent to the new peer:

```go
for _, sub := range subState.all() {
    frame := append([]byte{0x01}, sub...)
    conn.WriteFrame(wire.Frame{Body: frame, Kind: FrameMessage})
}
```

This ensures PUB/XPUB immediately knows which topics to deliver to the new peer,
with no race between subscription state and pipe addition.

### 4.8 Drop semantics for PUB.Send

`PUB.Send` and `XPUB.Send` attempt a non-blocking write to each matching pipe:

```go
conn.SetWriteDeadline(time.Now())  // immediate timeout
err := conn.WriteFrame(...)
conn.SetWriteDeadline(time.Time{}) // reset
if isTimeout(err):
    // drop for this peer; continue to next
```

A timeout error on a single peer does not fail the Send call. Send returns
`nil` as long as the socket is open and `len(msg) > 0`. This matches libzmq
PUB behaviour (fire-and-forget).

## 5. State machines

PUB, SUB, XPUB, and XSUB have **no sequencing constraints** between Send and
Recv. Operations are independent:

| Type  | Send | Recv | Subscribe/Unsubscribe |
|-------|------|------|-----------------------|
| PUB   | always allowed | ErrState | — |
| SUB   | ErrState | always allowed | always allowed |
| XPUB  | always allowed | always allowed | — |
| XSUB  | always allowed | always allowed | always allowed |

**PUB/SUB are asymmetric:** PUB is send-only from the application's point of
view; SUB is receive-only. Neither enforces an alternating sequence. Both sides
run goroutines in the background for the reverse direction (subscription frames
for PUB, nothing additional needed for SUB beyond the standard pipe reader).

**XPUB.Recv** fair-queues on `subCh`:

```go
select {
case msg := <-xpub.subCh:
    return msg, nil
case <-ctx.Done():
    return nil, ctx.Err()
case <-xpub.closeCh:
    return nil, ErrClosed
}
```

**XSUB.Send** writes a single raw subscription frame to all connected peers:

```go
for _, p := range pipeSet.all() {
    p.conn.WriteFrame(msg[0])
}
return nil
```

`XSUB.Send` does not block on slow peers (same drop semantics as PUB.Send).

## 6. Error model

### 6.1 New sentinels (`errors.go`, additive)

```go
var (
    ErrNoTopic = errors.New("zmq4: PUB/XPUB Send requires at least one frame (topic)")
)
```

All other errors are inherited from F5a (`ErrClosed`, `ErrState`,
`ErrIncompatiblePeer`, `ErrSecurityMismatch`).

### 6.2 Errors from lower layers

Same forwarding rules as F5a §6.2. Relevant additions for F5b:

- `PUB.Send` / `XPUB.Send`: per-pipe write timeout errors are swallowed (drop
  semantics). Only `ErrNoTopic` and `ErrClosed` propagate to the caller.
- `SUB.Subscribe` / `SUB.Unsubscribe`: per-pipe write errors are swallowed
  (the pipe's `subReader` will detect the dead connection on the next read and
  remove it). Only `ErrClosed` propagates.

### 6.3 PUB.Recv / SUB.Send

Both return `ErrState` immediately. No state is changed.

## 7. Test plan

### 7.1 Unit — PUB/SUB (`pub_sub_test.go`)

Each test uses `net.Pipe()`-backed `*conn.Conn` pairs via the existing
`connPair(t, socketType1, socketType2)` helper from F5a.

- **TestPUBSUBRoundTrip** — PUB.Send one message; SUB.Recv returns it; assert
  payload round-trips exactly.
- **TestPUBSUBTopicFilter** — PUB has 3 SUB peers subscribed to `"a"`, `"b"`,
  `"c"` respectively; PUB.Send with topic `"b-data"` (prefix `"b"`); assert
  only the `"b"` subscriber receives it.
- **TestSUBSubscribeAll** — `Subscribe(nil)` receives all messages regardless
  of topic.
- **TestSUBNoSubscriptionsGetsNothing** — SUB with no subscriptions; PUB.Send
  N messages; `SUB.Recv` returns nothing within timeout.
- **TestSUBRefCounting** — `Subscribe("x")` ×2, `Unsubscribe("x")` ×1 → still
  subscribed. `Unsubscribe("x")` again → no longer subscribed.
- **TestPUBMultipartMessage** — PUB.Send 3-frame message; SUB receives all 3
  frames intact.
- **TestPUBDropSlowPeer** — SUB peer with artificially full buffer; PUB.Send
  does not block; other SUB peers still receive messages.
- **TestSUBSubscribeAfterConnect** — SUB.Connect first, then Subscribe; assert
  PUB starts delivering matching messages after subscription arrives.
- **TestSUBUnsubscribe** — Subscribe then Unsubscribe; assert PUB stops
  delivering after unsubscription.
- **TestPUBSendNoTopic** — `PUB.Send(ctx, Message{})` returns
  `errors.Is(err, ErrNoTopic)`.
- **TestSUBSendReturnsErrState** — `SUB.Send` returns `ErrState`.
- **TestPUBRecvReturnsErrState** — `PUB.Recv`... wait, PUB has no Recv method.
  Compiler-enforced; no test needed.

### 7.2 Unit — XPUB/XSUB (`xpub_xsub_test.go`)

- **TestXPUBRecvSubscription** — XSUB connects and calls Subscribe("foo");
  XPUB.Recv returns a message with `msg[0][0] == 0x01` and `msg[0][1:] == "foo"`.
- **TestXPUBRecvUnsubscription** — XSUB.Unsubscribe("foo") after subscribing;
  XPUB.Recv returns a message with `msg[0][0] == 0x00`.
- **TestXPUBSendFiltered** — XPUB with an XSUB peer; XSUB.Subscribe("bar");
  XPUB.Send with topic "bar-data"; XSUB.Recv returns the message.
- **TestXSUBSendForwarding** — XSUB.Send raw subscription frame (`\x01foo`);
  assert XPUB.Recv returns that frame.
- **TestProxyPattern** — full proxy: PUB → XSUB → (proxy) → XPUB → SUB; assert
  messages flow end-to-end; assert SUB only receives matching topics.
- **TestXPUBCtxCancelRecv** — no subscriptions arriving; ctx canceled; XPUB.Recv
  returns `context.Canceled`.
- **TestXSUBCtxCancelRecv** — no messages; ctx canceled; XSUB.Recv returns
  `context.Canceled`.

### 7.3 Unit — lifecycle (`lifecycle_test.go`, additions)

- **TestPUBCloseUnblocksSend** — no peers connected; SUB peer arrives after
  Close; assert Clean shutdown, no goroutine leak.
- **TestSUBCloseUnblocksRecv** — goroutine blocked in `SUB.Recv`; `Close`;
  Recv returns `ErrClosed` within 100 ms.
- **TestXPUBCloseUnblocksRecv** — goroutine blocked in `XPUB.Recv`; `Close`;
  Recv returns `ErrClosed` within 100 ms.
- **TestSUBSubscribeAfterClose** — `Close` then `Subscribe` returns `ErrClosed`.
- **TestIncompatiblePeerPUBtoREQ** — PUB tries to connect to REQ listener;
  `Connect` returns `ErrIncompatiblePeer`.

### 7.4 Integration — transport combinations (`integration_test.go`, build tag `integration`)

Table-driven. One row per `(socket-type pair × transport × security mechanism)`.

- Socket-type pairs: `PUB/SUB`, `XPUB/XSUB`.
- Transports: `tcp`, `ipc`, `inproc`.
- Mechanisms: `NULL`, `PLAIN`, `CURVE`.
- Scenario: subscribe to one topic, send one matching message, assert receipt.

3 transports × 3 mechanisms × 2 socket-type pairs = **18 integration tests**.

Run via: `go test -tags integration ./...`

### 7.5 Interop tests against `libzmq` (`interop/`, build tag `interop`)

Per `00-meta-overview.md` §6. Same libzmq 4.3.5 container as F5a.

- **Directions:** `our Bind ↔ libzmq Connect`, `libzmq Bind ↔ our Connect`.
- **Socket-type pairs:** `PUB/SUB`, `XPUB/XSUB`.
- **Mechanisms:** `NULL`, `PLAIN`, `CURVE`.
- **Transports:** `tcp`, `ipc`.
- **Scenarios:** single-frame message (topic + payload), multipart (topic + 2
  payload frames).

2 directions × 2 pairs × 3 mechanisms × 2 transports × 2 scenarios =
**48 happy-path interop tests**.

Negative interop:
- `mechanism-mismatch`: our NULL PUB ↔ libzmq PLAIN SUB → both sides abort.
- `incompatible-socket-type`: our PUB ↔ libzmq REQ → connection rejected.

**2 negative tests.** Total: **50 interop tests.**

CI cadence: nightly + on demand. Not gating every push.

### 7.6 Race detector

`go test -race ./...` mandatory and gating. Primary race targets:
`TestPUBDropSlowPeer` (concurrent writes from PUB to multiple pipes),
`TestSUBRefCounting` (concurrent Subscribe/Unsubscribe), `TestProxyPattern`
(multiple goroutines on XPUB and XSUB simultaneously).

### 7.7 Done criteria

- All §7.1–§7.3 unit tests pass on `linux/amd64` and `darwin/arm64`.
- §7.4 integration tests (18) green.
- `go test -race ./...` clean.
- §7.5 interop suite (50 tests) green in nightly CI; manual run before tagging.
- `go vet ./...` clean.
- `staticcheck ./...` clean.
- `modernize -fix ./...` produces no diff (run before phase tag).
- Spec §1–§7 fully implemented; §9 open questions remain open or explicitly closed.
- `00-meta-overview.md` updated: F5b status flipped to complete, phase tag
  `phase-5b-pubsub-complete` added.

## 8. File structure

### Files created

| Path | Responsibility |
|------|----------------|
| `pub.go` | `PUB` struct, `pubPipe`, `pubPipeSet`, `NewPUB`, `Bind`, `Connect`, `Send`, `Close`. |
| `sub.go` | `SUB` struct, `subState`, `NewSUB`, `Bind`, `Connect`, `Subscribe`, `Unsubscribe`, `Recv`, `Close`. |
| `xpub.go` | `XPUB` struct, `NewXPUB`, `Bind`, `Connect`, `Send`, `Recv`, `Close`. |
| `xsub.go` | `XSUB` struct, `NewXSUB`, `Bind`, `Connect`, `Subscribe`, `Unsubscribe`, `Send`, `Recv`, `Close`. |
| `pub_sub_test.go` | §7.1 unit tests. |
| `xpub_xsub_test.go` | §7.2 unit tests. |

### Files modified

| Path | Change |
|------|--------|
| `errors.go` | Add `ErrNoTopic`. |
| `base.go` | Extend `socketBase.bind`/`connect` with pipe-factory parameter to support `pubPipe` construction for PUB/XPUB. |
| `lifecycle_test.go` | Add §7.3 lifecycle tests for PUB/SUB/XPUB/XSUB. |
| `integration_test.go` | Add §7.4 table rows for `PUB/SUB` and `XPUB/XSUB`. |
| `interop/interop_test.go` | Add §7.5 interop tests for `PUB/SUB` and `XPUB/XSUB`. |
| `doc.go` | Add PUB/SUB/XPUB/XSUB to package-level godoc. |
| `docs/specs/00-meta-overview.md` | Update F5b status to complete; add phase tag. |

## 9. Open questions

1. **XPUB verbose mode.** libzmq supports `ZMQ_XPUB_VERBOSE` which causes
   XPUB to forward duplicate subscription frames (normally deduplicated).
   Deferred to F6 as an `Option`.

2. **Drop vs. error on full XPUB subCh.** If the application does not call
   `XPUB.Recv` fast enough, `subCh` (capacity 64) fills. Currently the
   `subReader` goroutine blocks trying to send to `subCh`, which may starve
   subscription updates. Consider a non-blocking send with drop (and a debug
   counter) vs. keeping the current block. Deferred to F6 monitoring.

3. **XSUB.Send validation.** Currently `XSUB.Send` accepts any single-frame
   message and forwards it. Should it validate that `msg[0][0]` is `\x01` or
   `\x00`? Strict validation could reject malformed frames early; permissive
   is simpler. Decision deferred — default permissive for F5b.

4. **Missing Socket-Type from peer.** Inherited from F5a §9.4: peers omitting
   `Socket-Type` are accepted without check. Permissive; same as F5a.

5. **PUB.Send partial delivery observability.** Currently the drop of a message
   to a slow peer is silent. A future `WithDropCallback` option or monitoring
   event could surface this. Deferred to F6.

6. **XSUB.Send atomicity.** `XSUB.Send` writes the raw frame to all connected
   peers in a loop. If some writes succeed and one fails (dead pipe), the
   subscription is partially propagated. The dead pipe's `subReader` will
   detect the error on the next read and remove the pipe. This is acceptable
   for F5b.

## 10. References

- [RFC 29/PUBSUB — Publish-Subscribe Pattern](https://rfc.zeromq.org/spec/29/)
- [RFC 23/ZMTP — ZeroMQ Message Transport Protocol 3.1](https://rfc.zeromq.org/spec/23/) §2.4 (metadata).
- Project specs:
  - `00-meta-overview.md` §3 (layering), §4 (phase pipeline), §6 (testing strategy).
  - `00b-memory-model.md` (boundary ownership).
  - `05a-sockets-reqrep.md` §4 (socketBase, pipe, pipeSet, options reuse).
- libzmq man pages: [`zmq_socket(3)`](http://api.zeromq.org/4-3:zmq-socket)
  (PUB, SUB, XPUB, XSUB).
- Go stdlib: `bytes.HasPrefix`, `context.Context`, `sync.RWMutex`.
