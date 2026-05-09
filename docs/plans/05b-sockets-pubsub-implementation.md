# F5b Socket Layer Implementation Plan — PUB / SUB / XPUB / XSUB

> **For Claude:** REQUIRED: Use `superpowers:subagent-driven-development` to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking. Each task is one commit.

**Goal:** Implement PUB, SUB, XPUB, and XSUB socket types in the root `zmq4` package per `docs/specs/05b-sockets-pubsub.md`, delivering publisher-side topic filtering with subscription propagation and XPUB/XSUB proxy support.

**Architecture:** PUB/XPUB maintain a `pubPipeSet` (separate from `pipeSet`) of `pubPipe` objects, each with a `subReader` goroutine that reads subscription frames and a buffered `outCh` channel for non-blocking broadcast. `socketBase` is extended with two optional callbacks (`postHandshake`, `closeFn`) so PUB/XPUB/SUB can plug custom pipe-registration logic without breaking the REQ/REP/DEALER/ROUTER path. SUB and XSUB track active subscriptions in `subState` (reference-counted map) and send subscription frames to peers on `Subscribe`/`Unsubscribe` calls and on new connections. PUB.Send fans out to all matching `pubPipe.outCh` channels non-blocking (drop if full).

**Tech Stack:** Pure Go 1.26, stdlib only — `bytes`, `context`, `errors`, `fmt`, `net`, `sync`, `time`, `reflect`. Reuses `internal/conn` (F4), `internal/security/*` (F2), `internal/transport` (F3), `internal/wire` (F1). No new external deps.

**Decisions baked into the plan:**
- Publisher-side topic filtering: PUB/XPUB maintain per-`pubPipe` subscription lists and only send to matching peers.
- Drop semantics: PUB.Send does `select { case pp.outCh <- msg: default: }` per pipe; never blocks on slow peers.
- `pubPipe` has two goroutines: `subReader` (reads sub frames, updates filter) and `writer` (reads from `outCh`, writes to wire). This avoids exposing `SetWriteDeadline` on `conn.Conn`.
- `socketBase` gains `postHandshake func(*conn.Conn) error` and `closeFn func()` callbacks; existing REQ/REP/DEALER/ROUTER path is unchanged (nil callbacks = default behaviour).
- SUB's `postHandshake` sends the full current subscription list to every new peer before the pipe's reader goroutine starts.
- `subState` uses `map[string]int` for reference counting; key `""` represents subscribe-all.
- Tests use `inproc://` + `t.Name()` endpoints (net.Pipe-backed, no real network needed for unit tests). Timing: subscribe before publish; for inproc, Write on net.Pipe is synchronous once the reader goroutine is running.
- **No `modernize -fix` per task.** Run only at Task 15 (done-criteria sweep).
- **Phase tag:** `phase-5b-pubsub-complete` after Task 15.

---

## File Structure

### Files created

| Path | Responsibility |
|------|----------------|
| `pub.go` | `pubPipe`, `pubPipeSet`, `PUB` struct, `NewPUB`, `Bind`, `Connect`, `Send`, `Close`. |
| `sub.go` | `subState`, `SUB` struct, `NewSUB`, `Bind`, `Connect`, `Subscribe`, `Unsubscribe`, `Recv`, `Close`. |
| `xpub.go` | `XPUB` struct, `NewXPUB`, `Bind`, `Connect`, `Send`, `Recv`, `Close`. |
| `xsub.go` | `XSUB` struct, `NewXSUB`, `Bind`, `Connect`, `Subscribe`, `Unsubscribe`, `Send`, `Recv`, `Close`. |
| `pub_sub_test.go` | §7.1 unit tests for PUB/SUB. |
| `xpub_xsub_test.go` | §7.2 unit tests for XPUB/XSUB (including proxy pattern). |

### Files modified

| Path | Change |
|------|--------|
| `errors.go` | Add `ErrNoTopic`. |
| `base.go` | Add `postHandshake`/`closeFn` callbacks to `socketBase`; extend `compatiblePeers` map with PUB/SUB/XPUB/XSUB entries. |
| `lifecycle_test.go` | Add §7.3 lifecycle tests for PUB/SUB/XPUB/XSUB. |
| `integration_test.go` | Add §7.4 table rows for PUB/SUB and XPUB/XSUB pairs. |
| `interop/interop_test.go` | Add §7.5 interop tests for PUB/SUB and XPUB/XSUB. |
| `doc.go` | Add PUB/SUB/XPUB/XSUB to package-level godoc. |
| `docs/specs/00-meta-overview.md` | Flip F5b status to complete, add phase tag. |

---

## Chunk 1: Error sentinel + base.go extension

### Task 1: Add `ErrNoTopic` to `errors.go`

**Files:**
- Modify: `errors.go`

- [ ] **Step 1: Add sentinel**

Open `errors.go`. After the existing `ErrNoIdentity` line, add:

```go
ErrNoTopic = errors.New("zmq4: PUB/XPUB Send requires at least one frame (topic)")
```

The full var block becomes:

```go
var (
	ErrClosed           = errors.New("zmq4: socket closed")
	ErrState            = errors.New("zmq4: operation out of sequence")
	ErrNoRoute          = errors.New("zmq4: no route to peer")
	ErrIncompatiblePeer = errors.New("zmq4: incompatible peer socket type")
	ErrSecurityMismatch = errors.New("zmq4: security option not valid for this role")
	ErrNoIdentity       = errors.New("zmq4: ROUTER Send requires non-empty msg[0]")
	ErrNoTopic          = errors.New("zmq4: PUB/XPUB Send requires at least one frame (topic)")
)
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./...`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add errors.go
git commit -m "feat(F5b): add ErrNoTopic sentinel"
```

---

### Task 2: Extend `base.go` — callbacks + compatibility table

**Files:**
- Modify: `base.go`

The existing `socketBase` struct and `addConn` method need two additive changes:
1. Two optional callback fields (`postHandshake`, `closeFn`).
2. PUB/SUB/XPUB/XSUB entries in `compatiblePeers`.

- [ ] **Step 1: Extend `compatiblePeers`**

In `base.go`, find the `compatiblePeers` var block and add four new entries:

```go
var compatiblePeers = map[string]map[string]bool{
	"REQ":    {"REP": true, "ROUTER": true},
	"REP":    {"REQ": true, "DEALER": true},
	"DEALER": {"REP": true, "ROUTER": true, "DEALER": true},
	"ROUTER": {"REQ": true, "DEALER": true, "ROUTER": true},
	"PUB":    {"SUB": true, "XSUB": true},
	"SUB":    {"PUB": true, "XPUB": true},
	"XPUB":   {"SUB": true, "XSUB": true},
	"XSUB":   {"PUB": true, "XPUB": true},
}
```

- [ ] **Step 2: Add callback fields to `socketBase`**

Find the `socketBase` struct definition and add two fields:

```go
type socketBase struct {
	cfg       *socketConfig
	pipes     *pipeSet
	closeCh   chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	// postHandshake, when non-nil, is called by addConn instead of the
	// default newPipe path. The compatibility check always runs first.
	// Used by PUB/XPUB (pubPipe creation) and SUB/XSUB (subscription replay).
	postHandshake func(c *conn.Conn) error

	// closeFn, when non-nil, is called inside close() before waiting for
	// goroutines. Used by PUB/XPUB to close pubPipes and wait for their wg.
	closeFn func()
}
```

- [ ] **Step 3: Update `addConn` to honour `postHandshake`**

Find `addConn` and change the last half (after the compatibility check) to:

```go
func (sb *socketBase) addConn(c *conn.Conn, localSocketType string) error {
	peerType := c.PeerMetadata()["Socket-Type"]
	if peerType != "" {
		allowed := compatiblePeers[localSocketType]
		if !allowed[peerType] {
			return ErrIncompatiblePeer
		}
	}
	if sb.postHandshake != nil {
		return sb.postHandshake(c)
	}
	identity := peerIdentity(c.PeerMetadata())
	p := newPipe(c, identity)
	sb.pipes.add(p)
	p.start(sb.pipes, sb.closeCh)
	return nil
}
```

- [ ] **Step 4: Update `close()` to call `closeFn`**

Find the `close()` method. After `close(sb.closeCh)` (the first line of the `closeOnce.Do` body), add:

```go
if sb.closeFn != nil {
    sb.closeFn()
}
```

- [ ] **Step 5: Verify existing tests still pass**

Run: `go test -race ./...`
Expected: all existing REQ/REP/DEALER/ROUTER tests PASS (callbacks are nil by default; no behaviour change).

- [ ] **Step 6: Commit**

```bash
git add base.go
git commit -m "feat(F5b): extend socketBase — postHandshake/closeFn hooks + pub/sub compat table"
```

---

## Chunk 2: PUB socket

### Task 3: PUB socket (`pub.go`)

**Files:**
- Create: `pub.go`

`pubPipe` wraps a `*conn.Conn` with a per-peer subscription list and two goroutines: `subReader` (reads subscription frames from the SUB peer, updates the filter) and `writer` (drains `outCh` and writes to the wire). `pubPipeSet` is a goroutine-safe slice of `*pubPipe`. `PUB` embeds `socketBase` (for lifecycle) and holds its own `pubPipeSet`.

- [ ] **Step 1: Write failing test**

```go
// pub_sub_test.go (partial — create the file now, add more tests in Task 7)
package zmq4_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
)

func pubSubEP(t *testing.T) string {
	t.Helper()
	return "inproc://" + strings.ReplaceAll(t.Name(), "/", "_")
}

func psCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestPUBSendNoTopic(t *testing.T) {
	pub := zmq4.NewPUB()
	t.Cleanup(func() { pub.Close() })
	ctx := psCtx(t)
	err := pub.Send(ctx, zmq4.Message{})
	if !errors.Is(err, zmq4.ErrNoTopic) {
		t.Fatalf("want ErrNoTopic, got %v", err)
	}
}

func TestPUBCloseIdempotent(t *testing.T) {
	pub := zmq4.NewPUB()
	if err := pub.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := pub.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
```

- [ ] **Step 2: Run test — verify it fails**

Run: `go test -run 'TestPUB' ./...`
Expected: FAIL — `zmq4.NewPUB` undefined.

- [ ] **Step 3: Implement `pub.go`**

```go
package zmq4

import (
	"bytes"
	"context"
	"sync"

	"github.com/tomi77/zmq4/internal/conn"
	"github.com/tomi77/zmq4/internal/wire"
)

const pubOutChCap = 64

// pubPipe is one connected SUB/XSUB peer on a PUB or XPUB socket.
// It has two goroutines: subReader (reads subscription frames from the peer
// and updates the filter) and writer (drains outCh and sends to the wire).
type pubPipe struct {
	conn  *conn.Conn
	outCh chan Message // PUB drops to this channel non-blocking

	mu   sync.RWMutex
	subs [][]byte // sorted subscription prefixes; nil entry = subscribe-all

	wg        sync.WaitGroup
	subNotify chan<- Message // non-nil for XPUB: subscription frames go here
}

func newPubPipe(c *conn.Conn, subNotify chan<- Message) *pubPipe {
	return &pubPipe{
		conn:      c,
		outCh:     make(chan Message, pubOutChCap),
		subNotify: subNotify,
	}
}

func (pp *pubPipe) start(ps *pubPipeSet, closeCh <-chan struct{}) {
	pp.wg.Add(2)
	go pp.subReader(ps, closeCh)
	go pp.writer(closeCh)
}

func (pp *pubPipe) subReader(ps *pubPipeSet, closeCh <-chan struct{}) {
	defer pp.wg.Done()
	defer ps.remove(pp)
	for {
		f, err := pp.conn.ReadFrame()
		if err != nil {
			return
		}
		if len(f.Body) == 0 {
			continue
		}
		op, prefix := f.Body[0], append([]byte(nil), f.Body[1:]...)
		switch op {
		case 0x01:
			pp.addSub(prefix)
			if pp.subNotify != nil {
				frame := append([]byte(nil), f.Body...)
				select {
				case pp.subNotify <- Message{frame}:
				default: // drop if XPUB application is not consuming fast enough
				}
			}
		case 0x00:
			pp.removeSub(prefix)
			if pp.subNotify != nil {
				frame := append([]byte(nil), f.Body...)
				select {
				case pp.subNotify <- Message{frame}:
				default:
				}
			}
		}
	}
}

func (pp *pubPipe) writer(closeCh <-chan struct{}) {
	defer pp.wg.Done()
	for {
		select {
		case msg := <-pp.outCh:
			sendFrames(pp.conn, msg) // error = peer dead; subReader will detect on next read
		case <-closeCh:
			return
		}
	}
}

// matches reports whether topic matches any subscription prefix.
func (pp *pubPipe) matches(topic []byte) bool {
	pp.mu.RLock()
	defer pp.mu.RUnlock()
	for _, sub := range pp.subs {
		if len(sub) == 0 || bytes.HasPrefix(topic, sub) {
			return true
		}
	}
	return false
}

func (pp *pubPipe) addSub(prefix []byte) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	key := string(prefix)
	for _, s := range pp.subs {
		if string(s) == key {
			return // already present
		}
	}
	pp.subs = append(pp.subs, prefix)
}

func (pp *pubPipe) removeSub(prefix []byte) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	key := string(prefix)
	for i, s := range pp.subs {
		if string(s) == key {
			pp.subs = append(pp.subs[:i], pp.subs[i+1:]...)
			return
		}
	}
}

// pubPipeSet is a goroutine-safe set of pubPipe pointers.
type pubPipeSet struct {
	mu    sync.RWMutex
	pipes []*pubPipe
}

func newPubPipeSet() *pubPipeSet { return &pubPipeSet{} }

func (ps *pubPipeSet) add(pp *pubPipe) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.pipes = append(ps.pipes, pp)
}

func (ps *pubPipeSet) remove(pp *pubPipe) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, q := range ps.pipes {
		if q == pp {
			ps.pipes = append(ps.pipes[:i], ps.pipes[i+1:]...)
			return
		}
	}
}

func (ps *pubPipeSet) all() []*pubPipe {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	snap := make([]*pubPipe, len(ps.pipes))
	copy(snap, ps.pipes)
	return snap
}

// PUB is a publish socket. It fans out messages to all subscribers whose
// active subscription prefix matches msg[0] (the topic frame). Send never
// blocks on slow subscribers — messages are dropped per pipe if full.
type PUB struct {
	base     socketBase
	pubPipes *pubPipeSet
}

// NewPUB creates a new PUB socket with the given options.
func NewPUB(opts ...Option) *PUB {
	s := &PUB{
		base:     newSocketBase(newSocketConfig(opts)),
		pubPipes: newPubPipeSet(),
	}
	s.base.postHandshake = func(c *conn.Conn) error {
		pp := newPubPipe(c, nil)
		s.pubPipes.add(pp)
		pp.start(s.pubPipes, s.base.closeCh)
		return nil
	}
	s.base.closeFn = func() {
		for _, pp := range s.pubPipes.all() {
			pp.conn.Close()
		}
		for _, pp := range s.pubPipes.all() {
			pp.wg.Wait()
		}
	}
	return s
}

// Bind opens a listener on endpoint. Non-blocking after listener is open.
func (s *PUB) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "PUB")
}

// Connect dials endpoint and runs the ZMTP handshake. Blocking.
func (s *PUB) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "PUB")
}

// Send broadcasts msg to all peers whose subscription prefix matches msg[0].
// Non-matching peers and peers with full outbound buffers are silently skipped.
// Returns ErrNoTopic if len(msg) == 0. Returns ErrClosed after Close.
func (s *PUB) Send(ctx context.Context, msg Message) error {
	select {
	case <-s.base.closeCh:
		return ErrClosed
	default:
	}
	if len(msg) == 0 {
		return ErrNoTopic
	}
	topic := msg[0]
	for _, pp := range s.pubPipes.all() {
		if pp.matches(topic) {
			select {
			case pp.outCh <- msg:
			default: // drop — subscriber is slow
			}
		}
	}
	return nil
}

// Close stops all goroutines and frees resources. Idempotent.
func (s *PUB) Close() error {
	s.base.close()
	return nil
}

// subFrame builds a subscription frame: op (0x01/0x00) followed by topic.
func subFrame(op byte, topic []byte) wire.Frame {
	body := make([]byte, 1+len(topic))
	body[0] = op
	copy(body[1:], topic)
	return wire.Frame{Kind: wire.FrameMessage, Body: body}
}
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `go test -race -run 'TestPUB' -v ./...`
Expected: `TestPUBSendNoTopic` and `TestPUBCloseIdempotent` PASS.

- [ ] **Step 5: Commit**

```bash
git add pub.go pub_sub_test.go
git commit -m "feat(F5b): PUB socket — pubPipe/pubPipeSet, broadcast with topic filter, drop semantics"
```

---

## Chunk 3: SUB socket

### Task 4: SUB socket (`sub.go`)

**Files:**
- Create: `sub.go`
- Modify: `pub_sub_test.go` (add PUB/SUB round-trip tests)

- [ ] **Step 1: Write failing tests**

Add to `pub_sub_test.go`:

```go
func TestPUBSUBRoundTrip(t *testing.T) {
	ep := pubSubEP(t)
	ctx := psCtx(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { pub.Close() })

	sub := zmq4.NewSUB()
	if err := sub.Connect(ctx, ep); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { sub.Close() })

	if err := sub.Subscribe([]byte("hello")); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Give subReader goroutine time to process the subscription frame.
	// For inproc (net.Pipe), this is effectively synchronous once both
	// goroutines are scheduled; a brief sleep is sufficient.
	time.Sleep(10 * time.Millisecond)

	msg := zmq4.Message{[]byte("hello world")}
	if err := pub.Send(ctx, msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := sub.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(got[0]) != "hello world" {
		t.Fatalf("want %q, got %q", "hello world", got[0])
	}
}

func TestSUBNoSubscriptionsGetsNothing(t *testing.T) {
	ep := pubSubEP(t)
	ctx := psCtx(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pub.Close() })

	sub := zmq4.NewSUB() // no Subscribe call
	if err := sub.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Close() })

	time.Sleep(10 * time.Millisecond)

	if err := pub.Send(ctx, zmq4.Message{[]byte("anything")}); err != nil {
		t.Fatal(err)
	}

	// sub.Recv must time out — no subscription, no message.
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, err := sub.Recv(tctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
}

func TestSUBSubscribeAll(t *testing.T) {
	ep := pubSubEP(t)
	ctx := psCtx(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pub.Close() })

	sub := zmq4.NewSUB()
	if err := sub.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Close() })

	if err := sub.Subscribe(nil); err != nil { // nil = subscribe all
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)

	for _, topic := range []string{"foo", "bar", "baz"} {
		if err := pub.Send(ctx, zmq4.Message{[]byte(topic)}); err != nil {
			t.Fatalf("Send %q: %v", topic, err)
		}
	}
	seen := map[string]bool{}
	for range 3 {
		got, err := sub.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		seen[string(got[0])] = true
	}
	for _, topic := range []string{"foo", "bar", "baz"} {
		if !seen[topic] {
			t.Fatalf("subscribe-all: did not receive %q", topic)
		}
	}
}

func TestPUBSUBTopicFilter(t *testing.T) {
	ep := pubSubEP(t)
	ctx := psCtx(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pub.Close() })

	subA := zmq4.NewSUB()
	if err := subA.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { subA.Close() })
	subA.Subscribe([]byte("a"))

	subB := zmq4.NewSUB()
	if err := subB.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { subB.Close() })
	subB.Subscribe([]byte("b"))

	time.Sleep(20 * time.Millisecond)

	pub.Send(ctx, zmq4.Message{[]byte("a-data")})
	pub.Send(ctx, zmq4.Message{[]byte("b-data")})

	// subA receives "a-data"; subB receives "b-data".
	gotA, err := subA.Recv(ctx)
	if err != nil {
		t.Fatalf("subA Recv: %v", err)
	}
	if string(gotA[0]) != "a-data" {
		t.Fatalf("subA: want a-data, got %q", gotA[0])
	}
	gotB, err := subB.Recv(ctx)
	if err != nil {
		t.Fatalf("subB Recv: %v", err)
	}
	if string(gotB[0]) != "b-data" {
		t.Fatalf("subB: want b-data, got %q", gotB[0])
	}

	// subA must NOT receive "b-data" — verify via timeout.
	tctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	_, err = subA.Recv(tctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("subA should not receive b-data; got err=%v", err)
	}
}

func TestSUBRefCounting(t *testing.T) {
	ep := pubSubEP(t)
	ctx := psCtx(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pub.Close() })

	sub := zmq4.NewSUB()
	if err := sub.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Close() })

	sub.Subscribe([]byte("x")) // ref count = 1
	sub.Subscribe([]byte("x")) // ref count = 2
	sub.Unsubscribe([]byte("x")) // ref count = 1 — still subscribed
	time.Sleep(10 * time.Millisecond)

	pub.Send(ctx, zmq4.Message{[]byte("x-msg")})
	got, err := sub.Recv(ctx)
	if err != nil {
		t.Fatalf("after 1 unsub: Recv: %v", err)
	}
	if string(got[0]) != "x-msg" {
		t.Fatalf("want x-msg, got %q", got[0])
	}

	sub.Unsubscribe([]byte("x")) // ref count = 0 — unsubscribed
	time.Sleep(10 * time.Millisecond)

	pub.Send(ctx, zmq4.Message{[]byte("x-msg2")})
	tctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	_, err = sub.Recv(tctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("after full unsub: expected DeadlineExceeded, got %v", err)
	}
}

func TestSUBCloseUnblocksRecv(t *testing.T) {
	sub := zmq4.NewSUB()
	ctx := context.Background()

	var wg sync.WaitGroup
	var recvErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, recvErr = sub.Recv(ctx)
	}()

	time.Sleep(10 * time.Millisecond)
	sub.Close()
	wg.Wait()
	if !errors.Is(recvErr, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", recvErr)
	}
}
```

Add `"sync"` to the imports.

- [ ] **Step 2: Run test — verify it fails**

Run: `go test -run 'TestSUB|TestPUBSUB' ./...`
Expected: FAIL — `zmq4.NewSUB` undefined.

- [ ] **Step 3: Implement `sub.go`**

```go
package zmq4

import (
	"context"
	"sync"

	"github.com/tomi77/zmq4/internal/conn"
	"github.com/tomi77/zmq4/internal/wire"
)

// subState tracks active subscriptions with reference counts.
type subState struct {
	mu   sync.Mutex
	subs map[string]int // topic string → ref count; "" = subscribe-all
}

func newSubState() *subState {
	return &subState{subs: make(map[string]int)}
}

// add increments the ref count for topic; returns true if this is the first reference.
func (ss *subState) add(topic []byte) (isNew bool) {
	key := string(topic) // "" for nil/empty = subscribe-all
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.subs[key]++
	return ss.subs[key] == 1
}

// remove decrements the ref count; returns true when count reaches zero.
func (ss *subState) remove(topic []byte) (wasLast bool) {
	key := string(topic)
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.subs[key] <= 1 {
		delete(ss.subs, key)
		return true
	}
	ss.subs[key]--
	return false
}

// all returns a snapshot of currently active subscription prefixes.
func (ss *subState) all() [][]byte {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	result := make([][]byte, 0, len(ss.subs))
	for k := range ss.subs {
		result = append(result, []byte(k))
	}
	return result
}

// SUB is a subscribe socket. It fair-queues messages from connected PUB/XPUB
// peers that match at least one active subscription. A SUB with no subscriptions
// receives nothing. Subscribe(nil) = subscribe all.
type SUB struct {
	base  socketBase
	state *subState
}

// NewSUB creates a new SUB socket.
func NewSUB(opts ...Option) *SUB {
	s := &SUB{
		base:  newSocketBase(newSocketConfig(opts)),
		state: newSubState(),
	}
	s.base.postHandshake = s.onNewConn
	return s
}

// onNewConn sends the full current subscription list to the new peer before
// registering the pipe. Called by socketBase.addConn after compatibility check.
func (s *SUB) onNewConn(c *conn.Conn) error {
	for _, sub := range s.state.all() {
		if err := c.WriteFrame(subFrame(0x01, sub)); err != nil {
			return err
		}
	}
	identity := peerIdentity(c.PeerMetadata())
	p := newPipe(c, identity)
	s.base.pipes.add(p)
	p.start(s.base.pipes, s.base.closeCh)
	return nil
}

func (s *SUB) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "SUB")
}

func (s *SUB) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "SUB")
}

// Subscribe adds topic to the subscription list (ref-counted). If this is the
// first reference, sends a subscription frame to all connected peers.
// topic == nil or topic == []byte{} means subscribe to all messages.
// Returns ErrClosed after Close.
func (s *SUB) Subscribe(topic []byte) error {
	select {
	case <-s.base.closeCh:
		return ErrClosed
	default:
	}
	if !s.state.add(topic) {
		return nil // already subscribed
	}
	f := subFrame(0x01, topic)
	for _, p := range s.base.pipes.all() {
		p.conn.WriteFrame(f) //nolint:errcheck — dead pipe detected by reader goroutine
	}
	return nil
}

// Unsubscribe decrements the ref count for topic. When it reaches zero, sends
// an unsubscription frame to all connected peers. No-op if not subscribed.
// Returns ErrClosed after Close.
func (s *SUB) Unsubscribe(topic []byte) error {
	select {
	case <-s.base.closeCh:
		return ErrClosed
	default:
	}
	if !s.state.remove(topic) {
		return nil // ref count decremented but not zero, or was never subscribed
	}
	f := subFrame(0x00, topic)
	for _, p := range s.base.pipes.all() {
		p.conn.WriteFrame(f) //nolint:errcheck
	}
	return nil
}

// Recv fair-queues messages from all connected peers. PUB/XPUB already filter
// by subscription, so every received message matches an active subscription.
func (s *SUB) Recv(ctx context.Context) (Message, error) {
	msg, _, err := s.base.recvAny(ctx)
	return msg, err
}

// Close stops all goroutines and frees resources. Idempotent.
func (s *SUB) Close() error {
	s.base.close()
	return nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test -race -run 'TestSUB|TestPUBSUB' -v ./...`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add sub.go pub_sub_test.go
git commit -m "feat(F5b): SUB socket — subState ref-counting, Subscribe/Unsubscribe, subscription replay on connect"
```

---

## Chunk 4: XPUB socket

### Task 5: XPUB socket (`xpub.go`)

**Files:**
- Create: `xpub.go`
- Create: `xpub_xsub_test.go` (initial tests for XPUB)

XPUB is PUB with a `subCh chan Message` (capacity 64) that receives subscription/unsubscription frames from peers. `XPUB.Recv` returns these frames to the application. The `pubPipe.subNotify` channel feeds `subCh`.

- [ ] **Step 1: Write failing test**

```go
// xpub_xsub_test.go
package zmq4_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
)

func xpubEP(t *testing.T) string {
	t.Helper()
	return "inproc://" + strings.ReplaceAll(t.Name(), "/", "_")
}

func xCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestXPUBRecvSubscription(t *testing.T) {
	ep := xpubEP(t)
	ctx := xCtx(t)

	xpub := zmq4.NewXPUB()
	if err := xpub.Bind(ctx, ep); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { xpub.Close() })

	xsub := zmq4.NewXSUB()
	if err := xsub.Connect(ctx, ep); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { xsub.Close() })

	if err := xsub.Subscribe([]byte("foo")); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	got, err := xpub.Recv(ctx)
	if err != nil {
		t.Fatalf("XPUB Recv: %v", err)
	}
	if len(got) == 0 || len(got[0]) == 0 {
		t.Fatalf("want subscription frame, got empty message")
	}
	if got[0][0] != 0x01 {
		t.Fatalf("want subscribe op 0x01, got 0x%02x", got[0][0])
	}
	if string(got[0][1:]) != "foo" {
		t.Fatalf("want topic foo, got %q", got[0][1:])
	}
}

func TestXPUBRecvUnsubscription(t *testing.T) {
	ep := xpubEP(t)
	ctx := xCtx(t)

	xpub := zmq4.NewXPUB()
	if err := xpub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xpub.Close() })

	xsub := zmq4.NewXSUB()
	if err := xsub.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xsub.Close() })

	xsub.Subscribe([]byte("bar"))
	// Consume subscribe frame.
	sub, _ := xpub.Recv(ctx)
	if len(sub) == 0 || sub[0][0] != 0x01 {
		t.Fatalf("expected subscribe frame first, got %v", sub)
	}

	xsub.Unsubscribe([]byte("bar"))
	got, err := xpub.Recv(ctx)
	if err != nil {
		t.Fatalf("XPUB Recv unsub: %v", err)
	}
	if got[0][0] != 0x00 {
		t.Fatalf("want unsubscribe op 0x00, got 0x%02x", got[0][0])
	}
	if string(got[0][1:]) != "bar" {
		t.Fatalf("want topic bar, got %q", got[0][1:])
	}
}

func TestXPUBSendFiltered(t *testing.T) {
	ep := xpubEP(t)
	ctx := xCtx(t)

	xpub := zmq4.NewXPUB()
	if err := xpub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xpub.Close() })

	xsub := zmq4.NewXSUB()
	if err := xsub.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xsub.Close() })

	xsub.Subscribe([]byte("news"))
	// Drain subscription frame from XPUB.
	xpub.Recv(ctx)
	time.Sleep(10 * time.Millisecond)

	if err := xpub.Send(ctx, zmq4.Message{[]byte("news-flash")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := xsub.Recv(ctx)
	if err != nil {
		t.Fatalf("XSUB Recv: %v", err)
	}
	if string(got[0]) != "news-flash" {
		t.Fatalf("want news-flash, got %q", got[0])
	}
}

func TestXPUBCtxCancelRecv(t *testing.T) {
	xpub := zmq4.NewXPUB()
	t.Cleanup(func() { xpub.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := xpub.Recv(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
```

Add `"errors"` to the imports.

- [ ] **Step 2: Run test — verify it fails**

Run: `go test -run 'TestXPUB' ./...`
Expected: FAIL — `zmq4.NewXPUB` undefined.

- [ ] **Step 3: Implement `xpub.go`**

```go
package zmq4

import "context"

const xpubSubChCap = 64

// XPUB is an extended publish socket. It behaves like PUB for sending and
// exposes subscription/unsubscription frames to the application via Recv.
type XPUB struct {
	base     socketBase
	pubPipes *pubPipeSet
	subCh    chan Message // subscription events from all peers
}

// NewXPUB creates a new XPUB socket.
func NewXPUB(opts ...Option) *XPUB {
	s := &XPUB{
		base:     newSocketBase(newSocketConfig(opts)),
		pubPipes: newPubPipeSet(),
		subCh:    make(chan Message, xpubSubChCap),
	}
	s.base.postHandshake = func(c *conn.Conn) error {
		pp := newPubPipe(c, s.subCh)
		s.pubPipes.add(pp)
		pp.start(s.pubPipes, s.base.closeCh)
		return nil
	}
	s.base.closeFn = func() {
		for _, pp := range s.pubPipes.all() {
			pp.conn.Close()
		}
		for _, pp := range s.pubPipes.all() {
			pp.wg.Wait()
		}
	}
	return s
}

func (s *XPUB) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "XPUB")
}

func (s *XPUB) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "XPUB")
}

// Send broadcasts msg to all peers whose subscription matches msg[0].
// Drop semantics identical to PUB.Send.
func (s *XPUB) Send(ctx context.Context, msg Message) error {
	select {
	case <-s.base.closeCh:
		return ErrClosed
	default:
	}
	if len(msg) == 0 {
		return ErrNoTopic
	}
	topic := msg[0]
	for _, pp := range s.pubPipes.all() {
		if pp.matches(topic) {
			select {
			case pp.outCh <- msg:
			default:
			}
		}
	}
	return nil
}

// Recv blocks until a subscription or unsubscription frame arrives from a peer.
// msg[0][0] == 0x01 → subscribe; msg[0][0] == 0x00 → unsubscribe.
// msg[0][1:] is the topic prefix.
func (s *XPUB) Recv(ctx context.Context) (Message, error) {
	select {
	case msg := <-s.subCh:
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.base.closeCh:
		return nil, ErrClosed
	}
}

func (s *XPUB) Close() error {
	s.base.close()
	return nil
}
```

Note: `conn` package import is needed because `postHandshake` captures `c *conn.Conn`. Add to imports:

```go
import (
	"context"
	"github.com/tomi77/zmq4/internal/conn"
)
```

- [ ] **Step 4: Run tests**

Run: `go test -race -run 'TestXPUB' -v ./...`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add xpub.go xpub_xsub_test.go
git commit -m "feat(F5b): XPUB socket — pubPipe with subNotify channel, Recv returns subscription frames"
```

---

## Chunk 5: XSUB socket

### Task 6: XSUB socket (`xsub.go`)

**Files:**
- Create: `xsub.go`
- Modify: `xpub_xsub_test.go` (add proxy and XSUB tests)

XSUB is SUB with an additional `Send` method that forwards raw subscription frames to all connected peers. It has `Subscribe`/`Unsubscribe` convenience wrappers (same as SUB).

- [ ] **Step 1: Write failing tests**

Add to `xpub_xsub_test.go`:

```go
func TestXSUBSendForwarding(t *testing.T) {
	ep := xpubEP(t)
	ctx := xCtx(t)

	xpub := zmq4.NewXPUB()
	if err := xpub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xpub.Close() })

	xsub := zmq4.NewXSUB()
	if err := xsub.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xsub.Close() })

	// Send raw subscription frame via XSUB.Send.
	rawSub := zmq4.Message{[]byte("\x01myTopic")}
	if err := xsub.Send(ctx, rawSub); err != nil {
		t.Fatalf("XSUB Send: %v", err)
	}

	got, err := xpub.Recv(ctx)
	if err != nil {
		t.Fatalf("XPUB Recv: %v", err)
	}
	if got[0][0] != 0x01 || string(got[0][1:]) != "myTopic" {
		t.Fatalf("XPUB got unexpected frame: %v", got[0])
	}
}

func TestProxyPattern(t *testing.T) {
	// PUB → XSUB → (proxy goroutine) → XPUB → SUB
	ctx := xCtx(t)

	pubEP := "inproc://proxy_pub_" + strings.ReplaceAll(t.Name(), "/", "_")
	subEP := "inproc://proxy_sub_" + strings.ReplaceAll(t.Name(), "/", "_")

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, pubEP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pub.Close() })

	xsub := zmq4.NewXSUB()
	if err := xsub.Connect(ctx, pubEP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xsub.Close() })

	xpub := zmq4.NewXPUB()
	if err := xpub.Bind(ctx, subEP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xpub.Close() })

	sub := zmq4.NewSUB()
	if err := sub.Connect(ctx, subEP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Close() })

	sub.Subscribe([]byte("data"))

	// Proxy: XPUB→XSUB (subscriptions) and XSUB→XPUB (data).
	go func() {
		for {
			msg, err := xpub.Recv(ctx)
			if err != nil {
				return
			}
			xsub.Send(ctx, msg)
		}
	}()
	go func() {
		for {
			msg, err := xsub.Recv(ctx)
			if err != nil {
				return
			}
			xpub.Send(ctx, msg)
		}
	}()

	time.Sleep(30 * time.Millisecond) // let subscription propagate through proxy

	pub.Send(ctx, zmq4.Message{[]byte("data-msg")})

	got, err := sub.Recv(ctx)
	if err != nil {
		t.Fatalf("SUB Recv: %v", err)
	}
	if string(got[0]) != "data-msg" {
		t.Fatalf("want data-msg, got %q", got[0])
	}
}

func TestXSUBCtxCancelRecv(t *testing.T) {
	xsub := zmq4.NewXSUB()
	t.Cleanup(func() { xsub.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := xsub.Recv(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
```

- [ ] **Step 2: Run test — verify it fails**

Run: `go test -run 'TestXSUB|TestProxy' ./...`
Expected: FAIL — `zmq4.NewXSUB` undefined.

- [ ] **Step 3: Implement `xsub.go`**

```go
package zmq4

import (
	"context"

	"github.com/tomi77/zmq4/internal/conn"
)

// XSUB is an extended subscribe socket. It behaves like SUB for receiving
// and allows the application to send raw subscription frames via Send
// (for proxy use cases). Subscribe and Unsubscribe are convenience wrappers.
type XSUB struct {
	base  socketBase
	state *subState
}

// NewXSUB creates a new XSUB socket.
func NewXSUB(opts ...Option) *XSUB {
	s := &XSUB{
		base:  newSocketBase(newSocketConfig(opts)),
		state: newSubState(),
	}
	s.base.postHandshake = s.onNewConn
	return s
}

func (s *XSUB) onNewConn(c *conn.Conn) error {
	for _, sub := range s.state.all() {
		if err := c.WriteFrame(subFrame(0x01, sub)); err != nil {
			return err
		}
	}
	identity := peerIdentity(c.PeerMetadata())
	p := newPipe(c, identity)
	s.base.pipes.add(p)
	p.start(s.base.pipes, s.base.closeCh)
	return nil
}

func (s *XSUB) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "XSUB")
}

func (s *XSUB) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "XSUB")
}

// Subscribe adds topic and sends a \x01-prefixed frame upstream (ref-counted).
func (s *XSUB) Subscribe(topic []byte) error {
	select {
	case <-s.base.closeCh:
		return ErrClosed
	default:
	}
	if !s.state.add(topic) {
		return nil
	}
	f := subFrame(0x01, topic)
	for _, p := range s.base.pipes.all() {
		p.conn.WriteFrame(f) //nolint:errcheck
	}
	return nil
}

// Unsubscribe decrements ref count and sends \x00-prefixed frame upstream when zero.
func (s *XSUB) Unsubscribe(topic []byte) error {
	select {
	case <-s.base.closeCh:
		return ErrClosed
	default:
	}
	if !s.state.remove(topic) {
		return nil
	}
	f := subFrame(0x00, topic)
	for _, p := range s.base.pipes.all() {
		p.conn.WriteFrame(f) //nolint:errcheck
	}
	return nil
}

// Send forwards a raw subscription frame upstream to all connected peers.
// msg must be a single-frame message starting with 0x01 (subscribe) or 0x00
// (unsubscribe). Used for proxy forwarding from XPUB.Recv.
func (s *XSUB) Send(ctx context.Context, msg Message) error {
	select {
	case <-s.base.closeCh:
		return ErrClosed
	default:
	}
	if len(msg) == 0 {
		return nil
	}
	for _, p := range s.base.pipes.all() {
		// Non-blocking write; dead pipe detected by reader goroutine.
		p.conn.WriteFrame(subFrameRaw(msg[0])) //nolint:errcheck
	}
	return nil
}

// Recv fair-queues data messages from all connected peers.
func (s *XSUB) Recv(ctx context.Context) (Message, error) {
	msg, _, err := s.base.recvAny(ctx)
	return msg, err
}

func (s *XSUB) Close() error {
	s.base.close()
	return nil
}

// subFrameRaw wraps a raw bytes slice as a single-frame message frame.
func subFrameRaw(body []byte) wire.Frame {
	return wire.Frame{Kind: wire.FrameMessage, Body: body}
}
```

Add missing `"github.com/tomi77/zmq4/internal/wire"` import.

- [ ] **Step 4: Run tests**

Run: `go test -race -run 'TestXSUB|TestProxy|TestXPUB' -v ./...`
Expected: all PASS.

- [ ] **Step 5: Run all tests**

Run: `go test -race ./...`
Expected: all existing + new tests PASS.

- [ ] **Step 6: Commit**

```bash
git add xsub.go xpub_xsub_test.go
git commit -m "feat(F5b): XSUB socket — Subscribe/Unsubscribe + raw Send forwarding, proxy pattern test"
```

---

## Chunk 6: Lifecycle tests

### Task 7: Lifecycle tests additions (`lifecycle_test.go`)

**Files:**
- Modify: `lifecycle_test.go`

- [ ] **Step 1: Add lifecycle tests for F5b socket types**

Add to `lifecycle_test.go`:

```go
func TestPUBCloseUnblocksSend(t *testing.T) {
	// PUB.Send with no peers returns immediately (drop semantics); Close
	// while PUB.Send might be mid-iteration must not hang.
	pub := zmq4.NewPUB()
	ctx := psCtx(t) // uses the helper from pub_sub_test.go
	_ = ctx
	pub.Close()
	// After Close, Send must return ErrClosed.
	err := pub.Send(context.Background(), zmq4.Message{[]byte("x")})
	if !errors.Is(err, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestSUBSubscribeAfterClose(t *testing.T) {
	sub := zmq4.NewSUB()
	sub.Close()
	err := sub.Subscribe([]byte("x"))
	if !errors.Is(err, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestXPUBCloseUnblocksRecv(t *testing.T) {
	xpub := zmq4.NewXPUB()
	ctx := context.Background()

	var wg sync.WaitGroup
	var recvErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, recvErr = xpub.Recv(ctx)
	}()

	time.Sleep(10 * time.Millisecond)
	xpub.Close()
	wg.Wait()
	if !errors.Is(recvErr, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", recvErr)
	}
}

func TestIncompatiblePeerPUBtoREQ(t *testing.T) {
	ep := inprocEP(t) // reuse helper from req_rep_test.go
	ctx := newCtx(t)

	// REP listens; PUB tries to connect — incompatible.
	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })

	pub := zmq4.NewPUB()
	t.Cleanup(func() { pub.Close() })
	err := pub.Connect(ctx, ep)
	if !errors.Is(err, zmq4.ErrIncompatiblePeer) {
		t.Fatalf("want ErrIncompatiblePeer for PUB→REP, got %v", err)
	}
}
```

Note: `psCtx` is defined in `pub_sub_test.go` (package `zmq4_test`), so it's accessible here. If there's a naming conflict with the existing `newCtx` in `req_rep_test.go`, use `newCtx` instead and remove the `psCtx` reference.

- [ ] **Step 2: Run lifecycle tests**

Run: `go test -race -run 'TestPUBClose|TestSUBSubscribeAfter|TestXPUBClose|TestIncompat' -v ./...`
Expected: all PASS.

- [ ] **Step 3: Commit**

```bash
git add lifecycle_test.go
git commit -m "test(F5b): lifecycle tests — Close unblocks, Subscribe-after-close, incompatible peer"
```

---

## Chunk 7: Update `doc.go`

### Task 8: Update package godoc

**Files:**
- Modify: `doc.go`

- [ ] **Step 1: Add F5b socket types to package doc**

In `doc.go`, find the socket types section and extend it:

```go
// Package zmq4 provides a pure-Go implementation of the ZeroMQ core protocol
// stack (ZMTP 3.1).
//
// # Socket types
//
// Request-reply pattern (RFC 28):
//
//   - [REQ] — request socket (alternating Send→Recv)
//   - [REP] — reply socket (alternating Recv→Send)
//   - [DEALER] — async request socket (round-robin send, fair-queue recv)
//   - [ROUTER] — identity-routing socket (msg[0] is always the peer identity)
//
// Publish-subscribe pattern (RFC 29):
//
//   - [PUB] — publish socket (topic-filtered broadcast; drop on slow peers)
//   - [SUB] — subscribe socket (Subscribe/Unsubscribe + fair-queue recv)
//   - [XPUB] — extended publish (like PUB; Recv returns subscription frames)
//   - [XSUB] — extended subscribe (like SUB; Send forwards raw sub frames)
//
// # Creating a socket
//
//	pub := zmq4.NewPUB(zmq4.WithNULL())
//	if err := pub.Bind(ctx, "tcp://127.0.0.1:5555"); err != nil { ... }
//	defer pub.Close()
//
//	sub := zmq4.NewSUB()
//	if err := sub.Connect(ctx, "tcp://127.0.0.1:5555"); err != nil { ... }
//	sub.Subscribe([]byte("topic"))
//	msg, err := sub.Recv(ctx)
//
// # Security
//
// Select a security mechanism via constructor options:
//
//	zmq4.WithNULL()                       // no authentication (default)
//	zmq4.WithPLAIN(username, password)    // PLAIN credentials (Connect side)
//	zmq4.WithPLAINServer(auth)            // PLAIN authentication (Bind side)
//	zmq4.WithCURVE(clientOptions)         // CURVE encryption (Connect side)
//	zmq4.WithCURVEServer(serverOptions)   // CURVE encryption (Bind side)
//
// # Memory ownership
//
// Every [Message] returned by Recv is caller-owned: parts may be retained
// and mutated freely without affecting the socket's internal state.
package zmq4
```

- [ ] **Step 2: Build and test**

Run: `go build ./... && go test -race ./...`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add doc.go
git commit -m "docs(F5b): add PUB/SUB/XPUB/XSUB to package godoc"
```

---

## Chunk 8: Integration tests

### Task 9: Integration test additions (`integration_test.go`)

**Files:**
- Modify: `integration_test.go`

- [ ] **Step 1: Add PUB/SUB and XPUB/XSUB rows**

In `integration_test.go`, find the `rows` construction loop and add the two new pairs:

```go
for _, pair := range []string{"reqrep", "dealerrouter", "pubsub", "xpubxsub"} {
```

Add two new helper functions after `runDEALERROUTER`:

```go
func runPUBSUB(t *testing.T, ctx context.Context, ep string, serverOpts, clientOpts []zmq4.Option) {
	t.Helper()
	pub := zmq4.NewPUB(serverOpts...)
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	defer pub.Close()

	sub := zmq4.NewSUB(clientOpts...)
	if err := sub.Connect(ctx, ep); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer sub.Close()

	if err := sub.Subscribe([]byte("ping")); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	if err := pub.Send(ctx, zmq4.Message{[]byte("ping-payload")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := sub.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(got[0]) != "ping-payload" {
		t.Fatalf("want ping-payload, got %q", got[0])
	}
}

func runXPUBXSUB(t *testing.T, ctx context.Context, ep string, serverOpts, clientOpts []zmq4.Option) {
	t.Helper()
	xpub := zmq4.NewXPUB(serverOpts...)
	if err := xpub.Bind(ctx, ep); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	defer xpub.Close()

	xsub := zmq4.NewXSUB(clientOpts...)
	if err := xsub.Connect(ctx, ep); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer xsub.Close()

	if err := xsub.Subscribe([]byte("news")); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// XPUB sees the subscription frame.
	subMsg, err := xpub.Recv(ctx)
	if err != nil {
		t.Fatalf("XPUB Recv sub: %v", err)
	}
	if len(subMsg) == 0 || subMsg[0][0] != 0x01 {
		t.Fatalf("XPUB: expected subscribe frame, got %v", subMsg)
	}

	time.Sleep(10 * time.Millisecond)

	if err := xpub.Send(ctx, zmq4.Message{[]byte("news-item")}); err != nil {
		t.Fatalf("XPUB Send: %v", err)
	}
	got, err := xsub.Recv(ctx)
	if err != nil {
		t.Fatalf("XSUB Recv: %v", err)
	}
	if string(got[0]) != "news-item" {
		t.Fatalf("want news-item, got %q", got[0])
	}
}
```

Update `runIntegRow` to dispatch the new pairs:

```go
switch row.pair {
case "reqrep":
    runREQREP(t, ctx, ep, serverOpts, clientOpts)
case "dealerrouter":
    runDEALERROUTER(t, ctx, ep, serverOpts, clientOpts)
case "pubsub":
    runPUBSUB(t, ctx, ep, serverOpts, clientOpts)
case "xpubxsub":
    runXPUBXSUB(t, ctx, ep, serverOpts, clientOpts)
}
```

**Note:** The inproc endpoint name for integration tests is derived from pair name; duplicate endpoint names between reqrep and pubsub across parallel subtests must not collide. The existing `ep` derivation in `runIntegRow` already includes `row.pair` in the name, so this is safe.

- [ ] **Step 2: Run integration tests**

Run: `go test -race -tags integration -v ./...`
Expected: 36 subtests PASS (3 transports × 3 mechanisms × 4 pairs; was 18 for F5a, now 36).

- [ ] **Step 3: Commit**

```bash
git add integration_test.go
git commit -m "test(F5b): integration tests — 18 new PUB/SUB + XPUB/XSUB rows (36 total)"
```

---

## Chunk 9: Interop tests

### Task 10: Interop test additions (`interop/interop_test.go`)

**Files:**
- Modify: `interop/interop_test.go`

The interop tests exercise our PUB/SUB/XPUB/XSUB against the libzmq 4.3.5 container. The Python bridge in `internal/conn/interop/bridge/` needs to be extended to support these socket types.

- [ ] **Step 1: Check existing interop bridge**

```bash
ls interop/
cat internal/conn/interop/bridge/bridge.py | head -60
```

Understand how the bridge currently supports REQ/REP/DEALER/ROUTER.

- [ ] **Step 2: Extend Python bridge for PUB/SUB/XPUB/XSUB**

The bridge must support:
- `PUB` socket: bind or connect; send one message per received `send` command; the message topic is the first frame.
- `SUB` socket: bind or connect; subscribe to the topic passed in config; recv one message and print it.
- `XPUB` socket: like PUB; after each connect/accept, also report subscription frames received.
- `XSUB` socket: like SUB; uses raw subscription frame sending.

Extend `bridge.py` to handle `zmq.PUB`, `zmq.SUB`, `zmq.XPUB`, `zmq.XSUB`. The exact protocol depends on the existing bridge design. Follow the same patterns as REQ/REP.

- [ ] **Step 3: Add PUB/SUB and XPUB/XSUB rows to the interop matrix**

In `interop/interop_test.go`, find the `buildMatrix` function and extend the `pair` slice:

```go
for _, pair := range []string{"reqrep", "dealerrouter", "pubsub", "xpubxsub"} {
```

Add helper functions `runPUBSUBInterop` and `runXPUBXSUBInterop` following the same pattern as `runREQREPInterop` and `runDEALERROUTERInterop`. The PUB/SUB scenario:
- Our PUB Bind + libzmq SUB Connect: PUB sends topic-prefixed message; SUB (subscribed to that topic) receives it.
- Single-frame: one frame `"topic-payload"`.
- Multipart: `["topic", "payload-part1", "payload-part2"]`.

Update `runInteropRow` to dispatch `pubsub` and `xpubxsub` to the new helpers.

Total after adding 2 new pairs: 2 dirs × 4 pairs × 3 mechs × 2 transports × 2 scenarios = **96 happy-path tests + 2 negative = 98 total** (F5a had 50). Adjust the done-criteria count accordingly.

- [ ] **Step 4: Run interop tests**

Run: `go test -race -tags interop -v ./interop/...`
Expected: all PASS (requires Docker + libzmq bridge).

- [ ] **Step 5: Commit**

```bash
git add interop/ internal/conn/interop/bridge/
git commit -m "test(F5b): interop tests — PUB/SUB + XPUB/XSUB matrix (48 new happy-path tests)"
```

---

## Chunk 10: Done-criteria sweep + phase tag

### Task 11: Done-criteria sweep

**Files:**
- Modify: `docs/specs/00-meta-overview.md`

- [ ] **Step 1: Run full unit test suite with race detector**

Run: `go test -race ./...`
Expected: all PASS. No data races.

- [ ] **Step 2: Run integration tests**

Run: `go test -race -tags integration ./...`
Expected: 36 integration tests PASS.

- [ ] **Step 3: Run static analysis**

Run: `go vet ./...`
Expected: no output.

Run: `staticcheck ./...`
Expected: no output.

- [ ] **Step 4: Run modernize sweep**

Run: `modernize -fix ./...`
Run: `git diff`
Expected: empty diff (all code uses modern Go idioms). If not empty, commit the modernize changes:

```bash
git add -u
git commit -m "chore(F5b): modernize -fix sweep"
```

- [ ] **Step 5: Run interop tests (manual gate)**

Run: `go test -race -tags interop -v ./interop/...`
Expected: all tests PASS. Coordinate with CI if Docker unavailable locally.

- [ ] **Step 6: Update `docs/specs/00-meta-overview.md`**

Change the F5b row from "Design approved — implementation pending" to:
```
| F5b | `05b-sockets-pubsub.md` | ... | **Complete** — tagged `phase-5b-pubsub-complete`. |
```

Update the status header at the top to include `phase-5b-pubsub-complete`.

- [ ] **Step 7: Commit and tag**

```bash
git add docs/specs/00-meta-overview.md
git commit -m "chore(F5b): done-criteria sweep — staticcheck, modernize, meta-overview"
git tag phase-5b-pubsub-complete
```

---

## Summary

| Chunk | Tasks | Output |
|-------|-------|--------|
| 1 | 1–2 | `ErrNoTopic`, `base.go` extended |
| 2 | 3 | PUB socket + initial tests |
| 3 | 4 | SUB socket + PUB/SUB tests |
| 4 | 5 | XPUB socket |
| 5 | 6 | XSUB socket + proxy test |
| 6 | 7 | Lifecycle tests |
| 7 | 8 | doc.go update |
| 8 | 9 | Integration tests (36 total) |
| 9 | 10 | Interop tests |
| 10 | 11 | Done-criteria sweep + tag |
