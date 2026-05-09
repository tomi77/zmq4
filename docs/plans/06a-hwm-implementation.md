# F6a HWM — High-Water Marks Implementation Plan

> **For Claude:** REQUIRED: Use `superpowers:subagent-driven-development` to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking. Each task is one commit.

**Goal:** Add configurable per-socket send (SNDHWM) and receive (RCVHWM) high-water marks with per-socket-type overflow policies (Block / Drop), replacing hard-coded channel capacities throughout the codebase.

**Architecture:** `socketConfig` gains three new fields (`sndHWM`, `rcvHWM`, `sndOverflow`). The regular `pipe` gains an `outCh` channel and a `writeLoop` goroutine (mirroring the existing `pubPipe` design), making all sends asynchronous and bounded. `pubPipe.outCh` capacity becomes configurable. PUB and XPUB get Drop as their default overflow policy via an internal `withSndOverflow(Drop)` option prepended before user opts. REQ and REP assemble their envelope+payload into a single `Message` before queuing.

**Tech Stack:** Pure Go 1.26, stdlib only. No new external deps.

**Decisions baked into the plan:**
- `OverflowPolicy` is an exported type with two exported constants (`Block`, `Drop`). Zero value = `Block`.
- Default HWM for both send and receive: 1000 (matches libzmq default).
- Subscription control frames in SUB/XSUB bypass HWM and continue to use `conn.WriteFrame` directly — they are protocol frames, not user data.
- `pipe.send()` returns `bool`: `false` means socket closed (Block) or message dropped (Drop).
- `writeLoop` exits on write error by closing the connection (same effect as current `p.conn.Close()` calls in REQ/REP on partial write).
- `xpubSubChCap = 64` (XPUB subscription notify channel) is out of scope for F6a — it is a different concern.
- **No `modernize -fix` per task.** Run only at Task 9 (done-criteria sweep).
- **Phase tag:** `phase-6a-hwm-complete` after Task 9.

---

## Chunk 1: Options and pipe scaffolding

### Task 1: OverflowPolicy type + socketConfig HWM fields + options

**Files:**
- Modify: `options.go`
- Modify: `options_test.go`

- [ ] **Step 1: Write failing tests in `options_test.go`**

Add after the last existing test:

```go
func TestNewSocketConfigHWMDefaults(t *testing.T) {
	cfg := newSocketConfig(nil)
	if cfg.sndHWM != 1000 {
		t.Fatalf("sndHWM default: got %d, want 1000", cfg.sndHWM)
	}
	if cfg.rcvHWM != 1000 {
		t.Fatalf("rcvHWM default: got %d, want 1000", cfg.rcvHWM)
	}
	if cfg.sndOverflow != Block {
		t.Fatalf("sndOverflow default: got %v, want Block", cfg.sndOverflow)
	}
}

func TestWithSndHWMPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for n<=0")
		}
	}()
	WithSndHWM(0)
}

func TestWithRcvHWMPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for n<=0")
		}
	}()
	WithRcvHWM(0)
}

func TestWithSndHWMOption(t *testing.T) {
	cfg := newSocketConfig([]Option{WithSndHWM(42)})
	if cfg.sndHWM != 42 {
		t.Fatalf("got %d, want 42", cfg.sndHWM)
	}
}

func TestWithRcvHWMOption(t *testing.T) {
	cfg := newSocketConfig([]Option{WithRcvHWM(7)})
	if cfg.rcvHWM != 7 {
		t.Fatalf("got %d, want 7", cfg.rcvHWM)
	}
}

func TestWithSndHWMPolicyOption(t *testing.T) {
	cfg := newSocketConfig([]Option{WithSndHWMPolicy(Drop)})
	if cfg.sndOverflow != Drop {
		t.Fatalf("got %v, want Drop", cfg.sndOverflow)
	}
}

func TestWithSndOverflowInternal(t *testing.T) {
	cfg := newSocketConfig([]Option{withSndOverflow(Drop)})
	if cfg.sndOverflow != Drop {
		t.Fatalf("got %v, want Drop", cfg.sndOverflow)
	}
}

func TestWithSndHWMPolicyOverridesInternal(t *testing.T) {
	// User-supplied policy wins over socket-type internal default.
	cfg := newSocketConfig([]Option{withSndOverflow(Drop), WithSndHWMPolicy(Block)})
	if cfg.sndOverflow != Block {
		t.Fatalf("got %v, want Block", cfg.sndOverflow)
	}
}
```

- [ ] **Step 2: Run tests — confirm failures**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestNewSocketConfigHWM|TestWithSndHWM|TestWithRcvHWM|TestWithSndHWMPolicy|TestWithSndOverflow' ./... 2>&1 | head -30
```

Expected: compile errors (undefined: `Block`, `Drop`, `WithSndHWM`, etc.)

- [ ] **Step 3: Implement in `options.go`**

Add at the top of the file, before `const defaultHandshakeTimeout`:

```go
// OverflowPolicy specifies what happens when a pipe's send queue (SNDHWM) is full.
type OverflowPolicy int

const (
	// Block causes the sender to wait until space is available or the socket closes.
	Block OverflowPolicy = iota
	// Drop silently discards the message without blocking.
	Drop
)
```

Add three new fields to `socketConfig`:

```go
type socketConfig struct {
	// ... existing fields unchanged ...
	sndHWM      int            // outbound pipe queue capacity; default 1000
	rcvHWM      int            // inbound pipe queue capacity; default 1000
	sndOverflow OverflowPolicy // behaviour when sndHWM is reached; default Block
}
```

Update `newSocketConfig` to set defaults before applying opts:

```go
func newSocketConfig(opts []Option) *socketConfig {
	cfg := &socketConfig{
		handshakeTimeout: defaultHandshakeTimeout,
		sndHWM:           1000,
		rcvHWM:           1000,
		sndOverflow:      Block,
	}
	// ... rest unchanged ...
}
```

Add the three exported options and one unexported option at the bottom of `options.go`:

```go
// WithSndHWM sets the outbound pipe queue capacity. Panics if n <= 0.
func WithSndHWM(n int) Option {
	if n <= 0 {
		panic("zmq4: WithSndHWM: n must be > 0")
	}
	return func(cfg *socketConfig) { cfg.sndHWM = n }
}

// WithRcvHWM sets the inbound pipe queue capacity. Panics if n <= 0.
func WithRcvHWM(n int) Option {
	if n <= 0 {
		panic("zmq4: WithRcvHWM: n must be > 0")
	}
	return func(cfg *socketConfig) { cfg.rcvHWM = n }
}

// WithSndHWMPolicy overrides the default overflow policy for this socket type.
func WithSndHWMPolicy(p OverflowPolicy) Option {
	return func(cfg *socketConfig) { cfg.sndOverflow = p }
}

// withSndOverflow is an internal option used by socket-type constructors
// (e.g. NewPUB) to set a type-appropriate default before user opts are applied.
func withSndOverflow(p OverflowPolicy) Option {
	return func(cfg *socketConfig) { cfg.sndOverflow = p }
}
```

- [ ] **Step 4: Run tests — confirm pass**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestNewSocketConfigHWM|TestWithSndHWM|TestWithRcvHWM|TestWithSndHWMPolicy|TestWithSndOverflow' ./...
```

Expected: all PASS, no failures.

- [ ] **Step 5: Run full suite — confirm no regressions**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add options.go options_test.go && git commit -m "feat(F6a): OverflowPolicy type + sndHWM/rcvHWM/sndOverflow in socketConfig"
```

---

### Task 2: pipe — configurable inCh capacity (RCVHWM)

**Files:**
- Modify: `pipe.go`
- Modify: `pipe_test.go`

- [ ] **Step 1: Update existing `pipe_test.go` calls to `newPipe`**

`newPipe` signature will change in this task. Every call to `newPipe(nil, nil)` in `pipe_test.go` must become `newPipe(nil, nil, 1000, 1000, Block)`. Find them all:

```bash
grep -n "newPipe" /Users/tomaszrup/Projects/github.com/tomi77/zmq4/pipe_test.go
```

Replace each `newPipe(nil, nil)` with `newPipe(nil, nil, 1000, 1000, Block)`.

Also add a new test at the bottom of `pipe_test.go`:

```go
func TestPipeRcvHWMCapacity(t *testing.T) {
	p := newPipe(nil, nil, 1000, 7, Block)
	if cap(p.inCh) != 7 {
		t.Fatalf("inCh capacity: got %d, want 7", cap(p.inCh))
	}
}

func TestPipeSndHWMCapacity(t *testing.T) {
	p := newPipe(nil, nil, 13, 1000, Block)
	if cap(p.outCh) != 13 {
		t.Fatalf("outCh capacity: got %d, want 13", cap(p.outCh))
	}
}
```

- [ ] **Step 2: Run tests — confirm compile failure (outCh not yet added)**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestPipeRcvHWM|TestPipeSndHWM' ./... 2>&1 | head -20
```

Expected: compile error — wrong argument count on `newPipe` calls.

- [ ] **Step 3: Update `pipe.go`**

Remove the constant:

```go
// DELETE this line:
const pipeInChCap = 64
```

Update the `pipe` struct (add `outCh` and `overflow`):

```go
type pipe struct {
	conn     *conn.Conn
	identity []byte
	inCh     chan Message
	outCh    chan Message   // send queue; capacity = sndHWM
	overflow OverflowPolicy
	wg       sync.WaitGroup
}
```

Update `newPipe`:

```go
func newPipe(c *conn.Conn, identity []byte, sndHWM, rcvHWM int, overflow OverflowPolicy) *pipe {
	return &pipe{
		conn:     c,
		identity: identity,
		inCh:     make(chan Message, rcvHWM),
		outCh:    make(chan Message, sndHWM),
		overflow: overflow,
	}
}
```

- [ ] **Step 4: Fix compile errors in `base.go` and `pair.go`**

In `base.go` at line 147, update the `newPipe` call:

```go
// Before:
p := newPipe(c, identity)
// After:
p := newPipe(c, identity, sb.cfg.sndHWM, sb.cfg.rcvHWM, sb.cfg.sndOverflow)
```

In `pair.go` in `exclusivePeer`, update the `newPipe` call:

```go
// Before:
p := newPipe(c, identity)
// After:
p := newPipe(c, identity, s.base.cfg.sndHWM, s.base.cfg.rcvHWM, s.base.cfg.sndOverflow)
```

- [ ] **Step 5: Run tests — confirm pass**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestPipeRcvHWM|TestPipeSndHWM|TestPipeSet' ./...
```

Expected: `TestPipeRcvHWMCapacity` and `TestPipeSndHWMCapacity` PASS. All `TestPipeSet*` pass.

- [ ] **Step 6: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add pipe.go pipe_test.go base.go pair.go && git commit -m "feat(F6a): configurable inCh/outCh capacity in pipe (RCVHWM/SNDHWM scaffolding)"
```

---

### Task 3: pipe — `writeLoop` + `send()` (SNDHWM behaviour)

**Files:**
- Modify: `pipe.go`
- Modify: `pipe_test.go`

- [ ] **Step 1: Write failing tests in `pipe_test.go`**

Add at the bottom of `pipe_test.go`. These tests exercise only channel/queue semantics (conn can be nil):

```go
func TestPipeSendBlock(t *testing.T) {
	// outCh capacity 1; second send blocks until first is drained.
	closeCh := make(chan struct{})
	defer close(closeCh)

	p := newPipe(nil, nil, 1, 1000, Block)
	p.outCh <- Message{[]byte("first")} // fill the queue manually

	sent := make(chan bool, 1)
	go func() {
		sent <- p.send(Message{[]byte("second")}, closeCh)
	}()

	select {
	case <-sent:
		t.Fatal("send should have blocked")
	case <-time.After(20 * time.Millisecond):
		// correct: still blocking
	}

	// Drain the queue — unblocks the goroutine.
	<-p.outCh
	select {
	case ok := <-sent:
		if !ok {
			t.Fatal("send returned false, want true")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("send did not unblock after drain")
	}
}

func TestPipeSendDrop(t *testing.T) {
	closeCh := make(chan struct{})
	defer close(closeCh)

	p := newPipe(nil, nil, 1, 1000, Drop)
	p.outCh <- Message{[]byte("first")} // fill the queue

	ok := p.send(Message{[]byte("second")}, closeCh)
	if ok {
		t.Fatal("send with Drop policy on full queue should return false")
	}
	if len(p.outCh) != 1 {
		t.Fatalf("outCh len: got %d, want 1 (original message still there)", len(p.outCh))
	}
}

func TestPipeSendClosedSocket(t *testing.T) {
	closeCh := make(chan struct{})
	close(closeCh) // already closed

	p := newPipe(nil, nil, 1, 1000, Block)
	p.outCh <- Message{[]byte("fill")} // fill so Block would normally block

	ok := p.send(Message{[]byte("msg")}, closeCh)
	if ok {
		t.Fatal("send to closed socket should return false")
	}
}
```

Add `"time"` to the existing import block in `pipe_test.go` (leave `"net"` and `"testing"` — they are already there):

```go
import (
	"net"
	"testing"
	"time" // add this line
)
```

- [ ] **Step 2: Run tests — confirm failures**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestPipeSend' ./... 2>&1 | head -20
```

Expected: compile error (undefined method `p.send`).

- [ ] **Step 3: Add `writeLoop` and `send` to `pipe.go`**

Update `start` to launch two goroutines:

```go
func (p *pipe) start(ps *pipeSet, closeCh <-chan struct{}) {
	p.wg.Add(2)
	go p.readLoop(ps, closeCh)
	go p.writeLoop(closeCh)
}
```

Add `writeLoop` after `readLoop`:

```go
// writeLoop drains outCh and writes messages to conn. Exits on write error
// (closing the connection so readLoop also exits) or when closeCh is closed.
func (p *pipe) writeLoop(closeCh <-chan struct{}) {
	defer p.wg.Done()
	for {
		select {
		case msg := <-p.outCh:
			if err := sendFrames(p.conn, msg); err != nil {
				p.conn.Close()
				return
			}
		case <-closeCh:
			return
		}
	}
}
```

Add `send` after `writeLoop`:

```go
// send enqueues msg for delivery according to the pipe's overflow policy.
// Returns true if the message was queued, false if the socket is closing (Block)
// or the queue is full (Drop).
func (p *pipe) send(msg Message, closeCh <-chan struct{}) bool {
	switch p.overflow {
	case Drop:
		select {
		case p.outCh <- msg:
			return true
		default:
			return false
		}
	default: // Block
		select {
		case p.outCh <- msg:
			return true
		case <-closeCh:
			return false
		}
	}
}
```

- [ ] **Step 4: Run tests — confirm pass**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestPipeSend' ./...
```

Expected: all three TestPipeSend* PASS.

- [ ] **Step 5: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS. (writeLoop starts but `conn` may be nil in struct tests — verify the nil-conn structural tests in `pipe_test.go` don't call `start`.)

- [ ] **Step 6: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add pipe.go pipe_test.go && git commit -m "feat(F6a): pipe.writeLoop + pipe.send() — SNDHWM Block/Drop semantics"
```

---

## Chunk 2: pubPipe + socket-type send wiring

### Task 4: `pubPipe` — configurable `outCh` capacity

**Files:**
- Modify: `pub.go`
- Modify: `xpub.go`

- [ ] **Step 1: Remove constants and update `newPubPipe` in `pub.go`**

Remove:

```go
// DELETE:
const pubOutChCap = 64
```

Update `newPubPipe` signature and body:

```go
func newPubPipe(c *conn.Conn, subNotify chan<- Message, sndHWM int) *pubPipe {
	return &pubPipe{
		conn:      c,
		outCh:     make(chan Message, sndHWM),
		subNotify: subNotify,
	}
}
```

Update `NewPUB` to prepend `withSndOverflow(Drop)` and pass `cfg.sndHWM`:

```go
func NewPUB(opts ...Option) *PUB {
	s := &PUB{
		base:     newSocketBase(newSocketConfig(append([]Option{withSndOverflow(Drop)}, opts...))),
		pubPipes: newPubPipeSet(),
	}
	s.base.postHandshake = func(c *conn.Conn) error {
		pp := newPubPipe(c, nil, s.base.cfg.sndHWM)
		pp.wg.Add(2)
		s.pubPipes.add(pp)
		go pp.subReader(s.pubPipes)
		go pp.writer(s.base.closeCh)
		return nil
	}
	// closeFn unchanged
	s.base.closeFn = func() {
		pipes := s.pubPipes.all()
		for _, pp := range pipes {
			pp.conn.Close()
		}
		for _, pp := range pipes {
			pp.wg.Wait()
		}
	}
	return s
}
```

- [ ] **Step 2: Update `NewXPUB` in `xpub.go`**

Same two changes: prepend `withSndOverflow(Drop)`, pass `s.base.cfg.sndHWM` to `newPubPipe`.

**Do NOT remove `xpubSubChCap = 64`** — that constant controls the subscription-notify channel (`subCh`), which is out of scope for F6a. Only update the `newPubPipe` call:

```go
func NewXPUB(opts ...Option) *XPUB {
	s := &XPUB{
		base:     newSocketBase(newSocketConfig(append([]Option{withSndOverflow(Drop)}, opts...))),
		pubPipes: newPubPipeSet(),
		subCh:    make(chan Message, xpubSubChCap), // unchanged
	}
	s.base.postHandshake = func(c *conn.Conn) error {
		pp := newPubPipe(c, s.subCh, s.base.cfg.sndHWM) // sndHWM added
		pp.wg.Add(2)
		s.pubPipes.add(pp)
		go pp.subReader(s.pubPipes)
		go pp.writer(s.base.closeCh)
		return nil
	}
	// closeFn unchanged
	s.base.closeFn = func() {
		pipes := s.pubPipes.all()
		for _, pp := range pipes {
			pp.conn.Close()
		}
		for _, pp := range pipes {
			pp.wg.Wait()
		}
	}
	return s
}
```

- [ ] **Step 3: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add pub.go xpub.go && git commit -m "feat(F6a): configurable pubPipe.outCh + Drop default for PUB/XPUB"
```

---

### Task 5: PUSH / DEALER / ROUTER / PAIR — replace `sendFrames` with `p.send()`

**Files:**
- Modify: `push.go`
- Modify: `dealer.go`
- Modify: `router.go`
- Modify: `pair.go`

These four socket types call `sendFrames(p.conn, msg)` directly. Replace with `p.send(msg, s.base.closeCh)`.

- [ ] **Step 1: Update `push.go`**

```go
// Before:
func (s *PUSH) Send(ctx context.Context, msg Message) error {
	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		return err
	}
	return sendFrames(p.conn, msg)
}

// After:
func (s *PUSH) Send(ctx context.Context, msg Message) error {
	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		return err
	}
	if !p.send(msg, s.base.closeCh) {
		return ErrClosed
	}
	return nil
}
```

- [ ] **Step 2: Update `dealer.go`**

```go
// Before:
func (s *DEALER) Send(ctx context.Context, msg Message) error {
	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		return err
	}
	return sendFrames(p.conn, msg)
}

// After:
func (s *DEALER) Send(ctx context.Context, msg Message) error {
	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		return err
	}
	if !p.send(msg, s.base.closeCh) {
		return ErrClosed
	}
	return nil
}
```

- [ ] **Step 3: Update `router.go`**

```go
// Before:
func (s *ROUTER) Send(ctx context.Context, msg Message) error {
	if len(msg) == 0 || len(msg[0]) == 0 {
		return ErrNoIdentity
	}
	p := s.base.pipes.byIdentity(msg[0])
	if p == nil {
		return fmt.Errorf("%w: identity %x", ErrNoRoute, msg[0])
	}
	return sendFrames(p.conn, msg[1:])
}

// After:
func (s *ROUTER) Send(ctx context.Context, msg Message) error {
	if len(msg) == 0 || len(msg[0]) == 0 {
		return ErrNoIdentity
	}
	p := s.base.pipes.byIdentity(msg[0])
	if p == nil {
		return fmt.Errorf("%w: identity %x", ErrNoRoute, msg[0])
	}
	if !p.send(msg[1:], s.base.closeCh) {
		return ErrClosed
	}
	return nil
}
```

- [ ] **Step 4: Update `pair.go`**

```go
// Before:
func (s *PAIR) Send(ctx context.Context, msg Message) error {
	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		return err
	}
	return sendFrames(p.conn, msg)
}

// After:
func (s *PAIR) Send(ctx context.Context, msg Message) error {
	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		return err
	}
	if !p.send(msg, s.base.closeCh) {
		return ErrClosed
	}
	return nil
}
```

- [ ] **Step 5: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS. (Existing integration + interop tests cover PUSH/PULL, PAIR, DEALER/ROUTER send paths.)

- [ ] **Step 6: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add push.go dealer.go router.go pair.go && git commit -m "feat(F6a): PUSH/DEALER/ROUTER/PAIR — async send via pipe.send()"
```

---

### Task 6: REQ — async send (combine delimiter + payload)

**Files:**
- Modify: `req.go`

REQ currently sends an empty delimiter frame and then the payload in two synchronous `WriteFrame`/`sendFrames` calls. We pack both into a single `Message` and call `p.send()`.

- [ ] **Step 1: Rewrite `REQ.Send`**

Replace the block starting at `// Send empty delimiter then payload.` through the end of the send logic:

```go
// Before (excerpt):
	if err := p.conn.WriteFrame(emptyDelimiter); err != nil {
		s.mu.Lock()
		s.sent = false
		s.mu.Unlock()
		return err
	}
	if err := sendFrames(p.conn, msg); err != nil {
		p.conn.Close()
		s.mu.Lock()
		s.sent = false
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.activePipe = p
	s.mu.Unlock()
	return nil

// After:
	// Prepend the empty delimiter frame as the first part of the message.
	// writeLoop sends all parts in one uninterrupted sequence via sendFrames.
	combined := make(Message, 1+len(msg))
	combined[0] = nil // empty delimiter (zero-length frame)
	copy(combined[1:], msg)
	if !p.send(combined, s.base.closeCh) {
		s.mu.Lock()
		s.sent = false
		s.mu.Unlock()
		return ErrClosed
	}
	s.mu.Lock()
	s.activePipe = p
	s.mu.Unlock()
	return nil
```

Also remove the now-unused import of `"io"` — check: `io` is used in `Recv` for `io.EOF`, so leave it.

- [ ] **Step 2: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS. The existing REQ/REP unit tests and integration tests cover this path.

- [ ] **Step 3: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add req.go && git commit -m "feat(F6a): REQ — async send via pipe.send() (delimiter+payload combined)"
```

---

### Task 7: REP — async send (combine envelope + payload)

**Files:**
- Modify: `rep.go`

REP currently sends envelope frames (routing header + empty delimiter) and payload in separate `WriteFrame` + `sendFrames` calls. We combine them into one `Message`.

- [ ] **Step 1: Rewrite `REP.Send`**

Replace the send loop and `sendFrames` call with `p.send()`. The envelope `[][]byte` converts to `Message` (they are the same underlying type):

```go
// Before (excerpt):
	for _, ef := range env {
		if err := p.conn.WriteFrame(wire.Frame{
			Kind: wire.FrameMessage,
			More: true,
			Body: ef,
		}); err != nil {
			p.conn.Close()
			return err
		}
	}
	if err := sendFrames(p.conn, msg); err != nil {
		p.conn.Close()
		return err
	}
	return nil

// After:
	// Combine envelope frames (incl. empty delimiter) with payload into one
	// message. sendFrames in writeLoop sets More=true on all but the last frame.
	combined := append(Message(env), msg...)
	if !p.send(combined, s.base.closeCh) {
		return ErrClosed
	}
	return nil
```

Remove the now-unused import `"github.com/tomi77/zmq4/internal/wire"` if `wire` is no longer referenced in `rep.go`. Check all usages of `wire` in `rep.go` first:

```bash
grep "wire\." /Users/tomaszrup/Projects/github.com/tomi77/zmq4/rep.go
```

If `wire` is only used in the envelope send loop (now removed), delete the import.

- [ ] **Step 2: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS.

- [ ] **Step 3: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add rep.go && git commit -m "feat(F6a): REP — async send via pipe.send() (envelope+payload combined)"
```

---

## Chunk 3: Integration tests + done-criteria sweep

### Task 8: Integration tests — SNDHWM Block and Drop

**Files:**
- Modify: `integration_test.go`

Add two new tests at the bottom of `integration_test.go`. These use `inproc://` for synchronous in-process communication (no Docker needed).

`integration_test.go` is `package zmq4_test` — all types and constructors must be prefixed with `zmq4.`.

- [ ] **Step 1: Write the tests**

```go
func TestPUSHSndHWMBlock(t *testing.T) {
	// PUSH with sndHWM=1 blocks on the second send until PULL receives.
	endpoint := "inproc://TestPUSHSndHWMBlock"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	push := zmq4.NewPUSH(zmq4.WithSndHWM(1))
	pull := zmq4.NewPULL()
	defer push.Close()
	defer pull.Close()

	if err := push.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := pull.Connect(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // allow handshake

	// First send fills the queue.
	if err := push.Send(ctx, zmq4.Message{[]byte("msg1")}); err != nil {
		t.Fatalf("first send: %v", err)
	}

	// Second send should block; verify with a short timeout.
	done := make(chan error, 1)
	go func() {
		done <- push.Send(ctx, zmq4.Message{[]byte("msg2")})
	}()

	select {
	case err := <-done:
		t.Fatalf("second send completed immediately (want block): err=%v", err)
	case <-time.After(30 * time.Millisecond):
		// correct: still blocking
	}

	// Receive the first message — unblocks the queue.
	if _, err := pull.Recv(ctx); err != nil {
		t.Fatalf("recv msg1: %v", err)
	}

	// Second send should now complete.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second send after drain: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("second send did not complete after drain")
	}
}

func TestPUBSndHWMDrop(t *testing.T) {
	// PUB with sndHWM=1 drops messages silently when queue is full.
	endpoint := "inproc://TestPUBSndHWMDrop"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pub := zmq4.NewPUB(zmq4.WithSndHWM(1))
	sub := zmq4.NewSUB()
	defer pub.Close()
	defer sub.Close()

	if err := pub.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := sub.Connect(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := sub.Subscribe([]byte("")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // allow handshake + subscription

	// Send more messages than sndHWM=1 can hold; all sends must return nil
	// (PUB.Send never returns an error for drops).
	for i := range 5 {
		msg := zmq4.Message{[]byte(fmt.Sprintf("msg%d", i))}
		if err := pub.Send(ctx, msg); err != nil {
			t.Fatalf("send %d: unexpected error: %v", i, err)
		}
	}
	// Test passes if no hang and no unexpected error. Drop is silent.
}
```

Add `"fmt"` to the import block if not already present (`"fmt"` is already imported in the existing file — verify first).

- [ ] **Step 2: Run the new tests**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestPUSHSndHWMBlock|TestPUBSndHWMDrop' -v ./...
```

Expected: both PASS.

- [ ] **Step 3: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add integration_test.go && git commit -m "test(F6a): integration tests — PUSH SNDHWM block, PUB SNDHWM drop"
```

---

### Task 9: Done-criteria sweep

**Files:**
- Read-only tooling pass — no code changes expected.

- [ ] **Step 1: Run full test suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS, zero failures.

- [ ] **Step 2: Run staticcheck**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && staticcheck ./...
```

Expected: no output (zero findings). Fix any reported issues before continuing.

- [ ] **Step 3: Run modernize**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && modernize -fix ./...
```

If any files are changed, run `go test ./...` again and then commit:

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add -u && git commit -m "chore(F6a): modernize sweep"
```

- [ ] **Step 4: Update meta-overview**

In `docs/specs/00-meta-overview.md`, update the F6 row in the phases table. The `Spec` column stays `—` (no dedicated spec file for F6a — only the plan exists):

```markdown
| F6a | — | Configurable SNDHWM / RCVHWM with Block/Drop policies. | Integration + unit. | **Complete** — tagged `phase-6a-hwm-complete`. |
```

Also update the Status line at the top to add `F6a` to the completed list.

- [ ] **Step 5: Commit meta-overview update**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add docs/specs/00-meta-overview.md && git commit -m "docs(F6a): update meta-overview — F6a complete"
```

- [ ] **Step 6: Tag the phase**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git tag phase-6a-hwm-complete
```
