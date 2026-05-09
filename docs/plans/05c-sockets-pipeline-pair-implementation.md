# F5c Socket Layer Implementation Plan — PUSH / PULL / PAIR

> **For Claude:** REQUIRED: Use `superpowers:subagent-driven-development` to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking. Each task is one commit.

**Goal:** Implement PUSH, PULL, and PAIR socket types in the root `zmq4` package per `docs/specs/05c-sockets-pipeline-pair.md`, delivering pipeline fan-out and exclusive-pair semantics.

**Architecture:** PUSH and PULL are pure delegations to `socketBase` helpers (`sendWaitPipe` / `recvAny`) — zero extra state. PAIR embeds `socketBase` and installs a `postHandshake` hook that rejects a second peer with `ErrPairAlreadyConnected`; after the peer dies (pipe removed by `readLoop`), the hook accepts a new connection. All three socket types reuse the existing `pipeSet`, `pipe`, `sendFrames`, and `peerIdentity` machinery unchanged.

**Tech Stack:** Pure Go 1.26, stdlib only — `context`, `errors`. Reuses `internal/conn` (F4), all security packages (F2), `internal/transport` (F3), `internal/wire` (F1). No new external deps.

**Decisions baked into the plan:**
- PUSH and PULL have no `Recv`/`Send` respectively — omitting the method is the only compile-time guarantee.
- PAIR's `exclusivePeer` hook is a method on `*PAIR` so it closes over `s.base.pipes` naturally.
- `ErrPairAlreadyConnected` is returned from `addConn`, which closes `c` and returns the error. The existing peer is unaffected.
- Tests use `inproc://` + `t.Name()`-derived endpoints; timing via `time.Sleep(20ms)` is reserved for inter-process scenarios only.
- Interop rows exercise all three mechanisms (NULL/PLAIN/CURVE) for PUSH/PULL and PAIR — same as F5b. The spec's "NULL only" note in §7.4 is superseded by the full-matrix implementation used in F5a/F5b.
- Integration test adds rows to the existing `integRow` table: pair values `"pushpull"` and `"pair"`.
- **No `modernize -fix` per task.** Run only at Task 11 (done-criteria sweep).
- **Phase tag:** `phase-5c-pipeline-pair-complete` after Task 11.

---

## File Structure

### Files created

| Path | Responsibility |
|------|----------------|
| `push.go` | `PUSH` struct, `NewPUSH`, `Bind`, `Connect`, `Send`, `Close`. |
| `pull.go` | `PULL` struct, `NewPULL`, `Bind`, `Connect`, `Recv`, `Close`. |
| `pair.go` | `PAIR` struct, `NewPAIR`, `exclusivePeer` hook, `Bind`, `Connect`, `Send`, `Recv`, `Close`. |
| `push_pull_pair_test.go` | §7.1 unit tests for PUSH/PULL/PAIR. |

### Files modified

| Path | Change |
|------|--------|
| `errors.go` | Add `ErrPairAlreadyConnected`. |
| `base.go` | Extend `compatiblePeers` with PUSH/PULL/PAIR entries. |
| `lifecycle_test.go` | Add §7.2 lifecycle tests for PUSH/PULL/PAIR. |
| `integration_test.go` | Add §7.3 rows + `runPUSHPULL` + `runPAIR` functions. |
| `interop/interop_test.go` | Add §7.4 rows + `runGoPUSH` + `runGoPULL` + `runGoPAIR` functions. |
| `internal/conn/interop/bridge/bridge.py` | Add PUSH/PULL socket types and `run_scenario` branches. |
| `doc.go` | Add PUSH/PULL/PAIR to package-level godoc. |
| `docs/specs/00-meta-overview.md` | Flip F5c status to complete, add phase tag. |

---

## Chunk 1: Error sentinel + base.go extension

### Task 1: Add `ErrPairAlreadyConnected` to `errors.go`

**Files:**
- Modify: `errors.go`

- [ ] **Step 1: Add sentinel**

Open `errors.go`. After the `ErrNoTopic` line, add one entry. The full var block becomes:

```go
var (
	ErrClosed               = errors.New("zmq4: socket closed")
	ErrState                = errors.New("zmq4: operation out of sequence")
	ErrNoRoute              = errors.New("zmq4: no route to peer")
	ErrIncompatiblePeer     = errors.New("zmq4: incompatible peer socket type")
	ErrSecurityMismatch     = errors.New("zmq4: security option not valid for this role")
	ErrNoIdentity           = errors.New("zmq4: ROUTER Send requires non-empty msg[0]")
	ErrNoTopic              = errors.New("zmq4: PUB/XPUB Send requires at least one frame (topic)")
	ErrPairAlreadyConnected = errors.New("zmq4: PAIR socket already has a peer")
)
```

- [ ] **Step 2: Verify compilation**

```
go build ./...
```
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add errors.go
git commit -m "feat(F5c): add ErrPairAlreadyConnected sentinel"
```

---

### Task 2: Extend `compatiblePeers` in `base.go`

**Files:**
- Modify: `base.go`

- [ ] **Step 1: Add PUSH/PULL/PAIR entries**

In `base.go`, find the `compatiblePeers` map (currently ends after `"XSUB"` entry). Add three new entries:

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
	"PUSH":   {"PULL": true},
	"PULL":   {"PUSH": true},
	"PAIR":   {"PAIR": true},
}
```

- [ ] **Step 2: Verify**

```
go build ./...
go test -race ./...
```
Expected: all existing tests pass.

- [ ] **Step 3: Commit**

```bash
git add base.go
git commit -m "feat(F5c): extend compatiblePeers — PUSH/PULL/PAIR"
```

---

## Chunk 2: PUSH socket

### Task 3: Create `push.go`

**Files:**
- Create: `push.go`

- [ ] **Step 1: Write failing test first**

Add a temporary smoke test at the bottom of `dealer_router_test.go` (it will move to `push_pull_pair_test.go` in Task 6 — for now it drives development):

```go
func TestPUSHSmoke(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	pull := zmq4.NewPULL()
	if err := pull.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pull.Close() })

	push := zmq4.NewPUSH()
	if err := push.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { push.Close() })

	if err := push.Send(ctx, zmq4.Message{[]byte("hello")}); err != nil {
		t.Fatal(err)
	}
	got, err := pull.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[0]) != "hello" {
		t.Fatalf("want hello, got %q", got[0])
	}
}
```

- [ ] **Step 2: Run to verify compilation failure**

```
go test -run TestPUSHSmoke ./...
```
Expected: compile error — `zmq4.NewPUSH` and `zmq4.NewPULL` undefined.

- [ ] **Step 3: Create `push.go`**

```go
package zmq4

import "context"

// PUSH is a pipeline push socket. It pairs only with PULL peers.
// Send distributes messages round-robin; blocks until a peer is ready.
type PUSH struct {
	base socketBase
}

func NewPUSH(opts ...Option) *PUSH {
	return &PUSH{base: newSocketBase(newSocketConfig(opts))}
}

func (s *PUSH) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "PUSH")
}

func (s *PUSH) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "PUSH")
}

// Send round-robins across connected PULL peers. Blocks until a pipe is ready
// or ctx is done. Returns ErrClosed after Close.
func (s *PUSH) Send(ctx context.Context, msg Message) error {
	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		return err
	}
	return sendFrames(p.conn, msg)
}

func (s *PUSH) Close() error {
	s.base.close()
	return nil
}
```

- [ ] **Step 4: Run smoke test (still fails — PULL missing)**

```
go test -run TestPUSHSmoke ./...
```
Expected: compile error — `zmq4.NewPULL` undefined. PUSH compiles.

- [ ] **Step 5: Commit PUSH**

```bash
git add push.go
git commit -m "feat(F5c): PUSH socket — round-robin send, no recv"
```

---

## Chunk 3: PULL socket

### Task 4: Create `pull.go`

**Files:**
- Create: `pull.go`

- [ ] **Step 1: Create `pull.go`**

```go
package zmq4

import "context"

// PULL is a pipeline pull socket. It pairs only with PUSH peers.
// Recv fair-queues across all connected peers.
type PULL struct {
	base socketBase
}

func NewPULL(opts ...Option) *PULL {
	return &PULL{base: newSocketBase(newSocketConfig(opts))}
}

func (s *PULL) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "PULL")
}

func (s *PULL) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "PULL")
}

// Recv fair-queues across all connected PUSH peers. Blocks until a message
// arrives, ctx is done, or the socket is closed.
// Returns ErrClosed after Close.
func (s *PULL) Recv(ctx context.Context) (Message, error) {
	msg, _, err := s.base.recvAny(ctx)
	return msg, err
}

func (s *PULL) Close() error {
	s.base.close()
	return nil
}
```

- [ ] **Step 2: Run smoke test**

```
go test -race -run TestPUSHSmoke ./...
```
Expected: PASS.

- [ ] **Step 3: Commit PULL**

```bash
git add pull.go
git commit -m "feat(F5c): PULL socket — fair-queue recv, no send"
```

---

## Chunk 4: PAIR socket

### Task 5: Create `pair.go`

**Files:**
- Create: `pair.go`

- [ ] **Step 1: Write failing test**

Add to `dealer_router_test.go` temporarily:

```go
func TestPAIRSmoke(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	a := zmq4.NewPAIR()
	if err := a.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })

	b := zmq4.NewPAIR()
	if err := b.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	if err := b.Send(ctx, zmq4.Message{[]byte("ping")}); err != nil {
		t.Fatal(err)
	}
	got, err := a.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[0]) != "ping" {
		t.Fatalf("want ping, got %q", got[0])
	}
}

func TestPAIRSecondPeerRejected(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	server := zmq4.NewPAIR()
	if err := server.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	first := zmq4.NewPAIR()
	if err := first.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { first.Close() })

	second := zmq4.NewPAIR()
	t.Cleanup(func() { second.Close() })
	err := second.Connect(ctx, ep)
	if !errors.Is(err, zmq4.ErrPairAlreadyConnected) {
		t.Fatalf("want ErrPairAlreadyConnected, got %v", err)
	}
}
```

- [ ] **Step 2: Run to verify failure**

```
go test -run "TestPAIRSmoke|TestPAIRSecondPeerRejected" ./...
```
Expected: compile error — `zmq4.NewPAIR` undefined.

- [ ] **Step 3: Create `pair.go`**

```go
package zmq4

import (
	"context"
	"sync"

	"github.com/tomi77/zmq4/internal/conn"
)

// PAIR is an exclusive-pair socket. It pairs only with another PAIR peer.
// Exactly one peer is allowed at a time; a second peer is rejected at handshake
// with ErrPairAlreadyConnected. After the peer disconnects, PAIR accepts a new
// connection.
type PAIR struct {
	base socketBase
	mu   sync.Mutex // serialises the check-and-add sequence in exclusivePeer
}

func NewPAIR(opts ...Option) *PAIR {
	s := &PAIR{base: newSocketBase(newSocketConfig(opts))}
	s.base.postHandshake = s.exclusivePeer
	return s
}

// exclusivePeer is the postHandshake hook. mu serialises the len-check and
// add so that two simultaneous inbound connections cannot both pass the guard.
func (s *PAIR) exclusivePeer(c *conn.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.base.pipes.all()) > 0 {
		return ErrPairAlreadyConnected
	}
	identity := peerIdentity(c.PeerMetadata())
	p := newPipe(c, identity)
	s.base.pipes.add(p)
	p.start(s.base.pipes, s.base.closeCh)
	return nil
}

func (s *PAIR) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "PAIR")
}

func (s *PAIR) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "PAIR")
}

// Send waits for the peer to be connected, then sends msg.
// Returns ErrClosed after Close.
func (s *PAIR) Send(ctx context.Context, msg Message) error {
	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		return err
	}
	return sendFrames(p.conn, msg)
}

// Recv waits for a message from the peer.
// Returns ErrClosed after Close.
func (s *PAIR) Recv(ctx context.Context) (Message, error) {
	msg, _, err := s.base.recvAny(ctx)
	return msg, err
}

func (s *PAIR) Close() error {
	s.base.close()
	return nil
}
```

- [ ] **Step 4: Run tests**

```
go test -race -run "TestPAIRSmoke|TestPAIRSecondPeerRejected|TestPUSHSmoke" ./...
```
Expected: all three PASS.

- [ ] **Step 5: Remove temporary smoke tests from `dealer_router_test.go`**

Delete the following three functions from `dealer_router_test.go` — they will reappear with more coverage in `push_pull_pair_test.go` (Task 6):
- `TestPUSHSmoke` — added in **Task 3 Step 1** (Chunk 2)
- `TestPAIRSmoke` — added in **Task 5 Step 1** (this task)
- `TestPAIRSecondPeerRejected` — added in **Task 5 Step 1** (this task)

- [ ] **Step 6: Verify all existing tests still pass**

```
go test -race ./...
```
Expected: all PASS.

- [ ] **Step 7: Commit PAIR**

```bash
git add pair.go dealer_router_test.go
git commit -m "feat(F5c): PAIR socket — exclusive peer via postHandshake hook"
```

---

## Chunk 5: Unit tests

### Task 6: `push_pull_pair_test.go`

**Files:**
- Create: `push_pull_pair_test.go`

- [ ] **Step 1: Write tests**

```go
package zmq4_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
)

// TestPUSHPULLRoundTrip verifies a single PUSH→PULL message.
func TestPUSHPULLRoundTrip(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	pull := zmq4.NewPULL()
	if err := pull.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pull.Close() })

	push := zmq4.NewPUSH()
	if err := push.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { push.Close() })

	if err := push.Send(ctx, zmq4.Message{[]byte("hello")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := pull.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(got[0]) != "hello" {
		t.Fatalf("want hello, got %q", got[0])
	}
}

// TestPUSHPULLMultipart verifies multi-frame messages pass through intact.
func TestPUSHPULLMultipart(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	pull := zmq4.NewPULL()
	if err := pull.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pull.Close() })

	push := zmq4.NewPUSH()
	if err := push.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { push.Close() })

	want := zmq4.Message{[]byte("a"), []byte("b"), []byte("c")}
	if err := push.Send(ctx, want); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := pull.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if len(got) != 3 || string(got[0]) != "a" || string(got[1]) != "b" || string(got[2]) != "c" {
		t.Fatalf("want [a b c], got %v", got)
	}
}

// TestPUSHPULLRoundRobin verifies round-robin distribution across 3 PULL peers.
// 1 PUSH sends 9 messages; each PULL peer must receive at least 1.
// (Strict 3-each distribution is not guaranteed — pipe registration order varies.)
func TestPUSHPULLRoundRobin(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)
	const n = 3 // peers
	const msgs = 9

	push := zmq4.NewPUSH()
	if err := push.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { push.Close() })

	counts := make([]int, n)
	var mu sync.Mutex
	var wg sync.WaitGroup

	pulls := make([]*zmq4.PULL, n)
	for i := range n {
		pulls[i] = zmq4.NewPULL()
		if err := pulls[i].Connect(ctx, ep); err != nil {
			t.Fatalf("PULL[%d].Connect: %v", i, err)
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for {
				_, err := pulls[idx].Recv(ctx)
				if err != nil {
					return
				}
				mu.Lock()
				counts[idx]++
				mu.Unlock()
			}
		}(i)
	}

	// Allow peers to register before sending.
	time.Sleep(20 * time.Millisecond)

	for i := range msgs {
		if err := push.Send(ctx, zmq4.Message{[]byte{byte(i)}}); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
	}

	// Allow delivery, then close PULL peers to unblock goroutines deterministically.
	time.Sleep(20 * time.Millisecond)
	for _, p := range pulls {
		p.Close()
	}
	wg.Wait()

	total := 0
	for i, c := range counts {
		t.Logf("PULL[%d] received %d messages", i, c)
		total += c
	}
	if total != msgs {
		t.Fatalf("total messages received: want %d, got %d", msgs, total)
	}
	for i, c := range counts {
		if c == 0 {
			t.Errorf("PULL[%d] received 0 messages — round-robin broken", i)
		}
	}
}

// TestPUSHCtxCancelSend verifies Send unblocks on cancelled ctx when no peers.
func TestPUSHCtxCancelSend(t *testing.T) {
	push := zmq4.NewPUSH()
	t.Cleanup(func() { push.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := push.Send(ctx, zmq4.Message{[]byte("x")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// TestPULLCtxCancelRecv verifies Recv unblocks on cancelled ctx when no peers.
func TestPULLCtxCancelRecv(t *testing.T) {
	pull := zmq4.NewPULL()
	t.Cleanup(func() { pull.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := pull.Recv(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// TestPAIRRoundTrip verifies bidirectional PAIR↔PAIR exchange.
func TestPAIRRoundTrip(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	a := zmq4.NewPAIR()
	if err := a.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })

	b := zmq4.NewPAIR()
	if err := b.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	if err := b.Send(ctx, zmq4.Message{[]byte("ping")}); err != nil {
		t.Fatalf("b.Send: %v", err)
	}
	got, err := a.Recv(ctx)
	if err != nil {
		t.Fatalf("a.Recv: %v", err)
	}
	if string(got[0]) != "ping" {
		t.Fatalf("a.Recv: want ping, got %q", got[0])
	}

	if err := a.Send(ctx, zmq4.Message{[]byte("pong")}); err != nil {
		t.Fatalf("a.Send: %v", err)
	}
	got2, err := b.Recv(ctx)
	if err != nil {
		t.Fatalf("b.Recv: %v", err)
	}
	if string(got2[0]) != "pong" {
		t.Fatalf("b.Recv: want pong, got %q", got2[0])
	}
}

// TestPAIRSecondPeerRejected verifies the second peer gets ErrPairAlreadyConnected.
func TestPAIRSecondPeerRejected(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	server := zmq4.NewPAIR()
	if err := server.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	first := zmq4.NewPAIR()
	if err := first.Connect(ctx, ep); err != nil {
		t.Fatalf("first.Connect: %v", err)
	}
	t.Cleanup(func() { first.Close() })

	second := zmq4.NewPAIR()
	t.Cleanup(func() { second.Close() })
	err := second.Connect(ctx, ep)
	if !errors.Is(err, zmq4.ErrPairAlreadyConnected) {
		t.Fatalf("want ErrPairAlreadyConnected, got %v", err)
	}
}

// TestPAIRReconnect verifies PAIR accepts a new peer after the first one disconnects.
func TestPAIRReconnect(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	server := zmq4.NewPAIR()
	if err := server.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	first := zmq4.NewPAIR()
	if err := first.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	// Close the first peer.
	first.Close()

	// Retry until the server's readLoop removes the dead pipe from pipeSet.
	// A fixed sleep is unreliable; goroutine scheduling is non-deterministic.
	second := zmq4.NewPAIR()
	t.Cleanup(func() { second.Close() })
	var connectErr error
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		connectErr = second.Connect(ctx, ep)
		if connectErr == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if connectErr != nil {
		t.Fatalf("second.Connect after first closed: %v", connectErr)
	}

	if err := second.Send(ctx, zmq4.Message{[]byte("hi")}); err != nil {
		t.Fatalf("second.Send: %v", err)
	}
	got, err := server.Recv(ctx)
	if err != nil {
		t.Fatalf("server.Recv: %v", err)
	}
	if string(got[0]) != "hi" {
		t.Fatalf("server.Recv: want hi, got %q", got[0])
	}
}

// TestPAIRCtxCancelSend verifies Send unblocks on cancelled ctx when no peer.
func TestPAIRCtxCancelSend(t *testing.T) {
	pair := zmq4.NewPAIR()
	t.Cleanup(func() { pair.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := pair.Send(ctx, zmq4.Message{[]byte("x")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// TestPAIRCtxCancelRecv verifies Recv unblocks on cancelled ctx when no peer.
func TestPAIRCtxCancelRecv(t *testing.T) {
	pair := zmq4.NewPAIR()
	t.Cleanup(func() { pair.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := pair.Recv(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// TestPUSHIncompatiblePeer verifies PUSH rejects a non-PULL peer.
func TestPUSHIncompatiblePeer(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })

	push := zmq4.NewPUSH()
	t.Cleanup(func() { push.Close() })
	err := push.Connect(ctx, ep)
	if !errors.Is(err, zmq4.ErrIncompatiblePeer) {
		t.Fatalf("want ErrIncompatiblePeer for PUSH→REP, got %v", err)
	}
}

// TestPAIRIncompatiblePeer verifies PAIR rejects a non-PAIR peer.
func TestPAIRIncompatiblePeer(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })

	pair := zmq4.NewPAIR()
	t.Cleanup(func() { pair.Close() })
	err := pair.Connect(ctx, ep)
	if !errors.Is(err, zmq4.ErrIncompatiblePeer) {
		t.Fatalf("want ErrIncompatiblePeer for PAIR→REP, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests**

```
go test -race -run "TestPUSH|TestPULL|TestPAIR" ./...
```
Expected: all PASS.

- [ ] **Step 3: Commit**

```bash
git add push_pull_pair_test.go
git commit -m "test(F5c): unit tests — PUSH/PULL roundtrip, round-robin, PAIR exclusivity, reconnect"
```

---

## Chunk 6: Lifecycle tests

### Task 7: Lifecycle tests (additions to `lifecycle_test.go`)

**Files:**
- Modify: `lifecycle_test.go`

- [ ] **Step 1: Add tests at end of file**

Append to `lifecycle_test.go`:

```go
func TestPUSHCloseUnblocksSend(t *testing.T) {
	push := zmq4.NewPUSH() // no peers
	ctx := context.Background()

	var wg sync.WaitGroup
	var sendErr error
	wg.Go(func() {
		sendErr = push.Send(ctx, zmq4.Message{[]byte("x")})
	})

	time.Sleep(10 * time.Millisecond)
	push.Close()
	wg.Wait()
	if !errors.Is(sendErr, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", sendErr)
	}
}

func TestPULLCloseUnblocksRecv(t *testing.T) {
	pull := zmq4.NewPULL()
	ctx := context.Background()

	var wg sync.WaitGroup
	var recvErr error
	wg.Go(func() {
		_, recvErr = pull.Recv(ctx)
	})

	time.Sleep(10 * time.Millisecond)
	pull.Close()
	wg.Wait()
	if !errors.Is(recvErr, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", recvErr)
	}
}

func TestPAIRCloseUnblocksSend(t *testing.T) {
	pair := zmq4.NewPAIR() // no peer
	ctx := context.Background()

	var wg sync.WaitGroup
	var sendErr error
	wg.Go(func() {
		sendErr = pair.Send(ctx, zmq4.Message{[]byte("x")})
	})

	time.Sleep(10 * time.Millisecond)
	pair.Close()
	wg.Wait()
	if !errors.Is(sendErr, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", sendErr)
	}
}

func TestPAIRCloseUnblocksRecv(t *testing.T) {
	pair := zmq4.NewPAIR()
	ctx := context.Background()

	var wg sync.WaitGroup
	var recvErr error
	wg.Go(func() {
		_, recvErr = pair.Recv(ctx)
	})

	time.Sleep(10 * time.Millisecond)
	pair.Close()
	wg.Wait()
	if !errors.Is(recvErr, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", recvErr)
	}
}

func TestPUSHCloseIdempotent(t *testing.T) {
	push := zmq4.NewPUSH()
	if err := push.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := push.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestPULLCloseIdempotent(t *testing.T) {
	pull := zmq4.NewPULL()
	if err := pull.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := pull.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestPAIRCloseIdempotent(t *testing.T) {
	pair := zmq4.NewPAIR()
	if err := pair.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := pair.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
```

- [ ] **Step 2: Run tests**

```
go test -race -run "TestPUSHClose|TestPULLClose|TestPAIRClose" ./...
```
Expected: all PASS.

- [ ] **Step 3: Commit**

```bash
git add lifecycle_test.go
git commit -m "test(F5c): lifecycle tests — Close unblocks, idempotent for PUSH/PULL/PAIR"
```

---

## Chunk 7: Integration tests

### Task 8: Integration test rows (additions to `integration_test.go`)

**Files:**
- Modify: `integration_test.go`

- [ ] **Step 1: Add `"pushpull"` and `"pair"` to the pair slice**

In `TestIntegration`, find the inner `pair` loop:

```go
for _, pair := range []string{"reqrep", "dealerrouter", "pubsub", "xpubxsub"} {
```

Change it to:

```go
for _, pair := range []string{"reqrep", "dealerrouter", "pubsub", "xpubxsub", "pushpull", "pair"} {
```

- [ ] **Step 2: Add cases to `runIntegRow`**

In the `switch row.pair` block, add after `"xpubxsub"`:

```go
case "pushpull":
    runPUSHPULL(t, ctx, ep, serverOpts, clientOpts)
case "pair":
    runPAIR(t, ctx, ep, serverOpts, clientOpts)
```

- [ ] **Step 3: Add `runPUSHPULL` and `runPAIR` functions**

Add after the existing `runXPUBXSUB` function:

```go
func runPUSHPULL(t *testing.T, ctx context.Context, ep string, serverOpts, clientOpts []zmq4.Option) {
	t.Helper()

	pull := zmq4.NewPULL(serverOpts...)
	if err := pull.Bind(ctx, ep); err != nil {
		t.Fatalf("PULL.Bind: %v", err)
	}
	defer pull.Close()

	push := zmq4.NewPUSH(clientOpts...)
	if err := push.Connect(ctx, ep); err != nil {
		t.Fatalf("PUSH.Connect: %v", err)
	}
	defer push.Close()

	if err := push.Send(ctx, zmq4.Message{[]byte("hello")}); err != nil {
		t.Fatalf("PUSH.Send: %v", err)
	}
	got, err := pull.Recv(ctx)
	if err != nil {
		t.Fatalf("PULL.Recv: %v", err)
	}
	if len(got) == 0 || string(got[0]) != "hello" {
		t.Fatalf("want hello, got %q", got)
	}
}

func runPAIR(t *testing.T, ctx context.Context, ep string, serverOpts, clientOpts []zmq4.Option) {
	t.Helper()

	a := zmq4.NewPAIR(serverOpts...)
	if err := a.Bind(ctx, ep); err != nil {
		t.Fatalf("PAIR.Bind: %v", err)
	}
	defer a.Close()

	b := zmq4.NewPAIR(clientOpts...)
	if err := b.Connect(ctx, ep); err != nil {
		t.Fatalf("PAIR.Connect: %v", err)
	}
	defer b.Close()

	if err := b.Send(ctx, zmq4.Message{[]byte("ping")}); err != nil {
		t.Fatalf("PAIR b.Send: %v", err)
	}
	got, err := a.Recv(ctx)
	if err != nil {
		t.Fatalf("PAIR a.Recv: %v", err)
	}
	if len(got) == 0 || string(got[0]) != "ping" {
		t.Fatalf("want ping, got %q", got)
	}

	if err := a.Send(ctx, zmq4.Message{[]byte("pong")}); err != nil {
		t.Fatalf("PAIR a.Send: %v", err)
	}
	reply, err := b.Recv(ctx)
	if err != nil {
		t.Fatalf("PAIR b.Recv: %v", err)
	}
	if len(reply) == 0 || string(reply[0]) != "pong" {
		t.Fatalf("want pong, got %q", reply)
	}
}
```

- [ ] **Step 4: Run integration tests**

```
go test -race -tags integration -run TestIntegration ./...
```
Expected: all rows PASS including the 18 new `pushpull` and `pair` rows
(3 transports × 3 security × 2 patterns = 18 new subtests).

- [ ] **Step 5: Commit**

```bash
git add integration_test.go
git commit -m "test(F5c): integration tests — 18 new PUSH/PULL + PAIR rows (54 total)"
```

---

## Chunk 8: Interop tests

### Task 9: Interop test rows (additions to `interop/interop_test.go`)

**Files:**
- Modify: `interop/interop_test.go`

- [ ] **Step 1: Update `bridge.py` — add PUSH/PULL socket types**

Open `internal/conn/interop/bridge/bridge.py`.

**1a.** In `SOCKET_TYPES`, add two entries after `"XSUB"`:

```python
SOCKET_TYPES = {
    "PAIR":   zmq.PAIR,
    "REQ":    zmq.REQ,
    "REP":    zmq.REP,
    "DEALER": zmq.DEALER,
    "ROUTER": zmq.ROUTER,
    "PUB":    zmq.PUB,
    "SUB":    zmq.SUB,
    "XPUB":   zmq.XPUB,
    "XSUB":   zmq.XSUB,
    "PUSH":   zmq.PUSH,
    "PULL":   zmq.PULL,
}
```

**1b.** In `run_scenario`, add two new branches before the final `# PAIR, REP: passive echo` block:

```python
    if socket_type == "PUSH":
        # PUSH: active sender — always initiates.
        if scenario == "single":
            sock.send(b"INTEROP")
        elif scenario == "multipart":
            sock.send_multipart([b"INTEROP_P1", b"INTEROP_P2", b"INTEROP_P3"])
        else:
            raise ValueError(f"unknown scenario {scenario!r}")
        return

    if socket_type == "PULL":
        # PULL: passive receiver — waits for one message.
        if scenario == "single":
            sock.recv()
        elif scenario == "multipart":
            sock.recv_multipart()
        else:
            raise ValueError(f"unknown scenario {scenario!r}")
        return
```

Commit:
```bash
git add internal/conn/interop/bridge/bridge.py
git commit -m "feat(F5c): bridge.py — add PUSH/PULL socket types and run_scenario branches"
```

- [ ] **Step 2: Add `"pushpull"` and `"pair"` to `buildMatrix`**

In `buildMatrix`, find:

```go
for _, pair := range []string{"reqrep", "dealerrouter", "pubsub", "xpubxsub"} {
```

Change to:

```go
for _, pair := range []string{"reqrep", "dealerrouter", "pubsub", "xpubxsub", "pushpull", "pair"} {
```

Note: This adds 2 pairs × 2 dirs × 3 mechs × 2 schemes × 2 scenarios = 48 new rows
(total matrix grows from 96 to 144).

- [ ] **Step 3: Add cases to `socketTypeNames`**

In the `switch row.pair + "+" + string(row.dir)` block, add after the existing XPUB/XSUB cases:

```go
case "pushpull+dialer":
    return "PUSH", "PULL" // Go=PUSH dials, bridge=PULL listens
case "pushpull+listener":
    return "PULL", "PUSH" // Go=PULL listens, bridge=PUSH dials
case "pair+dialer":
    return "PAIR", "PAIR" // Go=PAIR dials, bridge=PAIR listens
case "pair+listener":
    return "PAIR", "PAIR" // Go=PAIR listens, bridge=PAIR dials
```

- [ ] **Step 4: Add cases to `runGoSocket`**

In the `switch goType` block, add after the existing XSUB case:

```go
case "PUSH":
    runGoPUSH(t, ctx, ep, opts, row.scenario, dial)
case "PULL":
    runGoPULL(t, ctx, ep, opts, row.scenario, dial)
case "PAIR":
    runGoPAIR(t, ctx, ep, opts, row.scenario, dial)
```

- [ ] **Step 5: Add `runGoPUSH`, `runGoPULL`, `runGoPAIR` functions**

Add after `runGoXSUB`:

```go
func runGoPUSH(t *testing.T, ctx context.Context, ep string, opts goOpts, sc fixture.Scenario, dial bool) {
	t.Helper()
	push := zmq4.NewPUSH(opts.clientOpts...)
	defer push.Close()

	if dial {
		if err := push.Connect(ctx, ep); err != nil {
			t.Fatalf("PUSH.Connect: %v", err)
		}
	} else {
		if err := push.Bind(ctx, ep); err != nil {
			t.Fatalf("PUSH.Bind: %v", err)
		}
	}

	payload := testPayload(sc)
	if err := push.Send(ctx, payload); err != nil {
		t.Fatalf("PUSH.Send: %v", err)
	}
}

func runGoPULL(t *testing.T, ctx context.Context, ep string, opts goOpts, sc fixture.Scenario, dial bool) {
	t.Helper()
	pull := zmq4.NewPULL(opts.serverOpts...)
	defer pull.Close()

	if dial {
		if err := pull.Connect(ctx, ep); err != nil {
			t.Fatalf("PULL.Connect: %v", err)
		}
	} else {
		if err := pull.Bind(ctx, ep); err != nil {
			t.Fatalf("PULL.Bind: %v", err)
		}
	}

	got, err := pull.Recv(ctx)
	if err != nil {
		t.Fatalf("PULL.Recv: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("PULL.Recv: got empty message")
	}
}

func runGoPAIR(t *testing.T, ctx context.Context, ep string, opts goOpts, sc fixture.Scenario, dial bool) {
	t.Helper()
	// PAIR: both sides symmetric; use clientOpts for dialer, serverOpts for listener.
	var pairOpts []zmq4.Option
	if dial {
		pairOpts = opts.clientOpts
	} else {
		pairOpts = opts.serverOpts
	}
	pair := zmq4.NewPAIR(pairOpts...)
	defer pair.Close()

	if dial {
		if err := pair.Connect(ctx, ep); err != nil {
			t.Fatalf("PAIR.Connect: %v", err)
		}
	} else {
		if err := pair.Bind(ctx, ep); err != nil {
			t.Fatalf("PAIR.Bind: %v", err)
		}
	}

	// Go PAIR always sends first; bridge PAIR always echoes (recv→send in
	// bridge.py's passive-echo block). This is direction-agnostic: when Go
	// dials the bridge listens and echoes; when Go listens the bridge dials
	// and also waits to recv (ZMQ passive-echo applies regardless of role).
	payload := testPayload(sc)
	if err := pair.Send(ctx, payload); err != nil {
		t.Fatalf("PAIR.Send: %v", err)
	}
	got, err := pair.Recv(ctx)
	if err != nil {
		t.Fatalf("PAIR.Recv: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("PAIR.Recv: got empty message")
	}
}
```

- [ ] **Step 6: Run interop tests**

```
go test -race -tags interop -v ./interop/... 2>&1 | tail -20
```
Expected: all new PUSH/PULL and PAIR rows PASS.
(Requires Docker and `zmq4-interop-bridge:latest` image.)

- [ ] **Step 7: Commit**

```bash
git add interop/interop_test.go
git commit -m "test(F5c): interop tests — PUSH/PULL + PAIR matrix (48 new rows)"
```

---

## Chunk 9: Docs + done-criteria sweep

### Task 10: Update `doc.go`

**Files:**
- Modify: `doc.go`

- [ ] **Step 1: Add PUSH/PULL/PAIR section to package godoc**

Replace the current `doc.go` content with:

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
// Pipeline pattern (RFC 30):
//
//   - [PUSH] — push socket (round-robin send; blocks until a peer is ready)
//   - [PULL] — pull socket (fair-queue recv; no send)
//
// Exclusive-pair pattern (RFC 31):
//
//   - [PAIR] — exclusive-pair socket (single peer; bidirectional)
//
// # Creating a socket
//
//	push := zmq4.NewPUSH()
//	if err := push.Bind(ctx, "tcp://127.0.0.1:5555"); err != nil { ... }
//	defer push.Close()
//
//	pull := zmq4.NewPULL()
//	if err := pull.Connect(ctx, "tcp://127.0.0.1:5555"); err != nil { ... }
//	msg, err := pull.Recv(ctx)
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

- [ ] **Step 2: Verify**

```
go build ./...
```
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add doc.go
git commit -m "docs(F5c): add PUSH/PULL/PAIR to package godoc"
```

---

### Task 11: Done-criteria sweep

**Files:**
- Modify: `docs/specs/00-meta-overview.md`

- [ ] **Step 1: Run full test suite with race detector**

```
go test -race ./...
```
Expected: all PASS, no data races.

- [ ] **Step 2: Run staticcheck**

```
staticcheck ./...
```
Expected: no output. (Install via `go install honnef.co/go/tools/cmd/staticcheck@latest` if missing.)

- [ ] **Step 3: Run modernize**

```
modernize -fix ./...
```
Expected: no changes (or apply any suggested fixes and re-run tests).

- [ ] **Step 4: Re-run tests after modernize**

```
go test -race ./...
```
Expected: all PASS.

- [ ] **Step 5: Update `docs/specs/00-meta-overview.md`**

Change the status header from:

```
> **Status:** living document. F1, F2a, F2b, F2c, F3, F4, F5a, and F5b complete
> and tagged ... F5c design approved, implementation pending.
```

to:

```
> **Status:** living document. F1, F2a, F2b, F2c, F3, F4, F5a, F5b, and F5c complete
> and tagged (`phase-1-wire-complete`, `phase-2a-null-complete`,
> `phase-2b-plain-complete`, `phase-2c-curve-complete`,
> `phase-3-transport-complete`, `phase-4-conn-complete`,
> `phase-5a-reqrep-complete`, `phase-5b-pubsub-complete`,
> `phase-5c-pipeline-pair-complete`). F6 pending.
```

Also change the F5c row in the phase table from `Design approved, implementation pending.` to `**Complete** — tagged \`phase-5c-pipeline-pair-complete\`.`

- [ ] **Step 6: Commit docs update**

```bash
git add docs/specs/00-meta-overview.md
git commit -m "chore(F5c): done-criteria sweep — staticcheck, modernize, meta-overview"
```

- [ ] **Step 7: Tag the phase**

```bash
git tag phase-5c-pipeline-pair-complete
```
