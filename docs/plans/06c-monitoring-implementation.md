# F6c Monitoring — Socket Events Implementation Plan

> **For Claude:** REQUIRED: Use `superpowers:subagent-driven-development` to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking. Each task is one commit.

**Goal:** Add channel-based socket lifecycle monitoring via `WithMonitor(chan<- SocketEvent)`, emitting events for bind, connect, accept, handshake, disconnect, and close.

**Architecture:** `socketConfig` gains one field (`monitorCh chan<- SocketEvent`). `socketBase` gets an `emit()` helper (zero-cost nil-check, non-blocking select). Lifecycle events are wired into the existing `bind`, `acceptLoop`, `doServerHandshake`, `connect`, and `close` methods. Unexpected disconnects are detected via an `onDisconnect func(addr string)` callback on `pipe`, set in `addConn` when monitoring is active.

**Tech Stack:** Pure Go 1.26, stdlib only. No new external deps.

**Decisions baked into the plan:**
- `EventClosed` is emitted per-pipe *before* `p.conn.Close()` (while the pipe is still alive). This avoids the empty-pipeSet problem that would occur if we waited until after `wg.Wait()`.
- `EventMonitorStopped` is emitted last, then `close(monitorCh)`. Callers may use `for ev := range ch`.
- `EventAcceptFailed` is suppressed when the error is caused by the socket's own shutdown (checked via `select { case <-closeCh: }`).
- `onDisconnect` on `pipe` uses signature `func(addr string)` (consistent with spec).
- `EventDisconnected` fires only for peer-initiated drops (I/O error while socket is still open). `EventClosed` fires for each pipe during `socket.Close()`. These are mutually exclusive because `readLoop` checks `closeCh` at deferred-cleanup time.
- **No `modernize -fix` per task.** Run only at Task 7 (done-criteria sweep).
- **Phase tag:** `phase-6c-monitoring-complete` after Task 7.

---

## Chunk 1: Event types + WithMonitor option

### Task 1: `event.go` — EventType constants + SocketEvent struct

**Files:**
- Create: `event.go`
- Create: `event_test.go`

- [ ] **Step 1: Write failing test in `event_test.go`**

New file `event_test.go` (`package zmq4`):

```go
package zmq4

import "testing"

func TestEventTypeValues(t *testing.T) {
	if EventListening != 1 {
		t.Fatalf("EventListening = %d, want 1", EventListening)
	}
	if EventMonitorStopped != 11 {
		t.Fatalf("EventMonitorStopped = %d, want 11", EventMonitorStopped)
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```
go test -run TestEventTypeValues -count=1 .
```

Expected: compile error — `EventListening` undefined.

- [ ] **Step 3: Create `event.go`**

```go
package zmq4

// EventType identifies the kind of lifecycle event a socket emitted.
type EventType int

const (
	// EventListening is emitted when Bind() establishes a listener.
	EventListening EventType = iota + 1
	// EventBindFailed is emitted when Bind() fails.
	EventBindFailed
	// EventAccepted is emitted when a raw incoming connection is accepted,
	// before the ZMTP handshake starts.
	EventAccepted
	// EventAcceptFailed is emitted when the accept loop encounters an error.
	EventAcceptFailed
	// EventConnected is emitted after transport.Dial succeeds, before the
	// ZMTP handshake starts.
	EventConnected
	// EventConnectFailed is emitted when transport.Dial fails.
	EventConnectFailed
	// EventHandshakeSucceeded is emitted when a ZMTP handshake completes
	// successfully, on both client and server sides.
	EventHandshakeSucceeded
	// EventHandshakeFailed is emitted when a ZMTP handshake fails.
	EventHandshakeFailed
	// EventDisconnected is emitted when a pipe is removed due to an unexpected
	// peer-initiated connection drop while the socket is still open.
	EventDisconnected
	// EventClosed is emitted once per pipe during socket.Close().
	EventClosed
	// EventMonitorStopped is the final event. The socket closes the monitor
	// channel immediately after emitting it.
	EventMonitorStopped
)

// SocketEvent is a lifecycle event emitted by a socket to its monitor channel.
type SocketEvent struct {
	Type     EventType
	Endpoint string // transport address; format varies by context (see WithMonitor)
	Err      error  // non-nil for *Failed and EventHandshakeFailed events
}
```

- [ ] **Step 4: Run test to confirm it passes**

```
go test -run TestEventTypeValues -count=1 .
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add event.go event_test.go
git commit -m "feat(F6c): EventType constants + SocketEvent struct"
```

---

### Task 2: `options.go` — `monitorCh` field + `WithMonitor` option

**Files:**
- Modify: `options.go`
- Modify: `options_test.go`

- [ ] **Step 1: Write failing tests in `options_test.go`**

Add after the last existing test:

```go
func TestWithMonitorStoresChannel(t *testing.T) {
	ch := make(chan SocketEvent, 1)
	cfg := newSocketConfig([]Option{WithMonitor(ch)})
	if cfg.monitorCh != ch {
		t.Fatal("monitorCh not set")
	}
}

func TestWithMonitorNilIsNoop(t *testing.T) {
	cfg := newSocketConfig([]Option{WithMonitor(nil)})
	if cfg.monitorCh != nil {
		t.Fatal("nil channel should leave monitorCh nil")
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```
go test -run "TestWithMonitor" -count=1 .
```

Expected: compile error — `WithMonitor` undefined.

- [ ] **Step 3: Add `monitorCh` field to `socketConfig` in `options.go`**

In `socketConfig`, add after the `zapDomain` field:

```go
monitorCh chan<- SocketEvent // non-nil when WithMonitor is used
```

- [ ] **Step 4: Add `WithMonitor` option to `options.go`**

Add after the `WithZAPDomain` function:

```go
// WithMonitor wires ch as the monitoring channel for this socket. The socket
// emits a SocketEvent for each lifecycle transition (bind, connect, handshake,
// disconnect, close). When the socket closes it emits EventMonitorStopped and
// then closes ch, so consumers may use:
//
//	for ev := range ch { … }
//
// The caller owns ch and must not close it. Events are dropped without blocking
// when ch is full; use a buffered channel sized to the expected burst. A nil ch
// is a no-op.
func WithMonitor(ch chan<- SocketEvent) Option {
	return func(cfg *socketConfig) { cfg.monitorCh = ch }
}
```

- [ ] **Step 5: Run tests to confirm they pass**

```
go test -run "TestWithMonitor" -count=1 .
```

Expected: PASS.

- [ ] **Step 6: Run full test suite to verify no regressions**

```
go test -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```
git add options.go options_test.go
git commit -m "feat(F6c): socketConfig.monitorCh field + WithMonitor option"
```

---

## Chunk 2: emit helper + lifecycle emission

### Task 3: `base.go` — `emit` helper + unit tests

**Files:**
- Modify: `base.go`
- Modify: `event_test.go`

- [ ] **Step 1: Add unit tests to `event_test.go`**

Add after `TestEventTypeValues`:

```go
func TestEmitNoopWhenNil(t *testing.T) {
	sb := newSocketBase(newSocketConfig(nil))
	// must not panic
	sb.emit(SocketEvent{Type: EventListening, Endpoint: "x"})
}

func TestEmitDeliversWhenSpace(t *testing.T) {
	ch := make(chan SocketEvent, 1)
	sb := newSocketBase(newSocketConfig([]Option{WithMonitor(ch)}))
	sb.emit(SocketEvent{Type: EventListening, Endpoint: "tcp://x"})
	ev := <-ch
	if ev.Type != EventListening {
		t.Fatalf("got Type=%v, want EventListening", ev.Type)
	}
	if ev.Endpoint != "tcp://x" {
		t.Fatalf("got Endpoint=%q, want %q", ev.Endpoint, "tcp://x")
	}
}

func TestEmitDropsWhenFull(t *testing.T) {
	ch := make(chan SocketEvent) // unbuffered — non-blocking send always fails
	sb := newSocketBase(newSocketConfig([]Option{WithMonitor(ch)}))

	done := make(chan struct{})
	go func() {
		sb.emit(SocketEvent{Type: EventListening, Endpoint: "x"})
		close(done)
	}()

	select {
	case <-done:
		// good — emit returned without blocking
	case <-time.After(10 * time.Millisecond):
		t.Fatal("emit blocked on full channel")
	}
}
```

Add `"time"` to the import block in `event_test.go`.

- [ ] **Step 2: Run tests to confirm they fail**

```
go test -run "TestEmit" -count=1 .
```

Expected: compile error — `emit` undefined on `socketBase`.

- [ ] **Step 3: Add `emit` to `base.go`**

Add after `newSocketBase`:

```go
// emit sends ev to the monitor channel if one is configured.
// Non-blocking: events are silently dropped when the channel is full.
func (sb *socketBase) emit(ev SocketEvent) {
	if sb.cfg.monitorCh == nil {
		return
	}
	select {
	case sb.cfg.monitorCh <- ev:
	default:
	}
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```
go test -run "TestEmit|TestEventType" -count=1 .
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add base.go event_test.go
git commit -m "feat(F6c): socketBase.emit helper"
```

---

### Task 4: `base.go` — emission in `bind`, `acceptLoop`, `doServerHandshake`, `connect`; basic integration tests

**Files:**
- Modify: `base.go`
- Create: `monitor_test.go`

- [ ] **Step 1: Write failing integration tests in `monitor_test.go`**

New file `monitor_test.go` (`package zmq4_test`):

```go
package zmq4_test

import (
	"context"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
	"github.com/tomi77/zmq4/internal/security/plain"
)

// drainN reads exactly n events from ch within timeout, failing the test on
// timeout.
func drainN(t *testing.T, ch <-chan zmq4.SocketEvent, n int, timeout time.Duration) []zmq4.SocketEvent {
	t.Helper()
	evs := make([]zmq4.SocketEvent, 0, n)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for len(evs) < n {
		select {
		case ev := <-ch:
			evs = append(evs, ev)
		case <-deadline.C:
			t.Fatalf("drainN: timeout after %v waiting for event %d/%d (got: %v)",
				timeout, len(evs)+1, n, evs)
		}
	}
	return evs
}

func TestMonitorBind(t *testing.T) {
	ch := make(chan zmq4.SocketEvent, 4)
	s := zmq4.NewPUSH(zmq4.WithNULL(), zmq4.WithMonitor(ch))
	defer s.Close()

	if err := s.Bind(context.Background(), "inproc://monitor-bind-test"); err != nil {
		t.Fatal(err)
	}

	evs := drainN(t, ch, 1, 100*time.Millisecond)
	if evs[0].Type != zmq4.EventListening {
		t.Fatalf("got %v, want EventListening", evs[0].Type)
	}
	if evs[0].Endpoint != "inproc://monitor-bind-test" {
		t.Fatalf("endpoint = %q, want %q", evs[0].Endpoint, "inproc://monitor-bind-test")
	}
	if evs[0].Err != nil {
		t.Fatalf("unexpected Err: %v", evs[0].Err)
	}
}

func TestMonitorBindFailed(t *testing.T) {
	ch := make(chan zmq4.SocketEvent, 4)
	s := zmq4.NewPUSH(zmq4.WithNULL(), zmq4.WithMonitor(ch))
	defer s.Close()

	// invalid endpoint — transport.Listen will fail
	_ = s.Bind(context.Background(), "tcp://256.256.256.256:99999")

	evs := drainN(t, ch, 1, 100*time.Millisecond)
	if evs[0].Type != zmq4.EventBindFailed {
		t.Fatalf("got %v, want EventBindFailed", evs[0].Type)
	}
	if evs[0].Err == nil {
		t.Fatal("EventBindFailed.Err must be non-nil")
	}
}

func TestMonitorConnect(t *testing.T) {
	const ep = "inproc://monitor-connect-test"

	serverCh := make(chan zmq4.SocketEvent, 8)
	server := zmq4.NewPULL(zmq4.WithNULL(), zmq4.WithMonitor(serverCh))
	defer server.Close()

	clientCh := make(chan zmq4.SocketEvent, 8)
	client := zmq4.NewPUSH(zmq4.WithNULL(), zmq4.WithMonitor(clientCh))
	defer client.Close()

	if err := server.Bind(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(context.Background(), ep); err != nil {
		t.Fatal(err)
	}

	// Server: EventListening (from Bind), EventAccepted, EventHandshakeSucceeded
	serverEvs := drainN(t, serverCh, 3, 200*time.Millisecond)
	wantServer := []zmq4.EventType{zmq4.EventListening, zmq4.EventAccepted, zmq4.EventHandshakeSucceeded}
	for i, want := range wantServer {
		if serverEvs[i].Type != want {
			t.Errorf("server event[%d]: got %v, want %v", i, serverEvs[i].Type, want)
		}
	}

	// Client: EventConnected, EventHandshakeSucceeded
	clientEvs := drainN(t, clientCh, 2, 200*time.Millisecond)
	wantClient := []zmq4.EventType{zmq4.EventConnected, zmq4.EventHandshakeSucceeded}
	for i, want := range wantClient {
		if clientEvs[i].Type != want {
			t.Errorf("client event[%d]: got %v, want %v", i, clientEvs[i].Type, want)
		}
	}
}

func TestMonitorConnectFailed(t *testing.T) {
	ch := make(chan zmq4.SocketEvent, 4)
	client := zmq4.NewPUSH(zmq4.WithNULL(), zmq4.WithMonitor(ch))
	defer client.Close()

	// No server listening on this endpoint.
	_ = client.Connect(context.Background(), "tcp://127.0.0.1:1") // port 1 is reserved/unreachable

	evs := drainN(t, ch, 1, 200*time.Millisecond)
	if evs[0].Type != zmq4.EventConnectFailed {
		t.Fatalf("got %v, want EventConnectFailed", evs[0].Type)
	}
	if evs[0].Err == nil {
		t.Fatal("EventConnectFailed.Err must be non-nil")
	}
}

func TestMonitorHandshakeFailed(t *testing.T) {
	const ep = "inproc://monitor-handshake-fail-test"

	serverCh := make(chan zmq4.SocketEvent, 8)
	// PLAIN server requires credentials; NULL client will fail the handshake.
	server := zmq4.NewPULL(
		zmq4.WithPLAINServer(plain.AuthenticatorFunc(func(_, _ string) bool { return true })),
		zmq4.WithMonitor(serverCh),
	)
	defer server.Close()

	clientCh := make(chan zmq4.SocketEvent, 8)
	client := zmq4.NewPUSH(zmq4.WithNULL(), zmq4.WithMonitor(clientCh))
	defer client.Close()

	if err := server.Bind(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	// Connect returns an error (handshake fails); ignore it here.
	_ = client.Connect(context.Background(), ep)

	// Server: EventListening, EventAccepted, EventHandshakeFailed
	serverEvs := drainN(t, serverCh, 3, 200*time.Millisecond)
	if serverEvs[2].Type != zmq4.EventHandshakeFailed {
		t.Fatalf("server event[2]: got %v, want EventHandshakeFailed", serverEvs[2].Type)
	}
	if serverEvs[2].Err == nil {
		t.Fatal("server EventHandshakeFailed.Err must be non-nil")
	}

	// Client: EventConnected, EventHandshakeFailed
	clientEvs := drainN(t, clientCh, 2, 200*time.Millisecond)
	if clientEvs[1].Type != zmq4.EventHandshakeFailed {
		t.Fatalf("client event[1]: got %v, want EventHandshakeFailed", clientEvs[1].Type)
	}
	if clientEvs[1].Err == nil {
		t.Fatal("client EventHandshakeFailed.Err must be non-nil")
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```
go test -run "TestMonitor(Bind|Connect|Handshake)" -count=1 .
```

Expected: FAIL — events not yet emitted.

- [ ] **Step 3: Wire emit calls into `bind()` in `base.go`**

Replace the current `bind` function body:

```go
func (sb *socketBase) bind(ctx context.Context, endpoint, socketType string) error {
	ln, err := transport.Listen(ctx, endpoint)
	if err != nil {
		sb.emit(SocketEvent{Type: EventBindFailed, Endpoint: endpoint, Err: err})
		return err
	}
	sb.emit(SocketEvent{Type: EventListening, Endpoint: endpoint})
	sb.listenersMu.Lock()
	sb.listeners = append(sb.listeners, ln)
	sb.listenersMu.Unlock()
	sb.wg.Add(1)
	go sb.acceptLoop(ln, socketType)
	return nil
}
```

- [ ] **Step 4: Wire emit calls into `acceptLoop()` in `base.go`**

Replace the current `acceptLoop` function body:

```go
func (sb *socketBase) acceptLoop(ln net.Listener, socketType string) {
	defer sb.wg.Done()
	defer ln.Close()
	for {
		raw, err := ln.Accept()
		if err != nil {
			select {
			case <-sb.closeCh:
				// Normal shutdown — listener was closed by close(); no event.
			default:
				sb.emit(SocketEvent{Type: EventAcceptFailed, Endpoint: ln.Addr().String(), Err: err})
			}
			return
		}
		sb.wg.Add(1)
		go sb.doServerHandshake(raw, socketType)
	}
}
```

- [ ] **Step 5: Wire emit calls into `doServerHandshake()` in `base.go`**

Replace the current `doServerHandshake` function body:

```go
func (sb *socketBase) doServerHandshake(raw net.Conn, socketType string) {
	defer sb.wg.Done()
	hsCtx, cancel := context.WithTimeout(context.Background(), sb.cfg.handshakeTimeout)
	defer cancel()

	addr := raw.RemoteAddr().String()
	sb.emit(SocketEvent{Type: EventAccepted, Endpoint: addr})

	mech, err := sb.cfg.serverMechFactory(socketType)
	if err != nil {
		raw.Close()
		return
	}
	if sb.cfg.zapCaller != nil {
		if zc, ok := mech.(security.ZAPConfigurer); ok {
			zc.ConfigureZAP(sb.cfg.zapCaller, sb.cfg.zapDomain)
		}
	}
	if pas, ok := mech.(security.PeerAddrSetter); ok {
		pas.SetPeerAddr(addr)
	}
	c, err := conn.ServerHandshake(hsCtx, raw, mech)
	if err != nil {
		sb.emit(SocketEvent{Type: EventHandshakeFailed, Endpoint: addr, Err: err})
		return // raw already closed by F4 on handshake failure
	}
	sb.emit(SocketEvent{Type: EventHandshakeSucceeded, Endpoint: addr})
	if err := sb.addConn(c, socketType); err != nil {
		c.Close()
	}
}
```

- [ ] **Step 6: Wire emit calls into `connect()` in `base.go`**

Replace the current `connect` function body:

```go
func (sb *socketBase) connect(ctx context.Context, endpoint, socketType string) error {
	raw, err := transport.Dial(ctx, endpoint)
	if err != nil {
		sb.emit(SocketEvent{Type: EventConnectFailed, Endpoint: endpoint, Err: err})
		return err
	}
	sb.emit(SocketEvent{Type: EventConnected, Endpoint: endpoint})
	hsCtx, cancel := context.WithTimeout(ctx, sb.cfg.handshakeTimeout)
	defer cancel()

	mech, err := sb.cfg.clientMechFactory(socketType)
	if err != nil {
		raw.Close()
		return err
	}
	c, err := conn.ClientHandshake(hsCtx, raw, mech)
	if err != nil {
		sb.emit(SocketEvent{Type: EventHandshakeFailed, Endpoint: endpoint, Err: err})
		return err
	}
	sb.emit(SocketEvent{Type: EventHandshakeSucceeded, Endpoint: endpoint})
	if err := sb.addConn(c, socketType); err != nil {
		c.Close()
		return err
	}
	return nil
}
```

- [ ] **Step 7: Run the new tests**

```
go test -run "TestMonitor(Bind|Connect|Handshake)" -count=1 -v .
```

Expected: PASS.

- [ ] **Step 8: Run full test suite**

```
go test -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 9: Commit**

```
git add base.go monitor_test.go
git commit -m "feat(F6c): emit lifecycle events in bind/connect/accept/handshake"
```

---

## Chunk 3: Disconnect callback + close() monitor sequence

### Task 5: `pipe.go` — `onDisconnect` callback + disconnect detection

**Files:**
- Modify: `pipe.go`
- Modify: `base.go`
- Modify: `monitor_test.go`

- [ ] **Step 1: Add `TestMonitorDisconnected` to `monitor_test.go`**

Add after `TestMonitorHandshakeFailed`:

```go
func TestMonitorDisconnected(t *testing.T) {
	const ep = "inproc://monitor-disconnected-test"

	serverCh := make(chan zmq4.SocketEvent, 8)
	server := zmq4.NewPULL(zmq4.WithNULL(), zmq4.WithMonitor(serverCh))
	defer server.Close()

	client := zmq4.NewPUSH(zmq4.WithNULL())

	if err := server.Bind(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(context.Background(), ep); err != nil {
		t.Fatal(err)
	}

	// Drain connection events on server side.
	drainN(t, serverCh, 3, 200*time.Millisecond) // Listening + Accepted + HandshakeSucceeded

	// Close client — server's readLoop will see an I/O error → EventDisconnected.
	client.Close()

	evs := drainN(t, serverCh, 1, 500*time.Millisecond)
	if evs[0].Type != zmq4.EventDisconnected {
		t.Fatalf("got %v, want EventDisconnected", evs[0].Type)
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```
go test -run TestMonitorDisconnected -count=1 .
```

Expected: FAIL or timeout — `EventDisconnected` not yet emitted.

- [ ] **Step 3: Add `onDisconnect` field to `pipe` struct in `pipe.go`**

In the `pipe` struct, add after the `overflow` field:

```go
onDisconnect func(addr string) // called when peer drops the connection unexpectedly
```

- [ ] **Step 4: Replace the three deferred calls in `readLoop` with a combined deferred function**

The current `readLoop` has:
```go
defer p.wg.Done()
defer close(p.inCh)
defer ps.remove(p)
```

Replace `defer ps.remove(p)` with a deferred function that also handles the disconnect callback:

```go
defer func() {
    ps.remove(p)
    if p.onDisconnect != nil {
        select {
        case <-closeCh:
            // Socket is shutting down; EventClosed is handled by close().
        default:
            p.onDisconnect(p.conn.RemoteAddr().String())
        }
    }
}()
```

The final `readLoop` defer block should look like:

```go
defer p.wg.Done()
defer close(p.inCh)
defer func() {
    ps.remove(p)
    if p.onDisconnect != nil {
        select {
        case <-closeCh:
        default:
            p.onDisconnect(p.conn.RemoteAddr().String())
        }
    }
}()
```

- [ ] **Step 5: Wire `onDisconnect` in `addConn` in `base.go`**

In `addConn`, after `p := newPipe(...)` and before `sb.pipes.add(p)`, add:

```go
if sb.cfg.monitorCh != nil {
    p.onDisconnect = func(addr string) {
        sb.emit(SocketEvent{Type: EventDisconnected, Endpoint: addr})
    }
}
```

- [ ] **Step 6: Run the new test**

```
go test -run TestMonitorDisconnected -count=1 -v .
```

Expected: PASS.

- [ ] **Step 7: Run full test suite**

```
go test -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```
git add pipe.go base.go monitor_test.go
git commit -m "feat(F6c): pipe onDisconnect callback + EventDisconnected emission"
```

---

### Task 6: `base.go` — `close()` monitor sequence; remaining integration tests

**Files:**
- Modify: `base.go`
- Modify: `monitor_test.go`

- [ ] **Step 1: Add `TestMonitorClose` and `TestMonitorDropsOnFull` to `monitor_test.go`**

Add after `TestMonitorDisconnected`:

```go
func TestMonitorClose(t *testing.T) {
	const ep = "inproc://monitor-close-test"

	serverCh := make(chan zmq4.SocketEvent, 16)
	server := zmq4.NewPULL(zmq4.WithNULL(), zmq4.WithMonitor(serverCh))

	client1 := zmq4.NewPUSH(zmq4.WithNULL())
	client2 := zmq4.NewPUSH(zmq4.WithNULL())
	defer client1.Close()
	defer client2.Close()

	if err := server.Bind(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	if err := client1.Connect(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	if err := client2.Connect(context.Background(), ep); err != nil {
		t.Fatal(err)
	}

	// Drain: EventListening + 2×(EventAccepted + EventHandshakeSucceeded) = 5 events.
	drainN(t, serverCh, 5, 500*time.Millisecond)

	// Close the server.
	server.Close()

	// Expect EventClosed ×2 + EventMonitorStopped = 3 events.
	evs := drainN(t, serverCh, 3, 500*time.Millisecond)

	closedCount := 0
	stoppedCount := 0
	for _, ev := range evs {
		switch ev.Type {
		case zmq4.EventClosed:
			closedCount++
		case zmq4.EventMonitorStopped:
			stoppedCount++
		default:
			t.Errorf("unexpected event type: %v", ev.Type)
		}
	}
	if closedCount != 2 {
		t.Errorf("EventClosed count: got %d, want 2", closedCount)
	}
	if stoppedCount != 1 {
		t.Errorf("EventMonitorStopped count: got %d, want 1", stoppedCount)
	}
	if evs[len(evs)-1].Type != zmq4.EventMonitorStopped {
		t.Errorf("last event: got %v, want EventMonitorStopped", evs[len(evs)-1].Type)
	}

	// Channel must be closed after EventMonitorStopped.
	select {
	case _, ok := <-serverCh:
		if ok {
			t.Fatal("unexpected event after EventMonitorStopped")
		}
		// ok == false: channel closed as expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("monitor channel not closed after EventMonitorStopped")
	}
}

func TestMonitorDropsOnFull(t *testing.T) {
	const ep = "inproc://monitor-drops-test"

	// Cap-1 channel: most events will be dropped, but emit must never block.
	serverCh := make(chan zmq4.SocketEvent, 1)
	server := zmq4.NewPULL(zmq4.WithNULL(), zmq4.WithMonitor(serverCh))

	client := zmq4.NewPUSH(zmq4.WithNULL())

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Bind(context.Background(), ep)
		_ = client.Connect(context.Background(), ep)
		client.Close()
		server.Close()
	}()

	select {
	case <-done:
		// no deadlock
	case <-time.After(2 * time.Second):
		t.Fatal("deadlock detected: socket operations blocked on full monitor channel")
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```
go test -run "TestMonitor(Close|Drops)" -count=1 .
```

Expected: FAIL — `EventClosed`/`EventMonitorStopped` not yet emitted; channel not closed.

- [ ] **Step 3: Update `close()` in `base.go`**

Replace the existing `closeOnce.Do` block with the following (additions highlighted by comments):

```go
func (sb *socketBase) close() {
	sb.closeOnce.Do(func() {
		close(sb.closeCh)
		if sb.closeFn != nil {
			sb.closeFn()
		}
		sb.listenersMu.Lock()
		for _, ln := range sb.listeners {
			ln.Close()
		}
		sb.listenersMu.Unlock()
		// Snapshot live pipes before closing them. Emit EventClosed for each
		// so the monitor receives the event while the pipe is still alive.
		closing := sb.pipes.all()
		for _, p := range closing {
			sb.emit(SocketEvent{Type: EventClosed, Endpoint: p.conn.RemoteAddr().String()})
			p.conn.Close()
		}
		sb.wg.Wait()
		// Close any pipes that were added after the first snapshot.
		for _, p := range sb.pipes.all() {
			p.conn.Close()
		}
		// Now wait for all reader goroutines to exit.
		for _, p := range sb.pipes.all() {
			p.wg.Wait()
		}
		// Seal the monitor channel.
		if sb.cfg.monitorCh != nil {
			sb.emit(SocketEvent{Type: EventMonitorStopped})
			close(sb.cfg.monitorCh)
		}
	})
}
```

Note: this combines the original two-loop `all()+Close()` into one loop (snapshot + emit + close per pipe). The second-pass loop for late-arriving pipes is preserved unchanged.

- [ ] **Step 4: Run the new tests**

```
go test -run "TestMonitor(Close|Drops)" -count=1 -v .
```

Expected: PASS.

- [ ] **Step 5: Run all monitor tests**

```
go test -run TestMonitor -count=1 -v .
```

Expected: all PASS.

- [ ] **Step 6: Run full test suite with race detector**

```
go test -race -count=1 ./...
```

Expected: all tests pass, no races.

- [ ] **Step 7: Commit**

```
git add base.go monitor_test.go
git commit -m "feat(F6c): EventClosed/EventMonitorStopped in close(); channel sealed"
```

---

## Chunk 4: Done-criteria sweep

### Task 7: modernize, staticcheck, meta-overview update, phase tag

**Files:**
- Modify: `docs/specs/00-meta-overview.md`

- [ ] **Step 1: Run `modernize -fix`**

```
modernize -fix ./...
```

If any files are modified, review the diff, then stage and commit:

```
git add -p
git commit -m "chore(F6c): modernize -fix"
```

If no files are modified: no commit needed.

- [ ] **Step 2: Run `go vet`**

```
go vet ./...
```

Expected: no output.

- [ ] **Step 3: Run `staticcheck`**

```
staticcheck ./...
```

Expected: no output.

- [ ] **Step 4: Run full test suite with race detector**

```
go test -race -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 5: Update `docs/specs/00-meta-overview.md`**

In the Status line at the top, add F6c to the completed list:

```
> **Status:** living document. F1, F2a, F2b, F2c, F3, F4, F5a, F5b, F5c, F6a, F6b, and F6c complete
> and tagged (`phase-1-wire-complete`, …, `phase-6b-zap-complete`,
> `phase-6c-monitoring-complete`). F6d pending.
```

In the phases table, update the F6c row:

```
| F6c | — | Socket monitoring events. | Unit + integration. | **Complete** — tagged `phase-6c-monitoring-complete`. |
```

- [ ] **Step 6: Commit meta-overview**

```
git add docs/specs/00-meta-overview.md
git commit -m "docs(F6c): update meta-overview — F6c complete"
```

- [ ] **Step 7: Tag the phase**

```
git tag phase-6c-monitoring-complete
```

---

## File summary

| File | Action | Purpose |
|------|--------|---------|
| `event.go` | Create | `EventType` constants + `SocketEvent` struct |
| `event_test.go` | Create | Unit tests: iota values, emit nil-guard, emit drop, emit deliver |
| `options.go` | Modify | `monitorCh` field in `socketConfig`; `WithMonitor` option |
| `options_test.go` | Modify | `TestWithMonitorStoresChannel`, `TestWithMonitorNilIsNoop` |
| `base.go` | Modify | `emit()` helper; emission in `bind`, `acceptLoop`, `doServerHandshake`, `connect`, `close` |
| `pipe.go` | Modify | `onDisconnect func(addr string)` field; disconnect detection in `readLoop` |
| `monitor_test.go` | Create | Integration tests: Bind, BindFailed, Connect, ConnectFailed, HandshakeFailed, Disconnected, Close, DropsOnFull |
| `docs/specs/00-meta-overview.md` | Modify | Mark F6c complete; add tag |
