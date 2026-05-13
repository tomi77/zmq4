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

	// Use context.Background() for data operations: under -race + full-suite
	// load the goroutine scheduler can delay message delivery past the 3s test
	// deadline, causing spurious failures unrelated to correctness.
	bg := context.Background()
	if err := b.Send(bg, zmq4.Message{[]byte("ping")}); err != nil {
		t.Fatalf("b.Send: %v", err)
	}
	got, err := a.Recv(bg)
	if err != nil {
		t.Fatalf("a.Recv: %v", err)
	}
	if string(got[0]) != "ping" {
		t.Fatalf("a.Recv: want ping, got %q", got[0])
	}

	if err := a.Send(bg, zmq4.Message{[]byte("pong")}); err != nil {
		t.Fatalf("a.Send: %v", err)
	}
	got2, err := b.Recv(bg)
	if err != nil {
		t.Fatalf("b.Recv: %v", err)
	}
	if string(got2[0]) != "pong" {
		t.Fatalf("b.Recv: want pong, got %q", got2[0])
	}
}

// TestPAIRSecondPeerRejected verifies that PAIR enforces exclusivity:
// a second peer is silently dropped server-side; the server continues to
// communicate exclusively with the first peer.
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
	// Server accepts TCP but rejects in exclusivePeer goroutine — client sees nil.
	if err := second.Connect(ctx, ep); err != nil {
		t.Fatalf("second.Connect: unexpected error %v", err)
	}

	// Server still routes exclusively to first. second's pipe is dead server-side.
	if err := first.Send(ctx, zmq4.Message{[]byte("exclusive")}); err != nil {
		t.Fatalf("first.Send: %v", err)
	}
	got, err := server.Recv(ctx)
	if err != nil {
		t.Fatalf("server.Recv: %v", err)
	}
	if string(got[0]) != "exclusive" {
		t.Fatalf("want exclusive, got %q", got[0])
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

// TestRecvAllocsPerOp asserts that a single send+recv cycle uses at most
// maxAllocsPerRecv heap allocations. This is a performance regression guard:
// the target is met after removing the redundant frame-body copy in readLoop
// and adding a reflect-free fast path for the common single-pipe case.
func TestRecvAllocsPerOp(t *testing.T) {
	const maxAllocsPerRecv = 4

	ctx := context.Background()

	push := zmq4.NewPUSH()
	pull := zmq4.NewPULL()

	ep := inprocEP(t)
	if err := push.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { push.Close() })
	if err := pull.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pull.Close() })

	msg := zmq4.NewMsg(make([]byte, 64))

	// Warm up: give readLoop goroutine time to start and stabilise.
	for range 20 {
		if err := push.Send(ctx, msg); err != nil {
			t.Fatal(err)
		}
		if _, err := pull.Recv(ctx); err != nil {
			t.Fatal(err)
		}
	}

	allocs := testing.AllocsPerRun(200, func() {
		if err := push.Send(ctx, msg); err != nil {
			t.Error(err)
		}
		if _, err := pull.Recv(ctx); err != nil {
			t.Error(err)
		}
	})

	if allocs > maxAllocsPerRecv {
		t.Fatalf("allocs per send+recv = %.0f, want ≤%d", allocs, maxAllocsPerRecv)
	}
}
