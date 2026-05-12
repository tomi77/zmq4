package zmq4_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
)

// pollCtx returns a 3-second context with automatic cancel on test end.
func pollCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// pollEP returns a unique inproc endpoint derived from the test name.
func pollEP(t *testing.T, suffix string) string {
	t.Helper()
	return "inproc://poller-" + t.Name() + suffix
}

func TestPollerPollINBlocking(t *testing.T) {
	ctx := pollCtx(t)
	ep := pollEP(t, "")

	pull := zmq4.NewPULL(zmq4.WithNULL())
	push := zmq4.NewPUSH(zmq4.WithNULL())
	defer pull.Close()
	defer push.Close()

	if err := pull.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	if err := push.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}

	p := zmq4.NewPoller()
	if err := p.Add(pull, zmq4.POLLIN); err != nil {
		t.Fatal(err)
	}

	sendErr := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		sendErr <- push.Send(ctx, zmq4.Message{[]byte("hello")})
	}()

	events, err := p.Poll(-1)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Events != zmq4.POLLIN {
		t.Fatalf("want POLLIN, got %v", events[0].Events)
	}
	if events[0].Socket != pull {
		t.Fatal("wrong socket in event")
	}

	if err := <-sendErr; err != nil {
		t.Errorf("Send: %v", err)
	}
}

func TestPollerPollTimeout(t *testing.T) {
	p := zmq4.NewPoller()
	pull := zmq4.NewPULL(zmq4.WithNULL())
	defer pull.Close()
	if err := p.Add(pull, zmq4.POLLIN); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	events, err := p.Poll(50 * time.Millisecond)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("want nil error on timeout, got %v", err)
	}
	if events != nil {
		t.Fatalf("want nil events on timeout, got %v", events)
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("Poll returned too early: %v", elapsed)
	}
}

func TestPollerPollClosedSocket(t *testing.T) {
	p := zmq4.NewPoller()
	pull := zmq4.NewPULL(zmq4.WithNULL())
	defer pull.Close()
	if err := p.Add(pull, zmq4.POLLIN); err != nil {
		t.Fatal(err)
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		pull.Close()
	}()

	_, err := p.Poll(-1)
	if err != zmq4.ErrClosed {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestPollerMultipleSocketsAllReady(t *testing.T) {
	ctx := pollCtx(t)
	ep1 := pollEP(t, "-1")
	ep2 := pollEP(t, "-2")

	pull1 := zmq4.NewPULL(zmq4.WithNULL())
	pull2 := zmq4.NewPULL(zmq4.WithNULL())
	push1 := zmq4.NewPUSH(zmq4.WithNULL())
	push2 := zmq4.NewPUSH(zmq4.WithNULL())
	defer pull1.Close()
	defer pull2.Close()
	defer push1.Close()
	defer push2.Close()

	if err := pull1.Bind(ctx, ep1); err != nil {
		t.Fatal(err)
	}
	if err := pull2.Bind(ctx, ep2); err != nil {
		t.Fatal(err)
	}
	if err := push1.Connect(ctx, ep1); err != nil {
		t.Fatal(err)
	}
	if err := push2.Connect(ctx, ep2); err != nil {
		t.Fatal(err)
	}

	p := zmq4.NewPoller()
	if err := p.Add(pull1, zmq4.POLLIN); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(pull2, zmq4.POLLIN); err != nil {
		t.Fatal(err)
	}

	// Send to both — then give time to deliver before polling.
	if err := push1.Send(ctx, zmq4.Message{[]byte("a")}); err != nil {
		t.Fatal(err)
	}
	if err := push2.Send(ctx, zmq4.Message{[]byte("b")}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	events, err := p.Poll(0) // non-blocking — both should already be ready
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events (both ready), got %d: %v", len(events), events)
	}
}

func TestPollerPollOUTReadyWithPeer(t *testing.T) {
	ctx := pollCtx(t)
	ep := pollEP(t, "")

	// Verifies that POLLOUT fires when a peer is connected and outCh has capacity.
	// SndHWM=1 so outCh capacity is 1; after the priming round-trip the outCh is drained.
	push := zmq4.NewPUSH(zmq4.WithNULL(), zmq4.WithSndHWM(1))
	pull := zmq4.NewPULL(zmq4.WithNULL())
	defer push.Close()
	defer pull.Close()

	if err := push.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	if err := pull.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}

	// Prime the connection: send and receive one message so the pipe is established
	// and outCh is drained before polling.
	if err := push.Send(ctx, zmq4.Message{[]byte("prime")}); err != nil {
		t.Fatal(err)
	}
	if _, err := pull.Recv(ctx); err != nil {
		t.Fatal(err)
	}

	// outCh has space (capacity 1, nothing queued); Poll should return POLLOUT immediately.
	// We can't reliably force outCh to be full without controlling writeLoop timing,
	// so we only verify the ready path here.

	// Poll with a short timeout; outCh is drained so POLLOUT should be immediate.
	// Instead, test the POLLOUT semantics: if space is available, Poll(0) returns POLLOUT.
	p := zmq4.NewPoller()
	if err := p.Add(push, zmq4.POLLOUT); err != nil {
		t.Fatal(err)
	}
	events, err := p.Poll(100 * time.Millisecond)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("want POLLOUT event, got none — push socket should have send space")
	}
	if events[0].Events&zmq4.POLLOUT == 0 {
		t.Fatalf("want POLLOUT bit set, got %v", events[0].Events)
	}
}

func TestPollerPollINNoPeersBlocksUntilPeer(t *testing.T) {
	ctx := pollCtx(t)
	ep := pollEP(t, "")

	pull := zmq4.NewPULL(zmq4.WithNULL())
	defer pull.Close()
	if err := pull.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}

	p := zmq4.NewPoller()
	if err := p.Add(pull, zmq4.POLLIN); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var pollEvents []zmq4.Event
	var pollErr error
	wg.Go(func() {
		pollEvents, pollErr = p.Poll(-1)
	})

	time.Sleep(30 * time.Millisecond)
	// Now connect and send — this triggers currentAdded() wakeup + inReady signal.
	push := zmq4.NewPUSH(zmq4.WithNULL())
	defer push.Close()
	if err := push.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // allow handshake
	if err := push.Send(ctx, zmq4.Message{[]byte("wakeup")}); err != nil {
		t.Fatal(err)
	}

	wg.Wait()
	if pollErr != nil {
		t.Fatalf("Poll: %v", pollErr)
	}
	if len(pollEvents) == 0 || pollEvents[0].Events&zmq4.POLLIN == 0 {
		t.Fatalf("want POLLIN event, got %v", pollEvents)
	}
}

func TestPollerMixedMask(t *testing.T) {
	ctx := pollCtx(t)
	ep := pollEP(t, "")

	push := zmq4.NewPUSH(zmq4.WithNULL())
	pull := zmq4.NewPULL(zmq4.WithNULL())
	defer push.Close()
	defer pull.Close()

	if err := push.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	if err := pull.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}

	// Send a message so PULL has data to receive.
	if err := push.Send(ctx, zmq4.Message{[]byte("msg")}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond) // allow delivery

	p := zmq4.NewPoller()
	// Register PULL with POLLIN|POLLOUT — POLLIN should fire (message waiting).
	// POLLOUT on PULL is unusual but structurally valid (outCh has space).
	if err := p.Add(pull, zmq4.POLLIN|zmq4.POLLOUT); err != nil {
		t.Fatal(err)
	}

	events, err := p.Poll(0)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Events&zmq4.POLLIN == 0 {
		t.Fatalf("want POLLIN bit set, got %v", events[0].Events)
	}
}
