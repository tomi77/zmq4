package zmq4_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
)

func TestCloseUnblocksRecv(t *testing.T) {
	dealer := zmq4.NewDEALER()
	ctx := context.Background()

	var wg sync.WaitGroup
	var recvErr error
	wg.Go(func() {
		_, recvErr = dealer.Recv(ctx)
	})

	time.Sleep(10 * time.Millisecond) // let goroutine block
	dealer.Close()
	wg.Wait()
	if !errors.Is(recvErr, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", recvErr)
	}
}

func TestCloseUnblocksSend(t *testing.T) {
	dealer := zmq4.NewDEALER() // no pipes
	ctx := context.Background()

	var wg sync.WaitGroup
	var sendErr error
	wg.Go(func() {
		sendErr = dealer.Send(ctx, zmq4.Message{[]byte("x")})
	})

	time.Sleep(10 * time.Millisecond)
	dealer.Close()
	wg.Wait()
	if !errors.Is(sendErr, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", sendErr)
	}
}

func TestCloseIdempotent(t *testing.T) {
	req := zmq4.NewREQ()
	if err := req.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := req.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestBindAcceptsMultiplePeers(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)
	const N = 5

	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })

	reqs := make([]*zmq4.REQ, N)
	for i := range reqs {
		reqs[i] = zmq4.NewREQ()
		if err := reqs[i].Connect(ctx, ep); err != nil {
			t.Fatalf("Connect[%d]: %v", i, err)
		}
		t.Cleanup(func() { reqs[i].Close() })
	}

	// Each REQ sends one message concurrently; REP services all N.
	for i := range N {
		go reqs[i].Send(ctx, zmq4.Message{[]byte{byte(i)}})
	}
	for range N {
		msg, err := rep.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if err := rep.Send(ctx, msg); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
}

func TestIncompatiblePeerRejected(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	// Bind a REP socket (compatible with REQ/DEALER).
	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })

	// Connect a REP to a REP — REP only allows REQ/DEALER peers.
	rep2 := zmq4.NewREP()
	err := rep2.Connect(ctx, ep)
	t.Cleanup(func() { rep2.Close() })
	if !errors.Is(err, zmq4.ErrIncompatiblePeer) {
		t.Fatalf("want ErrIncompatiblePeer for REP→REP, got %v", err)
	}
}

func TestPUBCloseUnblocksSend(t *testing.T) {
	pub := zmq4.NewPUB()
	pub.Close()
	err := pub.Send(context.Background(), zmq4.Message{[]byte("x")})
	if !errors.Is(err, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestSUBSubscribeAfterClose(t *testing.T) {
	sub := zmq4.NewSUB()
	sub.Close()
	err := sub.Subscribe("x")
	if !errors.Is(err, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestXPUBCloseUnblocksRecv(t *testing.T) {
	xpub := zmq4.NewXPUB()
	ctx := context.Background()

	var wg sync.WaitGroup
	var recvErr error
	wg.Go(func() {
		_, recvErr = xpub.Recv(ctx)
	})

	time.Sleep(10 * time.Millisecond)
	xpub.Close()
	wg.Wait()
	if !errors.Is(recvErr, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", recvErr)
	}
}

func TestIncompatiblePeerPUBtoREP(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

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
