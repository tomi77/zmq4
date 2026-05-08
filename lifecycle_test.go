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
