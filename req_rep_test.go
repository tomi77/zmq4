package zmq4_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
)

func inprocEP(t *testing.T) string {
	t.Helper()
	return "inproc://" + strings.ReplaceAll(t.Name(), "/", "_")
}

func newCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestREQREPRoundTrip(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)

	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { rep.Close() })

	req := zmq4.NewREQ()
	if err := req.Connect(ctx, ep); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { req.Close() })

	payload := zmq4.Message{[]byte("hello")}
	if err := req.Send(ctx, payload); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := rep.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(got[0]) != "hello" {
		t.Fatalf("want hello, got %q", got[0])
	}
	if err := rep.Send(ctx, zmq4.Message{[]byte("world")}); err != nil {
		t.Fatalf("Send reply: %v", err)
	}
	reply, err := req.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv reply: %v", err)
	}
	if string(reply[0]) != "world" {
		t.Fatalf("want world, got %q", reply[0])
	}
}

func TestREQREPMultiRoundTrips(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)
	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })

	req := zmq4.NewREQ()
	if err := req.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { req.Close() })

	for i := range 10 {
		send := zmq4.Message{[]byte{byte(i)}}
		if err := req.Send(ctx, send); err != nil {
			t.Fatalf("round %d Send: %v", i, err)
		}
		got, err := rep.Recv(ctx)
		if err != nil {
			t.Fatalf("round %d Recv: %v", i, err)
		}
		if got[0][0] != byte(i) {
			t.Fatalf("round %d: want %d, got %d", i, i, got[0][0])
		}
		if err := rep.Send(ctx, got); err != nil {
			t.Fatalf("round %d Send reply: %v", i, err)
		}
		reply, err := req.Recv(ctx)
		if err != nil {
			t.Fatalf("round %d Recv reply: %v", i, err)
		}
		if reply[0][0] != byte(i) {
			t.Fatalf("round %d reply: want %d, got %d", i, i, reply[0][0])
		}
	}
}

func TestREQREPMultipartPayload(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)
	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })
	req := zmq4.NewREQ()
	if err := req.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { req.Close() })

	msg := zmq4.Message{[]byte("a"), []byte("b"), []byte("c")}
	if err := req.Send(ctx, msg); err != nil {
		t.Fatal(err)
	}
	got, err := rep.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 parts, got %d: %v", len(got), got)
	}
	for i, want := range []string{"a", "b", "c"} {
		if string(got[i]) != want {
			t.Fatalf("part %d: want %q, got %q", i, want, got[i])
		}
	}
}

func TestREQDoubleState(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)
	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })
	req := zmq4.NewREQ()
	if err := req.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { req.Close() })

	if err := req.Send(ctx, zmq4.Message{[]byte("x")}); err != nil {
		t.Fatal(err)
	}
	err := req.Send(ctx, zmq4.Message{[]byte("y")})
	if !errors.Is(err, zmq4.ErrState) {
		t.Fatalf("want ErrState, got %v", err)
	}
}

func TestREQRecvBeforeSend(t *testing.T) {
	req := zmq4.NewREQ()
	t.Cleanup(func() { req.Close() })
	ctx := newCtx(t)
	_, err := req.Recv(ctx)
	if !errors.Is(err, zmq4.ErrState) {
		t.Fatalf("want ErrState, got %v", err)
	}
}

func TestREPDoubleState(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)
	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })
	req := zmq4.NewREQ()
	if err := req.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { req.Close() })

	if err := req.Send(ctx, zmq4.Message{[]byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := rep.Recv(ctx); err != nil {
		t.Fatal(err)
	}
	_, err := rep.Recv(ctx)
	if !errors.Is(err, zmq4.ErrState) {
		t.Fatalf("want ErrState, got %v", err)
	}
}

func TestREPSendBeforeRecv(t *testing.T) {
	rep := zmq4.NewREP()
	t.Cleanup(func() { rep.Close() })
	ctx := newCtx(t)
	err := rep.Send(ctx, zmq4.Message{[]byte("x")})
	if !errors.Is(err, zmq4.ErrState) {
		t.Fatalf("want ErrState, got %v", err)
	}
}

func TestREQCtxCancelSend(t *testing.T) {
	req := zmq4.NewREQ() // no pipes connected
	t.Cleanup(func() { req.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	err := req.Send(ctx, zmq4.Message{[]byte("x")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestREPFairQueue(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)
	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })

	const N = 3
	seen := make(map[int]int)
	reqs := make([]*zmq4.REQ, N)
	for i := range reqs {
		reqs[i] = zmq4.NewREQ()
		if err := reqs[i].Connect(ctx, ep); err != nil {
			t.Fatalf("Connect[%d]: %v", i, err)
		}
		t.Cleanup(func() { reqs[i].Close() })
		go func(idx int) {
			reqs[idx].Send(context.Background(), zmq4.Message{[]byte{byte(idx)}})
		}(i)
	}

	for range N {
		msg, err := rep.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		seen[int(msg[0][0])]++
		if err := rep.Send(ctx, msg); err != nil {
			t.Fatalf("Send echo: %v", err)
		}
	}
	for i := range N {
		if seen[i] != 1 {
			t.Fatalf("peer %d: expected 1 message, got %d", i, seen[i])
		}
	}
}

func TestREPNoDelimiterFromDEALER(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)
	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })

	dealer := zmq4.NewDEALER()
	if err := dealer.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dealer.Close() })

	want := zmq4.Message{[]byte("x"), []byte("y")}
	if err := dealer.Send(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := rep.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got[0]) != "x" || string(got[1]) != "y" {
		t.Fatalf("want [x y], got %v", got)
	}
	if err := rep.Send(ctx, zmq4.Message{[]byte("ok")}); err != nil {
		t.Fatal(err)
	}
	reply, err := dealer.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply[0]) != "ok" {
		t.Fatalf("want ok, got %q", reply[0])
	}
}
