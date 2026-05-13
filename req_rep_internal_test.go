package zmq4

import (
	"context"
	"strings"
	"testing"
)

// TestREQREPRoundTripAllocsLeq2 verifies that a full inproc REQ/REP round-trip
// uses ≤2 heap allocations after the inproc fast-path optimization (C).
// The budget breaks down as:
//
//	1 × buildInprocMsg in writeLoop (REQ→REP direction) = 1
//	1 × buildInprocMsg in writeLoop (REP→REQ direction) = 1
//
// The inproc fast path bypasses ZMTP wire serialization entirely: no
// ReadFrame body allocations, no readLoop Message-slice makes, no
// net.Buffers header escapes. Grand total: 2.
func TestREQREPRoundTripAllocsLeq2(t *testing.T) {
	ctx := context.Background()
	ep := "inproc://TestREQREPRoundTripAllocsLeq2_" + strings.ReplaceAll(t.Name(), "/", "_")
	rep := NewREP()
	req := NewREQ()
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	if err := req.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close(); req.Close() })

	msg := Message{[]byte("hello")}
	reply := Message{[]byte("world")}

	for range 20 {
		req.Send(ctx, msg)   //nolint:errcheck
		rep.Recv(ctx)        //nolint:errcheck
		rep.Send(ctx, reply) //nolint:errcheck
		req.Recv(ctx)        //nolint:errcheck
	}

	got := testing.AllocsPerRun(200, func() {
		req.Send(ctx, msg)   //nolint:errcheck
		rep.Recv(ctx)        //nolint:errcheck
		rep.Send(ctx, reply) //nolint:errcheck
		req.Recv(ctx)        //nolint:errcheck
	})
	if got > 2 {
		t.Fatalf("REQ/REP inproc round-trip: %.0f allocs/op, want ≤2", got)
	}
}

// TestREQSendAllocsZero verifies that REQ.Send does not allocate a Message
// slice to prepend the empty delimiter frame — the key hot path on every request.
func TestREQSendAllocsZero(t *testing.T) {
	s := NewREQ()
	p := newPipe(nil, nil, 10000, 1, Drop)
	s.base.pipes.add(p)

	msg := Message{[]byte("hello")}
	ctx := context.Background()

	got := testing.AllocsPerRun(100, func() {
		s.mu.Lock()
		s.sent = false
		s.mu.Unlock()
		_ = s.Send(ctx, msg)
	})
	if got > 0 {
		t.Fatalf("REQ.Send: %.0f allocs/op, want 0", got)
	}
}

// TestREPSendAllocsZero verifies that REP.Send does not allocate a Message
// slice to prepend the routing envelope — the key hot path on every reply.
func TestREPSendAllocsZero(t *testing.T) {
	s := NewREP()
	p := newPipe(nil, nil, 10000, 1, Drop)
	s.base.pipes.add(p)

	env := [][]byte{nil} // minimal routing envelope: one empty delimiter
	msg := Message{[]byte("hello")}

	got := testing.AllocsPerRun(100, func() {
		s.mu.Lock()
		s.recv = true
		s.envPipe = p
		s.envelope = env
		s.mu.Unlock()
		_ = s.Send(context.Background(), msg)
	})
	if got > 0 {
		t.Fatalf("REP.Send: %.0f allocs/op, want 0", got)
	}
}
