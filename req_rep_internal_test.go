package zmq4

import (
	"context"
	"strings"
	"testing"
)

// TestREQREPRoundTripAllocsLeq8 verifies that a full inproc REQ/REP round-trip
// uses ≤8 heap allocations. The budget breaks down as:
//
//	2 × (ReadFrame body per frame × 2 frames) = 4  (wire layer, unavoidable)
//	2 × 1 Message-slice make per receive       = 4  (readLoop, after pre-sizing)
//
// The nil-start readLoop (current baseline) allocates 2 Message slices per
// 2-frame receive (one for each append growth), giving 2×2+4 = 8 → 10 total.
// Pre-sizing with make(Message,0,2) drops that to 2×1+4 = 6 → 8 total.
func TestREQREPRoundTripAllocsLeq8(t *testing.T) {
	ctx := context.Background()
	ep := "inproc://TestREQREPRoundTripAllocsLeq8_" + strings.ReplaceAll(t.Name(), "/", "_")
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
	if got > 8 {
		t.Fatalf("REQ/REP inproc round-trip: %.0f allocs/op, want ≤8", got)
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
