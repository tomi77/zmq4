package zmq4

import (
	"context"
	"testing"
)

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
