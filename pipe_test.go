package zmq4

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPipeSetAddRemove(t *testing.T) {
	ps := newPipeSet()
	if ps.len() != 0 {
		t.Fatalf("want 0 pipes, got %d", ps.len())
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	p := newPipe(nil, nil, 1000, 1000, Block) // conn can be nil for structural tests
	ps.add(p)
	if ps.len() != 1 {
		t.Fatalf("after add: want 1, got %d", ps.len())
	}
	ps.remove(p)
	if ps.len() != 0 {
		t.Fatalf("after remove: want 0, got %d", ps.len())
	}
	_ = c2
}

func TestPipeSetNext(t *testing.T) {
	ps := newPipeSet()
	if got := ps.next(); got != nil {
		t.Fatalf("next on empty: got %v, want nil", got)
	}
	p1 := newPipe(nil, nil, 1000, 1000, Block)
	p2 := newPipe(nil, nil, 1000, 1000, Block)
	ps.add(p1)
	ps.add(p2)
	// Two calls must each return a non-nil pipe (round-robin)
	a := ps.next()
	b := ps.next()
	if a == nil {
		t.Fatal("next: got nil on non-empty pipeSet")
	}
	if b == nil {
		t.Fatal("next (2nd): got nil on non-empty pipeSet")
	}
	if a == b {
		t.Fatal("next: expected round-robin to return different pipes")
	}
}

func TestPipeSetByIdentity(t *testing.T) {
	ps := newPipeSet()
	id := []byte("abc")
	p := newPipe(nil, id, 1000, 1000, Block)
	ps.add(p)

	got := ps.byIdentity(id)
	if got != p {
		t.Fatalf("byIdentity: got %v, want %v", got, p)
	}
	if ps.byIdentity([]byte("zzz")) != nil {
		t.Fatal("byIdentity unknown: expected nil")
	}
}

func TestPipeSetAddedNotification(t *testing.T) {
	ps := newPipeSet()
	added := ps.currentAdded()

	// adding a pipe must close the channel
	p := newPipe(nil, nil, 1000, 1000, Block)
	ps.add(p)

	select {
	case <-added:
		// OK — channel was closed
	default:
		t.Fatal("added channel not closed after add")
	}
}

func TestPipeRcvHWMCapacity(t *testing.T) {
	p := newPipe(nil, nil, 1000, 7, Block)
	if cap(p.inCh) != 7 {
		t.Fatalf("inCh capacity: got %d, want 7", cap(p.inCh))
	}
}

func TestPipeSndHWMCapacity(t *testing.T) {
	p := newPipe(nil, nil, 13, 1000, Block)
	if cap(p.outCh) != 13 {
		t.Fatalf("outCh capacity: got %d, want 13", cap(p.outCh))
	}
}

func TestPipeSendBlock(t *testing.T) {
	// outCh capacity 1; second send blocks until first is drained.
	closeCh := make(chan struct{})
	defer close(closeCh)

	p := newPipe(nil, nil, 1, 1000, Block)
	p.outCh <- Message{[]byte("first")} // fill the queue manually

	sent := make(chan bool, 1)
	go func() {
		sent <- p.send(Message{[]byte("second")}, closeCh)
	}()

	select {
	case <-sent:
		t.Fatal("send should have blocked")
	case <-time.After(20 * time.Millisecond):
		// correct: still blocking
	}

	// Drain the queue — unblocks the goroutine.
	<-p.outCh
	select {
	case ok := <-sent:
		if !ok {
			t.Fatal("send returned false, want true")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("send did not unblock after drain")
	}
}

func TestPipeSendDrop(t *testing.T) {
	closeCh := make(chan struct{})
	defer close(closeCh)

	p := newPipe(nil, nil, 1, 1000, Drop)
	p.outCh <- Message{[]byte("first")} // fill the queue

	ok := p.send(Message{[]byte("second")}, closeCh)
	if ok {
		t.Fatal("send with Drop policy on full queue should return false")
	}
	if len(p.outCh) != 1 {
		t.Fatalf("outCh len: got %d, want 1 (original message still there)", len(p.outCh))
	}
}

func TestPipeSendClosedSocket(t *testing.T) {
	closeCh := make(chan struct{})
	close(closeCh) // already closed

	p := newPipe(nil, nil, 1, 1000, Block)
	p.outCh <- Message{[]byte("fill")} // fill so Block would normally block

	ok := p.send(Message{[]byte("msg")}, closeCh)
	if ok {
		t.Fatal("send to closed socket should return false")
	}
}

func TestPipeSetByIdentityReturnsNilAfterRemove(t *testing.T) {
	ps := newPipeSet()
	id := []byte("gone")
	p := newPipe(nil, id, 1000, 1000, Block)
	ps.add(p)
	ps.remove(p)
	if got := ps.byIdentity(id); got != nil {
		t.Fatalf("byIdentity after remove: got %v, want nil", got)
	}
}

// TestPipeSetByIdentityAllocsAtMostOne verifies that byIdentity performs at
// most one heap allocation regardless of how many pipes are registered.
// With an O(N) linear scan this may exceed 1 if string conversions are not
// optimised away by the compiler; a map-based implementation is O(1) by design.
func TestPipeSetByIdentityAllocsAtMostOne(t *testing.T) {
	ps := newPipeSet()
	const n = 100
	for i := range n {
		id := []byte{byte(i >> 8), byte(i)}
		ps.add(newPipe(nil, id, 1000, 1000, Block))
	}
	target := []byte{0, byte(n - 1)}
	got := testing.AllocsPerRun(100, func() {
		_ = ps.byIdentity(target)
	})
	if got > 1 {
		t.Fatalf("byIdentity with %d pipes: %.0f allocs/op, want ≤1", n, got)
	}
}

func TestPipeReadyChannels(t *testing.T) {
	p := newPipe(nil, nil, 1000, 1000, Block)
	if cap(p.inReady) != 1 {
		t.Fatalf("inReady cap: got %d, want 1", cap(p.inReady))
	}
	if cap(p.outReady) != 1 {
		t.Fatalf("outReady cap: got %d, want 1", cap(p.outReady))
	}
}

func TestPipeSetSinglePipe(t *testing.T) {
	ps := newPipeSet()

	if got := ps.singlePipe(); got != nil {
		t.Fatalf("empty pipeSet: singlePipe() = %v, want nil", got)
	}

	p1 := newPipe(nil, nil, 1000, 1000, Block)
	ps.add(p1)
	if got := ps.singlePipe(); got != p1 {
		t.Fatalf("one-pipe pipeSet: singlePipe() = %v, want p1", got)
	}

	p2 := newPipe(nil, nil, 1000, 1000, Block)
	ps.add(p2)
	if got := ps.singlePipe(); got != nil {
		t.Fatalf("two-pipe pipeSet: singlePipe() = %v, want nil", got)
	}
}

func TestPipeSetTwoPipes(t *testing.T) {
	ps := newPipeSet()

	if p1, p2 := ps.twoPipes(); p1 != nil || p2 != nil {
		t.Fatalf("empty pipeSet: twoPipes() = %v, %v, want nil, nil", p1, p2)
	}

	pa := newPipe(nil, nil, 1000, 1000, Block)
	ps.add(pa)
	if p1, p2 := ps.twoPipes(); p1 != nil || p2 != nil {
		t.Fatalf("one-pipe pipeSet: twoPipes() = %v, %v, want nil, nil", p1, p2)
	}

	pb := newPipe(nil, nil, 1000, 1000, Block)
	ps.add(pb)
	if p1, p2 := ps.twoPipes(); p1 != pa || p2 != pb {
		t.Fatalf("two-pipe pipeSet: twoPipes() = %v, %v, want pa, pb", p1, p2)
	}

	pc := newPipe(nil, nil, 1000, 1000, Block)
	ps.add(pc)
	if p1, p2 := ps.twoPipes(); p1 != nil || p2 != nil {
		t.Fatalf("three-pipe pipeSet: twoPipes() = %v, %v, want nil, nil", p1, p2)
	}
}

// TestRecvAnyTwoPipesAllocsZero verifies that recvAny with exactly 2 connected
// pipes makes zero heap allocations — no reflect.SelectCase slice and no
// snapshot allocation.
func TestRecvAnyTwoPipesAllocsZero(t *testing.T) {
	sb := newSocketBase(newSocketConfig(nil))

	p1 := newPipe(nil, []byte("p1"), 0, 1000, Block)
	p2 := newPipe(nil, []byte("p2"), 0, 1000, Block)
	sb.pipes.add(p1)
	sb.pipes.add(p2)

	msg := Message{[]byte("hello")}
	for range 1000 {
		p1.inCh <- msg
		p2.inCh <- msg
	}

	ctx := context.Background()
	got := testing.AllocsPerRun(100, func() {
		_, _, _ = sb.recvAny(ctx)
	})
	if got > 0 {
		t.Fatalf("recvAny with 2 pipes: %.0f allocs/op, want 0", got)
	}
}
