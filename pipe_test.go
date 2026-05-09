package zmq4

import (
	"net"
	"testing"
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
