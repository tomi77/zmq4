package zmq4

import "testing"

func TestPollerAddErrNotSocket(t *testing.T) {
	p := NewPoller()
	if err := p.Add("not a socket", POLLIN); err != ErrNotSocket {
		t.Fatalf("want ErrNotSocket, got %v", err)
	}
}

func TestPollerAddErrInvalidEvents(t *testing.T) {
	p := NewPoller()
	pull := NewPULL()
	defer pull.Close()
	if err := p.Add(pull, 0); err != ErrInvalidEvents {
		t.Fatalf("want ErrInvalidEvents, got %v", err)
	}
}

func TestPollerAddErrAlreadyRegistered(t *testing.T) {
	p := NewPoller()
	pull := NewPULL()
	defer pull.Close()
	if err := p.Add(pull, POLLIN); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := p.Add(pull, POLLIN); err != ErrAlreadyRegistered {
		t.Fatalf("want ErrAlreadyRegistered, got %v", err)
	}
}

func TestPollerRemoveErrNotRegistered(t *testing.T) {
	p := NewPoller()
	pull := NewPULL()
	defer pull.Close()
	if err := p.Remove(pull); err != ErrNotRegistered {
		t.Fatalf("want ErrNotRegistered, got %v", err)
	}
}

func TestPollerUpdateErrNotRegistered(t *testing.T) {
	p := NewPoller()
	pull := NewPULL()
	defer pull.Close()
	if err := p.Update(pull, POLLIN); err != ErrNotRegistered {
		t.Fatalf("want ErrNotRegistered, got %v", err)
	}
}

func TestPollerUpdateErrInvalidEvents(t *testing.T) {
	p := NewPoller()
	pull := NewPULL()
	defer pull.Close()
	if err := p.Add(pull, POLLIN); err != nil {
		t.Fatal(err)
	}
	if err := p.Update(pull, 0); err != ErrInvalidEvents {
		t.Fatalf("want ErrInvalidEvents, got %v", err)
	}
}

func TestPollerRemoveRoundTrip(t *testing.T) {
	p := NewPoller()
	pull := NewPULL()
	defer pull.Close()
	if err := p.Add(pull, POLLIN); err != nil {
		t.Fatal(err)
	}
	if err := p.Remove(pull); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	// can re-add after remove
	if err := p.Add(pull, POLLOUT); err != nil {
		t.Fatalf("re-Add after Remove: %v", err)
	}
}

func TestPollerUpdateMask(t *testing.T) {
	p := NewPoller()
	push := NewPUSH()
	defer push.Close()
	if err := p.Add(push, POLLIN); err != nil {
		t.Fatal(err)
	}
	if err := p.Update(push, POLLOUT); err != nil {
		t.Fatalf("Update: %v", err)
	}
	// verify the mask was updated
	if p.items[0].events != POLLOUT {
		t.Fatalf("after Update: events = %v, want POLLOUT", p.items[0].events)
	}
}

func TestPollerPollZeroSocketsNoBlock(t *testing.T) {
	p := NewPoller()
	events, err := p.Poll(0)
	if err != nil {
		t.Fatalf("want nil err, got %v", err)
	}
	if events != nil {
		t.Fatalf("want nil events, got %v", events)
	}
}

func TestPollerPollInNonBlocking(t *testing.T) {
	p := NewPoller()
	pull := NewPULL()
	defer pull.Close()
	if err := p.Add(pull, POLLIN); err != nil {
		t.Fatal(err)
	}

	// Manually inject a message into the first pipe's inCh.
	// No peer needed — we poke the internal channel directly.
	testPipe := newPipe(nil, nil, 10, 10, Block)
	pull.base.pipes.add(testPipe)
	testPipe.inCh <- Message{[]byte("hello")}

	events, err := p.Poll(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Events != POLLIN {
		t.Fatalf("want POLLIN, got %v", events[0].Events)
	}
	if events[0].Socket != pull {
		t.Fatal("wrong socket in event")
	}
}

func TestPollerPollOutNonBlocking(t *testing.T) {
	p := NewPoller()
	push := NewPUSH()
	defer push.Close()
	if err := p.Add(push, POLLOUT); err != nil {
		t.Fatal(err)
	}

	// Pipe with capacity 5, nothing queued → POLLOUT ready.
	testPipe := newPipe(nil, nil, 5, 10, Block)
	push.base.pipes.add(testPipe)

	events, err := p.Poll(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 || events[0].Events != POLLOUT {
		t.Fatalf("want POLLOUT event, got %v", events)
	}
}

func TestPollerPollOutFullQueueNoEvent(t *testing.T) {
	p := NewPoller()
	push := NewPUSH()
	defer push.Close()
	if err := p.Add(push, POLLOUT); err != nil {
		t.Fatal(err)
	}

	// Pipe with capacity 2, both slots filled → not POLLOUT-ready.
	testPipe := newPipe(nil, nil, 2, 10, Block)
	push.base.pipes.add(testPipe)
	testPipe.outCh <- Message{[]byte("a")}
	testPipe.outCh <- Message{[]byte("b")}

	events, err := p.Poll(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("want no events (outCh full), got %v", events)
	}
}

func TestPollerPollNoPeersNoBlock(t *testing.T) {
	p := NewPoller()
	pull := NewPULL()
	defer pull.Close()
	if err := p.Add(pull, POLLIN); err != nil {
		t.Fatal(err)
	}
	// No peers — Phase 1 finds nothing; timeout=0 returns nil immediately.
	events, err := p.Poll(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if events != nil {
		t.Fatalf("want nil, got %v", events)
	}
}
