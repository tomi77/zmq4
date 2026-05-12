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
