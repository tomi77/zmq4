package zmq4

import (
	"testing"
	"time"
)

func TestEventTypeValues(t *testing.T) {
	if EventListening != 1 {
		t.Fatalf("EventListening = %d, want 1", EventListening)
	}
	if EventMonitorStopped != 11 {
		t.Fatalf("EventMonitorStopped = %d, want 11", EventMonitorStopped)
	}
}

func TestEmitNoopWhenNil(t *testing.T) {
	sb := newSocketBase(newSocketConfig(nil))
	// must not panic
	sb.emit(SocketEvent{Type: EventListening, Endpoint: "x"})
}

func TestEmitDeliversWhenSpace(t *testing.T) {
	ch := make(chan SocketEvent, 1)
	sb := newSocketBase(newSocketConfig([]Option{WithMonitor(ch)}))
	sb.emit(SocketEvent{Type: EventListening, Endpoint: "tcp://x"})
	ev := <-ch
	if ev.Type != EventListening {
		t.Fatalf("got Type=%v, want EventListening", ev.Type)
	}
	if ev.Endpoint != "tcp://x" {
		t.Fatalf("got Endpoint=%q, want %q", ev.Endpoint, "tcp://x")
	}
}

func TestEmitDropsWhenFull(t *testing.T) {
	ch := make(chan SocketEvent) // unbuffered — non-blocking send always fails
	sb := newSocketBase(newSocketConfig([]Option{WithMonitor(ch)}))

	done := make(chan struct{})
	go func() {
		sb.emit(SocketEvent{Type: EventListening, Endpoint: "x"})
		close(done)
	}()

	select {
	case <-done:
		// good — emit returned without blocking
	case <-time.After(10 * time.Millisecond):
		t.Fatal("emit blocked on full channel")
	}
}
