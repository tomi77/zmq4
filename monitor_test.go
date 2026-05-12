package zmq4_test

import (
	"context"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
	"github.com/tomi77/zmq4/internal/security/plain"
)

// drainN reads exactly n events from ch within timeout, failing the test on
// timeout.
func drainN(t *testing.T, ch <-chan zmq4.SocketEvent, n int, timeout time.Duration) []zmq4.SocketEvent {
	t.Helper()
	evs := make([]zmq4.SocketEvent, 0, n)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for len(evs) < n {
		select {
		case ev := <-ch:
			evs = append(evs, ev)
		case <-deadline.C:
			t.Fatalf("drainN: timeout after %v waiting for event %d/%d (got: %v)",
				timeout, len(evs)+1, n, evs)
		}
	}
	return evs
}

func TestMonitorBind(t *testing.T) {
	ch := make(chan zmq4.SocketEvent, 4)
	s := zmq4.NewPUSH(zmq4.WithNULL(), zmq4.WithMonitor(ch))
	defer s.Close()

	if err := s.Bind(context.Background(), "inproc://monitor-bind-test"); err != nil {
		t.Fatal(err)
	}

	evs := drainN(t, ch, 1, 100*time.Millisecond)
	if evs[0].Type != zmq4.EventListening {
		t.Fatalf("got %v, want EventListening", evs[0].Type)
	}
	if evs[0].Endpoint != "inproc://monitor-bind-test" {
		t.Fatalf("endpoint = %q, want %q", evs[0].Endpoint, "inproc://monitor-bind-test")
	}
	if evs[0].Err != nil {
		t.Fatalf("unexpected Err: %v", evs[0].Err)
	}
}

func TestMonitorBindFailed(t *testing.T) {
	ch := make(chan zmq4.SocketEvent, 4)
	s := zmq4.NewPUSH(zmq4.WithNULL(), zmq4.WithMonitor(ch))
	defer s.Close()

	// invalid endpoint — transport.Listen will fail
	_ = s.Bind(context.Background(), "tcp://256.256.256.256:99999")

	evs := drainN(t, ch, 1, 100*time.Millisecond)
	if evs[0].Type != zmq4.EventBindFailed {
		t.Fatalf("got %v, want EventBindFailed", evs[0].Type)
	}
	if evs[0].Err == nil {
		t.Fatal("EventBindFailed.Err must be non-nil")
	}
}

func TestMonitorConnect(t *testing.T) {
	const ep = "inproc://monitor-connect-test"

	serverCh := make(chan zmq4.SocketEvent, 8)
	server := zmq4.NewPULL(zmq4.WithNULL(), zmq4.WithMonitor(serverCh))
	defer server.Close()

	clientCh := make(chan zmq4.SocketEvent, 8)
	client := zmq4.NewPUSH(zmq4.WithNULL(), zmq4.WithMonitor(clientCh))
	defer client.Close()

	if err := server.Bind(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(context.Background(), ep); err != nil {
		t.Fatal(err)
	}

	// Server: EventListening (from Bind), EventAccepted, EventHandshakeSucceeded
	serverEvs := drainN(t, serverCh, 3, 200*time.Millisecond)
	wantServer := []zmq4.EventType{zmq4.EventListening, zmq4.EventAccepted, zmq4.EventHandshakeSucceeded}
	for i, want := range wantServer {
		if serverEvs[i].Type != want {
			t.Errorf("server event[%d]: got %v, want %v", i, serverEvs[i].Type, want)
		}
	}

	// Client: EventConnected, EventHandshakeSucceeded
	clientEvs := drainN(t, clientCh, 2, 200*time.Millisecond)
	wantClient := []zmq4.EventType{zmq4.EventConnected, zmq4.EventHandshakeSucceeded}
	for i, want := range wantClient {
		if clientEvs[i].Type != want {
			t.Errorf("client event[%d]: got %v, want %v", i, clientEvs[i].Type, want)
		}
	}
}

func TestMonitorConnectFailed(t *testing.T) {
	ch := make(chan zmq4.SocketEvent, 4)
	client := zmq4.NewPUSH(zmq4.WithNULL(), zmq4.WithMonitor(ch))
	defer client.Close()

	// No server listening on this endpoint.
	_ = client.Connect(context.Background(), "tcp://127.0.0.1:1") // port 1 is reserved/unreachable

	evs := drainN(t, ch, 1, 200*time.Millisecond)
	if evs[0].Type != zmq4.EventConnectFailed {
		t.Fatalf("got %v, want EventConnectFailed", evs[0].Type)
	}
	if evs[0].Err == nil {
		t.Fatal("EventConnectFailed.Err must be non-nil")
	}
}

func TestMonitorHandshakeFailed(t *testing.T) {
	const ep = "inproc://monitor-handshake-fail-test"

	serverCh := make(chan zmq4.SocketEvent, 8)
	// PLAIN server requires credentials; NULL client will fail the handshake.
	server := zmq4.NewPULL(
		zmq4.WithPLAINServer(plain.Authenticator(func(_, _ []byte) error { return nil })),
		zmq4.WithMonitor(serverCh),
	)
	defer server.Close()

	clientCh := make(chan zmq4.SocketEvent, 8)
	client := zmq4.NewPUSH(zmq4.WithNULL(), zmq4.WithMonitor(clientCh))
	defer client.Close()

	if err := server.Bind(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	// Connect returns an error (handshake fails); ignore it here.
	_ = client.Connect(context.Background(), ep)

	// Server: EventListening, EventAccepted, EventHandshakeFailed
	serverEvs := drainN(t, serverCh, 3, 200*time.Millisecond)
	if serverEvs[2].Type != zmq4.EventHandshakeFailed {
		t.Fatalf("server event[2]: got %v, want EventHandshakeFailed", serverEvs[2].Type)
	}
	if serverEvs[2].Err == nil {
		t.Fatal("server EventHandshakeFailed.Err must be non-nil")
	}

	// Client: EventConnected, EventHandshakeFailed
	clientEvs := drainN(t, clientCh, 2, 200*time.Millisecond)
	if clientEvs[1].Type != zmq4.EventHandshakeFailed {
		t.Fatalf("client event[1]: got %v, want EventHandshakeFailed", clientEvs[1].Type)
	}
	if clientEvs[1].Err == nil {
		t.Fatal("client EventHandshakeFailed.Err must be non-nil")
	}
}

func TestMonitorDisconnected(t *testing.T) {
	const ep = "inproc://monitor-disconnected-test"

	serverCh := make(chan zmq4.SocketEvent, 8)
	server := zmq4.NewPULL(zmq4.WithNULL(), zmq4.WithMonitor(serverCh))
	defer server.Close()

	client := zmq4.NewPUSH(zmq4.WithNULL())

	if err := server.Bind(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(context.Background(), ep); err != nil {
		t.Fatal(err)
	}

	// Drain connection events on server side.
	drainN(t, serverCh, 3, 200*time.Millisecond) // Listening + Accepted + HandshakeSucceeded

	// Close client — server's readLoop will see an I/O error → EventDisconnected.
	client.Close()

	evs := drainN(t, serverCh, 1, 500*time.Millisecond)
	if evs[0].Type != zmq4.EventDisconnected {
		t.Fatalf("got %v, want EventDisconnected", evs[0].Type)
	}
}
