package plain

import (
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func BenchmarkClientHandshake(b *testing.B) {
	user := []byte("admin")
	pass := []byte("secret")
	mdC := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REQ")},
	}
	welcome := encodeWelcome()
	peerReady, err := wire.ReadyCommand{
		Metadata: wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("REP")},
		},
	}.Encode()
	if err != nil {
		b.Fatalf("encode peer READY: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		c, err := NewClient(user, pass, mdC)
		if err != nil {
			b.Fatalf("NewClient: %v", err)
		}
		if _, err := c.Start(); err != nil {
			b.Fatalf("Start: %v", err)
		}
		if _, _, err := c.Receive(welcome); err != nil {
			b.Fatalf("Receive(WELCOME): %v", err)
		}
		if _, _, err := c.Receive(peerReady); err != nil {
			b.Fatalf("Receive(READY): %v", err)
		}
	}
}

func BenchmarkServerHandshake(b *testing.B) {
	auth := func(_, _ []byte) error { return nil }
	mdS := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REP")},
	}
	hello, err := encodeHello(helloBody{Username: []byte("admin"), Password: []byte("secret")})
	if err != nil {
		b.Fatalf("encodeHello: %v", err)
	}
	initiate := wire.Command{
		Name: initiateCommandName,
		Data: wire.EncodeMetadata(wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("REQ")},
		}),
	}

	b.ReportAllocs()
	for b.Loop() {
		s := NewServer(auth, mdS)
		if _, _, err := s.Receive(hello); err != nil {
			b.Fatalf("Receive(HELLO): %v", err)
		}
		if _, _, err := s.Receive(initiate); err != nil {
			b.Fatalf("Receive(INITIATE): %v", err)
		}
	}
}

// TestClientHandshakeAllocBudget pins the per-handshake allocation count for
// the client happy path. The defensive-copy budget (per F2a/F2b spec §8.6) is
// one slice header + one Name buffer + one Value buffer per peer property
// returned in the metadata-bearing step. With one peer property, the steady
// state is: HELLO encode (1), INITIATE encode + metadata encode (2), state
// struct + slices (1+), peer-metadata defensive clone (3). Empirically 8/op.
func TestClientHandshakeAllocBudget(t *testing.T) {
	user := []byte("admin")
	pass := []byte("secret")
	mdC := wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("REQ")}}
	welcome := encodeWelcome()
	peerReady, err := wire.ReadyCommand{
		Metadata: wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("REP")}},
	}.Encode()
	if err != nil {
		t.Fatalf("encode peer READY: %v", err)
	}

	allocs := testing.AllocsPerRun(100, func() {
		c, _ := NewClient(user, pass, mdC)
		_, _ = c.Start()
		_, _, _ = c.Receive(welcome)
		_, _, _ = c.Receive(peerReady)
	})
	// Observed: 8 allocs/op on go1.26 darwin/arm64. Budget = observed + 1 slack.
	const budget = 9
	if allocs > budget {
		t.Fatalf("client allocs/op = %.0f, budget = %d", allocs, budget)
	}
}

// TestServerHandshakeAllocBudget pins the per-handshake allocation count for
// the server happy path. Same defensive-copy budget as the client side.
func TestServerHandshakeAllocBudget(t *testing.T) {
	mdS := wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("REP")}}
	hello, err := encodeHello(helloBody{Username: []byte("u"), Password: []byte("p")})
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	initiate := wire.Command{
		Name: initiateCommandName,
		Data: wire.EncodeMetadata(wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("REQ")}}),
	}

	allocs := testing.AllocsPerRun(100, func() {
		s := NewServer(func(_, _ []byte) error { return nil }, mdS)
		_, _, _ = s.Receive(hello)
		_, _, _ = s.Receive(initiate)
	})
	// Observed: 7 allocs/op on go1.26 darwin/arm64. Budget = observed + 1 slack.
	const budget = 8
	if allocs > budget {
		t.Fatalf("server allocs/op = %.0f, budget = %d", allocs, budget)
	}
}
