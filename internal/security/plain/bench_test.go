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
