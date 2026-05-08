package conn

import (
	"bytes"
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/curve"
	"github.com/tomi77/zmq4/internal/security/null"
	"github.com/tomi77/zmq4/internal/security/plain"
	"github.com/tomi77/zmq4/internal/wire"
)

// mechFactory builds one client- or server-side mechanism for a given
// row in the conformance table. Returning a fresh instance per call
// matches the F2 contract that mechanisms are single-shot.
type mechFactory struct {
	name      string
	newClient func(t *testing.T) security.ClientMechanism
	newServer func(t *testing.T) security.Mechanism
}

func nullFactory() mechFactory {
	md := wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("PAIR")}}
	return mechFactory{
		name:      "NULL",
		newClient: func(_ *testing.T) security.ClientMechanism { return null.New(md) },
		newServer: func(_ *testing.T) security.Mechanism { return null.New(md) },
	}
}

func plainFactory() mechFactory {
	md := wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("PAIR")}}
	return mechFactory{
		name: "PLAIN",
		newClient: func(t *testing.T) security.ClientMechanism {
			c, err := plain.NewClient([]byte("user"), []byte("pass"), md)
			if err != nil {
				t.Fatalf("plain.NewClient: %v", err)
			}
			return c
		},
		newServer: func(_ *testing.T) security.Mechanism {
			return plain.NewServer(func(_, _ []byte) error { return nil }, md)
		},
	}
}

func curveFactory(t *testing.T) mechFactory {
	t.Helper()
	clientPub, clientSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	serverPub, serverSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	md := wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("PAIR")}}
	return mechFactory{
		name: "CURVE",
		newClient: func(t *testing.T) security.ClientMechanism {
			c, err := curve.NewClient(curve.ClientOptions{
				ServerKey:     serverPub,
				OurPublicKey:  clientPub,
				OurSecretKey:  &clientSec,
				LocalMetadata: md,
			})
			if err != nil {
				t.Fatalf("curve.NewClient: %v", err)
			}
			return c
		},
		newServer: func(t *testing.T) security.Mechanism {
			s, err := curve.NewServer(curve.ServerOptions{
				OurPublicKey:  serverPub,
				OurSecretKey:  &serverSec,
				Authorizer:    func(_ curve.PublicKey, _ wire.Metadata) error { return nil },
				LocalMetadata: md,
			})
			if err != nil {
				t.Fatalf("curve.NewServer: %v", err)
			}
			return s
		},
	}
}

func TestConformanceTable(t *testing.T) {
	factories := []mechFactory{
		nullFactory(),
		plainFactory(),
		curveFactory(t),
	}
	for _, f := range factories {
		t.Run(f.name, func(t *testing.T) {
			c, s, cErr, sErr := runHandshakePair(t,
				func() security.ClientMechanism { return f.newClient(t) },
				func() security.Mechanism { return f.newServer(t) })
			if cErr != nil {
				t.Fatalf("client handshake: %v", cErr)
			}
			if sErr != nil {
				t.Fatalf("server handshake: %v", sErr)
			}
			if c == nil || s == nil {
				t.Fatalf("nil Conn returned")
			}

			// Property: post-handshake Wrap/Unwrap round-trips a
			// representative FrameMessage. Done via a real WriteFrame +
			// ReadFrame to exercise both directions.
			payload := bytes.Repeat([]byte{0xCD}, 1024)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				if err := c.WriteFrame(wire.Frame{Kind: wire.FrameMessage, Body: payload}); err != nil {
					t.Errorf("WriteFrame: %v", err)
				}
			}()
			got, err := s.ReadFrame()
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if !bytes.Equal(got.Body, payload) {
				t.Errorf("body mismatch: len(got)=%d len(want)=%d", len(got.Body), len(payload))
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatalf("WriteFrame did not return within 2 s")
			}

			// Property: PeerMetadata is non-nil for both sides and
			// carries the Socket-Type=PAIR property we injected.
			assertSocketTypePAIR := func(side string, md wire.Metadata) {
				t.Helper()
				if len(md) == 0 {
					t.Errorf("%s: PeerMetadata is empty", side)
					return
				}
				for _, p := range md {
					if string(p.Name) == "Socket-Type" && string(p.Value) == "PAIR" {
						return
					}
				}
				t.Errorf("%s: PeerMetadata missing Socket-Type=PAIR; got %+v", side, md)
			}
			assertSocketTypePAIR("client", c.PeerMetadata())
			assertSocketTypePAIR("server", s.PeerMetadata())

			// Property: PeerMetadata is decoupled from the mechanism
			// (defensive clone per spec §4.2). After dropping the mech
			// reference and forcing GC, PeerMetadata must remain valid.
			cMeta := c.PeerMetadata()
			c.mech = nil
			runtime.GC()
			runtime.GC()
			if len(cMeta) == 0 {
				t.Errorf("PeerMetadata empty after mech reference drop")
			}
			for _, p := range cMeta {
				if string(p.Name) == "Socket-Type" && string(p.Value) == "PAIR" {
					return
				}
			}
			t.Errorf("PeerMetadata corrupted after mech reference drop: %+v", cMeta)
		})
	}
}
