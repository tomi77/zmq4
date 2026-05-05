package curve

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

// donePair is a small test helper: returns a (client, server) curve
// pair fully through DONE, ready for Wrap/Unwrap.
func donePair(b *testing.B) (*ClientState, *ServerState) {
	b.Helper()
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)
	ready, _, _ := s.Receive(*initiate)
	c.Receive(*ready)
	return c, s
}

func BenchmarkClientHandshake(b *testing.B) {
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)

	// Pre-build server-side outputs once; we re-use them for each
	// client iteration. This benchmark measures the CLIENT's
	// per-handshake cost.
	cBoot, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	sBoot, _ := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
	})
	helloBoot, _ := cBoot.Start()
	welcomeBoot, _, _ := sBoot.Receive(helloBoot)
	initiateBoot, _, _ := cBoot.Receive(*welcomeBoot)
	readyBoot, _, _ := sBoot.Receive(*initiateBoot)

	b.ReportAllocs()
	for b.Loop() {
		c, _ := NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		})
		_, _ = c.Start()
		_, _, _ = c.Receive(*welcomeBoot)
		_, _, _ = c.Receive(*readyBoot)
	}
	_ = initiateBoot // keep boot variables alive
}

func BenchmarkServerHandshake(b *testing.B) {
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)
	cBoot, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	helloBoot, _ := cBoot.Start()

	// Build a representative INITIATE for a fresh server to consume
	// each iteration. We need the server's transient pub for
	// afterReady; rebuild per iteration instead.
	b.ReportAllocs()
	for b.Loop() {
		s, _ := NewServer(ServerOptions{
			OurPublicKey: serverPub, OurSecretKey: &serverSec,
			Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
		})
		welcome, _, _ := s.Receive(helloBoot)
		// Build INITIATE matching this server's per-handshake cookie+s'.
		initiate, _, _ := cBoot.Receive(*welcome)
		_, _, _ = s.Receive(*initiate)
		// Reset cBoot: it has now advanced past WELCOME. Restart it.
		cBoot, _ = NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		})
		helloBoot, _ = cBoot.Start()
	}
}

func BenchmarkWrap(b *testing.B) {
	for _, sz := range []int{64, 1024, 65536, 1 << 20} {
		b.Run(humanSize(sz), func(b *testing.B) {
			c, _ := donePair(b)
			payload := bytes.Repeat([]byte{0x42}, sz)
			b.SetBytes(int64(sz))
			b.ReportAllocs()
			for b.Loop() {
				_, _ = c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: payload})
			}
		})
	}
}

func BenchmarkUnwrap(b *testing.B) {
	for _, sz := range []int{64, 1024, 65536, 1 << 20} {
		b.Run(humanSize(sz), func(b *testing.B) {
			c, s := donePair(b)
			payload := bytes.Repeat([]byte{0x42}, sz)
			// Pre-seed s with one wrapped frame per iteration; the
			// receiver must accept monotonically-increasing nonces, so
			// we batch produce N frames then iterate.
			frame := wire.Frame{Kind: wire.FrameMessage, Body: payload}
			wraps := make([]wire.Frame, 1024)
			for i := range wraps {
				w, err := c.Wrap(frame)
				if err != nil {
					b.Fatalf("Wrap[%d]: %v", i, err)
				}
				wraps[i] = w
			}
			b.SetBytes(int64(sz))
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if _, err := s.Unwrap(wraps[i%len(wraps)]); err != nil {
					b.Fatalf("Unwrap: %v", err)
				}
				i++
				// Once we exhaust wraps[], rebuild — Unwrap rejects
				// replays.
				if i%len(wraps) == 0 {
					c, s = donePair(b)
					for j := range wraps {
						w, _ := c.Wrap(frame)
						wraps[j] = w
					}
				}
			}
		})
	}
}

func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return "1MiB"
	case n >= 1<<16:
		return "64KiB"
	case n >= 1<<10:
		return "1KiB"
	default:
		return "64B"
	}
}
