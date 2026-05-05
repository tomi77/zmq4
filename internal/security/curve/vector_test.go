package curve

import (
	"bytes"
	"flag"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

// vectorSeed is the 32-byte ChaCha8 seed for byte-deterministic
// vectors. NEVER change without regenerating every .bin file.
var vectorSeed = [32]byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

var updateVectors = flag.Bool("update-vectors", false,
	"regenerate testdata/curve-*.bin from the pinned ChaCha8 seed")

// newSeededRNG returns a *math/rand/v2.ChaCha8 — which implements
// io.Reader natively. Per the math/rand/v2 stability guarantee, the
// byte stream produced by ChaCha8.Read(p) is deterministic across Go
// versions for a fixed seed, so vectors stay stable.
func newSeededRNG() *mrand.ChaCha8 {
	return mrand.NewChaCha8(vectorSeed)
}

// buildAllVectors produces the canonical bytes for every vector. The
// returned map is in stable iteration order via the slice above.
func buildAllVectors(t *testing.T) []struct {
	name string
	body []byte
} {
	t.Helper()
	rng := newSeededRNG()

	clientPub, clientSec, err := GenerateKeyPair(rng)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	serverPub, serverSec, err := GenerateKeyPair(rng)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	c, err := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec, Rand: rng,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	s, err := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
		Rand:       rng,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	welcome, _, err := s.Receive(hello)
	if err != nil {
		t.Fatalf("server.Receive(HELLO): %v", err)
	}

	// Drive (c, s) — which has empty LocalMetadata on both sides — fully
	// to DONE. The client's INITIATE here is the empty-meta vector.
	initiateEmpty, _, err := c.Receive(*welcome)
	if err != nil {
		t.Fatalf("client.Receive(WELCOME): %v", err)
	}
	ready, _, err := s.Receive(*initiateEmpty)
	if err != nil {
		t.Fatalf("server.Receive(INITIATE): %v", err)
	}
	if _, _, err := c.Receive(*ready); err != nil {
		t.Fatalf("client.Receive(READY): %v", err)
	}

	// READY-with-identity: the server-side state's local meta is
	// ignored here; build via codec under the same afterReady.
	mdIdentity := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
		{Name: []byte("Identity"), Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
	}
	readyIdentity, err := encodeReady(mdIdentity, s.afterReady, 99, rng)
	if err != nil {
		t.Fatalf("encodeReady (identity): %v", err)
	}

	// INITIATE-with-socket-type: produced by an independent (cInit2,
	// sInit2) pair seeded from the same vectorSeed. The two INITIATE
	// fixtures are therefore independent fixtures (each reproducible
	// from `vectorSeed` alone), not consecutive frames of one stream.
	mdSocketType := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
	}
	cInit2, sInit2 := newSeededCURVEPair(t, mdSocketType, nil)
	hello2, _ := cInit2.Start()
	welcome2, _, _ := sInit2.Receive(hello2)
	initiateSocketType, _, _ := cInit2.Receive(*welcome2)

	// Build MESSAGE vectors from the (c, s) pair already in DONE.
	wrapEmpty, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: nil, More: false})
	if err != nil {
		t.Fatalf("Wrap empty: %v", err)
	}
	wrap16b, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: bytes.Repeat([]byte{0xAB}, 16), More: false})
	if err != nil {
		t.Fatalf("Wrap 16b: %v", err)
	}
	wrapMore, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: []byte{0xDE, 0xAD, 0xBE, 0xEF}, More: true})
	if err != nil {
		t.Fatalf("Wrap more: %v", err)
	}

	errCmd, err := wire.ErrorCommand{Reason: "Authentication failed"}.Encode()
	if err != nil {
		t.Fatalf("encode ERROR: %v", err)
	}

	mustEncCmd := func(cmd wire.Command) []byte {
		body, err := wire.EncodeCommand(cmd)
		if err != nil {
			t.Fatalf("EncodeCommand: %v", err)
		}
		return body
	}

	return []struct {
		name string
		body []byte
	}{
		{"curve-hello-empty.bin", mustEncCmd(hello)},
		{"curve-welcome.bin", mustEncCmd(*welcome)},
		{"curve-initiate-empty-meta.bin", mustEncCmd(*initiateEmpty)},
		{"curve-initiate-with-socket-type.bin", mustEncCmd(*initiateSocketType)},
		{"curve-ready-empty-meta.bin", mustEncCmd(*ready)},
		{"curve-ready-with-identity.bin", mustEncCmd(readyIdentity)},
		{"curve-message-empty.bin", wrapEmpty.Body},
		{"curve-message-16b.bin", wrap16b.Body},
		{"curve-message-more.bin", wrapMore.Body},
		{"curve-error.bin", mustEncCmd(errCmd)},
	}
}

// newSeededCURVEPair drives client+server through the same seeded RNG
// for fixture generation that does not depend on the live (c,s) pair.
func newSeededCURVEPair(t *testing.T, clientMd, serverMd wire.Metadata) (*ClientState, *ServerState) {
	t.Helper()
	rng := newSeededRNG()
	clientPub, clientSec, _ := GenerateKeyPair(rng)
	serverPub, serverSec, _ := GenerateKeyPair(rng)
	c, err := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		LocalMetadata: clientMd, Rand: rng,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	s, err := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		LocalMetadata: serverMd,
		Authorizer:    func(_ PublicKey, _ wire.Metadata) error { return nil },
		Rand:          rng,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return c, s
}

func TestCurveVectors(t *testing.T) {
	vectors := buildAllVectors(t)

	if *updateVectors {
		dir := "testdata"
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		for _, v := range vectors {
			if err := os.WriteFile(filepath.Join(dir, v.name), v.body, 0o644); err != nil {
				t.Fatalf("write %s: %v", v.name, err)
			}
		}
		t.Logf("regenerated %d vector files", len(vectors))
		return
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			path := filepath.Join("testdata", v.name)
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if !bytes.Equal(v.body, want) {
				t.Fatalf("byte mismatch for %s\ngot:  %x\nwant: %x", v.name, v.body, want)
			}
		})
	}
}
