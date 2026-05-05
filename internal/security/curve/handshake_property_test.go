package curve

import (
	"bytes"
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"testing"
	"testing/quick"

	"github.com/tomi77/zmq4/internal/wire"
)

// randCurveMetadata returns a random Metadata. Names use a small fixed
// vocabulary so parser corner cases stay exercised; values are random
// bytes up to 32 B.
func randCurveMetadata(rng *mrand.Rand) wire.Metadata {
	names := []string{
		"Socket-Type", "Identity", "Resource",
		"X-Foo", "X-Bar", "X-Baz",
	}
	n := rng.Intn(len(names) + 1)
	used := map[string]bool{}
	var md wire.Metadata
	for i := 0; i < n; i++ {
		name := names[rng.Intn(len(names))]
		if used[name] {
			continue
		}
		used[name] = true
		valLen := rng.Intn(33)
		val := make([]byte, valLen)
		rng.Read(val)
		md = append(md, wire.MetadataProperty{
			Name:  []byte(name),
			Value: val,
		})
	}
	return md
}

func metadataEqual(a, b wire.Metadata) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].Name, b[i].Name) ||
			!bytes.Equal(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}

func TestCurveHappyPathProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 1000}
	prop := func(seed int64) bool {
		rng := mrand.New(mrand.NewSource(seed))
		clientPub, clientSec, err := GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Logf("client keypair: %v", err)
			return false
		}
		serverPub, serverSec, err := GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Logf("server keypair: %v", err)
			return false
		}
		mdC := randCurveMetadata(rng)
		mdS := randCurveMetadata(rng)

		c, err := NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
			LocalMetadata: mdC,
		})
		if err != nil {
			t.Logf("NewClient: %v", err)
			return false
		}
		s, err := NewServer(ServerOptions{
			OurPublicKey: serverPub, OurSecretKey: &serverSec,
			LocalMetadata: mdS,
			Authorizer:    func(_ PublicKey, _ wire.Metadata) error { return nil },
		})
		if err != nil {
			t.Logf("NewServer: %v", err)
			return false
		}

		hello, _ := c.Start()
		welcome, done, err := s.Receive(hello)
		if err != nil || done {
			t.Logf("server.Receive(HELLO): err=%v done=%v", err, done)
			return false
		}
		initiate, done, err := c.Receive(*welcome)
		if err != nil || done {
			t.Logf("client.Receive(WELCOME): err=%v done=%v", err, done)
			return false
		}
		ready, done, err := s.Receive(*initiate)
		if err != nil || !done {
			t.Logf("server.Receive(INITIATE): err=%v done=%v", err, done)
			return false
		}
		out, done, err := c.Receive(*ready)
		if err != nil || !done || out != nil {
			t.Logf("client.Receive(READY): err=%v done=%v out=%v", err, done, out)
			return false
		}
		if !metadataEqual(c.PeerMetadata(), mdS) {
			t.Logf("client.PeerMetadata mismatch")
			return false
		}
		if !metadataEqual(s.PeerMetadata(), mdC) {
			t.Logf("server.PeerMetadata mismatch")
			return false
		}
		if s.PeerPublicKey() != clientPub {
			t.Logf("server.PeerPublicKey mismatch")
			return false
		}

		// 32 round-trips of random frames in alternating directions.
		for i := 0; i < 32; i++ {
			body := make([]byte, rng.Intn(257))
			rng.Read(body)
			more := rng.Intn(2) == 1
			f := wire.Frame{Kind: wire.FrameMessage, More: more, Body: body}

			if i%2 == 0 {
				wrapped, err := c.Wrap(f)
				if err != nil {
					t.Logf("c.Wrap[%d]: %v", i, err)
					return false
				}
				got, err := s.Unwrap(wrapped)
				if err != nil {
					t.Logf("s.Unwrap[%d]: %v", i, err)
					return false
				}
				if got.More != f.More || !bytes.Equal(got.Body, f.Body) {
					t.Logf("c→s round trip[%d] mismatch", i)
					return false
				}
			} else {
				wrapped, err := s.Wrap(f)
				if err != nil {
					t.Logf("s.Wrap[%d]: %v", i, err)
					return false
				}
				got, err := c.Unwrap(wrapped)
				if err != nil {
					t.Logf("c.Unwrap[%d]: %v", i, err)
					return false
				}
				if got.More != f.More || !bytes.Equal(got.Body, f.Body) {
					t.Logf("s→c round trip[%d] mismatch", i)
					return false
				}
			}
		}
		return true
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCurveAuthRejectProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 1000}
	prop := func(seed int64) bool {
		clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
		serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)
		c, _ := NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		})
		s, _ := NewServer(ServerOptions{
			OurPublicKey: serverPub, OurSecretKey: &serverSec,
			Authorizer: func(_ PublicKey, _ wire.Metadata) error { return errors.New("denied") },
		})
		hello, _ := c.Start()
		welcome, _, _ := s.Receive(hello)
		initiate, _, _ := c.Receive(*welcome)
		out, done, err := s.Receive(*initiate)
		if !errors.Is(err, ErrAuthRejected) || done || out == nil {
			t.Logf("server.Receive(INITIATE): err=%v done=%v out=%v", err, done, out)
			return false
		}
		ec, perr := wire.ParseError(*out)
		if perr != nil || ec.Reason != "denied" {
			t.Logf("ERROR reason = %q (parse err=%v)", ec.Reason, perr)
			return false
		}
		_, _, err = c.Receive(*out)
		if !errors.Is(err, ErrPeerError) {
			t.Logf("client.Receive(ERROR): %v", err)
			return false
		}
		_ = seed
		return true
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCurveTamperRejectionProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 100}
	prop := func(seed int64) bool {
		rng := mrand.New(mrand.NewSource(seed))
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
		// Pick which command in the handshake to tamper.
		victim := rng.Intn(4) // 0=HELLO,1=WELCOME,2=INITIATE,3=READY
		flip := func(cmd *wire.Command) {
			if len(cmd.Data) == 0 {
				return
			}
			cmd.Data[rng.Intn(len(cmd.Data))] ^= 1 << uint(rng.Intn(8))
		}
		if victim == 0 {
			flip(&hello)
			_, _, err := s.Receive(hello)
			return err != nil // some flavor of failure
		}
		welcome, _, _ := s.Receive(hello)
		if victim == 1 {
			flip(welcome)
			_, _, err := c.Receive(*welcome)
			return err != nil
		}
		initiate, _, _ := c.Receive(*welcome)
		if victim == 2 {
			flip(initiate)
			_, _, err := s.Receive(*initiate)
			return err != nil
		}
		ready, _, _ := s.Receive(*initiate)
		if victim == 3 {
			flip(ready)
			_, _, err := c.Receive(*ready)
			return err != nil
		}
		return true
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCurveReplayRejection(t *testing.T) {
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

	wrapped, _ := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: []byte("ok")})
	if _, err := s.Unwrap(wrapped); err != nil {
		t.Fatalf("first Unwrap: %v", err)
	}
	if _, err := s.Unwrap(wrapped); !errors.Is(err, ErrNonceReused) {
		t.Fatalf("replay = %v, want ErrNonceReused", err)
	}
}
