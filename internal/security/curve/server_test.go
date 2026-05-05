package curve

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func acceptAll(_ PublicKey, _ wire.Metadata) error { return nil }

func TestNewServerNilAuthorizerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("NewServer(nil Authorizer) did not panic")
		}
	}()
	_, sec := makePair(t)
	_, _ = NewServer(ServerOptions{
		OurPublicKey: PublicKey{1},
		OurSecretKey: &sec,
		Authorizer:   nil,
	})
}

func TestNewServerRejectsZeroOurPublicKey(t *testing.T) {
	_, sec := makePair(t)
	_, err := NewServer(ServerOptions{
		OurPublicKey: PublicKey{},
		OurSecretKey: &sec,
		Authorizer:   acceptAll,
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewServerRejectsNilOurSecretKey(t *testing.T) {
	_, err := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1},
		Authorizer:   acceptAll,
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewServerNotDone(t *testing.T) {
	_, sec := makePair(t)
	s, err := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.Done() {
		t.Fatalf("new server is Done()")
	}
}

func TestServerReceiveHelloEmitsValidWelcome(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	_ = clientLongPub

	s, err := NewServer(ServerOptions{
		OurPublicKey: serverLongPub,
		OurSecretKey: &serverLongSec,
		Authorizer:   acceptAll,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Build HELLO via a real ClientState so the test exercises the
	// production path on both sides.
	c, err := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	out, done, err := s.Receive(hello)
	if err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	if done {
		t.Fatalf("done=true after HELLO, want false")
	}
	if out == nil || out.Name != welcomeCommandName {
		t.Fatalf("out = %+v, want WELCOME", out)
	}
	if len(out.Data) != welcomeBodyLen {
		t.Fatalf("welcome len = %d, want %d", len(out.Data), welcomeBodyLen)
	}

	// Round-trip: client opens WELCOME successfully.
	if _, _, err := c.Receive(*out); err != nil {
		t.Fatalf("client.Receive(WELCOME): %v", err)
	}
}

// silence unused-import warnings for imports that fully grow in
// subsequent tasks. Drop these placeholders once the appended tests
// reference each import legitimately.
var (
	_ = bytes.Equal
	_ = strings.Contains
)

// silence unused-import warning for crypto/rand (used by future tasks).
var _ = rand.Reader
