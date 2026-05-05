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

func TestServerReceiveInitiateAcceptCompletesHandshake(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	mdC := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
		{Name: []byte("Identity"), Value: []byte("client-1")},
	}
	mdS := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
	}

	s, err := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		LocalMetadata: mdS, Authorizer: acceptAll,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	c, err := NewClient(ClientOptions{
		ServerKey:     serverLongPub,
		OurPublicKey:  clientLongPub,
		OurSecretKey:  &clientLongSec,
		LocalMetadata: mdC,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	hello, _ := c.Start()
	welcome, _, err := s.Receive(hello)
	if err != nil {
		t.Fatalf("server.Receive(HELLO): %v", err)
	}
	initiate, _, err := c.Receive(*welcome)
	if err != nil {
		t.Fatalf("client.Receive(WELCOME): %v", err)
	}

	ready, done, err := s.Receive(*initiate)
	if err != nil {
		t.Fatalf("server.Receive(INITIATE): %v", err)
	}
	if !done || ready == nil {
		t.Fatalf("server.Receive(INITIATE): out=%+v done=%v, want READY/true", ready, done)
	}
	if !s.Done() {
		t.Fatalf("Done() == false after INITIATE accept")
	}
	if s.PeerPublicKey() != clientLongPub {
		t.Fatalf("PeerPublicKey = %x, want %x", s.PeerPublicKey(), clientLongPub)
	}
	pm := s.PeerMetadata()
	if v, ok := pm.Get("Identity"); !ok || string(v) != "client-1" {
		t.Fatalf("PeerMetadata Identity = %q, want client-1", v)
	}

	// Client Receive(READY) closes the handshake on the client side.
	if _, cdone, err := c.Receive(*ready); err != nil || !cdone {
		t.Fatalf("client.Receive(READY): err=%v done=%v", err, cdone)
	}
	if !c.Done() {
		t.Fatalf("client not done")
	}
	if v, ok := c.PeerMetadata().Get("Socket-Type"); !ok || string(v) != "ROUTER" {
		t.Fatalf("client PeerMetadata Socket-Type = %q, want ROUTER", v)
	}
}

func TestServerPeerMetadataIndependentOfInputBuffer(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	mdC := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
	}

	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: acceptAll,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
		LocalMetadata: mdC,
	})

	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	// Wrap initiate.Data in a fresh buffer we can clobber.
	buf := make([]byte, len(initiate.Data))
	copy(buf, initiate.Data)
	initiateClone := wire.Command{Name: initiate.Name, Data: buf}

	if _, _, err := s.Receive(initiateClone); err != nil {
		t.Fatalf("server.Receive(INITIATE): %v", err)
	}
	for i := range buf {
		buf[i] = 0xFF
	}
	if v, ok := s.PeerMetadata().Get("Socket-Type"); !ok || string(v) != "DEALER" {
		t.Fatalf("PeerMetadata after clobber = %q, want DEALER", v)
	}
}

func TestServerReceiveTamperedInitiate(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: acceptAll,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	initiate.Data[len(initiate.Data)-1] ^= 0x01
	if _, _, err := s.Receive(*initiate); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestServerReceiveInitiateWithTamperedCookie(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: acceptAll,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	// Flip a bit inside the 96-byte cookie at the start of INITIATE.
	initiate.Data[5] ^= 0x01
	_, _, err := s.Receive(*initiate)
	// The cookie's secretbox auth tag fails ⇒ ErrBoxOpen.
	if !errors.Is(err, ErrBoxOpen) && !errors.Is(err, ErrCookieMismatch) {
		t.Fatalf("err = %v, want ErrBoxOpen or ErrCookieMismatch", err)
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
