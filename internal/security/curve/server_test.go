package curve

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/tomi77/zmq4/internal/security"
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

func TestServerReceiveInitiateRejectEmitsErrorAndFails(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	rejecter := func(_ PublicKey, _ wire.Metadata) error { return errors.New("denied") }

	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: rejecter,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	out, done, err := s.Receive(*initiate)
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("err = %v, want ErrAuthRejected", err)
	}
	if done {
		t.Fatalf("done=true on auth reject")
	}
	if out == nil || out.Name != wire.ErrorCommandName {
		t.Fatalf("out = %+v, want ERROR command", out)
	}
	ec, perr := wire.ParseError(*out)
	if perr != nil {
		t.Fatalf("ParseError(out): %v", perr)
	}
	if ec.Reason != "denied" {
		t.Fatalf("reason = %q, want denied", ec.Reason)
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Fatalf("err %q does not include reason", err)
	}

	// Subsequent Receive returns ErrAlreadyFailed.
	if _, _, err := s.Receive(*initiate); !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Receive after reject = %v, want ErrAlreadyFailed", err)
	}

	// Client.Receive(ERROR) returns ErrPeerError with the reason.
	if _, _, err := c.Receive(*out); !errors.Is(err, ErrPeerError) {
		t.Fatalf("client.Receive(ERROR) = %v, want ErrPeerError", err)
	}
}

func TestServerAuthRejectReasonSanitized(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	dirty := "bad creds\n\x00user=alice"
	rejecter := func(_ PublicKey, _ wire.Metadata) error { return errors.New(dirty) }
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: rejecter,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	out, _, _ := s.Receive(*initiate)
	ec, _ := wire.ParseError(*out)
	if strings.ContainsAny(ec.Reason, "\n\x00") {
		t.Fatalf("reason %q has non-VCHAR bytes", ec.Reason)
	}
	if len(ec.Reason) != len(dirty) {
		t.Fatalf("len(reason) = %d, want %d", len(ec.Reason), len(dirty))
	}
}

func TestServerAuthRejectReasonTruncated(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	long := strings.Repeat("a", 300)
	rejecter := func(_ PublicKey, _ wire.Metadata) error { return errors.New(long) }
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: rejecter,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	out, _, _ := s.Receive(*initiate)
	ec, _ := wire.ParseError(*out)
	if len(ec.Reason) != 255 {
		t.Fatalf("len(reason) = %d, want 255", len(ec.Reason))
	}
}

func TestServerReceiveErrorAtHelloStep(t *testing.T) {
	_, sec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1, 2, 3}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	errCmd, _ := wire.ErrorCommand{Reason: "client gives up"}.Encode()
	_, _, err := s.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("err = %v, want ErrPeerError", err)
	}
	if !strings.Contains(err.Error(), "client gives up") {
		t.Fatalf("error %q does not include reason", err)
	}
}

func TestServerReceiveUnexpectedCommandAtHelloStep(t *testing.T) {
	_, sec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1, 2, 3}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	if _, _, err := s.Receive(wire.Command{Name: "PING"}); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestServerReceiveInitiateAtAwaitHelloReturnsUnexpectedCommand(t *testing.T) {
	_, sec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1, 2, 3}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	bogus := wire.Command{Name: initiateCommandName, Data: make([]byte, initiateMinBodyLen)}
	if _, _, err := s.Receive(bogus); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestServerReceiveMalformedHello(t *testing.T) {
	_, sec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	bad := wire.Command{Name: helloCommandName, Data: []byte{0x01}}
	if _, _, err := s.Receive(bad); !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestServerReceiveAfterDone(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec, Authorizer: acceptAll,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)
	if _, _, err := s.Receive(*initiate); err != nil {
		t.Fatalf("server.Receive(INITIATE): %v", err)
	}

	if _, _, err := s.Receive(*initiate); !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("Receive after done = %v, want ErrAlreadyDone", err)
	}
}

func TestServerCloseIdempotentAndRedacts(t *testing.T) {
	_, sec := makePair(t)
	s, err := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.Close()
	s.Close()

	if _, _, err := s.Receive(wire.Command{Name: helloCommandName}); !errors.Is(err, security.ErrClosed) {
		t.Fatalf("Receive after Close = %v, want security.ErrClosed", err)
	}
	if _, err := s.Wrap(wire.Frame{}); !errors.Is(err, security.ErrClosed) {
		t.Fatalf("Wrap after Close = %v, want security.ErrClosed", err)
	}
	if _, err := s.Unwrap(wire.Frame{Kind: wire.FrameCommand, Body: make([]byte, 25)}); !errors.Is(err, security.ErrClosed) {
		t.Fatalf("Unwrap after Close = %v, want security.ErrClosed", err)
	}
	// Caller-owned long-term secret untouched.
	if sec == (SecretKey{}) {
		t.Fatalf("long-term secret was zeroed by Close")
	}
}

func TestServerWrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	_, sec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	if _, err := s.Wrap(wire.Frame{Kind: wire.FrameMessage}); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("err = %v, want security.ErrNotDone", err)
	}
}

func TestServerWrapUnwrapRoundTrip(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec, Authorizer: acceptAll,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)
	ready, _, _ := s.Receive(*initiate)
	c.Receive(*ready)

	in := wire.Frame{Kind: wire.FrameMessage, More: true, Body: []byte("ping")}
	wrapped, err := c.Wrap(in)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := s.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got.Kind != wire.FrameMessage || got.More != true || !bytes.Equal(got.Body, []byte("ping")) {
		t.Fatalf("round trip = %+v", got)
	}
	// Reverse direction.
	in2 := wire.Frame{Kind: wire.FrameMessage, More: false, Body: []byte("pong")}
	wrapped2, err := s.Wrap(in2)
	if err != nil {
		t.Fatalf("server Wrap: %v", err)
	}
	got2, err := c.Unwrap(wrapped2)
	if err != nil {
		t.Fatalf("client Unwrap: %v", err)
	}
	if !bytes.Equal(got2.Body, []byte("pong")) || got2.More {
		t.Fatalf("reverse round trip = %+v", got2)
	}
}

func TestServerStateName(t *testing.T) {
	serverPub, serverSec, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	s, err := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if got := s.Name(); got != "CURVE" {
		t.Fatalf("Name() = %q, want %q", got, "CURVE")
	}
}

// silence unused-import warning for crypto/rand (used by future tasks).
var _ = rand.Reader
