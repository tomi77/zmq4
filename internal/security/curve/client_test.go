package curve

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestNewClientRejectsZeroServerKey(t *testing.T) {
	_, sec := makePair(t)
	_, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{},
		OurPublicKey: PublicKey{1},
		OurSecretKey: &sec,
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewClientRejectsZeroOurPublicKey(t *testing.T) {
	_, sec := makePair(t)
	_, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{1},
		OurPublicKey: PublicKey{},
		OurSecretKey: &sec,
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewClientRejectsNilOurSecretKey(t *testing.T) {
	_, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{1},
		OurPublicKey: PublicKey{1},
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewClientNotDone(t *testing.T) {
	_, sec := makePair(t)
	c, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{1},
		OurPublicKey: PublicKey{1},
		OurSecretKey: &sec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Done() {
		t.Fatalf("new client is Done()")
	}
}

func TestClientStartEmitsValidHello(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)

	c, err := NewClient(ClientOptions{
		ServerKey:    serverLongPub,
		OurPublicKey: clientLongPub,
		OurSecretKey: &clientLongSec,
		Rand:         rand.Reader,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if hello.Name != helloCommandName {
		t.Fatalf("Name = %q, want %q", hello.Name, helloCommandName)
	}

	// Server-side parseHello should accept the produced HELLO.
	// Read C' from the cleartext part first.
	if len(hello.Data) != helloBodyLen {
		t.Fatalf("body len = %d, want %d", len(hello.Data), helloBodyLen)
	}
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	openShared := precompute(clientTransPub, &serverLongSec)
	if _, err := parseHello(hello, openShared); err != nil {
		t.Fatalf("parseHello: %v", err)
	}
}

func TestClientStartTwiceReturnsAlreadyStarted(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, err := NewClient(ClientOptions{
		ServerKey:    serverLongPub,
		OurPublicKey: clientLongPub,
		OurSecretKey: &clientLongSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if _, err := c.Start(); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start = %v, want ErrAlreadyStarted", err)
	}
}

// failingReadOnNthCall returns wantErr on the n-th Read; succeeds before
// that.
type failingReadOnNthCall struct {
	n     int
	calls int
	src   io.Reader
}

func (f *failingReadOnNthCall) Read(p []byte) (int, error) {
	f.calls++
	if f.calls == f.n {
		return 0, errors.New("synthetic")
	}
	return f.src.Read(p)
}

func TestClientStartFailsWhenRandFails(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	rng := &failingReadOnNthCall{n: 1, src: rand.Reader}
	c, err := NewClient(ClientOptions{
		ServerKey:    serverLongPub,
		OurPublicKey: clientLongPub,
		OurSecretKey: &clientLongSec,
		Rand:         rng,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); !errors.Is(err, ErrCryptoRand) {
		t.Fatalf("Start = %v, want ErrCryptoRand", err)
	}
}

func TestClientReceiveWelcomeEmitsValidInitiate(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	mdC := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
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
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Drive the server side manually with codec primitives so we can
	// build a valid WELCOME without depending on ServerState yet.
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	helloOpenShared := precompute(clientTransPub, &serverLongSec) // s × C'
	if _, err := parseHello(hello, helloOpenShared); err != nil {
		t.Fatalf("server-side parseHello: %v", err)
	}

	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, err := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	if err != nil {
		t.Fatalf("sealCookie: %v", err)
	}
	welcomeShared := precompute(clientTransPub, &serverLongSec) // s × C'
	welcome, err := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)
	if err != nil {
		t.Fatalf("encodeWelcome: %v", err)
	}

	out, done, err := c.Receive(welcome)
	if err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	if done {
		t.Fatalf("done=true after WELCOME, want false")
	}
	if out == nil || out.Name != initiateCommandName {
		t.Fatalf("out = %+v, want INITIATE", out)
	}

	// Open INITIATE with the server's afterReady = s' × C'.
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	gotCookie, gotVouch, gotLongPub, gotMeta, err := parseInitiate(*out, afterReadyServer)
	if err != nil {
		t.Fatalf("parseInitiate: %v", err)
	}
	if gotCookie != ck {
		t.Fatalf("cookie not echoed verbatim")
	}
	if gotLongPub != clientLongPub {
		t.Fatalf("client long pub = %x, want %x", gotLongPub, clientLongPub)
	}
	// Vouch authenticates (C' || S) under c × S; we open it via box.Open.
	gotC1, gotS, err := openVouch(gotVouch, clientLongPub, &serverLongSec)
	if err != nil {
		t.Fatalf("openVouch: %v", err)
	}
	if gotC1 != clientTransPub {
		t.Fatalf("vouch C' = %x, want %x", gotC1, clientTransPub)
	}
	if gotS != serverLongPub {
		t.Fatalf("vouch S = %x, want %x", gotS, serverLongPub)
	}
	if v, ok := gotMeta.Get("Socket-Type"); !ok || string(v) != "DEALER" {
		t.Fatalf("INITIATE Socket-Type = %q, want DEALER", v)
	}
}

func TestClientReceiveBeforeStart(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if _, _, err := c.Receive(wire.Command{Name: welcomeCommandName}); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Receive before Start = %v, want ErrNotStarted", err)
	}
}

func TestClientReceiveMalformedWelcome(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	bad := wire.Command{Name: welcomeCommandName, Data: []byte{0x01}}
	if _, _, err := c.Receive(bad); !errors.Is(err, ErrMalformedWelcome) {
		t.Fatalf("err = %v, want ErrMalformedWelcome", err)
	}
}

func TestClientReceiveTamperedWelcome(t *testing.T) {
	// Build a real WELCOME, flip a bit, expect ErrBoxOpen.
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	welcome, _ := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)

	welcome.Data[len(welcome.Data)-1] ^= 0x01
	if _, _, err := c.Receive(welcome); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

// silence unused-import warning if a refactor removes references.
var _ = bytes.Equal
var _ wire.Frame
