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

// silence unused-import warning if a refactor removes references.
var _ = bytes.Equal
var _ wire.Frame
