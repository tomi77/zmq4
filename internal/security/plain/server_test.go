package plain

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func acceptAll(_, _ []byte) error { return nil }

func TestNewServerNilAuthPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("NewServer(nil, ...) did not panic")
		}
	}()
	_ = NewServer(nil, nil)
}

func TestNewServerNotDone(t *testing.T) {
	s := NewServer(acceptAll, nil)
	if s.Done() {
		t.Fatalf("new server is Done()")
	}
}

func TestServerReceiveHelloAcceptEmitsWelcome(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, err := encodeHello(helloBody{Username: []byte("u"), Password: []byte("p")})
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
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
	if len(out.Data) != 0 {
		t.Fatalf("WELCOME body = %x, want empty", out.Data)
	}
}

// silence unused imports if the rest of the file doesn't use them yet.
var (
	_ = bytes.Equal
	_ = errors.Is
	_ = strings.Contains
	_ = wire.Command{}
)
