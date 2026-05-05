package plain

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tomi77/zmq4/internal/security"
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

func TestServerReceiveHelloRejectEmitsErrorAndFails(t *testing.T) {
	rejecter := func(_, _ []byte) error { return errors.New("denied") }
	s := NewServer(rejecter, nil)
	hello, _ := encodeHello(helloBody{Username: []byte("u"), Password: []byte("p")})

	out, done, err := s.Receive(hello)
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("err = %v, want ErrAuthRejected", err)
	}
	if done {
		t.Fatalf("done=true on auth reject, want false")
	}
	if out == nil || out.Name != wire.ErrorCommandName {
		t.Fatalf("out = %+v, want ERROR command", out)
	}
	ec, perr := wire.ParseError(*out)
	if perr != nil {
		t.Fatalf("ParseError(out): %v", perr)
	}
	if ec.Reason != "denied" {
		t.Fatalf("reason = %q, want \"denied\"", ec.Reason)
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Fatalf("err %q does not include reason", err)
	}
}

func TestServerAuthRejectReasonSanitized(t *testing.T) {
	dirty := "bad creds\n\x00user=alice"
	rejecter := func(_, _ []byte) error { return errors.New(dirty) }
	s := NewServer(rejecter, nil)
	hello, _ := encodeHello(helloBody{})

	out, _, _ := s.Receive(hello)
	ec, _ := wire.ParseError(*out)
	if strings.ContainsAny(ec.Reason, "\n\x00") {
		t.Fatalf("reason %q has non-VCHAR bytes", ec.Reason)
	}
	if len(ec.Reason) != len(dirty) {
		t.Fatalf("len(reason) = %d, want %d", len(ec.Reason), len(dirty))
	}
}

func TestServerAuthRejectReasonTruncated(t *testing.T) {
	long := strings.Repeat("a", 300)
	rejecter := func(_, _ []byte) error { return errors.New(long) }
	s := NewServer(rejecter, nil)
	hello, _ := encodeHello(helloBody{})

	out, _, _ := s.Receive(hello)
	ec, _ := wire.ParseError(*out)
	if len(ec.Reason) != 255 {
		t.Fatalf("len(reason) = %d, want 255", len(ec.Reason))
	}
}

func TestServerReceiveAfterAuthReject(t *testing.T) {
	rejecter := func(_, _ []byte) error { return errors.New("nope") }
	s := NewServer(rejecter, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("first Receive: %v", err)
	}
	_, _, err := s.Receive(hello)
	if !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Receive after reject = %v, want ErrAlreadyFailed", err)
	}
}

func TestServerReceiveInitiateCompletesHandshake(t *testing.T) {
	s := NewServer(acceptAll, wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REP")},
	})
	hello, _ := encodeHello(helloBody{Username: []byte("u"), Password: []byte("p")})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}

	clientMeta := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REQ")},
		{Name: []byte("Identity"), Value: []byte("client-1")},
	}
	initiate := wire.Command{
		Name: initiateCommandName,
		Data: wire.EncodeMetadata(clientMeta),
	}

	out, done, err := s.Receive(initiate)
	if err != nil {
		t.Fatalf("Receive(INITIATE): %v", err)
	}
	if !done {
		t.Fatalf("done=false after INITIATE, want true")
	}
	if out == nil || out.Name != wire.ReadyCommandName {
		t.Fatalf("out = %+v, want READY", out)
	}
	rc, perr := wire.ParseReady(*out)
	if perr != nil {
		t.Fatalf("ParseReady(out): %v", perr)
	}
	if v, ok := rc.Metadata.Get("Socket-Type"); !ok || string(v) != "REP" {
		t.Fatalf("READY Socket-Type = %q, want REP", v)
	}
	if !s.Done() {
		t.Fatalf("Done()=false after success")
	}
	pm := s.PeerMetadata()
	if v, ok := pm.Get("Identity"); !ok || string(v) != "client-1" {
		t.Fatalf("PeerMetadata Identity = %q, want client-1", v)
	}
}

func TestServerPeerMetadataIndependentOfInputBuffer(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}

	originalData := wire.EncodeMetadata(wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
	})
	buf := make([]byte, len(originalData))
	copy(buf, originalData)
	initiate := wire.Command{Name: initiateCommandName, Data: buf}

	if _, _, err := s.Receive(initiate); err != nil {
		t.Fatalf("Receive(INITIATE): %v", err)
	}

	for i := range buf {
		buf[i] = 0xFF
	}
	pm := s.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "DEALER" {
		t.Fatalf("PeerMetadata after clobber = %q, want DEALER", v)
	}
}

func TestServerReceiveMalformedHello(t *testing.T) {
	s := NewServer(acceptAll, nil)
	bad := wire.Command{Name: helloCommandName, Data: []byte{0xFF}} // claims 255-byte username, no body
	_, _, err := s.Receive(bad)
	if !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestServerReceiveUnexpectedCommandAtHelloStep(t *testing.T) {
	s := NewServer(acceptAll, nil)
	cmd := wire.Command{Name: "PING"}
	_, _, err := s.Receive(cmd)
	if !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestServerReceiveUnexpectedCommandAtInitiateStep(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	_, _, err := s.Receive(wire.Command{Name: "PING"})
	if !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestServerReceiveMalformedInitiate(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	bad := wire.Command{Name: initiateCommandName, Data: []byte{0x05, 'A'}}
	_, _, err := s.Receive(bad)
	if !errors.Is(err, ErrMalformedInitiate) {
		t.Fatalf("err = %v, want ErrMalformedInitiate", err)
	}
}

func TestServerReceiveErrorAtHelloStep(t *testing.T) {
	s := NewServer(acceptAll, nil)
	errCmd, _ := wire.ErrorCommand{Reason: "client gives up"}.Encode()
	_, _, err := s.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("err = %v, want ErrPeerError", err)
	}
	if !strings.Contains(err.Error(), "client gives up") {
		t.Fatalf("error %q does not include reason", err)
	}
}

func TestServerReceiveErrorAtInitiateStep(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	errCmd, _ := wire.ErrorCommand{Reason: "client aborts"}.Encode()
	_, _, err := s.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("err = %v, want ErrPeerError", err)
	}
}

func TestServerReceiveAfterDone(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	initiate := wire.Command{Name: initiateCommandName, Data: wire.EncodeMetadata(nil)}
	if _, _, err := s.Receive(initiate); err != nil {
		t.Fatalf("Receive(INITIATE): %v", err)
	}
	_, _, err := s.Receive(initiate)
	if !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("err = %v, want ErrAlreadyDone", err)
	}
}

func TestPlainServerWrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	s := NewServer(acceptAll, nil)
	f := wire.Frame{Kind: wire.FrameMessage, Body: []byte("x")}
	if _, err := s.Wrap(f); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("Wrap before Done = %v, want security.ErrNotDone", err)
	}
}

func TestPlainServerUnwrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	s := NewServer(acceptAll, nil)
	f := wire.Frame{Kind: wire.FrameMessage, Body: []byte("x")}
	if _, err := s.Unwrap(f); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("Unwrap before Done = %v, want security.ErrNotDone", err)
	}
}

func TestPlainServerWrapPassthrough(t *testing.T) {
	s := newPlainServerDone(t)
	want := wire.Frame{Kind: wire.FrameMessage, More: true, Body: []byte("payload")}
	got, err := s.Wrap(want)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if got.Kind != want.Kind || got.More != want.More || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("Wrap mutated frame: got=%+v want=%+v", got, want)
	}
}

func TestPlainServerUnwrapPassthrough(t *testing.T) {
	s := newPlainServerDone(t)
	want := wire.Frame{Kind: wire.FrameMessage, More: false, Body: []byte("payload")}
	got, err := s.Unwrap(want)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got.Kind != want.Kind || got.More != want.More || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("Unwrap mutated frame: got=%+v want=%+v", got, want)
	}
}

func newPlainServerDone(t *testing.T) *ServerState {
	t.Helper()
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{Username: []byte("u"), Password: []byte("p")})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	initiate := wire.Command{Name: initiateCommandName, Data: wire.EncodeMetadata(nil)}
	if _, _, err := s.Receive(initiate); err != nil {
		t.Fatalf("Receive(INITIATE): %v", err)
	}
	if !s.Done() {
		t.Fatalf("not done")
	}
	return s
}
