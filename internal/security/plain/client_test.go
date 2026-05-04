package plain

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestNewClientRejectsLongUsername(t *testing.T) {
	long := bytes.Repeat([]byte("u"), 256)
	_, err := NewClient(long, []byte("p"), nil)
	if !errors.Is(err, ErrCredentialsTooLong) {
		t.Fatalf("err = %v, want ErrCredentialsTooLong", err)
	}
}

func TestNewClientRejectsLongPassword(t *testing.T) {
	long := bytes.Repeat([]byte("p"), 256)
	_, err := NewClient([]byte("u"), long, nil)
	if !errors.Is(err, ErrCredentialsTooLong) {
		t.Fatalf("err = %v, want ErrCredentialsTooLong", err)
	}
}

func TestNewClientNotDone(t *testing.T) {
	c, err := NewClient([]byte("u"), []byte("p"), nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Done() {
		t.Fatalf("new client is Done()")
	}
}

func TestClientStartEmitsHello(t *testing.T) {
	c, err := NewClient([]byte("admin"), []byte("secret"), nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	cmd, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if cmd.Name != helloCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, helloCommandName)
	}
	body, err := parseHello(cmd)
	if err != nil {
		t.Fatalf("parseHello: %v", err)
	}
	if !bytes.Equal(body.Username, []byte("admin")) {
		t.Fatalf("Username = %x, want admin", body.Username)
	}
	if !bytes.Equal(body.Password, []byte("secret")) {
		t.Fatalf("Password = %x, want secret", body.Password)
	}
}

func TestClientStartTwiceReturnsAlreadyStarted(t *testing.T) {
	c, err := NewClient(nil, nil, nil)
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

func TestClientReceiveWelcomeEmitsInitiate(t *testing.T) {
	c, err := NewClient([]byte("u"), []byte("p"), wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REQ")},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	out, done, err := c.Receive(encodeWelcome())
	if err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	if done {
		t.Fatalf("done=true after WELCOME, want false")
	}
	if out == nil {
		t.Fatalf("out=nil after WELCOME, want INITIATE")
	}
	if out.Name != initiateCommandName {
		t.Fatalf("out.Name = %q, want %q", out.Name, initiateCommandName)
	}
	md, err := wire.ParseMetadata(out.Data)
	if err != nil {
		t.Fatalf("ParseMetadata(INITIATE): %v", err)
	}
	if v, ok := md.Get("Socket-Type"); !ok || string(v) != "REQ" {
		t.Fatalf("INITIATE Socket-Type = %q, want REQ", v)
	}
}

func TestClientReceiveReadyCompletesHandshake(t *testing.T) {
	c, err := NewClient([]byte("u"), []byte("p"), nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}

	peerReady, err := wire.ReadyCommand{
		Metadata: wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("REP")},
			{Name: []byte("Identity"), Value: []byte("server-1")},
		},
	}.Encode()
	if err != nil {
		t.Fatalf("encode peer READY: %v", err)
	}

	out, done, err := c.Receive(peerReady)
	if err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}
	if !done {
		t.Fatalf("done=false after READY, want true")
	}
	if out != nil {
		t.Fatalf("out=%+v after READY, want nil", out)
	}
	if !c.Done() {
		t.Fatalf("Done()=false after successful Receive")
	}
	pm := c.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "REP" {
		t.Fatalf("PeerMetadata Socket-Type = %q, want REP", v)
	}
	if v, ok := pm.Get("Identity"); !ok || string(v) != "server-1" {
		t.Fatalf("PeerMetadata Identity = %q, want server-1", v)
	}
}

func TestClientPeerMetadataIndependentOfInputBuffer(t *testing.T) {
	original, err := wire.ReadyCommand{
		Metadata: wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
		},
	}.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	buf := make([]byte, len(original.Data))
	copy(buf, original.Data)
	peerReady := wire.Command{Name: original.Name, Data: buf}

	c, err := NewClient(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	if _, _, err := c.Receive(peerReady); err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}

	for i := range buf {
		buf[i] = 0xFF
	}
	pm := c.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "DEALER" {
		t.Fatalf("PeerMetadata after clobber = %q, want DEALER", v)
	}
}

func TestClientReceiveBeforeStart(t *testing.T) {
	c, _ := NewClient(nil, nil, nil)
	_, _, err := c.Receive(encodeWelcome())
	if !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Receive before Start = %v, want ErrNotStarted", err)
	}
}

func TestClientReceiveErrorAtWelcomeStep(t *testing.T) {
	errCmd, _ := wire.ErrorCommand{Reason: "go away"}.Encode()
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := c.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("err = %v, want ErrPeerError", err)
	}
	if !strings.Contains(err.Error(), "go away") {
		t.Fatalf("error %q does not include reason", err)
	}
}

func TestClientReceiveErrorAtReadyStep(t *testing.T) {
	errCmd, _ := wire.ErrorCommand{Reason: "denied"}.Encode()
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	_, _, err := c.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("err = %v, want ErrPeerError", err)
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Fatalf("error %q does not include reason", err)
	}
}

func TestClientReceiveUnexpectedCommandAtWelcomeStep(t *testing.T) {
	cmd := wire.Command{Name: "PING"}
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := c.Receive(cmd)
	if !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestClientReceiveUnexpectedCommandAtReadyStep(t *testing.T) {
	cmd := wire.Command{Name: "PING"}
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	_, _, err := c.Receive(cmd)
	if !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestClientReceiveMalformedWelcome(t *testing.T) {
	bad := wire.Command{Name: welcomeCommandName, Data: []byte{0xAA}}
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := c.Receive(bad)
	if !errors.Is(err, ErrMalformedWelcome) {
		t.Fatalf("err = %v, want ErrMalformedWelcome", err)
	}
}

func TestClientReceiveMalformedReady(t *testing.T) {
	bad := wire.Command{
		Name: wire.ReadyCommandName,
		// nameLen=5 but only 2 bytes follow
		Data: []byte{0x05, 'A', 'B'},
	}
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	_, _, err := c.Receive(bad)
	if !errors.Is(err, ErrMalformedReady) {
		t.Fatalf("err = %v, want ErrMalformedReady", err)
	}
}

func TestClientReceiveAfterDone(t *testing.T) {
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	peerReady, _ := wire.ReadyCommand{}.Encode()
	if _, _, err := c.Receive(peerReady); err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}
	_, _, err := c.Receive(peerReady)
	if !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("Receive after done = %v, want ErrAlreadyDone", err)
	}
}

func TestClientReceiveAfterFailed(t *testing.T) {
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(wire.Command{Name: "PING"}); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("first Receive: %v", err)
	}
	_, _, err := c.Receive(wire.Command{Name: "PING"})
	if !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Receive after failure = %v, want ErrAlreadyFailed", err)
	}
}

func TestClientStartAfterFailedReturnsAlreadyFailed(t *testing.T) {
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(wire.Command{Name: "PING"}); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("Receive: %v", err)
	}
	_, err := c.Start()
	if !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Start after failure = %v, want ErrAlreadyFailed", err)
	}
}
