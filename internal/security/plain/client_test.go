package plain

import (
	"bytes"
	"errors"
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
