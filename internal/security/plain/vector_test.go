package plain

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func parseAsCommand(t *testing.T, raw []byte) wire.Command {
	t.Helper()
	cmd, err := wire.ParseCommand(raw)
	if err != nil {
		t.Fatalf("ParseCommand: %v", err)
	}
	return cmd
}

func TestVectorHelloEmpty(t *testing.T) {
	raw := readVector(t, "plain-hello-empty.bin")
	cmd := parseAsCommand(t, raw)
	body, err := parseHello(cmd)
	if err != nil {
		t.Fatalf("parseHello: %v", err)
	}
	if len(body.Username) != 0 || len(body.Password) != 0 {
		t.Fatalf("hello = %+v, want empty", body)
	}
	// Re-encode and compare bytes.
	cmd2, err := encodeHello(body)
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	raw2, err := wire.EncodeCommand(cmd2)
	if err != nil {
		t.Fatalf("EncodeCommand: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("re-encoded bytes differ: got %x want %x", raw2, raw)
	}
}

func TestVectorHelloCreds(t *testing.T) {
	raw := readVector(t, "plain-hello-creds.bin")
	cmd := parseAsCommand(t, raw)
	body, err := parseHello(cmd)
	if err != nil {
		t.Fatalf("parseHello: %v", err)
	}
	if string(body.Username) != "admin" || string(body.Password) != "secret" {
		t.Fatalf("hello = %+v, want admin/secret", body)
	}
}

func TestVectorWelcome(t *testing.T) {
	raw := readVector(t, "plain-welcome.bin")
	cmd := parseAsCommand(t, raw)
	if err := parseWelcome(cmd); err != nil {
		t.Fatalf("parseWelcome: %v", err)
	}
}

func TestVectorInitiateEmpty(t *testing.T) {
	raw := readVector(t, "plain-initiate-empty.bin")
	cmd := parseAsCommand(t, raw)
	if cmd.Name != initiateCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, initiateCommandName)
	}
	md, err := wire.ParseMetadata(cmd.Data)
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if len(md) != 0 {
		t.Fatalf("metadata = %+v, want empty", md)
	}
}

func TestVectorInitiateWithSocketType(t *testing.T) {
	raw := readVector(t, "plain-initiate-with-socket-type.bin")
	cmd := parseAsCommand(t, raw)

	// Drive Receive end-to-end: server consumes INITIATE → emits READY.
	s := NewServer(func(_, _ []byte) error { return nil }, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	out, done, err := s.Receive(cmd)
	if err != nil || !done || out == nil {
		t.Fatalf("Receive(INITIATE): out=%v done=%v err=%v", out, done, err)
	}
	if v, ok := s.PeerMetadata().Get("Socket-Type"); !ok || string(v) != "DEALER" {
		t.Fatalf("Socket-Type = %q, want DEALER", v)
	}
}

func TestVectorReadyWithIdentity(t *testing.T) {
	raw := readVector(t, "plain-ready-with-identity.bin")
	cmd := parseAsCommand(t, raw)
	rc, err := wire.ParseReady(cmd)
	if err != nil {
		t.Fatalf("ParseReady: %v", err)
	}
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if v, ok := rc.Metadata.Get("Identity"); !ok || !bytes.Equal(v, want) {
		t.Fatalf("Identity = %x, want %x", v, want)
	}
}

func TestVectorErrorAuthFailed(t *testing.T) {
	raw := readVector(t, "plain-error-auth-failed.bin")
	cmd := parseAsCommand(t, raw)

	// Drive client.Receive(ERROR) at the AWAIT_WELCOME step.
	c, err := NewClient(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err = c.Receive(cmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("Receive(ERROR) = %v, want ErrPeerError", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("Authentication failed")) {
		t.Fatalf("error %q does not contain peer reason", err)
	}
}
