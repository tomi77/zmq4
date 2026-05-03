package null

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestVectorReadyEmpty(t *testing.T) {
	raw := readVector(t, "null-ready-empty.bin")
	cmd := parseAsCommand(t, raw)
	rc, err := wire.ParseReady(cmd)
	if err != nil {
		t.Fatalf("ParseReady: %v", err)
	}
	if len(rc.Metadata) != 0 {
		t.Fatalf("metadata = %+v, want empty", rc.Metadata)
	}
	cmd2, err := rc.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	raw2, err := wire.EncodeCommand(cmd2)
	if err != nil {
		t.Fatalf("EncodeCommand: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("re-encoded bytes differ: got %x want %x", raw2, raw)
	}
}

func TestVectorReadySocketTypeReq(t *testing.T) {
	raw := readVector(t, "null-ready-socket-type-req.bin")
	cmd := parseAsCommand(t, raw)

	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(cmd); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	pm := s.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "REQ" {
		t.Fatalf("Socket-Type = %q, want REQ", v)
	}
}

func TestVectorReadyWithIdentity(t *testing.T) {
	raw := readVector(t, "null-ready-with-identity.bin")
	cmd := parseAsCommand(t, raw)
	rc, err := wire.ParseReady(cmd)
	if err != nil {
		t.Fatalf("ParseReady: %v", err)
	}
	if len(rc.Metadata) != 2 {
		t.Fatalf("metadata len = %d, want 2", len(rc.Metadata))
	}
	if v, ok := rc.Metadata.Get("Socket-Type"); !ok || string(v) != "ROUTER" {
		t.Fatalf("Socket-Type = %q, want ROUTER", v)
	}
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if v, ok := rc.Metadata.Get("Identity"); !ok || !bytes.Equal(v, want) {
		t.Fatalf("Identity = %x, want %x", v, want)
	}
}

func TestVectorError(t *testing.T) {
	raw := readVector(t, "null-error.bin")
	cmd := parseAsCommand(t, raw)

	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := s.Receive(cmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("Receive(ERROR) = %v, want ErrPeerError", err)
	}
	if !strings.Contains(err.Error(), "Invalid client") {
		t.Fatalf("error %q does not contain peer reason", err)
	}
}
