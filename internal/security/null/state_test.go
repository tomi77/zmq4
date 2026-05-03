package null

import (
	"errors"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestNewReturnsNotDone(t *testing.T) {
	s := New(nil)
	if s.Done() {
		t.Fatalf("new state must not be Done")
	}
}

func TestStartEmitsReadyWithLocalMetadata(t *testing.T) {
	md := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REQ")},
	}
	s := New(md)
	cmd, err := s.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if cmd.Name != wire.ReadyCommandName {
		t.Fatalf("Start emitted command %q, want READY", cmd.Name)
	}
	rc, err := wire.ParseReady(cmd)
	if err != nil {
		t.Fatalf("ParseReady on Start output: %v", err)
	}
	if len(rc.Metadata) != 1 ||
		string(rc.Metadata[0].Name) != "Socket-Type" ||
		string(rc.Metadata[0].Value) != "REQ" {
		t.Fatalf("Start metadata = %+v, want Socket-Type=REQ", rc.Metadata)
	}
}

func TestStartTwiceReturnsAlreadyStarted(t *testing.T) {
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	_, err := s.Start()
	if !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start error = %v, want ErrAlreadyStarted", err)
	}
}

func TestStartWithEmptyMetadata(t *testing.T) {
	s := New(nil)
	cmd, err := s.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	rc, err := wire.ParseReady(cmd)
	if err != nil {
		t.Fatalf("ParseReady: %v", err)
	}
	if len(rc.Metadata) != 0 {
		t.Fatalf("expected empty metadata, got %+v", rc.Metadata)
	}
}
