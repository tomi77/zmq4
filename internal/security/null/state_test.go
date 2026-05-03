package null

import (
	"errors"
	"strings"
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

func TestReceivePeerReadyCompletesHandshake(t *testing.T) {
	peerCmd, err := wire.ReadyCommand{
		Metadata: wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("REP")},
			{Name: []byte("Identity"), Value: []byte("peer-1")},
		},
	}.Encode()
	if err != nil {
		t.Fatalf("encode peer READY: %v", err)
	}

	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	out, done, err := s.Receive(peerCmd)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if out != nil {
		t.Fatalf("Receive returned non-nil out=%+v, want nil for NULL", out)
	}
	if !done {
		t.Fatalf("Receive done=false, want true after peer READY")
	}
	if !s.Done() {
		t.Fatalf("Done() = false after successful Receive")
	}
	pm := s.PeerMetadata()
	if len(pm) != 2 ||
		string(pm[0].Name) != "Socket-Type" || string(pm[0].Value) != "REP" ||
		string(pm[1].Name) != "Identity" || string(pm[1].Value) != "peer-1" {
		t.Fatalf("PeerMetadata = %+v, want Socket-Type=REP,Identity=peer-1", pm)
	}
}

func TestReceiveErrorWrapsReason(t *testing.T) {
	errCmd, err := wire.ErrorCommand{Reason: "Invalid client"}.Encode()
	if err != nil {
		t.Fatalf("encode ERROR: %v", err)
	}

	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	_, done, err := s.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("Receive(ERROR) error = %v, want ErrPeerError", err)
	}
	if done {
		t.Fatalf("Receive(ERROR) done=true, want false")
	}
	if !strings.Contains(err.Error(), "Invalid client") {
		t.Fatalf("error %q does not include peer reason", err)
	}
	if s.Done() {
		t.Fatalf("Done()=true after ERROR")
	}
}

func TestReceiveBeforeStart(t *testing.T) {
	s := New(nil)
	cmd, _ := wire.ReadyCommand{}.Encode()
	_, _, err := s.Receive(cmd)
	if !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Receive before Start = %v, want ErrNotStarted", err)
	}
}

func TestReceiveMalformedReady(t *testing.T) {
	bad := wire.Command{
		Name: wire.ReadyCommandName,
		// Truncated metadata: nameLen=5 but only 2 bytes follow.
		Data: []byte{0x05, 'A', 'B'},
	}
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := s.Receive(bad)
	if !errors.Is(err, ErrMalformedReady) {
		t.Fatalf("Receive(malformed) = %v, want ErrMalformedReady", err)
	}
}

func TestReceiveUnexpectedCommand(t *testing.T) {
	cmd := wire.Command{Name: "PING", Data: nil}
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := s.Receive(cmd)
	if !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("Receive(PING) = %v, want ErrUnexpectedCommand", err)
	}
}

func TestReceiveAfterDone(t *testing.T) {
	peerCmd, _ := wire.ReadyCommand{}.Encode()
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(peerCmd); err != nil {
		t.Fatalf("first Receive: %v", err)
	}
	_, _, err := s.Receive(peerCmd)
	if !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("second Receive = %v, want ErrAlreadyDone", err)
	}
}

func TestReceiveAfterFailed(t *testing.T) {
	cmd := wire.Command{Name: "PING"}
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(cmd); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("first Receive: %v", err)
	}
	_, _, err := s.Receive(cmd)
	if !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Receive after failure = %v, want ErrAlreadyFailed", err)
	}
}

func TestStartAfterFailedReturnsAlreadyFailed(t *testing.T) {
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(wire.Command{Name: "PING"}); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("Receive: %v", err)
	}
	_, err := s.Start()
	if !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Start after failure = %v, want ErrAlreadyFailed", err)
	}
}
