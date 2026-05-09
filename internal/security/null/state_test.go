package null

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tomi77/zmq4/internal/security"
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
	cmd, err := wire.ReadyCommand{}.Encode()
	if err != nil {
		t.Fatalf("encode READY: %v", err)
	}
	_, _, err = s.Receive(cmd)
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
	peerCmd, err := wire.ReadyCommand{}.Encode()
	if err != nil {
		t.Fatalf("encode READY: %v", err)
	}
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(peerCmd); err != nil {
		t.Fatalf("first Receive: %v", err)
	}
	_, _, err = s.Receive(peerCmd)
	if !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("second Receive = %v, want ErrAlreadyDone", err)
	}
	// Pin the side-effect: the duplicate Receive sets s.failed, so any
	// subsequent call now returns ErrAlreadyFailed.
	if _, err := s.Start(); !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Start after AlreadyDone = %v, want ErrAlreadyFailed", err)
	}
}

// TestStartAfterSuccessfulDone verifies that Start on a successfully
// completed (but not misused) state machine returns ErrAlreadyStarted,
// not ErrAlreadyFailed. DONE is a terminal success state until misuse
// transitions it to FAILED.
func TestStartAfterSuccessfulDone(t *testing.T) {
	peerCmd, err := wire.ReadyCommand{}.Encode()
	if err != nil {
		t.Fatalf("encode READY: %v", err)
	}
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(peerCmd); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	_, err = s.Start()
	if !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("Start after Done = %v, want ErrAlreadyStarted", err)
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

// TestPeerMetadataIndependentOfInputBuffer verifies that PeerMetadata
// survives the caller mutating (or freeing) the buffer that backed the
// Receive input. F4 will read frames into reusable buffers; null.State
// must not retain pointers into them.
func TestPeerMetadataIndependentOfInputBuffer(t *testing.T) {
	original, err := wire.ReadyCommand{
		Metadata: wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
		},
	}.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Copy into a buffer we own and can clobber afterwards.
	// Name is a string constant ("READY"); only Data aliases buf.
	buf := make([]byte, len(original.Data))
	copy(buf, original.Data)
	peerCmd := wire.Command{Name: original.Name, Data: buf}

	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(peerCmd); err != nil {
		t.Fatalf("Receive: %v", err)
	}

	// Clobber the input buffer.
	for i := range buf {
		buf[i] = 0xFF
	}

	pm := s.PeerMetadata()
	if len(pm) != 1 {
		t.Fatalf("PeerMetadata len = %d, want 1 (metadata lost?)", len(pm))
	}
	if string(pm[0].Name) != "Socket-Type" {
		t.Fatalf("PeerMetadata[0].Name = %q, want Socket-Type (buffer aliasing?)", pm[0].Name)
	}
	if string(pm[0].Value) != "DEALER" {
		t.Fatalf("PeerMetadata[0].Value = %q, want DEALER (buffer aliasing?)", pm[0].Value)
	}
}

func TestNullWrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	s := New(nil)
	f := wire.Frame{Kind: wire.FrameMessage, Body: []byte("hi")}
	if _, err := s.Wrap(f); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("Wrap before Done = %v, want security.ErrNotDone", err)
	}
}

func TestNullUnwrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	s := New(nil)
	f := wire.Frame{Kind: wire.FrameMessage, Body: []byte("hi")}
	if _, err := s.Unwrap(f); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("Unwrap before Done = %v, want security.ErrNotDone", err)
	}
}

func TestNullWrapPassthrough(t *testing.T) {
	s := newDoneState(t)
	want := wire.Frame{Kind: wire.FrameMessage, More: true, Body: []byte("payload")}
	got, err := s.Wrap(want)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if got.Kind != want.Kind || got.More != want.More || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("Wrap mutated frame: got=%+v want=%+v", got, want)
	}
}

func TestNullWrapAliasesInputBody(t *testing.T) {
	s := newDoneState(t)
	body := []byte("payload")
	in := wire.Frame{Kind: wire.FrameMessage, Body: body}
	got, err := s.Wrap(in)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	// NULL is pass-through: returned Body must alias the input.
	if len(got.Body) > 0 && len(body) > 0 && &got.Body[0] != &body[0] {
		t.Fatalf("Wrap allocated a new buffer; pass-through must alias input")
	}
}

func TestNullUnwrapPassthrough(t *testing.T) {
	s := newDoneState(t)
	want := wire.Frame{Kind: wire.FrameMessage, More: false, Body: []byte("payload")}
	got, err := s.Unwrap(want)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got.Kind != want.Kind || got.More != want.More || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("Unwrap mutated frame: got=%+v want=%+v", got, want)
	}
}

func TestStateName(t *testing.T) {
	s := New(nil)
	if got := s.Name(); got != "NULL" {
		t.Fatalf("Name() = %q, want %q", got, "NULL")
	}
}

// --- ZAP tests ---

type mockZAP struct {
	code string
	uid  string
	meta wire.Metadata
	err  error
}

func (m *mockZAP) Authenticate(domain, address, identity, mechanism string, credentials [][]byte) (string, string, wire.Metadata, error) {
	return m.code, m.uid, m.meta, m.err
}

func TestNullServerZAPAllow(t *testing.T) {
	s := New(nil)
	s.ConfigureZAP(&mockZAP{code: "200", uid: "alice"}, "test")
	s.SetPeerAddr("1.2.3.4:9000")

	// Server must Start() first.
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	peerReady, _ := wire.ReadyCommand{}.Encode()
	out, done, err := s.Receive(peerReady)
	if err != nil {
		t.Fatalf("Receive: unexpected error %v", err)
	}
	if out != nil {
		t.Fatalf("out = %v, want nil", out)
	}
	if !done {
		t.Fatal("done = false, want true")
	}
}

func TestNullServerZAPDeny(t *testing.T) {
	s := New(nil)
	s.ConfigureZAP(&mockZAP{code: "400"}, "test")
	s.SetPeerAddr("1.2.3.4:9000")

	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	peerReady, _ := wire.ReadyCommand{}.Encode()
	out, done, err := s.Receive(peerReady)
	if !errors.Is(err, security.ErrZAPDenied) {
		t.Fatalf("err = %v, want ErrZAPDenied", err)
	}
	if done {
		t.Fatal("done = true, want false")
	}
	if out == nil {
		t.Fatal("out = nil, want ERROR command")
	}
	if out.Name != wire.ErrorCommandName {
		t.Fatalf("out.Name = %q, want ERROR", out.Name)
	}
}

func TestNullServerZAPMetadataMerge(t *testing.T) {
	zapMeta := wire.Metadata{
		{Name: []byte("X-Role"), Value: []byte("admin")},
	}
	s := New(nil)
	s.ConfigureZAP(&mockZAP{code: "200", meta: zapMeta}, "test")
	s.SetPeerAddr("127.0.0.1:1")

	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	peerReady, _ := wire.ReadyCommand{
		Metadata: wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("PUSH")}},
	}.Encode()
	_, done, err := s.Receive(peerReady)
	if err != nil || !done {
		t.Fatalf("Receive: done=%v err=%v", done, err)
	}

	meta := s.PeerMetadata()
	v, ok := meta.Get("X-Role")
	if !ok || string(v) != "admin" {
		t.Fatalf("PeerMetadata X-Role = %q ok=%v, want admin", v, ok)
	}
	v, ok = meta.Get("Socket-Type")
	if !ok || string(v) != "PUSH" {
		t.Fatalf("PeerMetadata Socket-Type = %q ok=%v, want PUSH", v, ok)
	}
}

func TestNullServerNoZAPUnchanged(t *testing.T) {
	// Without ZAP, existing behaviour unchanged.
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	peerReady, _ := wire.ReadyCommand{}.Encode()
	_, done, err := s.Receive(peerReady)
	if err != nil || !done {
		t.Fatalf("Receive: done=%v err=%v", done, err)
	}
}

// newDoneState drives the NULL handshake to completion using a paired
// peer-side State so the test does not have to hand-craft READY bytes.
// Helper for the Wrap/Unwrap tests above.
func newDoneState(t *testing.T) *State {
	t.Helper()
	a := New(nil)
	if _, err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	peerReady, err := wire.ReadyCommand{}.Encode()
	if err != nil {
		t.Fatalf("encode peer READY: %v", err)
	}
	if _, _, err := a.Receive(peerReady); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !a.Done() {
		t.Fatalf("not done after Receive(READY)")
	}
	return a
}
