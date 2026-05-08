package conn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tomi77/zmq4/internal/security/null"
	"github.com/tomi77/zmq4/internal/security/plain"
	"github.com/tomi77/zmq4/internal/wire"
)

func TestEmitERRORHappyPath(t *testing.T) {
	var sink bytes.Buffer
	fw := wire.NewFrameWriter(&sink)
	emitERROR(fw, "no thanks")
	// The peer should see one FrameCommand containing an ERROR command
	// with reason "no thanks".
	fr := wire.NewFrameReader(&sink)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Kind != wire.FrameCommand {
		t.Fatalf("frame.Kind = %v, want FrameCommand", f.Kind)
	}
	cmd, err := wire.ParseCommand(f.Body)
	if err != nil {
		t.Fatalf("ParseCommand: %v", err)
	}
	ec, err := wire.ParseError(cmd)
	if err != nil {
		t.Fatalf("ParseError: %v", err)
	}
	if ec.Reason != "no thanks" {
		t.Fatalf("Reason = %q, want %q", ec.Reason, "no thanks")
	}
}

func TestEmitERRORTruncatesLongReason(t *testing.T) {
	long := strings.Repeat("x", 500)
	var sink bytes.Buffer
	fw := wire.NewFrameWriter(&sink)
	emitERROR(fw, long)
	fr := wire.NewFrameReader(&sink)
	f, _ := fr.ReadFrame()
	cmd, _ := wire.ParseCommand(f.Body)
	ec, err := wire.ParseError(cmd)
	if err != nil {
		t.Fatalf("ParseError: %v", err)
	}
	if len(ec.Reason) != 255 {
		t.Fatalf("Reason length = %d, want 255 (truncated)", len(ec.Reason))
	}
	if !strings.HasPrefix(ec.Reason, "xxxx") {
		t.Fatalf("Reason prefix unexpected: %q", ec.Reason[:10])
	}
}

func TestEmitERRORSwallowsWriteFailure(t *testing.T) {
	// Closed pipe → fw.WriteFrame returns io.ErrClosedPipe. emitERROR
	// must not panic and must return cleanly (it has no return value).
	a, b := net.Pipe()
	_ = a.Close()
	_ = b.Close()
	fw := wire.NewFrameWriter(a)
	emitERROR(fw, "doomed") // must not panic.
}

func TestRunWithCtxDeadlineSuccess(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	called := false
	err := runWithCtxDeadline(ctx, a, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("runWithCtxDeadline: %v", err)
	}
	if !called {
		t.Fatalf("inner fn was not invoked")
	}
	// After success, the deadline should be cleared so a fresh read on a
	// is not stuck with a past deadline.
	go func() { _, _ = b.Write([]byte{0xAA}) }()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(a, buf); err != nil {
		t.Fatalf("post-success read: %v (deadline not cleared?)", err)
	}
}

func TestRunWithCtxDeadlineCtxNoDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	err := runWithCtxDeadline(context.Background(), a, func() error {
		t.Fatalf("inner fn should NOT be called when ctx has no deadline")
		return nil
	})
	if !errors.Is(err, ErrNoDeadline) {
		t.Fatalf("err = %v, want ErrNoDeadline", err)
	}
}

func TestRunWithCtxDeadlineCtxCancelMidFn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := runWithCtxDeadline(ctx, a, func() error {
		// Block on a read; the ctx watcher will SetDeadline(past) and
		// unblock us with os.ErrDeadlineExceeded.
		buf := make([]byte, 1)
		_, err := io.ReadFull(a, buf)
		return err
	})
	if err == nil {
		t.Fatalf("expected error from cancelled handshake, got nil")
	}
}

// driveGreetingPair runs greetingExchange on both sides in goroutines
// and returns the two errors. Uses TCP loopback (not net.Pipe) so that
// the asymmetric send-ordering can complete without deadlocking when
// both peers happen to share the same role bit (the spec explicitly
// supports symmetric NULL conns and ErrRoleConflict for PLAIN/CURVE
// — both require a buffered transport, not net.Pipe's synchronous one).
func driveGreetingPair(t *testing.T, ourSide, peerSide greetingTestSide) (ourErr, peerErr error) {
	t.Helper()
	a, b := tcpPipePair(t)
	defer a.Close()
	defer b.Close()
	type res struct{ err error }
	ours := make(chan res, 1)
	peer := make(chan res, 1)
	go func() {
		err := greetingExchange(a, ourSide.role, ourSide.mech)
		ours <- res{err}
	}()
	go func() {
		err := greetingExchange(b, peerSide.role, peerSide.mech)
		peer <- res{err}
	}()
	return (<-ours).err, (<-peer).err
}

// tcpPipePair returns two connected TCP loopback net.Conns. Used by
// greeting tests that exercise role-symmetric scenarios: net.Pipe is
// synchronous (zero-buffer) so two simultaneous Writes deadlock; the
// TCP socket buffer accepts the 64-byte greeting without blocking and
// lets the test progress to the validation logic that is actually
// being exercised. The listener is closed inline once the pair is
// established (the pair's lifetime is independent of it).
func tcpPipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := lis.Accept()
		ch <- accepted{c, err}
	}()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	a, err := dialer.Dial("tcp", lis.Addr().String())
	if err != nil {
		_ = lis.Close()
		t.Fatalf("dial: %v", err)
	}
	res := <-ch
	if res.err != nil {
		_ = a.Close()
		_ = lis.Close()
		t.Fatalf("accept: %v", res.err)
	}
	_ = lis.Close() // listener is no longer needed; pair is established.
	return a, res.c
}

type greetingTestSide struct {
	role greetingRole // greetingRoleClient or greetingRoleServer
	mech mockMech
}

type mockMech struct {
	name string
}

func (m mockMech) Name() string { return m.name }

func TestGreetingExchangeNullBothSides(t *testing.T) {
	our, peer := driveGreetingPair(t,
		greetingTestSide{greetingRoleClient, mockMech{"NULL"}},
		greetingTestSide{greetingRoleServer, mockMech{"NULL"}})
	if our != nil || peer != nil {
		t.Fatalf("our=%v peer=%v, want both nil", our, peer)
	}
}

func TestGreetingExchangeMechanismMismatch(t *testing.T) {
	our, peer := driveGreetingPair(t,
		greetingTestSide{greetingRoleClient, mockMech{"NULL"}},
		greetingTestSide{greetingRoleServer, mockMech{"PLAIN"}})
	if !errors.Is(our, ErrMechanismMismatch) {
		t.Errorf("our: want ErrMechanismMismatch, got %v", our)
	}
	if !errors.Is(peer, ErrMechanismMismatch) {
		t.Errorf("peer: want ErrMechanismMismatch, got %v", peer)
	}
}

func TestGreetingExchangeRoleConflictPLAIN(t *testing.T) {
	our, peer := driveGreetingPair(t,
		greetingTestSide{greetingRoleServer, mockMech{"PLAIN"}},
		greetingTestSide{greetingRoleServer, mockMech{"PLAIN"}})
	// Both peers claim as-server=true → role conflict.
	if !errors.Is(our, ErrRoleConflict) && !errors.Is(peer, ErrRoleConflict) {
		t.Fatalf("expected ErrRoleConflict on at least one side, got our=%v peer=%v", our, peer)
	}
}

func TestGreetingExchangeRoleConflictNULLIgnored(t *testing.T) {
	// Two NULL "clients" (both as-server=0 since NULL is symmetric — the
	// greetingRoleClient enum maps to as-server=0). Should succeed.
	our, peer := driveGreetingPair(t,
		greetingTestSide{greetingRoleClient, mockMech{"NULL"}},
		greetingTestSide{greetingRoleClient, mockMech{"NULL"}})
	if our != nil || peer != nil {
		t.Fatalf("our=%v peer=%v, want both nil for symmetric NULL", our, peer)
	}
}

func TestGreetingFillerIgnored(t *testing.T) {
	// Hand-craft a greeting with non-zero filler. Validate it is accepted.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		var buf [wire.GreetingSize]byte
		_ = wire.EncodeGreeting(buf[:], wire.Greeting{Mechanism: "NULL"})
		// Stomp filler bytes 33..63 with garbage.
		for i := 33; i < 64; i++ {
			buf[i] = byte(0xAA + i&0x0F)
		}
		_, _ = b.Write(buf[:])
	}()
	if err := greetingExchange(a, greetingRoleServer, mockMech{"NULL"}); err != nil {
		t.Fatalf("greeting with garbage filler should be accepted, got %v", err)
	}
}

func TestGreetingPhaseAFailureAbortsBeforeRest(t *testing.T) {
	// Peer sends a corrupt signature (byte 0). Our side must abort with
	// ErrInvalidGreeting after reading phase A only — the remaining 53
	// bytes must NOT be read.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		// Send only the broken phase-A 11 bytes; do NOT send phase-B.
		bad := make([]byte, 11)
		bad[0] = 0xAA
		bad[9] = 0x7F
		bad[10] = 0x03
		_, _ = b.Write(bad)
	}()
	err := greetingExchange(a, greetingRoleServer, mockMech{"NULL"})
	if !errors.Is(err, ErrInvalidGreeting) && !errors.Is(err, wire.ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidGreeting or wire.ErrInvalidSignature", err)
	}
}

func TestGreetingVersionDowngradeAbortsBeforeRest(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		// Phase-A only with version major = 0x02 (ZMTP 2.x).
		bad := make([]byte, 11)
		bad[0] = 0xFF
		bad[9] = 0x7F
		bad[10] = 0x02
		_, _ = b.Write(bad)
	}()
	err := greetingExchange(a, greetingRoleServer, mockMech{"NULL"})
	if !errors.Is(err, wire.ErrUnsupportedVersion) {
		t.Fatalf("err = %v, want wire.ErrUnsupportedVersion", err)
	}
}

// Compile-time check: real mechanisms also satisfy mockMech's Name shape.
var _ = []interface{ Name() string }{
	(*null.State)(nil),
	(*plain.ClientState)(nil),
}
