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
