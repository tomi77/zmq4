//go:build !windows

package ipc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomi77/zmq4/internal/transport"
)

func newSocketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "zmq.sock")
}

func TestListenDialRoundTrip(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, err := Listen(ctx, path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()

	dc, err := Dial(ctx, path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dc.Close()
	got := <-ch
	if got.e != nil {
		t.Fatalf("Accept: %v", got.e)
	}
	defer got.c.Close()

	want := []byte("hello over ipc")
	if _, err := dc.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(got.c, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("recv = %q, want %q", buf, want)
	}
}

func TestListenEmptyPath(t *testing.T) {
	ctx := context.Background()
	_, err := Listen(ctx, "")
	if !errors.Is(err, transport.ErrEndpointMalformed) {
		t.Fatalf("Listen(\"\") err = %v, want ErrEndpointMalformed", err)
	}
}

func TestDialEmptyPath(t *testing.T) {
	ctx := context.Background()
	_, err := Dial(ctx, "")
	if !errors.Is(err, transport.ErrEndpointMalformed) {
		t.Fatalf("Dial(\"\") err = %v, want ErrEndpointMalformed", err)
	}
}

func TestDeadline(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, _ := Listen(ctx, path)
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()
	dc, _ := Dial(ctx, path)
	defer dc.Close()
	got := <-ch
	defer got.c.Close()

	_ = dc.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buf := make([]byte, 4)
	_, err := dc.Read(buf)
	if err == nil {
		t.Fatalf("Read with past deadline = nil, want timeout")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read err = %v, want net.Error{Timeout=true}", err)
	}
	_, _ = os.Stat(path) // touch to silence unused-import vet on go1.x; harmless
}

func TestUnlinkOnClose(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, err := Listen(ctx, path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("socket file missing after Listen: %v", err)
	}
	if err := lis.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket file still exists after Close: stat err = %v", err)
	}
}

func TestFileMode0600(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, err := Listen(ctx, path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode = %o, want 0600", mode)
	}
}

func TestStaleSocketRebind(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)

	// Simulate stale socket by creating a regular file at the path (a
	// crashed process would leave the actual socket node behind; for our
	// purposes a regular file produces the same EADDRINUSE-class failure
	// from net.ListenUnix).
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create stale: %v", err)
	}
	f.Close()

	_, err = Listen(ctx, path)
	if err == nil {
		t.Fatalf("Listen on stale path = nil, want bind failure")
	}
	if !strings.Contains(err.Error(), "transport/ipc:") {
		t.Fatalf("err = %q, want \"transport/ipc:\" prefix", err.Error())
	}
}

func TestCloseUnblocksRead(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, _ := Listen(ctx, path)
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()
	dc, _ := Dial(ctx, path)
	got := <-ch

	_ = got.c.Close()
	buf := make([]byte, 4)
	_, err := dc.Read(buf)
	if err == nil {
		t.Fatalf("Read after peer close = nil, want EOF")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read err = %v, want io.EOF", err)
	}
	dc.Close()
}

func TestCloseUnblocksAccept(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, err := Listen(ctx, path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, e := lis.Accept()
		errCh <- e
	}()
	time.Sleep(20 * time.Millisecond)
	_ = lis.Close()
	select {
	case e := <-errCh:
		if e == nil {
			t.Fatalf("Accept after Close = nil, want error")
		}
	case <-time.After(time.Second):
		t.Fatalf("Accept did not unblock within 1s")
	}
}
