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
