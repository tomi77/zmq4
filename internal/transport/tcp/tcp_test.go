package tcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestListenDialRoundTrip(t *testing.T) {
	ctx := context.Background()
	lis, err := Listen(ctx, "127.0.0.1:*")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	addr := lis.Addr().String()
	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, e := lis.Accept()
		ch <- accepted{c, e}
	}()

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	dc, err := Dial(dialCtx, addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dc.Close()

	got := <-ch
	if got.err != nil {
		t.Fatalf("Accept: %v", got.err)
	}
	defer got.c.Close()

	want := []byte("hello over tcp")
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

func TestCloseUnblocksAccept(t *testing.T) {
	ctx := context.Background()
	lis, err := Listen(ctx, "127.0.0.1:*")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, e := lis.Accept()
		errCh <- e
	}()

	time.Sleep(20 * time.Millisecond) // let Accept park
	if err := lis.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case e := <-errCh:
		if e == nil {
			t.Fatalf("Accept after Close = nil error, want non-nil")
		}
	case <-time.After(time.Second):
		t.Fatalf("Accept did not unblock within 1s")
	}
}

func TestListenAlreadyBound(t *testing.T) {
	ctx := context.Background()
	lis1, err := Listen(ctx, "127.0.0.1:*")
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	defer lis1.Close()
	addr := lis1.Addr().String()

	_, err = Listen(ctx, addr)
	if err == nil {
		t.Fatalf("second Listen on %s = nil error, want EADDRINUSE-class", addr)
	}
	// Wrapped via fmt.Errorf("transport/tcp: listen ...: %w", ...).
	// We don't pin syscall.EADDRINUSE because OS-level errno wrapping
	// varies; just verify the wrapper prefix.
	if !strings.Contains(err.Error(), "transport/tcp:") {
		t.Fatalf("err = %q, want \"transport/tcp:\" prefix", err.Error())
	}
}

func TestCloseUnblocksRead(t *testing.T) {
	ctx := context.Background()
	lis, _ := Listen(ctx, "127.0.0.1:*")
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
	dc, _ := Dial(ctx, lis.Addr().String())
	got := <-ch

	// Peer (got.c) closes; reader on dc must observe EOF.
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

func TestReadDeadline(t *testing.T) {
	ctx := context.Background()
	lis, _ := Listen(ctx, "127.0.0.1:*")
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

	dc, _ := Dial(ctx, lis.Addr().String())
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
}
