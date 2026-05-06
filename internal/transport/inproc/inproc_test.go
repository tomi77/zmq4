package inproc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tomi77/zmq4/internal/transport"
)

func TestListenEmptyName(t *testing.T) {
	_, err := Listen(context.Background(), "")
	if !errors.Is(err, transport.ErrEndpointMalformed) {
		t.Fatalf("Listen(\"\") err = %v, want ErrEndpointMalformed", err)
	}
}

func TestListenAlreadyBound(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()

	lis1, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis1.Close()

	_, err = Listen(ctx, name)
	if !errors.Is(err, transport.ErrInprocAlreadyBound) {
		t.Fatalf("second Listen err = %v, want ErrInprocAlreadyBound", err)
	}
}

func TestListenAddr(t *testing.T) {
	name := "test/" + t.Name()
	lis, err := Listen(context.Background(), name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()
	a := lis.Addr()
	if a.Network() != "inproc" {
		t.Fatalf("Addr.Network() = %q, want \"inproc\"", a.Network())
	}
	if a.String() != name {
		t.Fatalf("Addr.String() = %q, want %q", a.String(), name)
	}
}

func TestDialPostBindRoundTrip(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()
	lis, err := Listen(ctx, name)
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

	dc, err := Dial(ctx, name)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dc.Close()
	got := <-ch
	if got.e != nil {
		t.Fatalf("Accept: %v", got.e)
	}
	defer got.c.Close()

	want := []byte("hello over inproc")
	go func() {
		_, _ = dc.Write(want)
	}()
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(got.c, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("recv = %q, want %q", buf, want)
	}
}

func TestConnectBlocksUntilBind(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := Dial(ctx, name)
		ch <- p{c, e}
	}()

	// Give Dial time to block.
	select {
	case got := <-ch:
		t.Fatalf("Dial returned before Listen: conn=%v err=%v", got.c, got.e)
	case <-time.After(50 * time.Millisecond):
		// Expected: still blocked.
	}

	lis, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	// Accept the paired conn.
	ach := make(chan net.Conn, 1)
	go func() {
		c, _ := lis.Accept()
		ach <- c
	}()

	select {
	case got := <-ch:
		if got.e != nil {
			t.Fatalf("Dial after Listen err = %v", got.e)
		}
		defer got.c.Close()
		ac := <-ach
		defer ac.Close()
		// Round-trip a tiny payload.
		want := []byte("paired")
		go func() { _, _ = got.c.Write(want) }()
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(ac, buf); err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
		if !bytes.Equal(buf, want) {
			t.Fatalf("recv = %q, want %q", buf, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("Dial did not unblock after Listen within 1s")
	}
}
