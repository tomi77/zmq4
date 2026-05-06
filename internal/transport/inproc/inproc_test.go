package inproc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
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

func TestConnectCancelledByContext(t *testing.T) {
	parent := context.Background()
	name := "test/" + t.Name()
	ctx, cancel := context.WithTimeout(parent, 25*time.Millisecond)
	defer cancel()

	c, err := Dial(ctx, name)
	if err == nil {
		c.Close()
		t.Fatalf("Dial = %v, want context error", c)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial err = %v, want errors.Is(context.DeadlineExceeded)", err)
	}

	// Verify pending entry is cleaned up.
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if list, ok := registry.pending[name]; ok && len(list) > 0 {
		t.Fatalf("pending[%q] = %d entries after cancel, want 0", name, len(list))
	}
}

func TestConnectCancelledManually(t *testing.T) {
	parent := context.Background()
	name := "test/" + t.Name()
	ctx, cancel := context.WithCancel(parent)

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := Dial(ctx, name)
		ch <- p{c, e}
	}()
	time.Sleep(20 * time.Millisecond) // let Dial enqueue
	cancel()

	got := <-ch
	if got.e == nil {
		t.Fatalf("Dial = %v, want cancel error", got.c)
	}
	if !errors.Is(got.e, context.Canceled) {
		t.Fatalf("err = %v, want errors.Is(context.Canceled)", got.e)
	}
}

func TestCloseUnblocksAccept(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()
	lis, err := Listen(ctx, name)
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
		if !errors.Is(e, net.ErrClosed) {
			t.Fatalf("Accept err = %v, want net.ErrClosed", e)
		}
	case <-time.After(time.Second):
		t.Fatalf("Accept did not unblock within 1s")
	}
}

func TestBindRebindAfterClose(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()

	lis1, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	if err := lis1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	lis2, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("second Listen: %v", err)
	}
	defer lis2.Close()
}

func TestPendingDialBetweenCloseAndRebind(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()

	// First lifecycle: Listen + Close immediately, no Dial in between.
	lis1, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	if err := lis1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Now Dial: name is unbound; Dial must block.
	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := Dial(ctx, name)
		ch <- p{c, e}
	}()
	select {
	case got := <-ch:
		t.Fatalf("Dial returned without Listen: conn=%v err=%v", got.c, got.e)
	case <-time.After(50 * time.Millisecond):
		// expected: blocked
	}

	// Second Listen — pairs the pending Dial via Listen-drain.
	lis2, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("second Listen: %v", err)
	}
	defer lis2.Close()
	go func() {
		c, _ := lis2.Accept()
		if c != nil {
			c.Close()
		}
	}()
	select {
	case got := <-ch:
		if got.e != nil {
			t.Fatalf("Dial err = %v", got.e)
		}
		got.c.Close()
	case <-time.After(time.Second):
		t.Fatalf("Dial did not pair with second Listen within 1s")
	}
}

func TestQueuedConnsDeliveredAfterClose(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()
	lis, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// Dial creates a pair, enqueues the accept side; Accept is not yet
	// called. Then Close.
	dc, err := Dial(ctx, name)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dc.Close()
	if err := lis.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// First Accept should still deliver the queued conn.
	ac, err := lis.Accept()
	if err != nil {
		t.Fatalf("Accept after Close (queue non-empty) err = %v, want conn", err)
	}
	ac.Close()

	// Second Accept must return ErrClosed.
	if _, err := lis.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after queue drained err = %v, want net.ErrClosed", err)
	}
}

// TestCancelRacingDrain stresses the case where ctx fires concurrently
// with Listen-drain. Either Dial wins the conn (drain raced first) or
// Dial returns ctx.Err and the orphan conn is closed. Both outcomes are
// valid; what's invalid is goroutine/fd leak or panic.
func TestCancelRacingDrain(t *testing.T) {
	parent := context.Background()
	for i := 0; i < 200; i++ {
		name := "test/race/" + t.Name() + "/" + strconv.Itoa(i)
		ctx, cancel := context.WithCancel(parent)

		type p struct {
			c net.Conn
			e error
		}
		ch := make(chan p, 1)
		go func() {
			c, e := Dial(ctx, name)
			ch <- p{c, e}
		}()
		// Schedule cancel and Listen at "the same time" — Go scheduler
		// arbitrates which goroutine wins.
		go cancel()
		lis, err := Listen(parent, name)
		if err != nil {
			t.Fatalf("[%d] Listen: %v", i, err)
		}
		// Drain Accept regardless of Dial outcome.
		go func() {
			c, _ := lis.Accept()
			if c != nil {
				c.Close()
			}
		}()

		got := <-ch
		switch {
		case got.e == nil && got.c != nil:
			got.c.Close() // Dial won the race
		case got.e != nil && got.c == nil:
			if !errors.Is(got.e, context.Canceled) && !errors.Is(got.e, context.DeadlineExceeded) {
				t.Fatalf("[%d] Dial err = %v, want context error", i, got.e)
			}
		default:
			t.Fatalf("[%d] inconsistent Dial result: c=%v err=%v", i, got.c, got.e)
		}

		_ = lis.Close()
	}
}

func TestDeadline(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()
	lis, _ := Listen(ctx, name)
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
	dc, _ := Dial(ctx, name)
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

func TestPeerCloseEOF(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()
	lis, _ := Listen(ctx, name)
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
	dc, _ := Dial(ctx, name)
	got := <-ch

	_ = dc.Close()
	buf := make([]byte, 4)
	_, err := got.c.Read(buf)
	if err == nil {
		t.Fatalf("Read after peer close = nil, want EOF")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read err = %v, want io.EOF", err)
	}
	got.c.Close()
}
