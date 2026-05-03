package zmq4_test

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/tomi77/zmq4"
	"github.com/tomi77/zmq4/internal/wire"
)

func TestSocketAPIExists(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	s := zmq4.NewSocket(c1)
	_ = s // Recv, RecvMsg, Send, SendMsg, RecvFrame, SendFrame must exist
}

// TestRecvReturnsOwnedSlice verifies that mutating a Recv result does not
// affect the socket's internal state: the same payload can be received again
// unmodified.
func TestRecvReturnsOwnedSlice(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	sender := zmq4.NewSocket(c1)
	receiver := zmq4.NewSocket(c2)

	payload := []byte("hello")
	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	// Receiver goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()

		// First receive
		got, err := receiver.Recv()
		if err != nil {
			errCh <- err
			return
		}
		if string(got) != "hello" {
			errCh <- fmt.Errorf("want %q, got %q", "hello", got)
			return
		}

		// Mutate the received slice — must not affect socket internals.
		for i := range got {
			got[i] = 'X'
		}

		// Second receive
		got2, err := receiver.Recv()
		if err != nil {
			errCh <- err
			return
		}
		if string(got2) != "hello" {
			errCh <- fmt.Errorf("mutation of first Recv result corrupted second receive: got %q", got2)
			return
		}
	}()

	// Sender goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()

		// First send
		if err := sender.Send(payload); err != nil {
			errCh <- err
			return
		}

		// Second send
		if err := sender.Send(payload); err != nil {
			errCh <- err
		}
	}()

	wg.Wait()

	// Check for any errors
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

// TestRecvMsgPartsAreOwned verifies that mutating parts of a RecvMsg result
// does not affect subsequent receives.
func TestRecvMsgPartsAreOwned(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	sender := zmq4.NewSocket(c1)
	receiver := zmq4.NewSocket(c2)

	want := zmq4.Message{[]byte("part1"), []byte("part2")}
	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	// Receiver goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()

		// First receive
		got, err := receiver.RecvMsg()
		if err != nil {
			errCh <- err
			return
		}
		if len(got) != 2 {
			errCh <- fmt.Errorf("want 2 parts, got %d", len(got))
			return
		}

		// Mutate all parts.
		for _, part := range got {
			for i := range part {
				part[i] = 'X'
			}
		}

		// Second receive
		got2, err := receiver.RecvMsg()
		if err != nil {
			errCh <- err
			return
		}
		if string(got2[0]) != "part1" || string(got2[1]) != "part2" {
			errCh <- fmt.Errorf("mutation of first RecvMsg result corrupted second receive: got %q %q", got2[0], got2[1])
			return
		}
	}()

	// Sender goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()

		// First send
		if err := sender.SendMsg(want); err != nil {
			errCh <- err
			return
		}

		// Second send
		if err := sender.SendMsg(want); err != nil {
			errCh <- err
		}
	}()

	wg.Wait()

	// Check for any errors
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

// TestRecvFrameBodyAliasesBuffer verifies that successive RecvFrame calls
// reuse the same backing array when the frame body length does not change.
func TestRecvFrameBodyAliasesBuffer(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	sender := zmq4.NewSocket(c1)
	receiver := zmq4.NewSocket(c2)

	errCh := make(chan error, 4)

	// Sender goroutine: send "first" then "secnd" (both exactly 5 bytes).
	go func() {
		if err := sender.SendFrame(wire.Frame{Kind: wire.FrameMessage, Body: []byte("first")}); err != nil {
			errCh <- fmt.Errorf("send first: %w", err)
			return
		}
		if err := sender.SendFrame(wire.Frame{Kind: wire.FrameMessage, Body: []byte("secnd")}); err != nil {
			errCh <- fmt.Errorf("send secnd: %w", err)
		}
	}()

	// First receive.
	f1, err := receiver.RecvFrame()
	if err != nil {
		t.Fatalf("RecvFrame 1: %v", err)
	}
	if string(f1.Body) != "first" {
		t.Fatalf("want %q, got %q", "first", f1.Body)
	}
	ptr1 := &f1.Body[0]

	// Second receive — same body length, so buffer is reused.
	f2, err := receiver.RecvFrame()
	if err != nil {
		t.Fatalf("RecvFrame 2: %v", err)
	}
	if string(f2.Body) != "secnd" {
		t.Fatalf("want %q, got %q", "secnd", f2.Body)
	}

	// Both frames must alias the same backing array.
	if &f2.Body[0] != ptr1 {
		t.Fatalf("buffer was not reused: ptr1=%p, &f2.Body[0]=%p", ptr1, &f2.Body[0])
	}
	// f1.Body must have been overwritten by the second receive.
	if string(f1.Body) != "secnd" {
		t.Fatalf("aliasing contract: f1.Body should be %q after second RecvFrame, got %q", "secnd", f1.Body)
	}

	// Drain sender errors.
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

// TestRecvFrameCloneDetaches verifies that Clone produces an independent copy
// that is unaffected by a subsequent RecvFrame overwriting the shared buffer.
func TestRecvFrameCloneDetaches(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	sender := zmq4.NewSocket(c1)
	receiver := zmq4.NewSocket(c2)

	errCh := make(chan error, 4)

	// Sender goroutine.
	go func() {
		if err := sender.SendFrame(wire.Frame{Kind: wire.FrameMessage, Body: []byte("hello")}); err != nil {
			errCh <- fmt.Errorf("send hello: %w", err)
			return
		}
		if err := sender.SendFrame(wire.Frame{Kind: wire.FrameMessage, Body: []byte("world")}); err != nil {
			errCh <- fmt.Errorf("send world: %w", err)
		}
	}()

	// First receive, then clone before the second receive.
	f1, err := receiver.RecvFrame()
	if err != nil {
		t.Fatalf("RecvFrame 1: %v", err)
	}
	cloned := f1.Clone()

	// Second receive — this overwrites the shared buffer aliased by f1.Body.
	if _, err := receiver.RecvFrame(); err != nil {
		t.Fatalf("RecvFrame 2: %v", err)
	}

	// cloned must still hold the original value.
	if string(cloned.Body) != "hello" {
		t.Fatalf("Clone did not detach: cloned.Body = %q, want %q", cloned.Body, "hello")
	}

	// Drain sender errors.
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

// TestRecvFrameInvalidAfterNextCall documents the aliasing contract: a frame's
// Body is valid only until the next RecvFrame call on the same socket.
// No assertions are made about f1.Body content after the second receive,
// because its value is undefined at that point.
func TestRecvFrameInvalidAfterNextCall(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	sender := zmq4.NewSocket(c1)
	receiver := zmq4.NewSocket(c2)

	errCh := make(chan error, 4)

	// Sender goroutine.
	go func() {
		if err := sender.SendFrame(wire.Frame{Kind: wire.FrameMessage, Body: []byte("first")}); err != nil {
			errCh <- fmt.Errorf("send first: %w", err)
			return
		}
		if err := sender.SendFrame(wire.Frame{Kind: wire.FrameMessage, Body: []byte("second")}); err != nil {
			errCh <- fmt.Errorf("send second: %w", err)
		}
	}()

	f1, err := receiver.RecvFrame()
	if err != nil {
		t.Fatalf("RecvFrame 1: %v", err)
	}
	_ = f1 // Body valid here

	// Second RecvFrame invalidates f1.Body per the aliasing contract.
	if _, err := receiver.RecvFrame(); err != nil {
		t.Fatalf("RecvFrame 2: %v", err)
	}

	t.Log("aliasing contract holds: f1.Body must not be used after second RecvFrame")

	// Drain sender errors.
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}
