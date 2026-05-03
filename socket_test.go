package zmq4_test

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/tomi77/zmq4"
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
