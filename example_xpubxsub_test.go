package zmq4_test

import (
	"context"
	"fmt"

	"github.com/tomi77/zmq4"
)

// ExampleXPUB_recvSubscription demonstrates the extended Publish-Subscribe
// pattern. Unlike PUB, XPUB can receive subscription frames from subscribers,
// enabling dynamic subscription management and proxy topologies.
func ExampleXPUB_recvSubscription() {
	ctx := context.Background()

	xpub := zmq4.NewXPUB(zmq4.WithNULL())
	if err := xpub.Bind(ctx, "inproc://ex-xpub"); err != nil {
		return
	}
	defer xpub.Close()

	xsub := zmq4.NewXSUB(zmq4.WithNULL())
	if err := xsub.Connect(ctx, "inproc://ex-xpub"); err != nil {
		return
	}
	defer xsub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// XSUB.Subscribe sends a raw subscription frame upstream to XPUB.
		_ = xsub.Subscribe("prices")
	}()

	// XPUB.Recv returns the raw subscription frame: byte 0x01 + topic.
	frame, err := xpub.Recv(ctx)
	<-done
	if err != nil || frame.Frames() == 0 || len(frame.Frame(0)) == 0 {
		return
	}
	raw := frame.Frame(0)
	if raw[0] == 0x01 {
		fmt.Printf("XPUB sees subscribe for topic %q\n", string(raw[1:]))
	}
	// Output:
	// XPUB sees subscribe for topic "prices"
}
