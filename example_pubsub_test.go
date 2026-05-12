package zmq4_test

import (
	"context"
	"fmt"
	"time"

	"github.com/tomi77/zmq4"
)

// Example_pubsub demonstrates the Publish-Subscribe pattern (RFC 29).
// SUB subscribes to a topic prefix; PUB broadcasts to all matching subscribers.
func Example_pubsub() {
	ctx := context.Background()

	pub := zmq4.NewPUB(zmq4.WithNULL())
	if err := pub.Bind(ctx, "inproc://ex-pubsub"); err != nil {
		return
	}
	defer pub.Close()

	sub := zmq4.NewSUB(zmq4.WithNULL())
	if err := sub.Connect(ctx, "inproc://ex-pubsub"); err != nil {
		return
	}
	defer sub.Close()
	if err := sub.Subscribe("news"); err != nil {
		return
	}

	// Allow the subscription frame to propagate before publishing.
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		msg, err := sub.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("SUB received:", msg.String())
	}()

	_ = pub.Send(ctx, zmq4.NewStringMsg("news:flash"))
	<-done
	// Output:
	// SUB received: news:flash
}
