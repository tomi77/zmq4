package zmq4_test

import (
	"context"
	"fmt"

	"github.com/tomi77/zmq4"
)

// Example_pair demonstrates the Exclusive-Pair pattern (RFC 31).
// Two PAIR sockets form a single bidirectional channel.
func Example_pair() {
	ctx := context.Background()

	a := zmq4.NewPAIR(zmq4.WithNULL())
	if err := a.Bind(ctx, "inproc://ex-pair"); err != nil {
		return
	}
	defer a.Close()

	b := zmq4.NewPAIR(zmq4.WithNULL())
	if err := b.Connect(ctx, "inproc://ex-pair"); err != nil {
		return
	}
	defer b.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		msg, err := b.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("B received:", msg.String())
		_ = b.Send(ctx, zmq4.NewStringMsg("pong"))
	}()

	if err := a.Send(ctx, zmq4.NewStringMsg("ping")); err != nil {
		return
	}
	reply, err := a.Recv(ctx)
	if err == nil {
		fmt.Println("A received:", reply.String())
	}
	<-done
	// Output:
	// B received: ping
	// A received: pong
}
