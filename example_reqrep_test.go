package zmq4_test

import (
	"context"
	"fmt"

	"github.com/tomi77/zmq4"
)

// Example_reqrep demonstrates the Request-Reply pattern (RFC 28).
// REQ sends a request; REP receives it, prints it, and sends a reply.
func Example_reqrep() {
	ctx := context.Background()

	rep := zmq4.NewREP(zmq4.WithNULL())
	if err := rep.Bind(ctx, "inproc://ex-reqrep"); err != nil {
		return
	}
	defer rep.Close()

	req := zmq4.NewREQ(zmq4.WithNULL())
	if err := req.Connect(ctx, "inproc://ex-reqrep"); err != nil {
		return
	}
	defer req.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		msg, err := rep.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("REP received:", msg.String())
		_ = rep.Send(ctx, zmq4.NewStringMsg("pong"))
	}()

	if err := req.Send(ctx, zmq4.NewStringMsg("ping")); err != nil {
		return
	}
	reply, err := req.Recv(ctx)
	if err == nil {
		fmt.Println("REQ received:", reply.String())
	}
	<-done
	// Output:
	// REP received: ping
	// REQ received: pong
}
