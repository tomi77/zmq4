// pair demonstrates the Exclusive-Pair pattern (RFC 31).
// Two PAIR sockets form a single bidirectional channel between two peers.
// Run: go run ./examples/pair/
package main

import (
	"context"
	"fmt"
	"net"

	"github.com/tomi77/zmq4"
)

func main() {
	ctx := context.Background()
	ep := freePort()

	a := zmq4.NewPAIR(zmq4.WithNULL())
	if err := a.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer a.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		b := zmq4.NewPAIR(zmq4.WithNULL())
		if err := b.Connect(ctx, ep); err != nil {
			return
		}
		defer b.Close()

		msg, err := b.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("B received:", msg.String())
		_ = b.Send(ctx, zmq4.NewStringMsg("pong"))
	}()

	if err := a.Send(ctx, zmq4.NewStringMsg("ping")); err != nil {
		panic(err)
	}
	reply, err := a.Recv(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("A received:", reply.String())
	<-done
}

func freePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}
