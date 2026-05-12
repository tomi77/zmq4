// hello-world demonstrates the Request-Reply pattern (RFC 28).
// Run: go run ./examples/hello-world/
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

	rep := zmq4.NewREP(zmq4.WithNULL())
	if err := rep.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer rep.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		req := zmq4.NewREQ(zmq4.WithNULL())
		if err := req.Connect(ctx, ep); err != nil {
			return
		}
		defer req.Close()

		if err := req.Send(ctx, zmq4.NewStringMsg("Hello")); err != nil {
			return
		}
		msg, err := req.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("Client received:", msg.String())
	}()

	msg, err := rep.Recv(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Server received:", msg.String())
	if err := rep.Send(ctx, zmq4.NewStringMsg("World")); err != nil {
		panic(err)
	}
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
