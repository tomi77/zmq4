// pubsub demonstrates the Publish-Subscribe pattern (RFC 29).
// Run: go run ./examples/pubsub/
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/tomi77/zmq4"
)

func main() {
	ctx := context.Background()
	ep := freePort()

	pub := zmq4.NewPUB(zmq4.WithNULL())
	if err := pub.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer pub.Close()

	sub := zmq4.NewSUB(zmq4.WithNULL())
	if err := sub.Connect(ctx, ep); err != nil {
		panic(err)
	}
	defer sub.Close()
	if err := sub.Subscribe("prices"); err != nil {
		panic(err)
	}

	// Allow subscription to propagate.
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		msg, err := sub.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("Subscriber received:", msg.String())
	}()

	topics := []string{"prices:EUR/USD:1.0850", "news:ignored", "prices:BTC/USD:60000"}
	for _, t := range topics {
		if err := pub.Send(ctx, zmq4.NewStringMsg(t)); err != nil {
			panic(err)
		}
		fmt.Println("Publisher sent:", t)
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
