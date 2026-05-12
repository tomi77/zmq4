// xpubxsub-proxy demonstrates a publish-subscribe forwarding proxy.
// Publishers connect to the XSUB frontend; subscribers connect to the XPUB backend.
// The proxy forwards messages and subscription frames between the two sides.
// Run: go run ./examples/xpubxsub-proxy/
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/tomi77/zmq4"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	frontEP := freePort() // publishers connect here (XSUB)
	backEP := freePort()  // subscribers connect here (XPUB)

	// Proxy frontend: XSUB receives from publishers.
	xsub := zmq4.NewXSUB(zmq4.WithNULL())
	if err := xsub.Bind(ctx, frontEP); err != nil {
		panic(err)
	}
	defer xsub.Close()

	// Proxy backend: XPUB forwards to subscribers.
	xpub := zmq4.NewXPUB(zmq4.WithNULL())
	if err := xpub.Bind(ctx, backEP); err != nil {
		panic(err)
	}
	defer xpub.Close()

	// Subscriber connects to the XPUB backend.
	sub := zmq4.NewSUB(zmq4.WithNULL())
	if err := sub.Connect(ctx, backEP); err != nil {
		panic(err)
	}
	defer sub.Close()
	if err := sub.Subscribe(""); err != nil { // subscribe-all
		panic(err)
	}

	// Proxy loop: forward subscription frames (XPUB→XSUB) and messages (XSUB→XPUB).
	// In production this runs in its own goroutine indefinitely.
	go func() {
		for {
			// Forward subscription frames from backend to frontend.
			subFrame, err := xpub.Recv(ctx)
			if err != nil {
				return
			}
			if err := xsub.Send(ctx, subFrame); err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			// Forward messages from frontend to backend.
			msg, err := xsub.Recv(ctx)
			if err != nil {
				return
			}
			if err := xpub.Send(ctx, msg); err != nil {
				return
			}
		}
	}()

	// Publisher connects to the XSUB frontend.
	pub := zmq4.NewPUB(zmq4.WithNULL())
	if err := pub.Connect(ctx, frontEP); err != nil {
		panic(err)
	}
	defer pub.Close()

	// Allow subscriptions to propagate through the proxy.
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		msg, err := sub.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("Subscriber received:", msg.String())
	}()

	if err := pub.Send(ctx, zmq4.NewStringMsg("hello via proxy")); err != nil {
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
