package main

import (
	"context"

	"github.com/tomi77/zmq4"
)

func main() {
	sub := zmq4.NewSUB(zmq4.WithNULL())
	ctx := context.Background()

	if err := sub.Connect(ctx, "tcp://192.168.21.12:5556"); err != nil {
		panic(err)
	}
	if err := sub.Subscribe(""); err != nil {
		panic(err)
	}

	for {
		msg, err := sub.Recv(ctx)
		if err != nil {
			panic(err)
		}
		for _, frame := range msg {
			println("Received:", string(frame))
		}
	}
}
