// pipeline demonstrates the Pipeline pattern (RFC 30).
// A ventilator (PUSH) distributes tasks; workers (PULL) receive them.
// Run: go run ./examples/pipeline/
package main

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/tomi77/zmq4"
)

func main() {
	ctx := context.Background()
	ep := freePort()

	push := zmq4.NewPUSH(zmq4.WithNULL())
	if err := push.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer push.Close()

	const workers = 3
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pull := zmq4.NewPULL(zmq4.WithNULL())
			if err := pull.Connect(ctx, ep); err != nil {
				return
			}
			defer pull.Close()
			msg, err := pull.Recv(ctx)
			if err != nil {
				return
			}
			fmt.Printf("Worker %d received: %s\n", id, msg.String())
		}(i + 1)
	}

	for i := range workers {
		task := fmt.Sprintf("task-%d", i+1)
		if err := push.Send(ctx, zmq4.NewStringMsg(task)); err != nil {
			panic(err)
		}
	}
	wg.Wait()
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
