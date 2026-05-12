// router-dealer demonstrates asynchronous request-reply via ROUTER+DEALER.
// Unlike REQ/REP, DEALER does not enforce strict alternation, enabling
// pipelining and load-balancing patterns.
// Run: go run ./examples/router-dealer/
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

	router := zmq4.NewROUTER(zmq4.WithNULL())
	if err := router.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer router.Close()

	const workers = 2
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("worker-%d", id+1)
			dealer := zmq4.NewDEALER(zmq4.WithNULL(), zmq4.WithIdentity([]byte(name)))
			if err := dealer.Connect(ctx, ep); err != nil {
				return
			}
			defer dealer.Close()

			if err := dealer.Send(ctx, zmq4.NewStringMsg("task")); err != nil {
				return
			}
			reply, err := dealer.Recv(ctx)
			if err != nil {
				return
			}
			fmt.Printf("%s received: %s\n", name, reply.String())
		}(i)
	}

	// Service two worker requests.
	for range workers {
		msg, err := router.Recv(ctx)
		if err != nil {
			panic(err)
		}
		if msg.Frames() < 2 {
			continue
		}
		identity := msg.Frame(0)
		payload := msg.Frame(msg.Frames() - 1)
		fmt.Printf("ROUTER received from %q: %s\n", string(identity), string(payload))
		_ = router.Send(ctx, zmq4.NewMsg(identity, []byte("done")))
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
