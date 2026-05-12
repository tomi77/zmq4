package zmq4_test

import (
	"context"
	"fmt"

	"github.com/tomi77/zmq4"
)

// Example_routerDealer demonstrates asynchronous request-reply via ROUTER+DEALER.
// DEALER sends a message carrying its identity; ROUTER routes the reply back.
func Example_routerDealer() {
	ctx := context.Background()

	router := zmq4.NewROUTER(zmq4.WithNULL())
	if err := router.Bind(ctx, "inproc://ex-router-dealer"); err != nil {
		return
	}
	defer router.Close()

	dealer := zmq4.NewDEALER(zmq4.WithNULL(), zmq4.WithIdentity([]byte("worker-1")))
	if err := dealer.Connect(ctx, "inproc://ex-router-dealer"); err != nil {
		return
	}
	defer dealer.Close()

	// DEALER sends a task.
	if err := dealer.Send(ctx, zmq4.NewStringMsg("task")); err != nil {
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		reply, err := dealer.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("DEALER received:", reply.String())
	}()

	// ROUTER receives [identity, payload...].
	msg, err := router.Recv(ctx)
	if err != nil || msg.Frames() < 2 {
		return
	}
	identity := msg.Frame(0)
	payload := msg.Frame(msg.Frames() - 1)
	fmt.Printf("ROUTER received from %q: %s\n", string(identity), string(payload))

	// Reply: prepend the identity so ROUTER routes it back.
	_ = router.Send(ctx, zmq4.NewMsg(identity, []byte("done")))
	<-done
	// Output:
	// ROUTER received from "worker-1": task
	// DEALER received: done
}
