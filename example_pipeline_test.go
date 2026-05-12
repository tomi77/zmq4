package zmq4_test

import (
	"context"
	"fmt"

	"github.com/tomi77/zmq4"
)

// Example_pipeline demonstrates the Pipeline pattern (RFC 30).
// PUSH distributes tasks; PULL receives them.
func Example_pipeline() {
	ctx := context.Background()

	pull := zmq4.NewPULL(zmq4.WithNULL())
	if err := pull.Bind(ctx, "inproc://ex-pipeline"); err != nil {
		return
	}
	defer pull.Close()

	push := zmq4.NewPUSH(zmq4.WithNULL())
	if err := push.Connect(ctx, "inproc://ex-pipeline"); err != nil {
		return
	}
	defer push.Close()

	if err := push.Send(ctx, zmq4.NewStringMsg("task-1")); err != nil {
		return
	}
	msg, err := pull.Recv(ctx)
	if err == nil {
		fmt.Println("PULL received:", msg.String())
	}
	// Output:
	// PULL received: task-1
}
