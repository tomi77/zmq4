package zmq4_test

import (
	"net"
	"testing"

	"github.com/tomi77/zmq4"
)

func TestSocketAPIExists(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	s := zmq4.NewSocket(c1)
	_ = s // Recv, RecvMsg, Send, SendMsg, RecvFrame, SendFrame must exist
}
