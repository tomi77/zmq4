package zmq4_test

import (
	"testing"

	"github.com/tomi77/zmq4"
)

func TestMessageIsSliceOfSlices(t *testing.T) {
	msg := zmq4.Message{[]byte("hello"), []byte("world")}
	if len(msg) != 2 {
		t.Fatalf("want 2 parts, got %d", len(msg))
	}
}
