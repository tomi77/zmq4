package zmq4_test

import (
	"bytes"
	"testing"

	"github.com/tomi77/zmq4"
)

func TestMessageIsSliceOfSlices(t *testing.T) {
	msg := zmq4.Message{[]byte("hello"), []byte("world")}
	if len(msg) != 2 {
		t.Fatalf("want 2 parts, got %d", len(msg))
	}
}

func TestNewMsgEmpty(t *testing.T) {
	m := zmq4.NewMsg()
	if len(m) != 0 {
		t.Fatalf("want empty, got %v", m)
	}
}

func TestNewMsgFrames(t *testing.T) {
	m := zmq4.NewMsg([]byte("a"), []byte("b"))
	if len(m) != 2 {
		t.Fatalf("want 2 frames, got %d", len(m))
	}
	if string(m[0]) != "a" || string(m[1]) != "b" {
		t.Fatalf("unexpected content: %v", m)
	}
}

func TestNewStringMsg(t *testing.T) {
	m := zmq4.NewStringMsg("x", "y")
	if len(m) != 2 {
		t.Fatalf("want 2 frames, got %d", len(m))
	}
	if !bytes.Equal(m[0], []byte("x")) || !bytes.Equal(m[1], []byte("y")) {
		t.Fatalf("unexpected content: %v", m)
	}
}
