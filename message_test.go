package zmq4

import (
	"bytes"
	"testing"
)

func TestMessageIsSliceOfSlices(t *testing.T) {
	msg := Message{[]byte("hello"), []byte("world")}
	if len(msg) != 2 {
		t.Fatalf("want 2 parts, got %d", len(msg))
	}
}

func TestNewMsgEmpty(t *testing.T) {
	m := NewMsg()
	if len(m) != 0 {
		t.Fatalf("want empty, got %v", m)
	}
}

func TestNewMsgFrames(t *testing.T) {
	m := NewMsg([]byte("a"), []byte("b"))
	if len(m) != 2 {
		t.Fatalf("want 2 frames, got %d", len(m))
	}
	if string(m[0]) != "a" || string(m[1]) != "b" {
		t.Fatalf("unexpected content: %v", m)
	}
}

func TestNewStringMsg(t *testing.T) {
	m := NewStringMsg("x", "y")
	if len(m) != 2 {
		t.Fatalf("want 2 frames, got %d", len(m))
	}
	if !bytes.Equal(m[0], []byte("x")) || !bytes.Equal(m[1], []byte("y")) {
		t.Fatalf("unexpected content: %v", m)
	}
}

func TestMessageFrames(t *testing.T) {
	if (Message{}).Frames() != 0 {
		t.Fatal("empty message: want 0")
	}
	m := Message{[]byte("a"), []byte("b")}
	if m.Frames() != 2 {
		t.Fatalf("want 2, got %d", m.Frames())
	}
}

func TestMessageFrame(t *testing.T) {
	m := Message{[]byte("hello")}
	if !bytes.Equal(m.Frame(0), []byte("hello")) {
		t.Fatalf("Frame(0): got %v", m.Frame(0))
	}
}

func TestMessageFramePanicsOutOfBounds(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	(Message{[]byte("x")}).Frame(1)
}

func TestMessageFramePanicsNegative(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	(Message{[]byte("x")}).Frame(-1)
}

func TestMessageString(t *testing.T) {
	if (Message{}).String() != "" {
		t.Fatal("empty message: want empty string")
	}
	if (Message{[]byte("hi")}).String() != "hi" {
		t.Fatalf("single frame: want 'hi'")
	}
	// Multi-frame: only frame 0.
	if (Message{[]byte("a"), []byte("b")}).String() != "a" {
		t.Fatal("multi-frame: want 'a' (frame 0 only)")
	}
}
