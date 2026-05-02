package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestFrameWireSize(t *testing.T) {
	cases := []struct {
		name string
		f    Frame
		want int
	}{
		{"empty-message", Frame{Kind: FrameMessage, Body: nil}, 2},                       // 1 flag + 1 size
		{"short-message-1", Frame{Kind: FrameMessage, Body: []byte{0xAA}}, 3},            // 1+1+1
		{"short-boundary-255", Frame{Kind: FrameMessage, Body: make([]byte, 255)}, 257},  // 1+1+255
		{"long-boundary-256", Frame{Kind: FrameMessage, Body: make([]byte, 256)}, 265},   // 1+8+256
		{"empty-command", Frame{Kind: FrameCommand, Body: nil}, 2},
		{"short-command-1", Frame{Kind: FrameCommand, Body: []byte{0xAA}}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.f.WireSize(); got != c.want {
				t.Fatalf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestEncodeFrameShortMessage(t *testing.T) {
	body := []byte("hello")
	f := Frame{Kind: FrameMessage, Body: body}
	var buf [16]byte
	n, err := EncodeFrame(buf[:], f)
	if err != nil {
		t.Fatal(err)
	}
	if n != f.WireSize() {
		t.Fatalf("n=%d, want %d", n, f.WireSize())
	}
	want := []byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("got %x, want %x", buf[:n], want)
	}
}

func TestEncodeFrameShortMessageMore(t *testing.T) {
	f := Frame{Kind: FrameMessage, More: true, Body: []byte("X")}
	var buf [4]byte
	n, err := EncodeFrame(buf[:], f)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x01, 0x01, 'X'}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("got %x, want %x", buf[:n], want)
	}
}

func TestEncodeFrameLongMessage(t *testing.T) {
	body := bytes.Repeat([]byte{0xAB}, 300)
	f := Frame{Kind: FrameMessage, Body: body}
	buf := make([]byte, f.WireSize())
	if _, err := EncodeFrame(buf, f); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x02 {
		t.Fatalf("flags=0x%02X, want 0x02 (long message, no MORE)", buf[0])
	}
	if got := binary.BigEndian.Uint64(buf[1:9]); got != 300 {
		t.Fatalf("size=%d, want 300", got)
	}
	if !bytes.Equal(buf[9:], body) {
		t.Fatal("body mismatch")
	}
}

func TestEncodeFrameShortCommand(t *testing.T) {
	f := Frame{Kind: FrameCommand, Body: []byte("READY")}
	buf := make([]byte, f.WireSize())
	if _, err := EncodeFrame(buf, f); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x04 {
		t.Fatalf("flags=0x%02X, want 0x04", buf[0])
	}
	if buf[1] != 5 {
		t.Fatalf("size=%d, want 5", buf[1])
	}
}

func TestEncodeFrameLongCommand(t *testing.T) {
	body := bytes.Repeat([]byte{0xCD}, 500)
	f := Frame{Kind: FrameCommand, Body: body}
	buf := make([]byte, f.WireSize())
	if _, err := EncodeFrame(buf, f); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x06 {
		t.Fatalf("flags=0x%02X, want 0x06", buf[0])
	}
	if got := binary.BigEndian.Uint64(buf[1:9]); got != 500 {
		t.Fatalf("size=%d, want 500", got)
	}
}

func TestEncodeFrameShortBuffer(t *testing.T) {
	f := Frame{Kind: FrameMessage, Body: []byte("hello")}
	if _, err := EncodeFrame(make([]byte, 3), f); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}

func TestEncodeFrameCommandWithMore(t *testing.T) {
	f := Frame{Kind: FrameCommand, More: true, Body: []byte("READY")}
	buf := make([]byte, f.WireSize())
	if _, err := EncodeFrame(buf, f); !errors.Is(err, ErrCommandHasMore) {
		t.Fatalf("want ErrCommandHasMore, got %v", err)
	}
}

func TestEncodeFrameZeroAllocations(t *testing.T) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	buf := make([]byte, f.WireSize())
	got := testing.AllocsPerRun(1000, func() {
		_, _ = EncodeFrame(buf, f)
	})
	if got != 0 {
		t.Fatalf("EncodeFrame allocates %v allocs/op, want 0", got)
	}
}
