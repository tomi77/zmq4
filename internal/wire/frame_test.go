package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"testing/quick"
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

func TestDecodeFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		f    Frame
	}{
		{"empty-msg-last", Frame{Kind: FrameMessage}},
		{"empty-msg-more", Frame{Kind: FrameMessage, More: true}},
		{"short-msg-last", Frame{Kind: FrameMessage, Body: []byte("hi")}},
		{"short-msg-more", Frame{Kind: FrameMessage, More: true, Body: []byte("hi")}},
		{"boundary-255", Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{1}, 255)}},
		{"long-256", Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{2}, 256)}},
		{"long-1mib", Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{3}, 1<<20)}},
		{"short-cmd", Frame{Kind: FrameCommand, Body: []byte("READY")}},
		{"long-cmd", Frame{Kind: FrameCommand, Body: bytes.Repeat([]byte{4}, 500)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, c.f.WireSize())
			if _, err := EncodeFrame(buf, c.f); err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, n, err := DecodeFrame(buf)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if n != len(buf) {
				t.Fatalf("consumed %d, want %d", n, len(buf))
			}
			if got.Kind != c.f.Kind || got.More != c.f.More {
				t.Fatalf("got %+v, want %+v", got, c.f)
			}
			if !bytes.Equal(got.Body, c.f.Body) {
				t.Fatal("body mismatch")
			}
		})
	}
}

func TestDecodeFrameTruncated(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
	}{
		{"empty", []byte{}},
		{"flag-only", []byte{0x00}},
		{"short-trunc-body", []byte{0x00, 0x05, 'h', 'i'}},
		{"long-trunc-size", []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}}, // missing 1 size byte
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := DecodeFrame(c.buf); !errors.Is(err, ErrShortBuffer) {
				t.Fatalf("want ErrShortBuffer, got %v", err)
			}
		})
	}
}

func TestDecodeFrameReservedFlags(t *testing.T) {
	for _, flag := range []byte{0x08, 0x10, 0x20, 0x40, 0x80} {
		t.Run(fmt.Sprintf("flag-%02X", flag), func(t *testing.T) {
			buf := []byte{flag, 0x00}
			if _, _, err := DecodeFrame(buf); !errors.Is(err, ErrReservedFlags) {
				t.Fatalf("want ErrReservedFlags, got %v", err)
			}
		})
	}
}

func TestDecodeFrameCommandWithMoreInvalid(t *testing.T) {
	buf := []byte{0x05, 0x00} // 0x04 (command) | 0x01 (more)
	if _, _, err := DecodeFrame(buf); !errors.Is(err, ErrCommandHasMore) {
		t.Fatalf("want ErrCommandHasMore, got %v", err)
	}
	buf = []byte{0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // 0x06 | 0x01
	if _, _, err := DecodeFrame(buf); !errors.Is(err, ErrCommandHasMore) {
		t.Fatalf("want ErrCommandHasMore, got %v", err)
	}
}

func TestDecodeFrameZeroAllocations(t *testing.T) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	buf := make([]byte, f.WireSize())
	if _, err := EncodeFrame(buf, f); err != nil {
		t.Fatal(err)
	}
	got := testing.AllocsPerRun(1000, func() {
		_, _, _ = DecodeFrame(buf)
	})
	if got != 0 {
		t.Fatalf("DecodeFrame allocates %v allocs/op, want 0", got)
	}
}

func TestDecodeFrameBodyAliasesInput(t *testing.T) {
	src := []byte{0x00, 0x03, 'a', 'b', 'c'}
	got, _, err := DecodeFrame(src)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the input buffer; the Body should reflect it (zero-copy).
	src[2] = 'X'
	if got.Body[0] != 'X' {
		t.Fatal("Body does not alias src — zero-copy contract violated")
	}
}

func TestEncodeDecodeMultipartSequence(t *testing.T) {
	frames := []Frame{
		{Kind: FrameMessage, More: true, Body: []byte("part-1")},
		{Kind: FrameMessage, More: true, Body: []byte("part-2")},
		{Kind: FrameMessage, More: false, Body: []byte("part-3-last")},
	}
	var buf bytes.Buffer
	scratch := make([]byte, 64)
	for _, f := range frames {
		n, err := EncodeFrame(scratch[:f.WireSize()], f)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		buf.Write(scratch[:n])
	}

	in := buf.Bytes()
	var got []Frame
	for len(in) > 0 {
		f, n, err := DecodeFrame(in)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		got = append(got, Frame{Kind: f.Kind, More: f.More, Body: append([]byte(nil), f.Body...)})
		in = in[n:]
	}
	if len(got) != len(frames) {
		t.Fatalf("got %d frames, want %d", len(got), len(frames))
	}
	for i, f := range frames {
		if got[i].Kind != f.Kind || got[i].More != f.More || !bytes.Equal(got[i].Body, f.Body) {
			t.Fatalf("frame %d: got %+v, want %+v", i, got[i], f)
		}
	}
}

func TestFrameRoundTripProperty(t *testing.T) {
	prop := func(kind uint8, more bool, body []byte) bool {
		k := FrameMessage
		if kind%2 == 1 {
			k = FrameCommand
		}
		// Commands cannot have MORE.
		if k == FrameCommand {
			more = false
		}
		f := Frame{Kind: k, More: more, Body: body}
		buf := make([]byte, f.WireSize())
		if _, err := EncodeFrame(buf, f); err != nil {
			return false
		}
		got, n, err := DecodeFrame(buf)
		if err != nil || n != len(buf) {
			return false
		}
		return got.Kind == f.Kind && got.More == f.More && bytes.Equal(got.Body, f.Body)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}

func TestFrameCloneDetachesFromSource(t *testing.T) {
	src := []byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	f, n, err := DecodeFrame(src)
	if err != nil || n != len(src) {
		t.Fatalf("decode: err=%v n=%d", err, n)
	}
	clone := f.Clone()

	// Mutating src must not affect the clone.
	for i := 2; i < len(src); i++ {
		src[i] = 'X'
	}
	if !bytes.Equal(clone.Body, []byte("hello")) {
		t.Fatalf("clone.Body affected by src mutation: %q", clone.Body)
	}
	// The original frame, by contract, still aliases src.
	if !bytes.Equal(f.Body, []byte("XXXXX")) {
		t.Fatalf("original Body should alias src, got %q", f.Body)
	}
	// Other fields preserved.
	if clone.Kind != f.Kind || clone.More != f.More {
		t.Fatalf("clone metadata mismatch: %+v vs %+v", clone, f)
	}
}

func TestFrameCloneNilBody(t *testing.T) {
	f := Frame{Kind: FrameMessage, More: true, Body: nil}
	clone := f.Clone()
	if clone.Body != nil {
		t.Fatalf("clone of nil Body should be nil, got %v (len=%d)", clone.Body, len(clone.Body))
	}
	if clone.Kind != f.Kind || clone.More != f.More {
		t.Fatalf("clone metadata mismatch: %+v vs %+v", clone, f)
	}
}

func TestFrameCloneEmptyBody(t *testing.T) {
	// Empty (non-nil) body should clone to a non-nil empty slice — bytes.Clone preserves the distinction.
	f := Frame{Kind: FrameMessage, Body: []byte{}}
	clone := f.Clone()
	if clone.Body == nil {
		t.Fatal("clone of empty (non-nil) Body should not be nil")
	}
	if len(clone.Body) != 0 {
		t.Fatalf("clone.Body should be empty, got len=%d", len(clone.Body))
	}
}

func TestDecodeFrameTooLarge(t *testing.T) {
	// Long-frame header that claims exactly MaxFrameBodySize+1 bytes — must be
	// rejected before any allocation attempt.
	var buf [9]byte
	buf[0] = 0x02 // long message, no MORE
	binary.BigEndian.PutUint64(buf[1:], MaxFrameBodySize+1)
	if _, _, err := DecodeFrame(buf[:]); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
}
