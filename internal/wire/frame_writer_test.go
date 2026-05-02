package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestFrameWriterRoundTrip(t *testing.T) {
	frames := []Frame{
		{Kind: FrameMessage, More: true, Body: []byte("a")},
		{Kind: FrameMessage, Body: []byte("b")},
		{Kind: FrameCommand, Body: []byte("READY")},
		{Kind: FrameMessage, Body: bytes.Repeat([]byte{0x77}, 1000)},
	}
	var sink bytes.Buffer
	fw := NewFrameWriter(&sink)
	for _, f := range frames {
		if err := fw.WriteFrame(f); err != nil {
			t.Fatal(err)
		}
	}
	fr := NewFrameReader(&sink)
	for i, w := range frames {
		g, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if g.Kind != w.Kind || g.More != w.More || !bytes.Equal(g.Body, w.Body) {
			t.Fatalf("frame %d: got %+v, want %+v", i, g, w)
		}
	}
}

func TestFrameWriterCommandWithMoreRejected(t *testing.T) {
	fw := NewFrameWriter(&bytes.Buffer{})
	err := fw.WriteFrame(Frame{Kind: FrameCommand, More: true, Body: []byte("X")})
	if !errors.Is(err, ErrCommandHasMore) {
		t.Fatalf("want ErrCommandHasMore, got %v", err)
	}
}
