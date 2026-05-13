package wire

import (
	"bytes"
	"errors"
	"testing"
)

// TestFrameWriterWriteMsgMatchesSequential verifies WriteMsg produces identical
// on-wire bytes to the equivalent sequence of WriteFrame calls.
func TestFrameWriterWriteMsgMatchesSequential(t *testing.T) {
	frames := []Frame{
		{Kind: FrameMessage, More: true, Body: []byte("envelope")},
		{Kind: FrameMessage, More: false, Body: []byte("payload")},
	}
	var seq bytes.Buffer
	fw1 := NewFrameWriter(&seq)
	for _, f := range frames {
		if err := fw1.WriteFrame(f); err != nil {
			t.Fatal(err)
		}
	}
	var batch bytes.Buffer
	fw2 := NewFrameWriter(&batch)
	if err := fw2.WriteMsg(frames); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seq.Bytes(), batch.Bytes()) {
		t.Fatalf("WriteMsg bytes differ:\n  seq:   %x\n  batch: %x", seq.Bytes(), batch.Bytes())
	}
}

// TestFrameWriterWriteMsgAllocsAtMostOne verifies that WriteMsg for a 2-frame
// message allocates at most 1 heap object — the same as a single WriteFrame
// call. The one unavoidable allocation is the net.Buffers slice header that
// escapes to heap when passed to (*net.Buffers).WriteTo. The key property is
// that N frames costs 1 alloc, not N (as N sequential WriteFrame calls would).
func TestFrameWriterWriteMsgAllocsAtMostOne(t *testing.T) {
	var sink bytes.Buffer
	fw := NewFrameWriter(&sink)
	frames := []Frame{
		{Kind: FrameMessage, More: true, Body: []byte("a")},
		{Kind: FrameMessage, More: false, Body: []byte("b")},
	}
	got := testing.AllocsPerRun(100, func() {
		sink.Reset()
		_ = fw.WriteMsg(frames)
	})
	if got > 1 {
		t.Fatalf("WriteMsg 2 frames: %.0f allocs/op, want ≤1", got)
	}
}

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

func TestFrameWriterEmptyBody(t *testing.T) {
	frames := []Frame{
		{Kind: FrameMessage, Body: nil},
		{Kind: FrameMessage, Body: []byte{}},
		{Kind: FrameCommand, Body: []byte{}},
	}
	for _, f := range frames {
		var sink bytes.Buffer
		fw := NewFrameWriter(&sink)
		if err := fw.WriteFrame(f); err != nil {
			t.Fatalf("WriteFrame(%+v): %v", f, err)
		}
		fr := NewFrameReader(&sink)
		got, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame(%+v): %v", f, err)
		}
		if got.Kind != f.Kind || got.More != f.More || len(got.Body) != 0 {
			t.Fatalf("empty body: got %+v, want kind=%v more=%v body=[]", got, f.Kind, f.More)
		}
	}
}
