package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestFrameReaderHappyPath(t *testing.T) {
	want := []Frame{
		{Kind: FrameMessage, More: true, Body: []byte("hello")},
		{Kind: FrameMessage, Body: []byte("world")},
		{Kind: FrameCommand, Body: []byte("READY")},
		{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 300)},
	}
	var buf bytes.Buffer
	scratch := make([]byte, 1024)
	for _, f := range want {
		n, err := EncodeFrame(scratch[:f.WireSize()], f)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(scratch[:n])
	}
	fr := NewFrameReader(&buf)
	for i, w := range want {
		g, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if g.Kind != w.Kind || g.More != w.More || !bytes.Equal(g.Body, w.Body) {
			t.Fatalf("frame %d: got %+v, want %+v", i, g, w)
		}
	}
	if _, err := fr.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF after last frame, got %v", err)
	}
}

func TestFrameReaderPartialReads(t *testing.T) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0x42}, 100)}
	var buf bytes.Buffer
	scratch := make([]byte, f.WireSize())
	if _, err := EncodeFrame(scratch, f); err != nil {
		t.Fatal(err)
	}
	buf.Write(scratch)

	fr := NewFrameReader(iotest.OneByteReader(&buf))
	got, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Body, f.Body) {
		t.Fatal("body mismatch under partial reads")
	}
}

func TestFrameReaderTruncatedMidFrame(t *testing.T) {
	full := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0x10}, 50)}
	scratch := make([]byte, full.WireSize())
	if _, err := EncodeFrame(scratch, full); err != nil {
		t.Fatal(err)
	}
	// Truncate halfway.
	r := bytes.NewReader(scratch[:len(scratch)-10])
	fr := NewFrameReader(r)
	if _, err := fr.ReadFrame(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestFrameReaderReservedFlags(t *testing.T) {
	bad := []byte{0x08, 0x00}
	fr := NewFrameReader(bytes.NewReader(bad))
	if _, err := fr.ReadFrame(); !errors.Is(err, ErrReservedFlags) {
		t.Fatalf("want ErrReservedFlags, got %v", err)
	}
}
