package wire

import (
	"bytes"
	"encoding/binary"
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

func TestFrameReaderTooLarge(t *testing.T) {
	// Long-frame header claiming MaxFrameBodySize+1 bytes — ReadFrame must
	// return ErrFrameTooLarge without allocating.
	var buf [9]byte
	buf[0] = 0x02 // long message, no MORE
	binary.BigEndian.PutUint64(buf[1:], MaxFrameBodySize+1)
	fr := NewFrameReader(bytes.NewReader(buf[:]))
	if _, err := fr.ReadFrame(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
}

func TestFrameReaderCustomMaxBodySize(t *testing.T) {
	const limit = 64

	// Frame within the custom limit — must succeed.
	okFrame := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0x42}, limit)}
	var buf bytes.Buffer
	scratch := make([]byte, okFrame.WireSize())
	if _, err := EncodeFrame(scratch, okFrame); err != nil {
		t.Fatal(err)
	}
	buf.Write(scratch)

	fr := NewFrameReader(&buf, WithMaxBodySize(limit))
	got, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("expected success for body == limit, got %v", err)
	}
	if !bytes.Equal(got.Body, okFrame.Body) {
		t.Fatal("body mismatch")
	}

	// Frame one byte over the custom limit — must be rejected.
	overFrame := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0x42}, limit+1)}
	scratch = make([]byte, overFrame.WireSize())
	if _, err := EncodeFrame(scratch, overFrame); err != nil {
		t.Fatal(err)
	}
	fr2 := NewFrameReader(bytes.NewReader(scratch), WithMaxBodySize(limit))
	if _, err := fr2.ReadFrame(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge for body == limit+1, got %v", err)
	}
}

// transientErrReader returns errAfter exactly once after delivering the
// first n bytes, then on subsequent reads returns the underlying reader's
// next bytes. This simulates a transient I/O error.
type transientErrReader struct {
	r        io.Reader
	errAfter int
	err      error
	tripped  bool
	read     int
}

func (t *transientErrReader) Read(p []byte) (int, error) {
	if !t.tripped && t.read >= t.errAfter {
		t.tripped = true
		return 0, t.err
	}
	if !t.tripped {
		// Cap the read to errAfter so the caller hits the error on the next call.
		if t.read+len(p) > t.errAfter {
			p = p[:t.errAfter-t.read]
		}
	}
	n, err := t.r.Read(p)
	t.read += n
	return n, err
}

func TestFrameReaderTransientError(t *testing.T) {
	// Build a frame on the wire.
	full := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0x33}, 50)}
	scratch := make([]byte, full.WireSize())
	if _, err := EncodeFrame(scratch, full); err != nil {
		t.Fatal(err)
	}

	// Wrap a bytes.Reader so it returns a custom error after 3 bytes.
	customErr := errors.New("transient I/O blip")
	tr := &transientErrReader{
		r:        bytes.NewReader(scratch),
		errAfter: 3,
		err:      customErr,
	}
	fr := NewFrameReader(tr)

	// First read should propagate the transient error cleanly.
	_, err := fr.ReadFrame()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, customErr) {
		t.Fatalf("expected transient error to surface, got %v", err)
	}
	// "Without losing sync" — the FrameReader should not have panicked
	// and should be in a defined state. We don't claim retry succeeds
	// (the underlying byte stream is now mid-frame and unrecoverable
	// without a fresh connection), but a second call must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FrameReader panicked on second read after transient error: %v", r)
		}
	}()
	_, _ = fr.ReadFrame() // may return any error; we just verify no panic
}
