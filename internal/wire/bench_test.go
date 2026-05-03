package wire

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkEncodeFrame1KiB(b *testing.B) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	buf := make([]byte, f.WireSize())
	b.SetBytes(int64(f.WireSize()))
	for b.Loop() {
		_, _ = EncodeFrame(buf, f)
	}
}

func BenchmarkDecodeFrame1KiB(b *testing.B) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	buf := make([]byte, f.WireSize())
	_, _ = EncodeFrame(buf, f)
	b.SetBytes(int64(f.WireSize()))
	for b.Loop() {
		_, _, _ = DecodeFrame(buf)
	}
}

func BenchmarkEncodeGreeting(b *testing.B) {
	var buf [GreetingSize]byte
	g := Greeting{Mechanism: "NULL"}
	for b.Loop() {
		_ = EncodeGreeting(buf[:], g)
	}
}

type loopingReader struct {
	buf []byte
	off int
}

func (r *loopingReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.off >= len(r.buf) {
			r.off = 0
		}
		k := copy(p[n:], r.buf[r.off:])
		r.off += k
		n += k
	}
	return n, nil
}

func BenchmarkFrameReader1KiB(b *testing.B) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	buf := make([]byte, f.WireSize())
	if _, err := EncodeFrame(buf, f); err != nil {
		b.Fatal(err)
	}
	src := &loopingReader{buf: buf}
	fr := NewFrameReader(src)
	b.SetBytes(int64(f.WireSize()))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := fr.ReadFrame(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFrameWriter1KiB(b *testing.B) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	fw := NewFrameWriter(io.Discard)
	b.SetBytes(int64(f.WireSize()))
	b.ReportAllocs()
	for b.Loop() {
		if err := fw.WriteFrame(f); err != nil {
			b.Fatal(err)
		}
	}
}
