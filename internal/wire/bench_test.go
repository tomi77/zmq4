package wire

import (
	"bytes"
	"testing"
)

func BenchmarkEncodeFrame1KiB(b *testing.B) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	buf := make([]byte, f.WireSize())
	b.SetBytes(int64(f.WireSize()))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeFrame(buf, f)
	}
}

func BenchmarkDecodeFrame1KiB(b *testing.B) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	buf := make([]byte, f.WireSize())
	_, _ = EncodeFrame(buf, f)
	b.SetBytes(int64(f.WireSize()))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = DecodeFrame(buf)
	}
}

func BenchmarkEncodeGreeting(b *testing.B) {
	var buf [GreetingSize]byte
	g := Greeting{Mechanism: "NULL"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeGreeting(buf[:], g)
	}
}
