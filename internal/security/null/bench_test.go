package null

import (
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func BenchmarkHandshake(b *testing.B) {
	md := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REQ")},
	}
	peerCmd, err := wire.ReadyCommand{Metadata: md}.Encode()
	if err != nil {
		b.Fatalf("encode peer: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := New(md)
		if _, err := s.Start(); err != nil {
			b.Fatalf("Start: %v", err)
		}
		if _, _, err := s.Receive(peerCmd); err != nil {
			b.Fatalf("Receive: %v", err)
		}
	}
}
