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
	for b.Loop() {
		s := New(md)
		if _, err := s.Start(); err != nil {
			b.Fatalf("Start: %v", err)
		}
		if _, _, err := s.Receive(peerCmd); err != nil {
			b.Fatalf("Receive: %v", err)
		}
	}
}

// TestStartAndReceiveAllocBudget pins the per-handshake allocation
// budget for null.State itself, separate from the wire codec.
//
// Start: zero null.State-owned allocations on top of wire encode (the
// returned Command aliases wire's encoded buffer; null does not copy).
//
// Receive(READY) with N metadata properties: 1 + 2N null.State-owned
// allocations from metaclone.Clone (one for the Metadata slice, one Name
// and one Value buffer per property). This is the defensive-copy
// budget required by the buffer-independence contract pinned in
// TestPeerMetadataIndependentOfInputBuffer.
//
// To isolate null.State's allocations from wire's, we call
// testing.AllocsPerRun separately for the wire encode/decode baseline
// and for the full Start+Receive path; the difference is null's share.
func TestStartAndReceiveAllocBudget(t *testing.T) {
	md := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REQ")},
	}
	peerCmd, err := wire.ReadyCommand{Metadata: md}.Encode()
	if err != nil {
		t.Fatalf("encode peer: %v", err)
	}

	// Baseline: wire encode + parse, no null.State.
	wireOnly := testing.AllocsPerRun(100, func() {
		c, _ := wire.ReadyCommand{Metadata: md}.Encode()
		_, _ = wire.ParseReady(c)
	})

	// Full path: full Start+Receive cycle on a fresh State.
	full := testing.AllocsPerRun(100, func() {
		s := New(md)
		_, _ = s.Start()
		_, _, _ = s.Receive(peerCmd)
	})

	nullShare := full - wireOnly
	// 1 metadata-slice + 2 byte buffers per property; here N=1.
	const wantNullShare = 3.0
	if nullShare != wantNullShare {
		t.Fatalf("null.State alloc share = %v (full=%v, wire=%v), want %v: metaclone.Clone budget changed",
			nullShare, full, wireOnly, wantNullShare)
	}
}
