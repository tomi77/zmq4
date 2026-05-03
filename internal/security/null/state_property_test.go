package null

import (
	"bytes"
	"math/rand"
	"testing"
	"testing/quick"

	"github.com/tomi77/zmq4/internal/wire"
)

// TestNullHandshakeProperty: random metadata round-trip via two State
// instances exchanging commands. Covers both lock-step and full-duplex
// orderings.
func TestNullHandshakeProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 1000}

	prop := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		mdA := randMetadata(rng)
		mdB := randMetadata(rng)

		a := New(mdA)
		b := New(mdB)

		cmdA, err := a.Start()
		if err != nil {
			t.Logf("a.Start: %v", err)
			return false
		}
		cmdB, err := b.Start()
		if err != nil {
			t.Logf("b.Start: %v", err)
			return false
		}

		// Ordering chosen by rng: 0=A receives first, 1=B receives first.
		if rng.Intn(2) == 0 {
			if _, _, err := a.Receive(cmdB); err != nil {
				t.Logf("seed=%d a.Receive: %v", seed, err)
				return false
			}
			if _, _, err := b.Receive(cmdA); err != nil {
				t.Logf("seed=%d b.Receive: %v", seed, err)
				return false
			}
		} else {
			if _, _, err := b.Receive(cmdA); err != nil {
				t.Logf("seed=%d b.Receive: %v", seed, err)
				return false
			}
			if _, _, err := a.Receive(cmdB); err != nil {
				t.Logf("seed=%d a.Receive: %v", seed, err)
				return false
			}
		}

		if !a.Done() || !b.Done() {
			t.Logf("seed=%d a.Done=%v b.Done=%v", seed, a.Done(), b.Done())
			return false
		}
		if !metadataEqual(a.PeerMetadata(), mdB) {
			t.Logf("seed=%d a.PeerMetadata != mdB", seed)
			return false
		}
		if !metadataEqual(b.PeerMetadata(), mdA) {
			t.Logf("seed=%d b.PeerMetadata != mdA", seed)
			return false
		}
		return true
	}

	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

// randMetadata produces a deterministic random Metadata of up to 6
// properties, with property names from a small allowlist (so we don't
// violate isMetadataName) and value byte-blobs of length 0..32. The
// size distribution is biased toward smaller sets because it makes n
// random picks with deduplication; the actual property count may be
// less than n on collision (full 6-property metadata is rare).
func randMetadata(rng *rand.Rand) wire.Metadata {
	names := []string{
		"Socket-Type", "Identity", "Resource",
		"X-Foo", "X-Bar", "X-Baz",
	}
	n := rng.Intn(len(names) + 1) // 0..6
	used := map[string]bool{}
	var md wire.Metadata
	for range n {
		name := names[rng.Intn(len(names))]
		if used[name] {
			continue
		}
		used[name] = true
		valLen := rng.Intn(33)
		val := make([]byte, valLen)
		for j := range val {
			val[j] = byte(rng.Intn(256))
		}
		md = append(md, wire.MetadataProperty{
			Name:  []byte(name),
			Value: val,
		})
	}
	return md
}

func metadataEqual(a, b wire.Metadata) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].Name, b[i].Name) ||
			!bytes.Equal(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}
