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

		// Order chosen by seed: 0=A receives first, 1=B receives first.
		if rng.Intn(2) == 0 {
			if _, _, err := a.Receive(cmdB); err != nil {
				return false
			}
			if _, _, err := b.Receive(cmdA); err != nil {
				return false
			}
		} else {
			if _, _, err := b.Receive(cmdA); err != nil {
				return false
			}
			if _, _, err := a.Receive(cmdB); err != nil {
				return false
			}
		}

		if !a.Done() || !b.Done() {
			return false
		}
		return metadataEqual(a.PeerMetadata(), mdB) &&
			metadataEqual(b.PeerMetadata(), mdA)
	}

	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

// randMetadata produces a deterministic random Metadata of size 0..6
// with property names from a small allowlist (so we don't violate
// isMetadataName) and value byte-blobs of length 0..32.
func randMetadata(rng *rand.Rand) wire.Metadata {
	names := []string{
		"Socket-Type", "Identity", "Resource",
		"X-Foo", "X-Bar", "X-Baz",
	}
	n := rng.Intn(len(names) + 1) // 0..6
	used := map[string]bool{}
	var md wire.Metadata
	for i := 0; i < n; i++ {
		name := names[rng.Intn(len(names))]
		if used[name] {
			continue
		}
		used[name] = true
		valLen := rng.Intn(33)
		val := make([]byte, valLen)
		rng.Read(val)
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
