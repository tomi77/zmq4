package metaclone

import "github.com/tomi77/zmq4/internal/wire"

// Clone returns a deep copy of src: a fresh Metadata slice plus fresh
// Name/Value backing arrays for each property. The result aliases none
// of src's backing storage. Empty/nil input returns nil.
func Clone(src wire.Metadata) wire.Metadata {
	if len(src) == 0 {
		return nil
	}
	dst := make(wire.Metadata, len(src))
	for i, p := range src {
		name := make([]byte, len(p.Name))
		copy(name, p.Name)
		value := make([]byte, len(p.Value))
		copy(value, p.Value)
		dst[i] = wire.MetadataProperty{Name: name, Value: value}
	}
	return dst
}
