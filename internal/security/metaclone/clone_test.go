package metaclone

import (
	"bytes"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestCloneEmpty(t *testing.T) {
	if got := Clone(nil); got != nil {
		t.Fatalf("Clone(nil) = %+v, want nil", got)
	}
	if got := Clone(wire.Metadata{}); got != nil {
		t.Fatalf("Clone(empty) = %+v, want nil", got)
	}
}

func TestCloneIndependentBuffers(t *testing.T) {
	name := []byte("Socket-Type")
	value := []byte("REQ")
	src := wire.Metadata{
		{Name: name, Value: value},
	}
	dst := Clone(src)

	// Mutate the source buffers.
	for i := range name {
		name[i] = 0xFF
	}
	for i := range value {
		value[i] = 0xFF
	}

	if !bytes.Equal(dst[0].Name, []byte("Socket-Type")) {
		t.Fatalf("dst.Name = %x, want unchanged", dst[0].Name)
	}
	if !bytes.Equal(dst[0].Value, []byte("REQ")) {
		t.Fatalf("dst.Value = %x, want unchanged", dst[0].Value)
	}
}
