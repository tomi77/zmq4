package seccommon

import (
	"bytes"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestCloneMetadataEmpty(t *testing.T) {
	if got := CloneMetadata(nil); got != nil {
		t.Fatalf("CloneMetadata(nil) = %+v, want nil", got)
	}
	if got := CloneMetadata(wire.Metadata{}); got != nil {
		t.Fatalf("CloneMetadata(empty) = %+v, want nil", got)
	}
}

func TestCloneMetadataIndependentBuffers(t *testing.T) {
	name := []byte("Socket-Type")
	value := []byte("REQ")
	src := wire.Metadata{
		{Name: name, Value: value},
	}
	dst := CloneMetadata(src)

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
