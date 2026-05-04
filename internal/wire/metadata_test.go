package wire

import (
	"bytes"
	"testing"
)

func TestEncodeMetadataRoundTrip(t *testing.T) {
	md := Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
		{Name: []byte("Identity"), Value: []byte{0x01, 0x02, 0x03}},
	}
	raw := EncodeMetadata(md)
	got, err := ParseMetadata(raw)
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if len(got) != len(md) {
		t.Fatalf("len = %d, want %d", len(got), len(md))
	}
	for i := range md {
		if !bytes.Equal(got[i].Name, md[i].Name) ||
			!bytes.Equal(got[i].Value, md[i].Value) {
			t.Fatalf("[%d] = %+v, want %+v", i, got[i], md[i])
		}
	}
}

func TestEncodeMetadataEmpty(t *testing.T) {
	raw := EncodeMetadata(nil)
	if len(raw) != 0 {
		t.Fatalf("EncodeMetadata(nil) = %x, want empty", raw)
	}
	got, err := ParseMetadata(raw)
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ParseMetadata(empty) = %+v, want empty", got)
	}
}

func TestParseMetadataRejectsZeroLengthName(t *testing.T) {
	// One-byte input: nameLen=0 → invalid per RFC 37 §2.4 (name must be 1..255).
	_, err := ParseMetadata([]byte{0x00})
	if err == nil {
		t.Fatalf("ParseMetadata(zero name): err=nil, want non-nil")
	}
}
