package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadyEncodeDecodeRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		rc   ReadyCommand
	}{
		{"empty", ReadyCommand{}},
		{"single-prop", ReadyCommand{Metadata: Metadata{
			{Name: "Socket-Type", Value: []byte("REQ")},
		}}},
		{"multi-prop-ordered", ReadyCommand{Metadata: Metadata{
			{Name: "Socket-Type", Value: []byte("DEALER")},
			{Name: "Identity", Value: []byte("client-1")},
			{Name: "Resource", Value: []byte("/tmp/foo")},
		}}},
		{"binary-value", ReadyCommand{Metadata: Metadata{
			{Name: "X-Bin", Value: []byte{0x00, 0xFF, 0x80}},
		}}},
		{"empty-value", ReadyCommand{Metadata: Metadata{
			{Name: "X-Empty", Value: []byte{}},
		}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := c.rc.Encode()
			if cmd.Name != "READY" {
				t.Fatalf("encoded command name=%q, want READY", cmd.Name)
			}
			got, err := ParseReady(cmd)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Metadata) != len(c.rc.Metadata) {
				t.Fatalf("metadata length: got %d, want %d", len(got.Metadata), len(c.rc.Metadata))
			}
			for i, p := range c.rc.Metadata {
				if got.Metadata[i].Name != p.Name || !bytes.Equal(got.Metadata[i].Value, p.Value) {
					t.Fatalf("property %d: got %+v, want %+v", i, got.Metadata[i], p)
				}
			}
		})
	}
}

func TestParseReadyWrongCommandName(t *testing.T) {
	if _, err := ParseReady(Command{Name: "ERROR"}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}

func TestParseReadyMalformedMetadata(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"name-len-zero", []byte{0x00}},
		{"name-truncated", []byte{0x05, 'A', 'B'}},
		{"value-size-truncated", []byte{0x01, 'X', 0x00, 0x00}},
		{"value-truncated", []byte{0x01, 'X', 0x00, 0x00, 0x00, 0x05, 'a', 'b'}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := Command{Name: "READY", Data: c.data}
			if _, err := ParseReady(cmd); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("want ErrInvalidCommand, got %v", err)
			}
		})
	}
}

func TestMetadataGetCaseInsensitive(t *testing.T) {
	m := Metadata{
		{Name: "Socket-Type", Value: []byte("REQ")},
	}
	v, ok := m.Get("socket-type")
	if !ok || string(v) != "REQ" {
		t.Fatalf("Get returned (%q, %v), want (REQ, true)", v, ok)
	}
	if _, ok := m.Get("Identity"); ok {
		t.Fatal("Get returned ok=true for missing key")
	}
}
