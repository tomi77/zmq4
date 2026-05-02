package wire

import (
	"bytes"
	"errors"
	"testing"
	"testing/quick"
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

func TestReadyRoundTripProperty(t *testing.T) {
	allowedNameChars := []byte{}
	for c := byte('A'); c <= 'Z'; c++ {
		allowedNameChars = append(allowedNameChars, c)
	}
	for c := byte('a'); c <= 'z'; c++ {
		allowedNameChars = append(allowedNameChars, c)
	}
	for c := byte('0'); c <= '9'; c++ {
		allowedNameChars = append(allowedNameChars, c)
	}
	allowedNameChars = append(allowedNameChars, '-', '_', '.', '+')

	prop := func(seed int64, propCount uint8) bool {
		n := int(propCount) % 5 // 0..4 properties
		md := make(Metadata, 0, n)
		used := map[string]bool{}
		for i := 0; i < n; i++ {
			// Generate a unique name 1..16 chars from allowed set.
			nameLen := 1 + int(uint(seed>>uint(i*4))%16)
			name := make([]byte, nameLen)
			for j := 0; j < nameLen; j++ {
				name[j] = allowedNameChars[uint(seed>>uint(j+i))%uint(len(allowedNameChars))]
			}
			// Make sure name is unique to preserve order semantics in the test.
			ns := string(name)
			if used[ns] {
				ns = ns + "X" // simple disambiguation
			}
			used[ns] = true
			// Generate a value 0..32 bytes (any byte).
			valLen := int(uint(seed>>uint(i*7)) % 33)
			val := make([]byte, valLen)
			for j := 0; j < valLen; j++ {
				val[j] = byte(seed >> uint(j))
			}
			md = append(md, MetadataProperty{Name: ns, Value: val})
		}
		rc := ReadyCommand{Metadata: md}
		cmd := rc.Encode()
		got, err := ParseReady(cmd)
		if err != nil {
			return false
		}
		if len(got.Metadata) != len(rc.Metadata) {
			return false
		}
		for i := range rc.Metadata {
			if got.Metadata[i].Name != rc.Metadata[i].Name {
				return false
			}
			if !bytes.Equal(got.Metadata[i].Value, rc.Metadata[i].Value) {
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}
