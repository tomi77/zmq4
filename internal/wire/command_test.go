package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeParseCommandRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		cmd  Command
	}{
		{"ready", Command{Name: "READY", Data: []byte("metadata")}},
		{"empty-data", Command{Name: "PING", Data: nil}},
		{"max-name-len", Command{Name: string(bytes.Repeat([]byte{'A'}, 255)), Data: []byte{0x00}}},
		{"binary-data", Command{Name: "ERROR", Data: []byte{0x00, 0xFF, 0x80, 0x7F}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, err := EncodeCommand(c.cmd)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseCommand(body)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != c.cmd.Name || !bytes.Equal(got.Data, c.cmd.Data) {
				t.Fatalf("got %+v, want %+v", got, c.cmd)
			}
		})
	}
}

func TestEncodeCommandRejectInvalidName(t *testing.T) {
	cases := []struct {
		name string
		nm   string
	}{
		{"empty", ""},
		{"too-long", string(bytes.Repeat([]byte{'A'}, 256))},
		{"non-letter", "FOO_BAR"},
		{"digit", "F00"},
		{"non-ascii", "FOOÉ"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := EncodeCommand(Command{Name: c.nm}); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("want ErrInvalidCommand, got %v", err)
			}
		})
	}
}

func TestParseCommandTruncated(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"empty", []byte{}},
		{"name-len-zero", []byte{0x00}},
		{"name-truncated", []byte{0x05, 'R', 'E', 'A'}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseCommand(c.body); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("want ErrInvalidCommand, got %v", err)
			}
		})
	}
}

func TestParseCommandNonLetterName(t *testing.T) {
	body := []byte{0x03, 'F', '0', '0'} // digit in name
	if _, err := ParseCommand(body); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}

func TestCommandCloneDetachesFromSource(t *testing.T) {
	src := []byte{0x05, 'R', 'E', 'A', 'D', 'Y', 0xDE, 0xAD, 0xBE, 0xEF}
	c, err := ParseCommand(src)
	if err != nil {
		t.Fatal(err)
	}
	clone := c.Clone()

	// Mutating src must not affect the clone's Data.
	for i := 6; i < len(src); i++ {
		src[i] = 0x00
	}
	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if !bytes.Equal(clone.Data, want) {
		t.Fatalf("clone.Data affected by src mutation: %x", clone.Data)
	}
	if clone.Name != c.Name {
		t.Fatalf("clone.Name mismatch: %q vs %q", clone.Name, c.Name)
	}
	// Original Data, by contract, still aliases src.
	if !bytes.Equal(c.Data, []byte{0x00, 0x00, 0x00, 0x00}) {
		t.Fatalf("original Data should alias src, got %x", c.Data)
	}
}

func TestCommandCloneNilData(t *testing.T) {
	c := Command{Name: "PING", Data: nil}
	clone := c.Clone()
	if clone.Data != nil {
		t.Fatalf("clone of nil Data should be nil, got %v (len=%d)", clone.Data, len(clone.Data))
	}
	if clone.Name != c.Name {
		t.Fatalf("clone.Name mismatch: %q vs %q", clone.Name, c.Name)
	}
}

func TestMessageCommandName(t *testing.T) {
	if MessageCommandName != "MESSAGE" {
		t.Fatalf("MessageCommandName = %q, want %q", MessageCommandName, "MESSAGE")
	}
}
