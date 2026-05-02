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
