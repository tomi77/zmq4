package wire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestErrorEncodeDecodeRoundTrip(t *testing.T) {
	cases := []ErrorCommand{
		{Reason: ""},
		{Reason: "Authentication failure"},
		{Reason: strings.Repeat("X", 255)},
	}
	for _, ec := range cases {
		cmd := ec.Encode()
		got, err := ParseError(cmd)
		if err != nil {
			t.Fatalf("%q: %v", ec.Reason, err)
		}
		if got.Reason != ec.Reason {
			t.Fatalf("got %q, want %q", got.Reason, ec.Reason)
		}
	}
}

func TestErrorEncodeOversized(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on oversized reason")
		}
	}()
	_ = ErrorCommand{Reason: strings.Repeat("X", 256)}.Encode()
}

func TestParseErrorMalformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"reason-truncated", []byte{0x05, 'a', 'b'}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := Command{Name: "ERROR", Data: c.data}
			if _, err := ParseError(cmd); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("want ErrInvalidCommand, got %v", err)
			}
		})
	}
}

func TestParseErrorTrailingData(t *testing.T) {
	cmd := Command{Name: "ERROR", Data: append([]byte{0x02, 'a', 'b'}, 0xFF)}
	if _, err := ParseError(cmd); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}

func TestParseErrorWrongName(t *testing.T) {
	if _, err := ParseError(Command{Name: "READY"}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}

func TestErrorEncodeWireBytes(t *testing.T) {
	ec := ErrorCommand{Reason: "X"}
	cmd := ec.Encode()
	if !bytes.Equal(cmd.Data, []byte{0x01, 'X'}) {
		t.Fatalf("got %x, want %x", cmd.Data, []byte{0x01, 'X'})
	}
}
