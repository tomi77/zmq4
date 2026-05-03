package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestPingPongRoundTrip(t *testing.T) {
	pings := []PingCommand{
		{TTL: 0, Context: nil},
		{TTL: 100, Context: []byte("ctx")},
		{TTL: 0xFFFF, Context: bytes.Repeat([]byte{0xAA}, 16)},
	}
	for _, p := range pings {
		cmd, err := p.Encode()
		if err != nil {
			t.Fatalf("ping encode: %v", err)
		}
		got, err := ParsePing(cmd)
		if err != nil {
			t.Fatalf("ping: %v", err)
		}
		if got.TTL != p.TTL || !bytes.Equal(got.Context, p.Context) {
			t.Fatalf("got %+v, want %+v", got, p)
		}
	}

	pongs := []PongCommand{
		{Context: nil},
		{Context: []byte("ctx")},
		{Context: bytes.Repeat([]byte{0xBB}, 16)},
	}
	for _, p := range pongs {
		cmd, err := p.Encode()
		if err != nil {
			t.Fatalf("pong encode: %v", err)
		}
		got, err := ParsePong(cmd)
		if err != nil {
			t.Fatalf("pong: %v", err)
		}
		if !bytes.Equal(got.Context, p.Context) {
			t.Fatalf("got %x, want %x", got.Context, p.Context)
		}
	}
}

func TestPingEncodeOversizedContext(t *testing.T) {
	if _, err := (PingCommand{Context: make([]byte, 17)}).Encode(); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}

func TestPongEncodeOversizedContext(t *testing.T) {
	if _, err := (PongCommand{Context: make([]byte, 17)}).Encode(); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}

func TestParsePingMalformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"ttl-truncated", []byte{0x00}},
		{"context-too-long", append([]byte{0x00, 0x10}, bytes.Repeat([]byte{0xCC}, 17)...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := Command{Name: "PING", Data: c.data}
			if _, err := ParsePing(cmd); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("want ErrInvalidCommand, got %v", err)
			}
		})
	}
}

func TestParsePingWrongName(t *testing.T) {
	if _, err := ParsePing(Command{Name: "PONG"}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}

func TestParsePongTooLong(t *testing.T) {
	cmd := Command{Name: "PONG", Data: bytes.Repeat([]byte{0xDD}, 17)}
	if _, err := ParsePong(cmd); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}
