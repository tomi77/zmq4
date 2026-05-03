package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestSubscribeCancelRoundTrip(t *testing.T) {
	subs := []SubscribeCommand{
		{Topic: nil},
		{Topic: []byte("news")},
		{Topic: bytes.Repeat([]byte{0xFF}, 4096)},
	}
	for _, s := range subs {
		cmd, err := s.Encode()
		if err != nil {
			t.Fatalf("subscribe encode: %v", err)
		}
		got, err := ParseSubscribe(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Topic, s.Topic) {
			t.Fatalf("got %x, want %x", got.Topic, s.Topic)
		}
	}
	cancels := []CancelCommand{
		{Topic: nil},
		{Topic: []byte("news")},
	}
	for _, c := range cancels {
		cmd, err := c.Encode()
		if err != nil {
			t.Fatalf("cancel encode: %v", err)
		}
		got, err := ParseCancel(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Topic, c.Topic) {
			t.Fatalf("got %x, want %x", got.Topic, c.Topic)
		}
	}
}

func TestParseSubscribeWrongName(t *testing.T) {
	if _, err := ParseSubscribe(Command{Name: "CANCEL"}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}
