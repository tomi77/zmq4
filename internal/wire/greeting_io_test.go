package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestReadGreetingHappyPath(t *testing.T) {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL", AsServer: true}); err != nil {
		t.Fatal(err)
	}
	g, err := ReadGreeting(bytes.NewReader(buf[:]))
	if err != nil {
		t.Fatal(err)
	}
	want := Greeting{Mechanism: "NULL", AsServer: true}
	if g != want {
		t.Fatalf("got %+v, want %+v", g, want)
	}
}

func TestReadGreetingPartialReads(t *testing.T) {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "PLAIN"}); err != nil {
		t.Fatal(err)
	}
	r := iotest.OneByteReader(bytes.NewReader(buf[:]))
	g, err := ReadGreeting(r)
	if err != nil {
		t.Fatal(err)
	}
	if g.Mechanism != "PLAIN" {
		t.Fatalf("got mechanism %q, want PLAIN", g.Mechanism)
	}
}

func TestReadGreetingTruncated(t *testing.T) {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadGreeting(bytes.NewReader(buf[:GreetingSize-1])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestWriteGreetingHappyPath(t *testing.T) {
	var sink bytes.Buffer
	if err := WriteGreeting(&sink, Greeting{Mechanism: "CURVE", AsServer: true}); err != nil {
		t.Fatal(err)
	}
	if sink.Len() != GreetingSize {
		t.Fatalf("wrote %d bytes, want %d", sink.Len(), GreetingSize)
	}
	g, err := DecodeGreeting(sink.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	want := Greeting{Mechanism: "CURVE", AsServer: true}
	if g != want {
		t.Fatalf("got %+v, want %+v", g, want)
	}
}
