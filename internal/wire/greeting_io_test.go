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

func TestReadGreetingPhaseAHappyPath(t *testing.T) {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"}); err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(buf[:11])
	if err := ReadGreetingPhaseA(r); err != nil {
		t.Fatalf("ReadGreetingPhaseA: %v", err)
	}
}

func TestReadGreetingPhaseATruncated(t *testing.T) {
	var buf [GreetingSize]byte
	_ = EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"})
	if err := ReadGreetingPhaseA(bytes.NewReader(buf[:5])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadGreetingPhaseABadSignature(t *testing.T) {
	bad := make([]byte, 11)
	bad[0] = 0xAA
	bad[9] = 0x7F
	bad[10] = 0x03
	if err := ReadGreetingPhaseA(bytes.NewReader(bad)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

func TestReadGreetingPhaseABadVersionMajor(t *testing.T) {
	bad := make([]byte, 11)
	bad[0] = 0xFF
	bad[9] = 0x7F
	bad[10] = 0x02 // major = 2 → ZMTP 2.x
	if err := ReadGreetingPhaseA(bytes.NewReader(bad)); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
}

func TestReadGreetingPhaseAStopsAfter11Bytes(t *testing.T) {
	// Reader yields one byte at a time; assert ReadGreetingPhaseA reads
	// exactly 11 and no more.
	var buf [GreetingSize]byte
	_ = EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"})
	cr := &countingReader{src: bytes.NewReader(buf[:])}
	if err := ReadGreetingPhaseA(cr); err != nil {
		t.Fatal(err)
	}
	if cr.n != 11 {
		t.Fatalf("read %d bytes, want exactly 11", cr.n)
	}
}

type countingReader struct {
	src io.Reader
	n   int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.n += n
	return n, err
}
