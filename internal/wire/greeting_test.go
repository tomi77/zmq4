package wire

import (
	"bytes"
	"errors"
	"testing"
	"testing/quick"
)

func TestEncodeGreetingDecodeGreetingRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		greeting Greeting
	}{
		{"null-client", Greeting{Mechanism: "NULL", AsServer: false}},
		{"null-server", Greeting{Mechanism: "NULL", AsServer: true}},
		{"plain-client", Greeting{Mechanism: "PLAIN", AsServer: false}},
		{"curve-server", Greeting{Mechanism: "CURVE", AsServer: true}},
		{"max-len-mechanism", Greeting{Mechanism: "ABCDEFGHIJKLMNOPQRST", AsServer: false}}, // 20 chars
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf [GreetingSize]byte
			if err := EncodeGreeting(buf[:], c.greeting); err != nil {
				t.Fatalf("EncodeGreeting: %v", err)
			}
			got, err := DecodeGreeting(buf[:])
			if err != nil {
				t.Fatalf("DecodeGreeting: %v", err)
			}
			if got != c.greeting {
				t.Fatalf("round trip mismatch: got %+v, want %+v", got, c.greeting)
			}
		})
	}
}

func TestEncodeGreetingShortBuffer(t *testing.T) {
	short := make([]byte, GreetingSize-1)
	if err := EncodeGreeting(short, Greeting{Mechanism: "NULL"}); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}

func TestEncodeGreetingOversizedMechanism(t *testing.T) {
	var buf [GreetingSize]byte
	err := EncodeGreeting(buf[:], Greeting{Mechanism: "ABCDEFGHIJKLMNOPQRSTU"}) // 21 chars
	if !errors.Is(err, ErrInvalidMechanism) {
		t.Fatalf("want ErrInvalidMechanism, got %v", err)
	}
}

func TestDecodeGreetingShortBuffer(t *testing.T) {
	if _, err := DecodeGreeting(make([]byte, GreetingSize-1)); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}

func TestDecodeGreetingBadSignature(t *testing.T) {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"}); err != nil {
		t.Fatalf("setup encode: %v", err)
	}
	corrupt := buf
	corrupt[0] = 0x00
	if _, err := DecodeGreeting(corrupt[:]); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("byte 0 corrupted: want ErrInvalidSignature, got %v", err)
	}
	corrupt = buf
	corrupt[9] = 0x00
	if _, err := DecodeGreeting(corrupt[:]); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("byte 9 corrupted: want ErrInvalidSignature, got %v", err)
	}
}

func TestDecodeGreetingUnsupportedVersion(t *testing.T) {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"}); err != nil {
		t.Fatalf("setup encode: %v", err)
	}
	cases := []struct {
		name        string
		major, minor byte
	}{
		{"3.0", 0x03, 0x00},
		{"4.0", 0x04, 0x00},
		{"2.0", 0x02, 0x00},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tweaked := buf
			tweaked[10] = c.major
			tweaked[11] = c.minor
			if _, err := DecodeGreeting(tweaked[:]); !errors.Is(err, ErrUnsupportedVersion) {
				t.Fatalf("want ErrUnsupportedVersion, got %v", err)
			}
		})
	}
}

func TestDecodeGreetingMechanismValidation(t *testing.T) {
	mkBuf := func(mechBytes []byte) [GreetingSize]byte {
		var buf [GreetingSize]byte
		buf[0] = 0xFF
		buf[9] = 0x7F
		buf[10] = 0x03
		buf[11] = 0x01
		copy(buf[12:32], mechBytes)
		return buf
	}
	t.Run("non-ascii", func(t *testing.T) {
		buf := mkBuf([]byte{0xC3, 0xA9}) // "é" — disallowed
		if _, err := DecodeGreeting(buf[:]); !errors.Is(err, ErrInvalidMechanism) {
			t.Fatalf("want ErrInvalidMechanism, got %v", err)
		}
	})
	t.Run("disallowed-char", func(t *testing.T) {
		buf := mkBuf([]byte("FOO BAR")) // space — disallowed
		if _, err := DecodeGreeting(buf[:]); !errors.Is(err, ErrInvalidMechanism) {
			t.Fatalf("want ErrInvalidMechanism, got %v", err)
		}
	})
	t.Run("non-zero-after-name", func(t *testing.T) {
		buf := mkBuf([]byte("NULL"))
		buf[12+5] = 'X' // garbage after NUL terminator
		if _, err := DecodeGreeting(buf[:]); !errors.Is(err, ErrInvalidMechanism) {
			t.Fatalf("want ErrInvalidMechanism, got %v", err)
		}
	})
}

func TestEncodeGreetingFillerIsZero(t *testing.T) {
	var buf [GreetingSize]byte
	for i := range buf {
		buf[i] = 0xAA // pre-fill to detect leftover data
	}
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"}); err != nil {
		t.Fatal(err)
	}
	expectedFiller := make([]byte, 31)
	if !bytes.Equal(buf[33:64], expectedFiller) {
		t.Fatalf("filler not zeroed: %x", buf[33:64])
	}
}

func TestEncodeGreetingZeroAllocations(t *testing.T) {
	var buf [GreetingSize]byte
	g := Greeting{Mechanism: "NULL"}
	got := testing.AllocsPerRun(1000, func() {
		_ = EncodeGreeting(buf[:], g)
	})
	if got != 0 {
		t.Fatalf("EncodeGreeting allocates %v allocs/op, want 0", got)
	}
}

func TestGreetingRoundTripProperty(t *testing.T) {
	allowed := []byte{}
	for c := byte('A'); c <= 'Z'; c++ {
		allowed = append(allowed, c)
	}
	for c := byte('0'); c <= '9'; c++ {
		allowed = append(allowed, c)
	}
	allowed = append(allowed, '-', '_', '.', '+')

	prop := func(seed int64, asServer bool) bool {
		// Build a deterministic mechanism string from seed: 0..20 chars
		// from the allowed set.
		n := int(uint(seed) % 21) // 0..20 chars
		mech := make([]byte, n)
		for i := 0; i < n; i++ {
			mech[i] = allowed[uint(seed>>uint(i))%uint(len(allowed))]
		}
		g := Greeting{Mechanism: string(mech), AsServer: asServer}
		var buf [GreetingSize]byte
		if err := EncodeGreeting(buf[:], g); err != nil {
			return false
		}
		got, err := DecodeGreeting(buf[:])
		if err != nil {
			return false
		}
		return got == g
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}
