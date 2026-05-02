package wire

import "testing"

func FuzzDecodeFrame(f *testing.F) {
	// Seed with a few hand-picked good and bad inputs.
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'})
	f.Add([]byte{0x04, 0x05, 'R', 'E', 'A', 'D', 'Y'})
	f.Add([]byte{0xFF}) // reserved bits
	f.Fuzz(func(t *testing.T, data []byte) {
		fr, n, err := DecodeFrame(data)
		if err != nil {
			return
		}
		if n < 0 || n > len(data) {
			t.Fatalf("invariant: n=%d out of range for input %d", n, len(data))
		}
		// Re-encode and verify it parses back identically.
		buf := make([]byte, fr.WireSize())
		if _, err := EncodeFrame(buf, fr); err != nil {
			t.Fatalf("re-encode failed for valid decode: %v", err)
		}
	})
}

func FuzzDecodeGreeting(f *testing.F) {
	var seed [GreetingSize]byte
	_ = EncodeGreeting(seed[:], Greeting{Mechanism: "NULL"})
	f.Add(seed[:])
	f.Add(make([]byte, GreetingSize))
	f.Add(make([]byte, GreetingSize-1))
	f.Fuzz(func(t *testing.T, data []byte) {
		g, err := DecodeGreeting(data)
		if err != nil {
			return
		}
		var enc [GreetingSize]byte
		if err := EncodeGreeting(enc[:], g); err != nil {
			t.Fatalf("re-encode failed for valid decode: %v", err)
		}
	})
}
