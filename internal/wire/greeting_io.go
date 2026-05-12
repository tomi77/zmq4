package wire

import (
	"fmt"
	"io"
)

// ReadGreetingPhaseA reads the first 11 bytes of a ZMTP 3.1 greeting
// (signature 10 B + version major 1 B) from r and validates them.
//
// On any byte mismatch, returns the appropriate sentinel without
// consuming additional bytes:
//   - signature bytes wrong → ErrInvalidSignature.
//   - version major != 0x03 → ErrUnsupportedVersion.
//
// Truncated input returns io.ErrUnexpectedEOF.
//
// This is the lockstep gate at the top of a ZMTP greeting per RFC 23
// §3.2: it lets a peer reject a connection cleanly before the
// remaining 53 bytes are read.
func ReadGreetingPhaseA(r io.Reader) error {
	var hdr [11]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if hdr[0] != 0xFF || hdr[9] != 0x7F {
		return fmt.Errorf("%w: got 0x%02X..0x%02X, want 0xFF..0x7F", ErrInvalidSignature, hdr[0], hdr[9])
	}
	// bytes 1-8 are padding; "not significant" per ZMTP spec RFC 23 §3.2.
	// libzmq 4.x sets byte 8 = 0x01 as a ZMTP 2.0 backward-compat marker.
	if hdr[10] != 0x03 {
		return fmt.Errorf("%w: got major %d, want 3", ErrUnsupportedVersion, hdr[10])
	}
	return nil
}

// ReadGreeting reads exactly GreetingSize bytes from r and decodes them.
// Returns io.ErrUnexpectedEOF on truncated input.
//
// Internally calls ReadGreetingPhaseA on the first 11 bytes (signature
// + version major), then reads the remaining 53 bytes (version minor +
// mechanism + as-server + filler) and decodes the full buffer.
func ReadGreeting(r io.Reader) (Greeting, error) {
	var buf [GreetingSize]byte
	// Phase-A: signature + version major. Validates inline; on failure we
	// abort before reading the remaining 53 bytes (RFC 23 §3.2 lockstep).
	if err := ReadGreetingPhaseA(r); err != nil {
		return Greeting{}, err
	}
	// Reconstruct the validated phase-A bytes; ReadGreetingPhaseA does not
	// return them, but we know exactly what they are post-validation.
	buf[0] = 0xFF
	// buf[1..8] = 0 (already zero)
	buf[9] = 0x7F
	buf[10] = 0x03
	if _, err := io.ReadFull(r, buf[11:]); err != nil {
		if err == io.EOF {
			return Greeting{}, io.ErrUnexpectedEOF
		}
		return Greeting{}, err
	}
	return DecodeGreeting(buf[:])
}

// WriteGreeting encodes g and writes the resulting GreetingSize bytes to w.
func WriteGreeting(w io.Writer, g Greeting) error {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], g); err != nil {
		return err
	}
	_, err := w.Write(buf[:])
	return err
}
