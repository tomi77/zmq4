package wire

import "fmt"

// GreetingSize is the on-wire size of a complete ZMTP 3.1 greeting.
const GreetingSize = 64

// Greeting is the parsed form of the ZMTP 3.1 connection greeting.
type Greeting struct {
	// Mechanism is the security mechanism name (e.g. "NULL", "PLAIN", "CURVE").
	// Must be ≤20 ASCII characters from the set [A-Z 0-9 - _ . +].
	Mechanism string
	// AsServer signals the peer's role for mechanism negotiation.
	AsServer bool
}

// EncodeGreeting writes a 64-byte greeting into dst.
//
// Returns ErrShortBuffer if len(dst) < GreetingSize.
// Returns ErrInvalidMechanism if g.Mechanism is too long or contains
// disallowed characters.
func EncodeGreeting(dst []byte, g Greeting) error {
	if len(dst) < GreetingSize {
		return ErrShortBuffer
	}
	if err := validateMechanism(g.Mechanism); err != nil {
		return err
	}
	// Signature
	dst[0] = 0xFF
	for i := 1; i < 9; i++ {
		dst[i] = 0
	}
	dst[9] = 0x7F
	// Version
	dst[10] = 0x03
	dst[11] = 0x01
	// Mechanism (NUL-padded)
	for i := 0; i < 20; i++ {
		dst[12+i] = 0
	}
	copy(dst[12:32], g.Mechanism)
	// As-server
	dst[32] = 0
	if g.AsServer {
		dst[32] = 1
	}
	// Filler
	for i := 33; i < 64; i++ {
		dst[i] = 0
	}
	return nil
}

// DecodeGreeting parses a 64-byte greeting from src.
func DecodeGreeting(src []byte) (Greeting, error) {
	if len(src) < GreetingSize {
		return Greeting{}, ErrShortBuffer
	}
	if src[0] != 0xFF || src[9] != 0x7F {
		return Greeting{}, fmt.Errorf("%w: got 0x%02X..0x%02X, want 0xFF..0x7F", ErrInvalidSignature, src[0], src[9])
	}
	if src[10] != 0x03 || src[11] != 0x01 {
		return Greeting{}, fmt.Errorf("%w: got %d.%d, want 3.1", ErrUnsupportedVersion, src[10], src[11])
	}
	mech, err := parseMechanism(src[12:32])
	if err != nil {
		return Greeting{}, err
	}
	return Greeting{
		Mechanism: mech,
		AsServer:  src[32] == 1,
	}, nil
}

// validateMechanism returns ErrInvalidMechanism if name is too long or
// contains disallowed characters.
func validateMechanism(name string) error {
	if len(name) > 20 {
		return fmt.Errorf("%w: mechanism name too long (%d > 20)", ErrInvalidMechanism, len(name))
	}
	for i := 0; i < len(name); i++ {
		if !isMechanismChar(name[i]) {
			return fmt.Errorf("%w: invalid char 0x%02X at offset %d", ErrInvalidMechanism, name[i], i)
		}
	}
	return nil
}

// parseMechanism reads the 20-byte mechanism field. It returns the
// non-NUL prefix and verifies the trailing bytes are NUL-padded.
func parseMechanism(field []byte) (string, error) {
	end := -1
	for i := 0; i < len(field); i++ {
		c := field[i]
		if c == 0x00 {
			end = i
			break
		}
		if !isMechanismChar(c) {
			return "", fmt.Errorf("%w: invalid char 0x%02X at offset %d", ErrInvalidMechanism, c, i)
		}
	}
	var name string
	if end == -1 {
		name = string(field)
	} else {
		name = string(field[:end])
		// Verify the rest is NUL.
		for i := end + 1; i < len(field); i++ {
			if field[i] != 0x00 {
				return "", fmt.Errorf("%w: non-NUL byte 0x%02X after terminator at offset %d", ErrInvalidMechanism, field[i], i)
			}
		}
	}
	return name, nil
}

func isMechanismChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_' || c == '.' || c == '+':
		return true
	}
	return false
}
