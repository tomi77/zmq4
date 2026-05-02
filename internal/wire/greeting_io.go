package wire

import "io"

// ReadGreeting reads exactly GreetingSize bytes from r and decodes them.
// Returns io.ErrUnexpectedEOF on truncated input.
func ReadGreeting(r io.Reader) (Greeting, error) {
	var buf [GreetingSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
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
