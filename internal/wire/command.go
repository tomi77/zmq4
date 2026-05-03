package wire

import (
	"bytes"
	"fmt"
)

// Command is a parsed command-frame body.
//
// Data aliases the input buffer when produced by ParseCommand. If the
// command is retained beyond the next ParseCommand call on the same
// buffer, call Clone to detach Data.
type Command struct {
	Name string // ASCII letters only, 1..255 chars
	Data []byte // command-specific payload
}

// Clone returns a deep copy of c with a freshly allocated Data, detaching
// it from any source buffer aliased by ParseCommand. A nil Data is
// preserved as nil (not converted to an empty slice).
func (c Command) Clone() Command {
	c.Data = bytes.Clone(c.Data)
	return c
}

// ParseCommand parses a command body (the bytes inside a command Frame.Body).
// On success, Data aliases body.
func ParseCommand(body []byte) (Command, error) {
	if len(body) < 1 {
		return Command{}, fmt.Errorf("%w: empty body", ErrInvalidCommand)
	}
	nameLen := int(body[0])
	if nameLen == 0 {
		return Command{}, fmt.Errorf("%w: name length is zero", ErrInvalidCommand)
	}
	if 1+nameLen > len(body) {
		return Command{}, fmt.Errorf("%w: name truncated (length %d, body %d)", ErrInvalidCommand, nameLen, len(body)-1)
	}
	for i := range nameLen {
		if !isCommandNameChar(body[1+i]) {
			return Command{}, fmt.Errorf("%w: non-letter byte 0x%02X in name at offset %d", ErrInvalidCommand, body[1+i], i)
		}
	}
	return Command{
		Name: string(body[1 : 1+nameLen]),
		Data: body[1+nameLen:],
	}, nil
}

// EncodeCommand returns the wire body for c, suitable as Frame.Body.
func EncodeCommand(c Command) ([]byte, error) {
	if err := validateCommandName(c.Name); err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(c.Name)+len(c.Data))
	out[0] = byte(len(c.Name))
	copy(out[1:], c.Name)
	copy(out[1+len(c.Name):], c.Data)
	return out, nil
}

func validateCommandName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("%w: empty command name", ErrInvalidCommand)
	}
	if len(name) > 255 {
		return fmt.Errorf("%w: command name too long (%d > 255)", ErrInvalidCommand, len(name))
	}
	for i := 0; i < len(name); i++ {
		if !isCommandNameChar(name[i]) {
			return fmt.Errorf("%w: non-letter byte 0x%02X in name at offset %d", ErrInvalidCommand, name[i], i)
		}
	}
	return nil
}

// isCommandNameChar implements the ABNF "ALPHA" rule (A-Z / a-z).
func isCommandNameChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}
