package wire

import "fmt"

// ErrorCommandName is the wire name for the ERROR command.
const ErrorCommandName = "ERROR"

// ErrorCommand is the parsed body of an ERROR command (RFC 37).
type ErrorCommand struct {
	// Reason: 0..255 visible-ASCII characters describing the failure.
	Reason string
}

// ParseError parses cmd as an ERROR command body.
func ParseError(cmd Command) (ErrorCommand, error) {
	if cmd.Name != ErrorCommandName {
		return ErrorCommand{}, fmt.Errorf("%w: expected ERROR, got %q", ErrInvalidCommand, cmd.Name)
	}
	if len(cmd.Data) < 1 {
		return ErrorCommand{}, fmt.Errorf("%w: ERROR body missing reason-size", ErrInvalidCommand)
	}
	reasonLen := int(cmd.Data[0])
	if 1+reasonLen != len(cmd.Data) {
		return ErrorCommand{}, fmt.Errorf("%w: ERROR reason length %d does not match body %d", ErrInvalidCommand, reasonLen, len(cmd.Data)-1)
	}
	return ErrorCommand{Reason: string(cmd.Data[1 : 1+reasonLen])}, nil
}

// Encode produces the wire form. Panics if Reason is longer than 255
// characters — callers must validate before calling.
func (ec ErrorCommand) Encode() Command {
	if len(ec.Reason) > 255 {
		panic("wire: ErrorCommand.Reason exceeds 255 chars")
	}
	data := make([]byte, 1+len(ec.Reason))
	data[0] = byte(len(ec.Reason))
	copy(data[1:], ec.Reason)
	return Command{Name: ErrorCommandName, Data: data}
}
