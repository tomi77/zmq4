package wire

import (
	"encoding/binary"
	"fmt"
)

// PingCommandName / PongCommandName are the wire names.
const (
	PingCommandName = "PING"
	PongCommandName = "PONG"
)

// PingContextMaxSize is the largest allowed PING / PONG context.
const PingContextMaxSize = 16

// PingCommand is the parsed body of a PING heartbeat (RFC 37).
type PingCommand struct {
	TTL     uint16 // tenths of a second
	Context []byte // 0..16 bytes; echoed by PONG
}

// PongCommand is the response to PING.
type PongCommand struct {
	Context []byte // 0..16 bytes; should equal the PING's context
}

// ParsePing parses cmd as a PING body.
func ParsePing(cmd Command) (PingCommand, error) {
	if cmd.Name != PingCommandName {
		return PingCommand{}, fmt.Errorf("%w: expected PING, got %q", ErrInvalidCommand, cmd.Name)
	}
	if len(cmd.Data) < 2 {
		return PingCommand{}, fmt.Errorf("%w: PING TTL truncated", ErrInvalidCommand)
	}
	ctx := cmd.Data[2:]
	if len(ctx) > PingContextMaxSize {
		return PingCommand{}, fmt.Errorf("%w: PING context %d > 16", ErrInvalidCommand, len(ctx))
	}
	return PingCommand{
		TTL:     binary.BigEndian.Uint16(cmd.Data[:2]),
		Context: ctx,
	}, nil
}

// Encode produces the Command form. Returns ErrInvalidCommand if
// Context exceeds 16 bytes.
func (pc PingCommand) Encode() (Command, error) {
	if len(pc.Context) > PingContextMaxSize {
		return Command{}, fmt.Errorf("%w: PING context %d > %d", ErrInvalidCommand, len(pc.Context), PingContextMaxSize)
	}
	data := make([]byte, 2+len(pc.Context))
	binary.BigEndian.PutUint16(data[:2], pc.TTL)
	copy(data[2:], pc.Context)
	return Command{Name: PingCommandName, Data: data}, nil
}

// ParsePong parses cmd as a PONG body.
func ParsePong(cmd Command) (PongCommand, error) {
	if cmd.Name != PongCommandName {
		return PongCommand{}, fmt.Errorf("%w: expected PONG, got %q", ErrInvalidCommand, cmd.Name)
	}
	if len(cmd.Data) > PingContextMaxSize {
		return PongCommand{}, fmt.Errorf("%w: PONG context %d > 16", ErrInvalidCommand, len(cmd.Data))
	}
	return PongCommand{Context: cmd.Data}, nil
}

// Encode produces the Command form. Returns ErrInvalidCommand if
// Context exceeds 16 bytes. Data aliases pc.Context.
func (pc PongCommand) Encode() (Command, error) {
	if len(pc.Context) > PingContextMaxSize {
		return Command{}, fmt.Errorf("%w: PONG context %d > %d", ErrInvalidCommand, len(pc.Context), PingContextMaxSize)
	}
	return Command{Name: PongCommandName, Data: pc.Context}, nil
}
