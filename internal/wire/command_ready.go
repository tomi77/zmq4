package wire

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ReadyCommandName is the wire name for the READY command.
const ReadyCommandName = "READY"

// ReadyCommand is the parsed body of a READY command (RFC 37).
type ReadyCommand struct {
	Metadata Metadata
}

// Metadata is an ordered list of properties carried by READY (and
// potentially other commands). Order is preserved on round-trip.
type Metadata []MetadataProperty

// MetadataProperty is one name/value pair.
type MetadataProperty struct {
	// Name: 1..255 chars from [A-Z a-z 0-9 - _ . +]. Case-insensitive on lookup.
	Name string
	// Value: 0..2^32-1 bytes, opaque.
	Value []byte
}

// Get returns the value of the first property whose name matches name
// (case-insensitive ASCII) and a boolean indicating presence.
func (m Metadata) Get(name string) ([]byte, bool) {
	for _, p := range m {
		if strings.EqualFold(p.Name, name) {
			return p.Value, true
		}
	}
	return nil, false
}

// ParseReady parses cmd as a READY command body.
func ParseReady(cmd Command) (ReadyCommand, error) {
	if cmd.Name != ReadyCommandName {
		return ReadyCommand{}, fmt.Errorf("%w: expected READY, got %q", ErrInvalidCommand, cmd.Name)
	}
	md, err := parseMetadata(cmd.Data)
	if err != nil {
		return ReadyCommand{}, err
	}
	return ReadyCommand{Metadata: md}, nil
}

// Encode returns the Command form of rc, suitable for embedding in a
// FrameCommand body via EncodeCommand.
func (rc ReadyCommand) Encode() Command {
	data := encodeMetadata(rc.Metadata)
	return Command{Name: ReadyCommandName, Data: data}
}

func parseMetadata(data []byte) (Metadata, error) {
	var out Metadata
	for off := 0; off < len(data); {
		if off+1 > len(data) {
			return nil, fmt.Errorf("%w: metadata truncated at name-size", ErrInvalidCommand)
		}
		nameLen := int(data[off])
		off++
		if nameLen == 0 {
			return nil, fmt.Errorf("%w: metadata property has zero-length name", ErrInvalidCommand)
		}
		if off+nameLen > len(data) {
			return nil, fmt.Errorf("%w: metadata name truncated", ErrInvalidCommand)
		}
		name := string(data[off : off+nameLen])
		off += nameLen
		if !isMetadataName(name) {
			return nil, fmt.Errorf("%w: invalid metadata name %q", ErrInvalidCommand, name)
		}
		if off+4 > len(data) {
			return nil, fmt.Errorf("%w: metadata value-size truncated", ErrInvalidCommand)
		}
		valSize := binary.BigEndian.Uint32(data[off : off+4])
		off += 4
		if off+int(valSize) > len(data) {
			return nil, fmt.Errorf("%w: metadata value truncated", ErrInvalidCommand)
		}
		out = append(out, MetadataProperty{Name: name, Value: data[off : off+int(valSize)]})
		off += int(valSize)
	}
	return out, nil
}

func encodeMetadata(md Metadata) []byte {
	size := 0
	for _, p := range md {
		size += 1 + len(p.Name) + 4 + len(p.Value)
	}
	out := make([]byte, size)
	off := 0
	for _, p := range md {
		out[off] = byte(len(p.Name))
		off++
		copy(out[off:], p.Name)
		off += len(p.Name)
		binary.BigEndian.PutUint32(out[off:off+4], uint32(len(p.Value)))
		off += 4
		copy(out[off:], p.Value)
		off += len(p.Value)
	}
	return out
}

func isMetadataName(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == '+':
		default:
			return false
		}
	}
	return true
}
