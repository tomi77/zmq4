package wire

import (
	"encoding/binary"
	"fmt"
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
//
// When produced by ParseReady, both Name and Value alias the input
// buffer (zero-copy). Copy them if you retain the property past the
// next parse call.
type MetadataProperty struct {
	// Name: 1..255 chars from [A-Z a-z 0-9 - _ . +]. Compared
	// case-insensitively via Metadata.Get.
	Name []byte
	// Value: 0..2^32-1 bytes, opaque.
	Value []byte
}

// Get returns the value of the first property whose name matches name
// (case-insensitive ASCII) and a boolean indicating presence.
func (m Metadata) Get(name string) ([]byte, bool) {
	for _, p := range m {
		if eqFoldBytes(p.Name, name) {
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
	md, err := ParseMetadata(cmd.Data)
	if err != nil {
		return ReadyCommand{}, err
	}
	return ReadyCommand{Metadata: md}, nil
}

// Encode returns the Command form of rc, suitable for embedding in a
// FrameCommand body via EncodeCommand. Returns ErrInvalidCommand if any
// property has an invalid name or a value exceeding 2^32-1 bytes.
func (rc ReadyCommand) Encode() (Command, error) {
	for _, p := range rc.Metadata {
		if !isMetadataName(p.Name) {
			return Command{}, fmt.Errorf("%w: invalid metadata name %q", ErrInvalidCommand, p.Name)
		}
		if uint64(len(p.Value)) > 0xFFFFFFFF {
			return Command{}, fmt.Errorf("%w: metadata value too large (%d > 2^32-1)", ErrInvalidCommand, len(p.Value))
		}
	}
	return Command{Name: ReadyCommandName, Data: EncodeMetadata(rc.Metadata)}, nil
}

// ParseMetadata decodes a metadata blob (sequence of *property as defined
// in RFC 37 §2.4) into a Metadata value. The returned slice aliases the
// input buffer; copy if you need an independent lifetime.
//
// Used by ParseReady (READY) and by internal/security/plain (INITIATE).
func ParseMetadata(data []byte) (Metadata, error) {
	var out Metadata
	for off := 0; off < len(data); {
		nameLen := int(data[off])
		off++
		if nameLen == 0 {
			return nil, fmt.Errorf("%w: metadata property has zero-length name", ErrInvalidCommand)
		}
		if off+nameLen > len(data) {
			return nil, fmt.Errorf("%w: metadata name truncated", ErrInvalidCommand)
		}
		name := data[off : off+nameLen]
		off += nameLen
		if !isMetadataName(name) {
			return nil, fmt.Errorf("%w: invalid metadata name %q", ErrInvalidCommand, name)
		}
		if off+4 > len(data) {
			return nil, fmt.Errorf("%w: metadata value-size truncated", ErrInvalidCommand)
		}
		valSize := binary.BigEndian.Uint32(data[off : off+4])
		off += 4
		// Compare in uint64 so a valSize > 2^31-1 can't wrap to a
		// negative int on 32-bit platforms and slip past the bound check.
		if uint64(valSize) > uint64(len(data)-off) {
			return nil, fmt.Errorf("%w: metadata value truncated", ErrInvalidCommand)
		}
		end := off + int(valSize)
		out = append(out, MetadataProperty{Name: name, Value: data[off:end]})
		off = end
	}
	return out, nil
}

// EncodeMetadata is the inverse of ParseMetadata.
//
// Used by (ReadyCommand).Encode and by internal/security/plain.
func EncodeMetadata(md Metadata) []byte {
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

func isMetadataName(s []byte) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}
	for i := range s {
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

// eqFoldBytes reports whether b equals s under ASCII case folding,
// without allocating a string from b.
func eqFoldBytes(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := range b {
		bc, sc := b[i], s[i]
		if bc == sc {
			continue
		}
		if 'A' <= bc && bc <= 'Z' {
			bc += 'a' - 'A'
		}
		if 'A' <= sc && sc <= 'Z' {
			sc += 'a' - 'A'
		}
		if bc != sc {
			return false
		}
	}
	return true
}
