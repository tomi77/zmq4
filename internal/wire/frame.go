package wire

import (
	"bytes"
	"encoding/binary"
)

// FrameKind distinguishes message frames from command frames.
type FrameKind uint8

const (
	// FrameMessage carries application payload.
	FrameMessage FrameKind = iota
	// FrameCommand carries protocol metadata (READY, ERROR, PING, ...).
	FrameCommand
)

// MaxShortBodySize is the largest body that can use the short-size encoding.
const MaxShortBodySize = 255

// MaxFrameBodySize is the upper bound on a single frame body accepted by
// ReadFrame and DecodeFrame. Frames claiming a larger size are rejected with
// ErrFrameTooLarge before any allocation is attempted.
const MaxFrameBodySize = 32 << 20 // 32 MiB

// Frame is a single ZMTP 3.1 frame.
//
// For decoded frames, Body aliases the source buffer (zero-copy). The
// caller owns the buffer's lifetime. If the frame is retained beyond the
// next DecodeFrame call on the same buffer, call Clone to detach Body.
// Streaming readers (FrameReader) always allocate a fresh Body slice.
type Frame struct {
	Kind FrameKind
	More bool   // continuation flag; must be false when Kind == FrameCommand
	Body []byte // raw payload; for commands, see ParseCommand
}

// Clone returns a deep copy of f with a freshly allocated Body, detaching
// it from any source buffer aliased by DecodeFrame. A nil Body is preserved
// as nil (not converted to an empty slice).
func (f Frame) Clone() Frame {
	f.Body = bytes.Clone(f.Body)
	return f
}

// WireSize returns the total on-wire size of f, including the flags byte
// and the size field.
func (f Frame) WireSize() int {
	if len(f.Body) <= MaxShortBodySize {
		return 1 + 1 + len(f.Body)
	}
	return 1 + 8 + len(f.Body)
}

// EncodeFrame writes f's wire representation into dst. Returns the number
// of bytes written. dst must be at least f.WireSize() bytes long.
func EncodeFrame(dst []byte, f Frame) (int, error) {
	need := f.WireSize()
	if len(dst) < need {
		return 0, ErrShortBuffer
	}
	if f.Kind == FrameCommand && f.More {
		return 0, ErrCommandHasMore
	}

	var flags byte
	if f.More {
		flags |= 0x01
	}
	long := len(f.Body) > MaxShortBodySize
	if long {
		flags |= 0x02
	}
	if f.Kind == FrameCommand {
		flags |= 0x04
	}
	dst[0] = flags

	off := 1
	if long {
		binary.BigEndian.PutUint64(dst[off:off+8], uint64(len(f.Body)))
		off += 8
	} else {
		dst[off] = byte(len(f.Body))
		off++
	}
	copy(dst[off:], f.Body)
	return need, nil
}

// DecodeFrame parses one frame starting at src[0]. Returns the parsed
// frame, the number of input bytes consumed, and any error. Body
// aliases src (zero-copy); copy if you retain it past the next decode.
func DecodeFrame(src []byte) (Frame, int, error) {
	if len(src) < 1 {
		return Frame{}, 0, ErrShortBuffer
	}
	flags := src[0]
	if flags&0xF8 != 0 {
		return Frame{}, 0, ErrReservedFlags
	}
	more := flags&0x01 != 0
	long := flags&0x02 != 0
	cmd := flags&0x04 != 0
	if cmd && more {
		return Frame{}, 0, ErrCommandHasMore
	}

	off := 1
	var size uint64
	if long {
		if len(src) < off+8 {
			return Frame{}, 0, ErrShortBuffer
		}
		size = binary.BigEndian.Uint64(src[off : off+8])
		off += 8
	} else {
		if len(src) < off+1 {
			return Frame{}, 0, ErrShortBuffer
		}
		size = uint64(src[off])
		off++
	}

	if size > MaxFrameBodySize {
		return Frame{}, 0, ErrFrameTooLarge
	}
	if uint64(len(src)-off) < size {
		return Frame{}, 0, ErrShortBuffer
	}
	end := off + int(size)
	kind := FrameMessage
	if cmd {
		kind = FrameCommand
	}
	return Frame{
		Kind: kind,
		More: more,
		Body: src[off:end],
	}, end, nil
}
