package wire

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

// Frame is a single ZMTP 3.1 frame.
//
// For decoded frames, Body aliases the source buffer (zero-copy). The
// caller owns the buffer's lifetime — copy if you retain Body past the
// next decode call. Streaming readers (FrameReader) always allocate a
// fresh Body slice.
type Frame struct {
	Kind FrameKind
	More bool   // continuation flag; must be false when Kind == FrameCommand
	Body []byte // raw payload; for commands, see ParseCommand
}

// WireSize returns the total on-wire size of f, including the flags byte
// and the size field.
func (f Frame) WireSize() int {
	if len(f.Body) <= MaxShortBodySize {
		return 1 + 1 + len(f.Body)
	}
	return 1 + 8 + len(f.Body)
}
