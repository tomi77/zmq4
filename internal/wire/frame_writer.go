package wire

import (
	"encoding/binary"
	"io"
	"net"
)

// FrameWriter writes ZMTP 3.1 frames to an io.Writer. Not safe for
// concurrent use.
//
// When the underlying writer is a *net.TCPConn or any io.Writer that
// supports the writev fast path used by net.Buffers, header and body
// are emitted in a single writev syscall. Otherwise the standard
// library falls back to two sequential Writes.
type FrameWriter struct {
	w       io.Writer
	header  [9]byte
	bufsArr [2][]byte // backing array for the per-call net.Buffers slice
}

// NewFrameWriter returns a FrameWriter wrapping w.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// WriteFrame encodes f and writes it to the underlying writer. Returns
// ErrCommandHasMore if f is a command with the MORE flag set.
func (fw *FrameWriter) WriteFrame(f Frame) error {
	if f.Kind == FrameCommand && f.More {
		return ErrCommandHasMore
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
	fw.header[0] = flags
	hdrLen := 2
	if long {
		binary.BigEndian.PutUint64(fw.header[1:9], uint64(len(f.Body)))
		hdrLen = 9
	} else {
		fw.header[1] = byte(len(f.Body))
	}
	if len(f.Body) == 0 {
		_, err := fw.w.Write(fw.header[:hdrLen])
		return err
	}
	// Reuse bufsArr instead of a fresh net.Buffers literal: the literal
	// would heap-allocate the underlying [2][]byte on every call.
	fw.bufsArr[0] = fw.header[:hdrLen]
	fw.bufsArr[1] = f.Body
	bufs := net.Buffers(fw.bufsArr[:])
	_, err := bufs.WriteTo(fw.w)
	return err
}
