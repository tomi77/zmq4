package wire

import (
	"encoding/binary"
	"io"
)

// FrameWriter writes ZMTP 3.1 frames to an io.Writer. Not safe for
// concurrent use.
type FrameWriter struct {
	w      io.Writer
	header [9]byte
}

// NewFrameWriter returns a FrameWriter wrapping w.
func NewFrameWriter(w io.Writer) *FrameWriter { return &FrameWriter{w: w} }

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
	if _, err := fw.w.Write(fw.header[:hdrLen]); err != nil {
		return err
	}
	if len(f.Body) > 0 {
		if _, err := fw.w.Write(f.Body); err != nil {
			return err
		}
	}
	return nil
}
