package wire

import (
	"encoding/binary"
	"io"
	"net"
)

// MsgMaxFrames is the maximum number of frames in WriteMsg's zero-allocation
// path. Messages longer than this fall back to sequential WriteFrame calls.
const MsgMaxFrames = 8

// msgMaxFrames is the internal alias used within this file.
const msgMaxFrames = MsgMaxFrames

// FrameWriter writes ZMTP 3.1 frames to an io.Writer. Not safe for
// concurrent use.
//
// When the underlying writer is a *net.TCPConn or any io.Writer that
// supports the writev fast path used by net.Buffers, header and body
// are emitted in a single writev syscall. Otherwise the standard
// library falls back to two sequential Writes.
type FrameWriter struct {
	w        io.Writer
	header   [9]byte
	bufsArr  [2][]byte // backing array for the per-call net.Buffers slice
	msgHdrs  [msgMaxFrames][9]byte        // header scratch for WriteMsg
	msgBufs  [msgMaxFrames * 2][]byte    // buffers scratch for WriteMsg
}

// NewFrameWriter returns a FrameWriter wrapping w.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// WriteMsg encodes all frames in a single net.Buffers.WriteTo call.
// For ≤8 frames the header scratch arrays are reused from the struct (zero allocation).
// Falls back to sequential WriteFrame calls for messages exceeding msgMaxFrames frames.
func (fw *FrameWriter) WriteMsg(frames []Frame) error {
	n := len(frames)
	switch {
	case n == 0:
		return nil
	case n == 1:
		return fw.WriteFrame(frames[0])
	case n > msgMaxFrames:
		for _, f := range frames {
			if err := fw.WriteFrame(f); err != nil {
				return err
			}
		}
		return nil
	}
	for i, f := range frames {
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
		fw.msgHdrs[i][0] = flags
		hdrLen := 2
		if long {
			binary.BigEndian.PutUint64(fw.msgHdrs[i][1:9], uint64(len(f.Body)))
			hdrLen = 9
		} else {
			fw.msgHdrs[i][1] = byte(len(f.Body))
		}
		fw.msgBufs[i*2] = fw.msgHdrs[i][:hdrLen]
		fw.msgBufs[i*2+1] = f.Body
	}
	bufs := net.Buffers(fw.msgBufs[:n*2])
	_, err := bufs.WriteTo(fw.w)
	return err
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
	// Reuse bufsArr instead of a fresh net.Buffers literal: the literal
	// would heap-allocate the underlying [2][]byte on every call.
	// net.Buffers.WriteTo handles partial writes internally (retries until
	// all bytes are flushed or an error occurs), so both empty and non-empty
	// bodies are safe against partial-write silently dropping data.
	fw.bufsArr[0] = fw.header[:hdrLen]
	fw.bufsArr[1] = f.Body
	bufs := net.Buffers(fw.bufsArr[:])
	_, err := bufs.WriteTo(fw.w)
	return err
}
