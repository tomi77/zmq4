package wire

import (
	"encoding/binary"
	"io"
)

// Option configures a FrameReader.
type Option func(*FrameReader)

// WithMaxBodySize sets the maximum frame body size accepted by ReadFrame.
// Frames claiming a larger body are rejected with ErrFrameTooLarge before any
// allocation. Panics if n <= 0.
func WithMaxBodySize(n int64) Option {
	if n <= 0 {
		panic("wire: WithMaxBodySize: n must be positive")
	}
	return func(fr *FrameReader) { fr.maxBodySize = n }
}

// FrameReader reads ZMTP 3.1 frames from an io.Reader. Each ReadFrame
// allocates a fresh Body slice. Not safe for concurrent use.
type FrameReader struct {
	r           io.Reader
	header      [9]byte
	maxBodySize int64
}

// NewFrameReader returns a FrameReader that reads from r. Without options the
// body size limit is MaxFrameBodySize.
func NewFrameReader(r io.Reader, opts ...Option) *FrameReader {
	fr := &FrameReader{r: r, maxBodySize: MaxFrameBodySize}
	for _, o := range opts {
		o(fr)
	}
	return fr
}

// ReadFrame reads the next frame from the underlying reader. Returns
// io.EOF only when the stream cleanly ends between frames; a truncated
// frame surfaces io.ErrUnexpectedEOF.
func (fr *FrameReader) ReadFrame() (Frame, error) {
	// Flags byte.
	if _, err := io.ReadFull(fr.r, fr.header[:1]); err != nil {
		return Frame{}, err // io.EOF passes through cleanly here.
	}
	flags := fr.header[0]
	if flags&0xF8 != 0 {
		return Frame{}, ErrReservedFlags
	}
	more := flags&0x01 != 0
	long := flags&0x02 != 0
	cmd := flags&0x04 != 0
	if cmd && more {
		return Frame{}, ErrCommandHasMore
	}

	var size uint64
	if long {
		if _, err := io.ReadFull(fr.r, fr.header[:8]); err != nil {
			return Frame{}, mapEOF(err)
		}
		size = binary.BigEndian.Uint64(fr.header[:8])
	} else {
		if _, err := io.ReadFull(fr.r, fr.header[:1]); err != nil {
			return Frame{}, mapEOF(err)
		}
		size = uint64(fr.header[0])
	}

	if size > uint64(fr.maxBodySize) {
		return Frame{}, ErrFrameTooLarge
	}
	body := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(fr.r, body); err != nil {
			return Frame{}, mapEOF(err)
		}
	}
	kind := FrameMessage
	if cmd {
		kind = FrameCommand
	}
	return Frame{Kind: kind, More: more, Body: body}, nil
}

// mapEOF converts a clean io.EOF mid-frame into io.ErrUnexpectedEOF.
func mapEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
