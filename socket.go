package zmq4

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/tomi77/zmq4/internal/wire"
)

// Socket is a ZeroMQ socket.
//
// The current implementation is a minimal scaffold that directly wraps a
// net.Conn.  F5 will replace the internals with full connection management,
// routing, and socket-type semantics while keeping this method set.
type Socket struct {
	conn net.Conn
	fr   *wire.FrameReader
	fw   *wire.FrameWriter
	zcr  zeroCopyReader
}

// NewSocket wraps conn in a Socket.  Intended for testing and low-level use;
// F5 will add type-specific constructors (NewREQ, NewREP, etc.).
func NewSocket(conn net.Conn) *Socket {
	return &Socket{
		conn: conn,
		fr:   wire.NewFrameReader(conn),
		fw:   wire.NewFrameWriter(conn),
		zcr:  zeroCopyReader{r: conn},
	}
}

// Recv receives a single-part message. The returned slice is owned by the caller.
func (s *Socket) Recv() ([]byte, error) {
	f, err := s.fr.ReadFrame()
	if err != nil {
		return nil, err
	}
	return f.Body, nil
}

// RecvMsg receives a multi-part message. Each part is owned by the caller.
func (s *Socket) RecvMsg() (Message, error) {
	var msg Message
	for {
		f, err := s.fr.ReadFrame()
		if err != nil {
			return nil, err
		}
		msg = append(msg, f.Body)
		if !f.More {
			break
		}
	}
	return msg, nil
}

// Send sends a single-part message.
func (s *Socket) Send(data []byte) error {
	return s.fw.WriteFrame(wire.Frame{Kind: wire.FrameMessage, Body: data})
}

// SendMsg sends a multi-part message.
func (s *Socket) SendMsg(msg Message) error {
	for i, part := range msg {
		more := i < len(msg)-1
		if err := s.fw.WriteFrame(wire.Frame{Kind: wire.FrameMessage, More: more, Body: part}); err != nil {
			return err
		}
	}
	return nil
}

// RecvFrame receives one wire frame. Frame.Body aliases the socket's internal
// read buffer; it is valid only until the next RecvFrame call on this socket.
// Call [wire.Frame.Clone] to detach if you need to retain it longer.
func (s *Socket) RecvFrame() (wire.Frame, error) {
	return s.zcr.readFrame()
}

// SendFrame sends one wire frame without copying Frame.Body.
func (s *Socket) SendFrame(f wire.Frame) error {
	return s.fw.WriteFrame(f)
}

// zeroCopyReader reads ZMTP 3.1 message frames reusing a single body buffer.
// Successive calls alias the same backing array, so a frame's Body is valid
// only until the next readFrame call.
type zeroCopyReader struct {
	r      io.Reader
	header [9]byte
	body   []byte
}

func (z *zeroCopyReader) readFrame() (wire.Frame, error) {
	if _, err := io.ReadFull(z.r, z.header[:1]); err != nil {
		return wire.Frame{}, err
	}
	flags := z.header[0]
	more := flags&0x01 != 0
	long := flags&0x02 != 0

	var size uint64
	if long {
		if _, err := io.ReadFull(z.r, z.header[:8]); err != nil {
			return wire.Frame{}, mapEOF(err)
		}
		size = binary.BigEndian.Uint64(z.header[:8])
	} else {
		if _, err := io.ReadFull(z.r, z.header[:1]); err != nil {
			return wire.Frame{}, mapEOF(err)
		}
		size = uint64(z.header[0])
	}

	if size > wire.MaxFrameBodySize {
		return wire.Frame{}, wire.ErrFrameTooLarge
	}

	if uint64(cap(z.body)) >= size {
		z.body = z.body[:size]
	} else {
		z.body = make([]byte, size)
	}
	if size > 0 {
		if _, err := io.ReadFull(z.r, z.body); err != nil {
			return wire.Frame{}, mapEOF(err)
		}
	}
	return wire.Frame{Kind: wire.FrameMessage, More: more, Body: z.body}, nil
}

func mapEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
