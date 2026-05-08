package conn

import (
	"errors"
	"net"
	"sync"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/wire"
)

// Conn is one ZMTP 3.1 connection: a single, full-duplex peering over a
// raw net.Conn that has completed greeting and security handshake.
// Returned by ClientHandshake / ServerHandshake; never constructed by F5
// directly.
//
// ReadFrame is not goroutine-safe (one reader at a time). WriteFrame is
// goroutine-safe (internal mutex serialises bytes on raw). Close is
// idempotent; concurrent reads/writes after Close observe net.ErrClosed
// (or io.ErrClosedPipe for inproc per F3 §4.4).
type Conn struct {
	raw      net.Conn
	fr       *wire.FrameReader
	fw       *wire.FrameWriter
	mech     security.Mechanism
	peerMeta wire.Metadata

	writeMu sync.Mutex

	closeMu sync.Mutex
	closed  bool
}

// ReadFrame is implemented in Chunk 3.
func (c *Conn) ReadFrame() (wire.Frame, error) {
	return wire.Frame{}, errors.New("conn: ReadFrame not implemented")
}

// WriteFrame is implemented in Chunk 3.
func (c *Conn) WriteFrame(f wire.Frame) error {
	return errors.New("conn: WriteFrame not implemented")
}

// PeerMetadata returns the metadata advertised by the peer in handshake.
// The returned Metadata is a defensive clone made at handshake done
// (spec §4.2): owned by *Conn, decoupled from the mechanism, stable for
// the lifetime of the *Conn. Callers MUST NOT mutate it.
func (c *Conn) PeerMetadata() wire.Metadata { return c.peerMeta }

// Close releases the underlying raw net.Conn and unblocks any in-flight
// reader or writer. Idempotent. After Close, ReadFrame and WriteFrame
// return net.ErrClosed (or io.ErrClosedPipe for inproc).
//
// ZMTP 3.1 has no graceful disconnect handshake; F4 just releases the
// FD. F5 owns linger semantics for in-flight messages.
func (c *Conn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return nil
	}
	c.closed = true
	c.closeMu.Unlock()
	return c.raw.Close()
}

// RemoteAddr returns the underlying raw net.Conn's remote address.
// Stable for the lifetime of the *Conn including post-Close.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// LocalAddr returns the underlying raw net.Conn's local address.
// Stable for the lifetime of the *Conn including post-Close.
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }
