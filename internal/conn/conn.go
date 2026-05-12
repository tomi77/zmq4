package conn

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"

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
	closed  atomic.Bool
}

// ReadFrame reads one post-handshake application frame. NOT goroutine-safe.
// See *Conn doc-comment for the full return-value contract.
func (c *Conn) ReadFrame() (wire.Frame, error) {
	f, err := c.fr.ReadFrame()
	if err != nil {
		return wire.Frame{}, err
	}
	if f.Kind == wire.FrameMessage {
		// NULL/PLAIN: alias pass-through. CURVE: not expected on this
		// path — CURVE wraps user data into MESSAGE commands. CURVE.Unwrap
		// returns its own error which we forward via %w.
		return c.mech.Unwrap(f)
	}
	// f.Kind == FrameCommand
	cmd, perr := wire.ParseCommand(f.Body)
	if perr != nil {
		return wire.Frame{}, fmt.Errorf("conn: bad post-handshake command: %w", perr)
	}
	switch cmd.Name {
	case wire.MessageCommandName:
		return c.mech.Unwrap(f) // CURVE-only data path.
	case wire.ErrorCommandName:
		ec, eperr := wire.ParseError(cmd)
		if eperr != nil {
			return wire.Frame{}, fmt.Errorf("conn: malformed peer ERROR: %w", eperr)
		}
		return wire.Frame{}, &ErrPeerError{Reason: ec.Reason}
	default:
		// SUBSCRIBE / CANCEL / PING / PONG / unknown — pass through to F5.
		return f, nil
	}
}

// WriteFrame writes one post-handshake application frame. Goroutine-safe
// via internal mutex (one writer at a time on raw; bytes per frame are
// atomic on the wire). See *Conn doc-comment for the full return-value
// contract.
func (c *Conn) WriteFrame(f wire.Frame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed.Load() {
		return net.ErrClosed
	}

	if f.Kind == wire.FrameMessage {
		out, err := c.mech.Wrap(f)
		if err != nil {
			return fmt.Errorf("conn: mech.Wrap: %w", err)
		}
		return c.fw.WriteFrame(out)
	}
	// FrameCommand: F5 owns command-name correctness; F4 sends verbatim
	// (RFC 25 — only MESSAGE commands are encrypted; SUBSCRIBE/CANCEL/
	// PING/PONG go plaintext even under CURVE).
	return c.fw.WriteFrame(f)
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
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	return c.raw.Close()
}

// RemoteAddr returns the underlying raw net.Conn's remote address.
// Stable for the lifetime of the *Conn including post-Close.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// LocalAddr returns the underlying raw net.Conn's local address.
// Stable for the lifetime of the *Conn including post-Close.
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }
