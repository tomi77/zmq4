package zmq4

import (
	"context"

	"github.com/tomi77/zmq4/internal/conn"
	"github.com/tomi77/zmq4/internal/wire"
)

// XSUB is an extended subscribe socket. It behaves like SUB for receiving
// and allows the application to send raw subscription frames via Send
// (for proxy use cases). Subscribe and Unsubscribe are convenience wrappers.
type XSUB struct {
	base  socketBase
	state *subState
}

// NewXSUB creates a new XSUB socket.
func NewXSUB(opts ...Option) *XSUB {
	s := &XSUB{
		base:  newSocketBase(newSocketConfig(opts)),
		state: newSubState(),
	}
	s.base.postHandshake = s.onNewConn
	return s
}

func (s *XSUB) onNewConn(c *conn.Conn) error {
	for _, sub := range s.state.all() {
		if err := c.WriteFrame(subFrame(0x01, sub)); err != nil {
			return err
		}
	}
	identity := peerIdentity(c.PeerMetadata())
	p := newPipe(c, identity, s.base.cfg.sndHWM, s.base.cfg.rcvHWM, s.base.cfg.sndOverflow)
	s.base.pipes.add(p)
	p.start(s.base.pipes, s.base.closeCh)
	return nil
}

func (s *XSUB) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "XSUB")
}

func (s *XSUB) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "XSUB")
}

// Subscribe adds topic and sends a subscribe frame upstream (ref-counted).
func (s *XSUB) Subscribe(topic []byte) error {
	select {
	case <-s.base.closeCh:
		return ErrClosed
	default:
	}
	if !s.state.add(topic) {
		return nil
	}
	f := subFrame(0x01, topic)
	for _, p := range s.base.pipes.all() {
		p.conn.WriteFrame(f) //nolint:errcheck
	}
	return nil
}

// Unsubscribe decrements ref count and sends an unsubscribe frame upstream when zero.
func (s *XSUB) Unsubscribe(topic []byte) error {
	select {
	case <-s.base.closeCh:
		return ErrClosed
	default:
	}
	if !s.state.remove(topic) {
		return nil
	}
	f := subFrame(0x00, topic)
	for _, p := range s.base.pipes.all() {
		p.conn.WriteFrame(f) //nolint:errcheck
	}
	return nil
}

// Send forwards a raw subscription frame upstream to all connected peers.
// msg[0][0] must be 0x01 (subscribe) or 0x00 (unsubscribe). Used for proxy
// forwarding of frames received from XPUB.Recv.
func (s *XSUB) Send(ctx context.Context, msg Message) error {
	select {
	case <-s.base.closeCh:
		return ErrClosed
	default:
	}
	if len(msg) == 0 {
		return nil
	}
	body := append([]byte(nil), msg[0]...) // copy caller's frame
	f := wire.Frame{Kind: wire.FrameMessage, Body: body}
	for _, p := range s.base.pipes.all() {
		p.conn.WriteFrame(f) //nolint:errcheck
	}
	return nil
}

// Recv fair-queues data messages from all connected peers.
func (s *XSUB) Recv(ctx context.Context) (Message, error) {
	msg, _, err := s.base.recvAny(ctx)
	return msg, err
}

func (s *XSUB) Close() error {
	s.base.close()
	return nil
}
