package zmq4

import (
	"context"
	"sync"

	"github.com/tomi77/zmq4/internal/conn"
)

// PAIR is an exclusive-pair socket. It pairs only with another PAIR peer.
// Exactly one peer is allowed at a time; a second peer is rejected at handshake
// with ErrPairAlreadyConnected. After the peer disconnects, PAIR accepts a new
// connection.
type PAIR struct {
	base socketBase
	mu   sync.Mutex // serialises the check-and-add sequence in exclusivePeer
}

func NewPAIR(opts ...Option) *PAIR {
	s := &PAIR{base: newSocketBase(newSocketConfig(opts))}
	s.base.postHandshake = s.exclusivePeer
	return s
}

// exclusivePeer is the postHandshake hook. mu serialises the len-check and
// add so that two simultaneous inbound connections cannot both pass the guard.
func (s *PAIR) exclusivePeer(c *conn.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.base.pipes.len() > 0 {
		return ErrPairAlreadyConnected
	}
	identity := peerIdentity(c.PeerMetadata())
	p := newPipe(c, identity)
	s.base.pipes.add(p)
	p.start(s.base.pipes, s.base.closeCh)
	return nil
}

func (s *PAIR) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "PAIR")
}

func (s *PAIR) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "PAIR")
}

// Send waits for the peer to be connected, then sends msg.
// Returns ErrClosed after Close.
func (s *PAIR) Send(ctx context.Context, msg Message) error {
	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		return err
	}
	return sendFrames(p.conn, msg)
}

// Recv waits for a message from the peer.
// Returns ErrClosed after Close.
func (s *PAIR) Recv(ctx context.Context) (Message, error) {
	msg, _, err := s.base.recvAny(ctx)
	return msg, err
}

func (s *PAIR) Close() error {
	s.base.close()
	return nil
}
