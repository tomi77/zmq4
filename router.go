package zmq4

import (
	"context"
	"fmt"
)

// ROUTER is an identity-routing socket.
// Recv prepends peer identity as msg[0] (fresh copy, caller-owned).
// Send routes via msg[0] identity, sends msg[1:] on the wire.
type ROUTER struct {
	base socketBase
}

func NewROUTER(opts ...Option) *ROUTER {
	return &ROUTER{base: newSocketBase(newSocketConfig(opts))}
}

func (s *ROUTER) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "ROUTER")
}

func (s *ROUTER) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "ROUTER")
}

// Recv fair-queues and prepends sender identity as msg[0].
// msg[0] is a freshly allocated slice (caller-owned).
func (s *ROUTER) Recv(ctx context.Context) (Message, error) {
	msg, p, err := s.base.recvAny(ctx)
	if err != nil {
		return nil, err
	}
	// Prepend fresh copy of identity — caller-owned per memory contract.
	identity := append([]byte(nil), p.identity...)
	result := make(Message, 1+len(msg))
	result[0] = identity
	copy(result[1:], msg)
	return result, nil
}

// Send routes to the pipe identified by msg[0], sends msg[1:].
// Returns ErrNoIdentity if msg is empty or msg[0] is empty.
// Returns ErrNoRoute if no pipe has that identity.
func (s *ROUTER) Send(ctx context.Context, msg Message) error {
	if len(msg) == 0 || len(msg[0]) == 0 {
		return ErrNoIdentity
	}
	p := s.base.pipes.byIdentity(msg[0])
	if p == nil {
		return fmt.Errorf("%w: identity %x", ErrNoRoute, msg[0])
	}
	return sendFrames(p.conn, msg[1:])
}

func (s *ROUTER) Close() error {
	s.base.close()
	return nil
}
