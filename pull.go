package zmq4

import "context"

// PULL is a pipeline pull socket. It pairs only with PUSH peers.
// Recv fair-queues across all connected peers.
type PULL struct {
	base socketBase
}

func NewPULL(opts ...Option) *PULL {
	return &PULL{base: newSocketBase(newSocketConfig(opts))}
}

func (s *PULL) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "PULL")
}

func (s *PULL) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "PULL")
}

// Recv fair-queues across all connected PUSH peers. Blocks until a message
// arrives, ctx is done, or the socket is closed.
// Returns ErrClosed after Close.
func (s *PULL) Recv(ctx context.Context) (Message, error) {
	msg, _, err := s.base.recvAny(ctx)
	return msg, err
}

func (s *PULL) Close() error {
	s.base.close()
	return nil
}
