package zmq4

import "context"

// PUSH is a pipeline push socket. It pairs only with PULL peers.
// Send distributes messages round-robin; blocks until a peer is ready.
type PUSH struct {
	base socketBase
}

func NewPUSH(opts ...Option) *PUSH {
	return &PUSH{base: newSocketBase(newSocketConfig(opts))}
}

func (s *PUSH) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "PUSH")
}

func (s *PUSH) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "PUSH")
}

// Send round-robins across connected PULL peers. Blocks until a pipe is ready
// or ctx is done. Returns ErrClosed after Close.
func (s *PUSH) Send(ctx context.Context, msg Message) error {
	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		return err
	}
	if !p.send(pipeMsg{body: msg}, s.base.closeCh) {
		return ErrClosed
	}
	return nil
}

func (s *PUSH) Close() error {
	s.base.close()
	return nil
}
