package zmq4

import "context"

// DEALER is an asynchronous request socket. No sequencing constraint.
// Send round-robins across peers; Recv fair-queues.
type DEALER struct {
	base socketBase
}

func NewDEALER(opts ...Option) *DEALER {
	return &DEALER{base: newSocketBase(newSocketConfig(opts))}
}

func (s *DEALER) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "DEALER")
}

func (s *DEALER) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "DEALER")
}

func (s *DEALER) Send(ctx context.Context, msg Message) error {
	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		return err
	}
	return sendFrames(p.conn, msg)
}

func (s *DEALER) Recv(ctx context.Context) (Message, error) {
	msg, _, err := s.base.recvAny(ctx)
	return msg, err
}

func (s *DEALER) Close() error {
	s.base.close()
	return nil
}
