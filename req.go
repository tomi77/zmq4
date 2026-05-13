package zmq4

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// REQ is a request socket. Pairs with REP and ROUTER.
// Send and Recv alternate strictly (idle→sent→idle).
// REQ prepends an empty delimiter frame on Send and strips it on Recv.
type REQ struct {
	base       socketBase
	mu         sync.Mutex
	sent       bool  // true = "sent" state; must Recv before Send
	activePipe *pipe // pipe used by the last Send
}

// NewREQ creates a new REQ socket with the given options.
func NewREQ(opts ...Option) *REQ {
	return &REQ{base: newSocketBase(newSocketConfig(opts))}
}

func (s *REQ) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "REQ")
}

func (s *REQ) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "REQ")
}

// Send selects a pipe, prepends empty delimiter, sends msg.
// Returns ErrState if already in "sent" state.
func (s *REQ) Send(ctx context.Context, msg Message) error {
	s.mu.Lock()
	if s.sent {
		s.mu.Unlock()
		return fmt.Errorf("%w: REQ must Recv before sending again", ErrState)
	}
	s.sent = true // claim the slot atomically before releasing the lock
	s.mu.Unlock()

	p, err := s.base.sendWaitPipe(ctx)
	if err != nil {
		s.mu.Lock()
		s.sent = false
		s.mu.Unlock()
		return err
	}

	// Send the empty delimiter frame followed by the payload. reqDelimiter is
	// a package-level read-only slice so no allocation is needed here.
	if !p.send(pipeMsg{prefix: reqDelimiter, body: msg}, s.base.closeCh) {
		s.mu.Lock()
		s.sent = false
		s.mu.Unlock()
		return ErrClosed
	}
	s.mu.Lock()
	s.activePipe = p
	s.mu.Unlock()
	return nil
}

// Recv waits for a reply on the active pipe, strips the delimiter.
// Returns ErrState if not in "sent" state.
func (s *REQ) Recv(ctx context.Context) (Message, error) {
	s.mu.Lock()
	if !s.sent {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: REQ must Send before receiving", ErrState)
	}
	p := s.activePipe
	s.mu.Unlock()

	var raw Message
	select {
	case msg, ok := <-p.inCh:
		if !ok {
			s.mu.Lock()
			s.sent = false
			s.activePipe = nil
			s.mu.Unlock()
			return nil, io.EOF
		}
		raw = msg
	case <-ctx.Done():
		s.mu.Lock()
		s.sent = false
		s.activePipe = nil
		s.mu.Unlock()
		return nil, ctx.Err()
	case <-s.base.closeCh:
		// Socket is closed — don't bother resetting state.
		return nil, ErrClosed
	}

	s.mu.Lock()
	s.sent = false
	s.activePipe = nil
	s.mu.Unlock()

	return stripDelimiter(raw), nil
}

func (s *REQ) Close() error {
	s.base.close()
	return nil
}

// stripDelimiter removes leading empty-body frames from a message.
// If no delimiter is found, returns msg unchanged (DEALER→REQ path).
func stripDelimiter(msg Message) Message {
	for len(msg) > 0 && len(msg[0]) == 0 {
		msg = msg[1:]
	}
	return msg
}
