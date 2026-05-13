package zmq4

import (
	"context"
	"fmt"
	"sync"
)

// REP is a reply socket. Pairs with REQ and DEALER.
// Recv and Send alternate strictly (idle→recv→idle).
// REP extracts the routing envelope on Recv and prepends it on Send.
type REP struct {
	base     socketBase
	mu       sync.Mutex
	recv     bool     // true = "recv" state; must Send before Recv
	envPipe  *pipe    // pipe that delivered the last Recv
	envelope [][]byte // routing envelope (frames up to and incl. delimiter)
}

// NewREP creates a new REP socket with the given options.
func NewREP(opts ...Option) *REP {
	return &REP{base: newSocketBase(newSocketConfig(opts))}
}

func (s *REP) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "REP")
}

func (s *REP) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "REP")
}

// Recv fair-queues across all pipes, extracts routing envelope, returns payload.
// Returns ErrState if already in "recv" state (i.e. must Send before receiving again).
func (s *REP) Recv(ctx context.Context) (Message, error) {
	s.mu.Lock()
	if s.recv {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: REP must Send before receiving again", ErrState)
	}
	s.recv = true // claim the slot atomically before releasing the lock (TOCTOU guard)
	s.mu.Unlock()

	msg, p, err := s.base.recvAny(ctx)
	if err != nil {
		s.mu.Lock()
		s.recv = false
		s.mu.Unlock()
		return nil, err
	}

	envelope, payload := splitEnvelope(msg)

	s.mu.Lock()
	s.envPipe = p
	s.envelope = envelope
	s.mu.Unlock()

	return payload, nil
}

// Send prepends the stored routing envelope and sends the reply on the original pipe.
// Returns ErrState if not in "recv" state (i.e. must Recv before sending).
func (s *REP) Send(ctx context.Context, msg Message) error {
	s.mu.Lock()
	if !s.recv {
		s.mu.Unlock()
		return fmt.Errorf("%w: REP must Recv before sending", ErrState)
	}
	p := s.envPipe
	env := s.envelope
	s.recv = false
	s.envPipe = nil
	s.envelope = nil
	s.mu.Unlock()

	// Send envelope frames (incl. empty delimiter) followed by payload without
	// allocating a combined Message slice.
	if !p.send(pipeMsg{prefix: env, body: msg}, s.base.closeCh) {
		return ErrClosed
	}
	return nil
}

func (s *REP) Close() error {
	s.base.close()
	return nil
}

// splitEnvelope splits a raw message into (envelope, payload).
// The envelope is all frames up to and including the first empty-body frame
// (the delimiter). The delimiter frame (empty body) is included as the last
// element of the returned envelope. If no empty frame is found (DEALER→REP
// path without delimiter), envelope is nil and all frames are treated as
// payload (per spec §9.7 resolution).
func splitEnvelope(msg Message) (envelope [][]byte, payload Message) {
	for i, part := range msg {
		if len(part) == 0 {
			// Cap the envelope slice at i+1 so that REP.Send's
			// append(env, reply...) always allocates a fresh array and
			// cannot overwrite payload frames in the shared backing array.
			return msg[:i+1 : i+1], msg[i+1:]
		}
	}
	// No delimiter found — DEALER peer; treat all frames as payload.
	// msg is caller-owned (readLoop allocates each frame independently).
	return nil, msg
}
