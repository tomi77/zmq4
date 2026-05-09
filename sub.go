package zmq4

import (
	"context"
	"sync"

	"github.com/tomi77/zmq4/internal/conn"
)

// subState tracks active subscriptions with reference counts.
type subState struct {
	mu   sync.Mutex
	subs map[string]int // topic → ref count; "" = subscribe-all
}

func newSubState() *subState {
	return &subState{subs: make(map[string]int)}
}

// add increments the ref count for topic; returns true if this is the first reference.
func (ss *subState) add(topic []byte) (isNew bool) {
	key := string(topic)
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.subs[key]++
	return ss.subs[key] == 1
}

// remove decrements the ref count; returns true when count reaches zero.
func (ss *subState) remove(topic []byte) (wasLast bool) {
	key := string(topic)
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.subs[key] <= 1 {
		delete(ss.subs, key)
		return true
	}
	ss.subs[key]--
	return false
}

// all returns a snapshot of currently active subscription prefixes.
func (ss *subState) all() [][]byte {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	result := make([][]byte, 0, len(ss.subs))
	for k := range ss.subs {
		result = append(result, []byte(k))
	}
	return result
}

// SUB is a subscribe socket. It fair-queues messages from connected PUB/XPUB
// peers that match at least one active subscription. Subscribe(nil) = subscribe-all.
type SUB struct {
	base  socketBase
	state *subState
}

// NewSUB creates a new SUB socket.
func NewSUB(opts ...Option) *SUB {
	s := &SUB{
		base:  newSocketBase(newSocketConfig(opts)),
		state: newSubState(),
	}
	s.base.postHandshake = s.onNewConn
	return s
}

// onNewConn replays the current subscription list to the new peer, then
// registers the pipe for fair-queue receive.
func (s *SUB) onNewConn(c *conn.Conn) error {
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

func (s *SUB) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "SUB")
}

func (s *SUB) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "SUB")
}

// Subscribe adds topic to the subscription list (ref-counted). On the first
// reference, sends a subscription frame to all connected peers.
// topic == nil or []byte{} subscribes to all messages.
func (s *SUB) Subscribe(topic []byte) error {
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

// Unsubscribe decrements the ref count for topic. When zero, sends an
// unsubscription frame to all connected peers.
func (s *SUB) Unsubscribe(topic []byte) error {
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

// Recv fair-queues messages from all connected peers.
func (s *SUB) Recv(ctx context.Context) (Message, error) {
	msg, _, err := s.base.recvAny(ctx)
	return msg, err
}

// Close stops all goroutines and frees resources. Idempotent.
func (s *SUB) Close() error {
	s.base.close()
	return nil
}
