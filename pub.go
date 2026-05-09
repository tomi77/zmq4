package zmq4

import (
	"bytes"
	"context"
	"sync"

	"github.com/tomi77/zmq4/internal/conn"
	"github.com/tomi77/zmq4/internal/wire"
)

const pubOutChCap = 64

// pubPipe is one connected SUB/XSUB peer on a PUB or XPUB socket.
// It has two goroutines: subReader (reads subscription frames from the peer
// and updates the filter) and writer (drains outCh and sends to the wire).
type pubPipe struct {
	conn  *conn.Conn
	outCh chan Message

	mu   sync.RWMutex
	subs [][]byte // subscription prefixes; nil/empty entry = subscribe-all

	wg        sync.WaitGroup
	subNotify chan<- Message // non-nil for XPUB: subscription frames go here
}

func newPubPipe(c *conn.Conn, subNotify chan<- Message) *pubPipe {
	return &pubPipe{
		conn:      c,
		outCh:     make(chan Message, pubOutChCap),
		subNotify: subNotify,
	}
}

func (pp *pubPipe) start(ps *pubPipeSet, closeCh <-chan struct{}) {
	pp.wg.Add(2)
	go pp.subReader(ps)
	go pp.writer(closeCh)
}

func (pp *pubPipe) subReader(ps *pubPipeSet) {
	defer pp.wg.Done()
	defer ps.remove(pp)
	for {
		f, err := pp.conn.ReadFrame()
		if err != nil {
			return
		}
		if len(f.Body) == 0 {
			continue
		}
		op, prefix := f.Body[0], append([]byte(nil), f.Body[1:]...)
		switch op {
		case 0x01:
			pp.addSub(prefix)
			if pp.subNotify != nil {
				frame := append([]byte(nil), f.Body...)
				select {
				case pp.subNotify <- Message{frame}:
				default:
				}
			}
		case 0x00:
			pp.removeSub(prefix)
			if pp.subNotify != nil {
				frame := append([]byte(nil), f.Body...)
				select {
				case pp.subNotify <- Message{frame}:
				default:
				}
			}
		}
	}
}

func (pp *pubPipe) writer(closeCh <-chan struct{}) {
	defer pp.wg.Done()
	for {
		select {
		case msg := <-pp.outCh:
			sendFrames(pp.conn, msg) //nolint:errcheck
		case <-closeCh:
			return
		}
	}
}

func (pp *pubPipe) matches(topic []byte) bool {
	pp.mu.RLock()
	defer pp.mu.RUnlock()
	for _, sub := range pp.subs {
		if len(sub) == 0 || bytes.HasPrefix(topic, sub) {
			return true
		}
	}
	return false
}

func (pp *pubPipe) addSub(prefix []byte) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	key := string(prefix)
	for _, s := range pp.subs {
		if string(s) == key {
			return
		}
	}
	pp.subs = append(pp.subs, prefix)
}

func (pp *pubPipe) removeSub(prefix []byte) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	key := string(prefix)
	for i, s := range pp.subs {
		if string(s) == key {
			pp.subs = append(pp.subs[:i], pp.subs[i+1:]...)
			return
		}
	}
}

// pubPipeSet is a goroutine-safe set of pubPipe pointers.
type pubPipeSet struct {
	mu    sync.RWMutex
	pipes []*pubPipe
}

func newPubPipeSet() *pubPipeSet { return &pubPipeSet{} }

func (ps *pubPipeSet) add(pp *pubPipe) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.pipes = append(ps.pipes, pp)
}

func (ps *pubPipeSet) remove(pp *pubPipe) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, q := range ps.pipes {
		if q == pp {
			ps.pipes = append(ps.pipes[:i], ps.pipes[i+1:]...)
			return
		}
	}
}

func (ps *pubPipeSet) all() []*pubPipe {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	snap := make([]*pubPipe, len(ps.pipes))
	copy(snap, ps.pipes)
	return snap
}

// PUB is a publish socket. It fans out messages to all subscribers whose
// active subscription prefix matches msg[0] (the topic frame). Send never
// blocks on slow subscribers — messages are dropped per pipe if full.
type PUB struct {
	base     socketBase
	pubPipes *pubPipeSet
}

// NewPUB creates a new PUB socket with the given options.
func NewPUB(opts ...Option) *PUB {
	s := &PUB{
		base:     newSocketBase(newSocketConfig(opts)),
		pubPipes: newPubPipeSet(),
	}
	s.base.postHandshake = func(c *conn.Conn) error {
		pp := newPubPipe(c, nil)
		s.pubPipes.add(pp)
		pp.start(s.pubPipes, s.base.closeCh)
		return nil
	}
	s.base.closeFn = func() {
		for _, pp := range s.pubPipes.all() {
			pp.conn.Close()
		}
		for _, pp := range s.pubPipes.all() {
			pp.wg.Wait()
		}
	}
	return s
}

// Bind opens a listener on endpoint. Non-blocking after listener is open.
func (s *PUB) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "PUB")
}

// Connect dials endpoint and runs the ZMTP handshake. Blocking.
func (s *PUB) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "PUB")
}

// Send broadcasts msg to all peers whose subscription prefix matches msg[0].
// Non-matching peers and peers with full outbound buffers are silently skipped.
// Returns ErrNoTopic if len(msg) == 0. Returns ErrClosed after Close.
func (s *PUB) Send(ctx context.Context, msg Message) error {
	select {
	case <-s.base.closeCh:
		return ErrClosed
	default:
	}
	if len(msg) == 0 {
		return ErrNoTopic
	}
	topic := msg[0]
	for _, pp := range s.pubPipes.all() {
		if pp.matches(topic) {
			select {
			case pp.outCh <- msg:
			default:
			}
		}
	}
	return nil
}

// Close stops all goroutines and frees resources. Idempotent.
func (s *PUB) Close() error {
	s.base.close()
	return nil
}

// subFrame builds a subscription frame: op (0x01=subscribe, 0x00=unsubscribe)
// followed by topic bytes. Used by SUB/XSUB to notify PUB/XPUB peers.
func subFrame(op byte, topic []byte) wire.Frame {
	body := make([]byte, 1+len(topic))
	body[0] = op
	copy(body[1:], topic)
	return wire.Frame{Kind: wire.FrameMessage, Body: body}
}
