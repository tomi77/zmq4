package zmq4

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"

	"github.com/tomi77/zmq4/internal/conn"
	"github.com/tomi77/zmq4/internal/wire"
)

// pubPipe is one connected SUB/XSUB peer on a PUB or XPUB socket.
// It has two goroutines: subReader (reads subscription frames from the peer
// and updates the filter) and writer (drains outCh and sends to the wire).
type pubPipe struct {
	conn  *conn.Conn
	outCh chan Message

	mu      sync.Mutex              // serialises addSub / removeSub writes only
	subsPtr atomic.Pointer[[][]byte] // copy-on-write; matches() reads are lock-free

	wg        sync.WaitGroup
	subNotify chan<- Message // non-nil for XPUB: subscription frames go here
}

func newPubPipe(c *conn.Conn, subNotify chan<- Message, sndHWM int) *pubPipe {
	pp := &pubPipe{
		conn:      c,
		outCh:     make(chan Message, sndHWM),
		subNotify: subNotify,
	}
	pp.subsPtr.Store(&[][]byte{})
	return pp
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
		if f.Kind != wire.FrameMessage {
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
			sendFrames(pp.conn, nil, msg) //nolint:errcheck
		case <-closeCh:
			return
		}
	}
}

func (pp *pubPipe) matches(topic []byte) bool {
	for _, sub := range *pp.subsPtr.Load() {
		if len(sub) == 0 || bytes.HasPrefix(topic, sub) {
			return true
		}
	}
	return false
}

func (pp *pubPipe) addSub(prefix []byte) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	old := *pp.subsPtr.Load()
	key := string(prefix)
	for _, s := range old {
		if string(s) == key {
			return
		}
	}
	next := make([][]byte, len(old)+1)
	copy(next, old)
	next[len(old)] = prefix
	pp.subsPtr.Store(&next)
}

func (pp *pubPipe) removeSub(prefix []byte) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	old := *pp.subsPtr.Load()
	key := string(prefix)
	for i, s := range old {
		if string(s) == key {
			next := make([][]byte, len(old)-1)
			copy(next, old[:i])
			copy(next[i:], old[i+1:])
			pp.subsPtr.Store(&next)
			return
		}
	}
}

// pubPipeSet is a goroutine-safe set of pubPipe pointers.
type pubPipeSet struct {
	mu       sync.Mutex              // serialises add / remove writes only
	pipesPtr atomic.Pointer[[]*pubPipe] // copy-on-write; all() reads are lock-free
}

func newPubPipeSet() *pubPipeSet {
	ps := &pubPipeSet{}
	ps.pipesPtr.Store(&[]*pubPipe{})
	return ps
}

func (ps *pubPipeSet) add(pp *pubPipe) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	old := *ps.pipesPtr.Load()
	next := make([]*pubPipe, len(old)+1)
	copy(next, old)
	next[len(old)] = pp
	ps.pipesPtr.Store(&next)
}

func (ps *pubPipeSet) remove(pp *pubPipe) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	old := *ps.pipesPtr.Load()
	for i, q := range old {
		if q == pp {
			next := make([]*pubPipe, len(old)-1)
			copy(next, old[:i])
			copy(next[i:], old[i+1:])
			ps.pipesPtr.Store(&next)
			return
		}
	}
}

func (ps *pubPipeSet) all() []*pubPipe {
	return *ps.pipesPtr.Load()
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
		base:     newSocketBase(newSocketConfig(append([]Option{withSndOverflow(Drop)}, opts...))),
		pubPipes: newPubPipeSet(),
	}
	s.base.postHandshake = func(c *conn.Conn) error {
		signalInprocNoPipe(c)
		pp := newPubPipe(c, nil, s.base.cfg.sndHWM)
		pp.wg.Add(2)
		s.pubPipes.add(pp)
		go pp.subReader(s.pubPipes)
		go pp.writer(s.base.closeCh)
		return nil
	}
	s.base.closeFn = func() {
		pipes := s.pubPipes.all()
		for _, pp := range pipes {
			pp.conn.Close()
		}
		for _, pp := range pipes {
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
	var shared Message
	for _, pp := range s.pubPipes.all() {
		if pp.matches(topic) {
			if shared == nil {
				shared = msg.Clone()
			}
			select {
			case pp.outCh <- shared:
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
