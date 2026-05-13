package zmq4

import (
	"context"

	"github.com/tomi77/zmq4/internal/conn"
)

const xpubSubChCap = 64

// XPUB is an extended publish socket. It behaves like PUB for sending and
// exposes subscription/unsubscription frames to the application via Recv.
type XPUB struct {
	base     socketBase
	pubPipes *pubPipeSet
	subCh    chan Message // subscription events from all peers
}

// NewXPUB creates a new XPUB socket.
func NewXPUB(opts ...Option) *XPUB {
	s := &XPUB{
		base:     newSocketBase(newSocketConfig(append([]Option{withSndOverflow(Drop)}, opts...))),
		pubPipes: newPubPipeSet(),
		subCh:    make(chan Message, xpubSubChCap),
	}
	s.base.postHandshake = func(c *conn.Conn) error {
		signalInprocNoPipe(c)
		pp := newPubPipe(c, s.subCh, s.base.cfg.sndHWM)
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

func (s *XPUB) Bind(ctx context.Context, endpoint string) error {
	return s.base.bind(ctx, endpoint, "XPUB")
}

func (s *XPUB) Connect(ctx context.Context, endpoint string) error {
	return s.base.connect(ctx, endpoint, "XPUB")
}

// Send broadcasts msg to all peers whose subscription matches msg[0].
// Drop semantics identical to PUB.Send.
func (s *XPUB) Send(ctx context.Context, msg Message) error {
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

// Recv blocks until a subscription or unsubscription frame arrives from a peer.
// msg[0][0] == 0x01 → subscribe; msg[0][0] == 0x00 → unsubscribe.
// msg[0][1:] is the topic prefix.
func (s *XPUB) Recv(ctx context.Context) (Message, error) {
	select {
	case msg := <-s.subCh:
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.base.closeCh:
		return nil, ErrClosed
	}
}

// Close stops all goroutines and frees resources. Idempotent.
func (s *XPUB) Close() error {
	s.base.close()
	return nil
}
