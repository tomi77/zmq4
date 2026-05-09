package zmq4

import (
	"crypto/rand"
	"sync"

	"github.com/tomi77/zmq4/internal/conn"
	"github.com/tomi77/zmq4/internal/wire"
)

// pipe represents one live ZMTP connection inside a socket.
type pipe struct {
	conn     *conn.Conn
	identity []byte    // peer identity; stable after construction
	inCh     chan Message
	outCh    chan Message   // send queue; capacity = sndHWM
	overflow OverflowPolicy
	wg       sync.WaitGroup
}

func newPipe(c *conn.Conn, identity []byte, sndHWM, rcvHWM int, overflow OverflowPolicy) *pipe {
	return &pipe{
		conn:     c,
		identity: identity,
		inCh:     make(chan Message, rcvHWM),
		outCh:    make(chan Message, sndHWM),
		overflow: overflow,
	}
}

// start launches the reader goroutine. closeCh is closed by the socket
// to stop all reader goroutines on Close.
func (p *pipe) start(ps *pipeSet, closeCh <-chan struct{}) {
	p.wg.Add(1)
	go p.readLoop(ps, closeCh)
}

// readLoop reads multipart messages from the conn and delivers them to
// inCh. Exits when conn.ReadFrame returns an error (including net.ErrClosed
// after socket.Close) or closeCh is closed. A partially-assembled multipart
// message in progress is discarded on exit.
func (p *pipe) readLoop(ps *pipeSet, closeCh <-chan struct{}) {
	defer p.wg.Done()
	defer close(p.inCh)
	defer ps.remove(p)

	var msg Message
	for {
		f, err := p.conn.ReadFrame()
		if err != nil {
			return
		}
		body := append([]byte(nil), f.Body...) // owned copy
		msg = append(msg, body)
		if !f.More {
			select {
			case p.inCh <- msg:
			case <-closeCh:
				return
			}
			msg = nil
		}
	}
}

// pipeSet is a goroutine-safe set of active pipes.
type pipeSet struct {
	mu    sync.Mutex
	pipes []*pipe
	robin int
	added chan struct{}
}

func newPipeSet() *pipeSet {
	return &pipeSet{added: make(chan struct{})}
}

func (ps *pipeSet) add(p *pipe) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.pipes = append(ps.pipes, p)
	close(ps.added)
	ps.added = make(chan struct{})
}

func (ps *pipeSet) remove(p *pipe) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, q := range ps.pipes {
		if q == p {
			ps.pipes = append(ps.pipes[:i], ps.pipes[i+1:]...)
			if i < ps.robin {
				ps.robin--
			}
			if ps.robin >= len(ps.pipes) {
				ps.robin = 0
			}
			return
		}
	}
}

// next returns the next pipe in round-robin order; nil if empty.
func (ps *pipeSet) next() *pipe {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if len(ps.pipes) == 0 {
		return nil
	}
	p := ps.pipes[ps.robin%len(ps.pipes)]
	ps.robin++
	return p
}

// byIdentity returns the pipe with the given identity; nil if not found.
func (ps *pipeSet) byIdentity(id []byte) *pipe {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for _, p := range ps.pipes {
		if string(p.identity) == string(id) {
			return p
		}
	}
	return nil
}

// all returns a snapshot of all current pipes.
func (ps *pipeSet) all() []*pipe {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	snap := make([]*pipe, len(ps.pipes))
	copy(snap, ps.pipes)
	return snap
}

// currentAdded returns the current added-notification channel.
func (ps *pipeSet) currentAdded() chan struct{} {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.added
}

func (ps *pipeSet) len() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return len(ps.pipes)
}

// peerIdentity extracts the peer's identity from handshake metadata or
// generates a random 5-byte identity. meta is wire.Metadata from
// conn.Conn.PeerMetadata(); its Get method performs case-insensitive lookup.
func peerIdentity(meta wire.Metadata) []byte {
	if id, ok := meta.Get("Identity"); ok && len(id) > 0 {
		return append([]byte(nil), id...) // owned copy
	}
	return randomIdentity()
}

// randomIdentity generates a 5-byte random identity using crypto/rand.
func randomIdentity() []byte {
	id := make([]byte, 5)
	if _, err := rand.Read(id); err != nil {
		panic("zmq4: crypto/rand failure: " + err.Error())
	}
	return id
}

// sendFrames writes all parts of msg to c, setting More on all but the last.
func sendFrames(c *conn.Conn, msg Message) error {
	for i, part := range msg {
		more := i < len(msg)-1
		if err := c.WriteFrame(wire.Frame{
			Kind: wire.FrameMessage,
			More: more,
			Body: part,
		}); err != nil {
			return err
		}
	}
	return nil
}

// emptyDelimiter is the zero-length FrameMessage used as REQ envelope delimiter.
var emptyDelimiter = wire.Frame{Kind: wire.FrameMessage, More: true, Body: nil}
