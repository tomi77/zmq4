package zmq4

import (
	"crypto/rand"
	"sync"

	"github.com/tomi77/zmq4/internal/conn"
	"github.com/tomi77/zmq4/internal/wire"
)

// pipeMsg is a message queued for delivery in pipe.outCh. prefix, when
// non-nil, is sent before body as a single uninterrupted ZMTP message.
// Carrying prefix separately avoids allocating a combined Message slice
// in REQ (prepends one empty delimiter) and REP (prepends a routing envelope).
type pipeMsg struct {
	prefix [][]byte
	body   Message
}

// reqDelimiter is the read-only single-element prefix used by REQ.Send.
// Shared across all REQ sockets; never mutated.
var reqDelimiter = [][]byte{nil}

// pipe represents one live ZMTP connection inside a socket.
type pipe struct {
	conn         *conn.Conn
	identity     []byte // peer identity; stable after construction
	inCh         chan Message
	outCh        chan pipeMsg // send queue; capacity = sndHWM
	overflow     OverflowPolicy
	onDisconnect func(addr string) // called when peer drops the connection unexpectedly
	inReady      chan struct{}     // capacity 1; poked by readLoop after each inCh enqueue
	outReady     chan struct{}     // capacity 1; poked by writeLoop after each outCh dequeue
	wg           sync.WaitGroup
}

func newPipe(c *conn.Conn, identity []byte, sndHWM, rcvHWM int, overflow OverflowPolicy) *pipe {
	return &pipe{
		conn:     c,
		identity: identity,
		inCh:     make(chan Message, rcvHWM),
		outCh:    make(chan pipeMsg, sndHWM),
		overflow: overflow,
		inReady:  make(chan struct{}, 1),
		outReady: make(chan struct{}, 1),
	}
}

// start launches the reader and writer goroutines. closeCh is closed by the
// socket to stop all goroutines on Close.
func (p *pipe) start(ps *pipeSet, closeCh <-chan struct{}) {
	p.wg.Add(2)
	go p.readLoop(ps, closeCh)
	go p.writeLoop(closeCh)
}

// readLoop reads multipart messages from the conn and delivers them to
// inCh. Exits when conn.ReadFrame returns an error (including net.ErrClosed
// after socket.Close) or closeCh is closed. A partially-assembled multipart
// message in progress is discarded on exit.
func (p *pipe) readLoop(ps *pipeSet, closeCh <-chan struct{}) {
	defer p.wg.Done()
	defer close(p.inCh)
	defer func() {
		ps.remove(p)
		if p.onDisconnect != nil {
			select {
			case <-closeCh:
				// Socket is shutting down; EventClosed is handled by close().
			default:
				p.onDisconnect(p.conn.RemoteAddr().String())
			}
		}
	}()

	// Pre-size for the common 2-frame case (REQ/REP delimiter+payload).
	// Avoids a realloc when the second frame arrives in the next loop iteration,
	// where the compiler cannot merge the two appends into a single allocation.
	msg := make(Message, 0, 2)
	for {
		f, err := p.conn.ReadFrame()
		if err != nil {
			return
		}
		// f.Body is freshly allocated by FrameReader on every ReadFrame call
		// (mech.Unwrap for NULL/PLAIN is pass-through; CURVE returns a new buffer).
		// No copy needed — the slice is already owned.
		msg = append(msg, f.Body)
		if !f.More {
			select {
			case p.inCh <- msg:
				select {
				case p.inReady <- struct{}{}:
				default:
				}
			case <-closeCh:
				return
			}
			msg = make(Message, 0, 2)
		}
	}
}

// writeLoop drains outCh and writes messages to conn. Exits on write error
// (closing the connection so readLoop also exits) or when closeCh is closed.
func (p *pipe) writeLoop(closeCh <-chan struct{}) {
	defer p.wg.Done()
	for {
		select {
		case pm := <-p.outCh:
			if err := sendFrames(p.conn, pm.prefix, pm.body); err != nil {
				p.conn.Close()
				return
			}
			select {
			case p.outReady <- struct{}{}:
			default:
			}
		case <-closeCh:
			return
		}
	}
}

// send enqueues pm for delivery according to the pipe's overflow policy.
// Returns true if the message was queued, false if the socket is closing (Block)
// or the queue is full (Drop).
func (p *pipe) send(pm pipeMsg, closeCh <-chan struct{}) bool {
	switch p.overflow {
	case Drop:
		select {
		case p.outCh <- pm:
			return true
		default:
			return false
		}
	default: // Block
		select {
		case p.outCh <- pm:
			return true
		case <-closeCh:
			return false
		}
	}
}

// pipeSet is a goroutine-safe set of active pipes.
type pipeSet struct {
	mu    sync.Mutex
	pipes []*pipe
	byID  map[string]*pipe // identity → pipe; O(1) lookup for ROUTER routing
	robin int
	added chan struct{}
}

func newPipeSet() *pipeSet {
	return &pipeSet{
		byID:  make(map[string]*pipe),
		added: make(chan struct{}),
	}
}

func (ps *pipeSet) add(p *pipe) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.pipes = append(ps.pipes, p)
	ps.byID[string(p.identity)] = p
	close(ps.added)
	ps.added = make(chan struct{})
}

func (ps *pipeSet) remove(p *pipe) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.byID, string(p.identity))
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
	return ps.byID[string(id)]
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

// singlePipe returns the sole connected pipe when exactly one peer is active,
// nil otherwise. Used by recvAny as a reflect-free fast path.
func (ps *pipeSet) singlePipe() *pipe {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if len(ps.pipes) == 1 {
		return ps.pipes[0]
	}
	return nil
}

// twoPipes returns both pipes when exactly two peers are active, nil otherwise.
// Used by recvAny as a reflect-free fast path.
func (ps *pipeSet) twoPipes() (*pipe, *pipe) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if len(ps.pipes) == 2 {
		return ps.pipes[0], ps.pipes[1]
	}
	return nil, nil
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

// sendFrames writes prefix then body to c as a single ZMTP message, setting
// More on all frames except the last. Either slice may be nil.
func sendFrames(c *conn.Conn, prefix [][]byte, body Message) error {
	last := len(prefix) + len(body) - 1
	i := 0
	for _, part := range prefix {
		if err := c.WriteFrame(wire.Frame{Kind: wire.FrameMessage, More: i < last, Body: part}); err != nil {
			return err
		}
		i++
	}
	for _, part := range body {
		if err := c.WriteFrame(wire.Frame{Kind: wire.FrameMessage, More: i < last, Body: part}); err != nil {
			return err
		}
		i++
	}
	return nil
}
