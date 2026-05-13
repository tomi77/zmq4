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

// inprocLink is a shared lifecycle signal between two inproc-paired pipes.
// closed is closed by the first writeLoop that exits, waking both readLoops.
type inprocLink struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *inprocLink) close() {
	l.closeOnce.Do(func() { close(l.closed) })
}

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

	// Inproc fast path (optimization C). Set by linkInproc before start().
	// Both fields are nil for TCP/IPC pipes.
	peer       *pipe        // direct delivery target; writeLoop skips ZMTP
	inprocLink *inprocLink  // shared lifecycle signal; both readLoops watch it

	// linkReady is closed when the link decision is made (either linkInproc or
	// markNonInproc). readLoop and writeLoop block on linkReady at startup so
	// they observe peer/inprocLink before choosing the data path.
	linkReady chan struct{}

	// inChCloseOnce ensures inCh is closed exactly once. For non-inproc pipes
	// readLoop closes it; for inproc pipes the peer's writeLoop closes it via
	// closeInCh(). Using sync.Once prevents the double-close panic in all paths.
	inChCloseOnce sync.Once
}

func newPipe(c *conn.Conn, identity []byte, sndHWM, rcvHWM int, overflow OverflowPolicy) *pipe {
	return &pipe{
		conn:      c,
		identity:  identity,
		inCh:      make(chan Message, rcvHWM),
		outCh:     make(chan pipeMsg, sndHWM),
		overflow:  overflow,
		inReady:   make(chan struct{}, 1),
		outReady:  make(chan struct{}, 1),
		linkReady: make(chan struct{}),
	}
}

// closeInCh closes inCh exactly once; safe to call from multiple goroutines.
func (p *pipe) closeInCh() {
	p.inChCloseOnce.Do(func() { close(p.inCh) })
}

// markNonInproc closes linkReady for non-inproc pipes so goroutines start
// without waiting. Must be called before start() for TCP/IPC pipes.
func (p *pipe) markNonInproc() {
	close(p.linkReady)
}

// linkInproc connects two pipe halves for direct inproc message passing.
// It sets the peer and inprocLink fields on both pipes and closes their
// linkReady channels so goroutines can proceed with the fast path.
// Must be called before either pipe's start().
func linkInproc(a, b *pipe) {
	link := &inprocLink{closed: make(chan struct{})}
	a.peer = b
	b.peer = a
	a.inprocLink = link
	b.inprocLink = link
	close(a.linkReady)
	close(b.linkReady)
}

// start launches the reader and writer goroutines. closeCh is closed by the
// socket to stop all goroutines on Close.
func (p *pipe) start(ps *pipeSet, closeCh <-chan struct{}) {
	p.wg.Add(2)
	go p.readLoop(ps, closeCh)
	go p.writeLoop(closeCh)
}

// readLoop reads multipart messages from the conn and delivers them to
// inCh, OR for inproc pipes waits for the peer's writeLoop to exit.
// Exits when conn.ReadFrame returns an error (including net.ErrClosed
// after socket.Close) or closeCh is closed.
func (p *pipe) readLoop(ps *pipeSet, closeCh <-chan struct{}) {
	defer p.wg.Done()

	// Wait for the link decision (inproc vs. conn-based). For non-inproc
	// pipes markNonInproc() has pre-closed linkReady so this is immediate.
	// For the first inproc pipe this blocks until the second addConn calls
	// linkInproc, which guarantees peer/inprocLink are visible via the
	// channel-close happens-before.
	var inproc bool
	select {
	case <-p.linkReady:
		inproc = p.inprocLink != nil
	case <-closeCh:
		// Socket closed before link was established; clean up and exit.
		ps.remove(p)
		p.closeInCh()
		return
	}

	// selfClose is set when we exit via closeCh (intentional socket close).
	// For inproc pipes on the closeCh path we skip ps.remove so that close()
	// can snapshot and emit EventClosed; it owns cleanup for that path.
	var selfClose bool

	defer func() {
		if !selfClose {
			ps.remove(p)
		}
		if p.onDisconnect != nil && !selfClose {
			// Peer disconnected (inproc or conn-based): emit EventDisconnected
			// unless our socket is also shutting down simultaneously.
			select {
			case <-closeCh:
				// Both sides closing at the same time; EventClosed handled by close().
			default:
				if p.conn != nil {
					p.onDisconnect(p.conn.RemoteAddr().String())
				}
			}
		}
	}()

	if inproc {
		// Inproc: peer's inprocWriteLoop owns inCh exclusively via
		// defer peer.closeInCh(). readLoop must not close it.
		select {
		case <-p.inprocLink.closed:
			selfClose = false
		case <-closeCh:
			selfClose = true
			p.inprocLink.close()
		}
		return
	}

	// Non-inproc: readLoop is the sole closer of inCh.
	defer p.closeInCh()

	// Non-inproc: read ZMTP frames from the conn.
	// Pre-size for the common 2-frame case (REQ/REP delimiter+payload).
	msg := make(Message, 0, 2)
	for {
		f, err := p.conn.ReadFrame()
		if err != nil {
			return
		}
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

// writeLoop drains outCh and writes messages to the peer. For inproc pipes
// it delivers directly to the peer's inCh (bypassing ZMTP serialization).
// For conn-based pipes it encodes frames and writes via conn.WriteMsg.
// After each batch it signals outReady. Exits on error, peer shutdown, or
// when closeCh is closed.
func (p *pipe) writeLoop(closeCh <-chan struct{}) {
	defer p.wg.Done()

	// Wait for the link decision before choosing the data path.
	select {
	case <-p.linkReady:
	case <-closeCh:
		return
	}

	if p.inprocLink != nil {
		p.inprocWriteLoop(closeCh)
		return
	}

	// Non-inproc: conn-based write path with opportunistic drain.
	for {
		select {
		case pm := <-p.outCh:
			if err := sendFrames(p.conn, pm.prefix, pm.body); err != nil {
				p.conn.Close()
				return
			}
			// Opportunistic drain: process any messages already waiting in
			// outCh without returning to the outer select (which yields to
			// the scheduler). A single outReady token covers the whole batch.
			for {
				select {
				case pm = <-p.outCh:
					if err := sendFrames(p.conn, pm.prefix, pm.body); err != nil {
						p.conn.Close()
						return
					}
				default:
					goto batchDone
				}
			}
		batchDone:
			select {
			case p.outReady <- struct{}{}:
			default:
			}
		case <-closeCh:
			return
		}
	}
}

// inprocWriteLoop is the fast-path writer for inproc-paired pipes. It
// delivers pipeMsg directly to peer.inCh as a combined Message slice,
// bypassing ZMTP encoding/decoding entirely. When it exits it closes
// peer.inCh (the only writer, so no concurrent-close race) and fires
// the shared inprocLink to wake both readLoops.
func (p *pipe) inprocWriteLoop(closeCh <-chan struct{}) {
	peer := p.peer
	link := p.inprocLink
	defer link.close()
	defer peer.closeInCh()

	for {
		select {
		case pm := <-p.outCh:
			msg := buildInprocMsg(pm)
			select {
			case peer.inCh <- msg:
				select {
				case peer.inReady <- struct{}{}:
				default:
				}
			case <-link.closed:
				return
			case <-closeCh:
				return
			}
			// Opportunistic drain.
			for {
				select {
				case pm = <-p.outCh:
					msg = buildInprocMsg(pm)
					select {
					case peer.inCh <- msg:
						select {
						case peer.inReady <- struct{}{}:
						default:
						}
					case <-link.closed:
						return
					case <-closeCh:
						return
					}
				default:
					goto inprocDone
				}
			}
		inprocDone:
			select {
			case p.outReady <- struct{}{}:
			default:
			}
		case <-closeCh:
			return
		}
	}
}

// buildInprocMsg combines a pipeMsg's prefix and body into a single Message
// slice for direct delivery to the peer's inCh. One allocation per call.
func buildInprocMsg(pm pipeMsg) Message {
	total := len(pm.prefix) + len(pm.body)
	msg := make(Message, 0, total)
	msg = append(msg, pm.prefix...)
	msg = append(msg, pm.body...)
	return msg
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

// sendFrames writes prefix then body to c as a single ZMTP message, holding
// the write lock exactly once for the entire multi-frame payload.
func sendFrames(c *conn.Conn, prefix [][]byte, body Message) error {
	return c.WriteMsg(prefix, body)
}
