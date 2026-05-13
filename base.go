package zmq4

import (
	"context"
	"net"
	"reflect"
	"sync"

	"github.com/tomi77/zmq4/internal/conn"
	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/transport"
)

// inprocPendingPipes holds the first party of an inproc pair while waiting
// for the second addConn call to arrive. Key: pairID (uint64).
// Value is either a *pipe (will participate in the fast path) or nil (the
// arriving party uses a non-pipe type such as pubPipe, so the partner must
// fall back to conn-based I/O). Entries live only between the two addConn
// calls; removed by LoadAndDelete.
var inprocPendingPipes sync.Map

// linkOrStorePipe applies the inproc / non-inproc link decision to p.
// For inproc connections it either links p with its waiting peer or stores p
// for the partner to link later. For non-inproc connections it calls
// markNonInproc immediately. Must be called before p.start().
func linkOrStorePipe(c *conn.Conn, p *pipe) {
	pairID, ok := c.InprocPairID()
	if !ok {
		p.markNonInproc()
		return
	}
	// LoadOrStore is atomic: exactly one caller stores, the other loads.
	// This avoids the TOCTOU race between LoadAndDelete + Store.
	actual, loaded := inprocPendingPipes.LoadOrStore(pairID, p)
	if loaded {
		inprocPendingPipes.Delete(pairID)
		if peer, ok := actual.(*pipe); ok && peer != nil {
			linkInproc(p, peer)
		} else {
			// nil sentinel: partner is a non-pipe socket (e.g. pubPipe).
			p.markNonInproc()
		}
	}
	// else: stored as first of pair; goroutines wait on linkReady.
}

// signalInprocNoPipe is called by postHandshake hooks that produce a non-*pipe
// connection (e.g. pubPipe). It either wakes a waiting *pipe partner in
// non-inproc mode, or stores a nil sentinel so the arriving partner knows to
// skip the fast path.
func signalInprocNoPipe(c *conn.Conn) {
	pairID, ok := c.InprocPairID()
	if !ok {
		return
	}
	actual, loaded := inprocPendingPipes.LoadOrStore(pairID, (*pipe)(nil))
	if loaded {
		inprocPendingPipes.Delete(pairID)
		if peer, ok := actual.(*pipe); ok && peer != nil {
			// Partner pipe was waiting; wake it in non-inproc mode.
			peer.markNonInproc()
		}
	}
	// else: nil sentinel stored; arriving *pipe partner will find it.
}

// compatiblePeers maps local socket type to allowed peer socket types.
var compatiblePeers = map[string]map[string]bool{
	"REQ":    {"REP": true, "ROUTER": true},
	"REP":    {"REQ": true, "DEALER": true},
	"DEALER": {"REP": true, "ROUTER": true, "DEALER": true},
	"ROUTER": {"REQ": true, "DEALER": true, "ROUTER": true},
	"PUB":    {"SUB": true, "XSUB": true},
	"SUB":    {"PUB": true, "XPUB": true},
	"XPUB":   {"SUB": true, "XSUB": true},
	"XSUB":   {"PUB": true, "XPUB": true},
	"PUSH":   {"PULL": true},
	"PULL":   {"PUSH": true},
	"PAIR":   {"PAIR": true},
}

// socketBase holds shared goroutine and lifecycle machinery for all socket
// types. Concrete types embed socketBase.
type socketBase struct {
	cfg         *socketConfig
	pipes       *pipeSet
	closeCh     chan struct{}
	closeOnce   sync.Once
	wg          sync.WaitGroup // tracks acceptor + handshake goroutines
	listeners   []net.Listener
	listenersMu sync.Mutex

	// monitorMu guards monitorSealed. emit holds a read lock while sending;
	// close() sets monitorSealed=true and closes the channel under a write
	// lock. This prevents a concurrent emit from racing with close(monitorCh).
	monitorMu     sync.RWMutex
	monitorSealed bool

	// postHandshake, when non-nil, is called by addConn instead of the
	// default newPipe path. The compatibility check always runs first.
	// Used by PUB/XPUB (pubPipe creation) and SUB/XSUB (subscription replay).
	postHandshake func(c *conn.Conn) error

	// closeFn, when non-nil, is called inside close() before waiting for
	// goroutines. Used by PUB/XPUB to close pubPipes and wait for their wg.
	closeFn func()
}

func newSocketBase(cfg *socketConfig) socketBase {
	return socketBase{
		cfg:     cfg,
		pipes:   newPipeSet(),
		closeCh: make(chan struct{}),
	}
}

// emit sends ev to the monitor channel if one is configured and not yet
// sealed. Non-blocking: events are silently dropped when the channel is full.
// Holds monitorMu.RLock so it cannot race with the close(monitorCh) in
// close() which holds the write lock.
func (sb *socketBase) emit(ev SocketEvent) {
	if sb.cfg.monitorCh == nil {
		return
	}
	sb.monitorMu.RLock()
	defer sb.monitorMu.RUnlock()
	if sb.monitorSealed {
		return
	}
	select {
	case sb.cfg.monitorCh <- ev:
	default:
	}
}

// bind opens a listener on endpoint and launches a background acceptor
// goroutine. Non-blocking after the listener is established.
func (sb *socketBase) bind(ctx context.Context, endpoint, socketType string) error {
	ln, err := transport.Listen(ctx, endpoint)
	if err != nil {
		sb.emit(SocketEvent{Type: EventBindFailed, Endpoint: endpoint, Err: err})
		return err
	}
	sb.emit(SocketEvent{Type: EventListening, Endpoint: endpoint})
	sb.listenersMu.Lock()
	sb.listeners = append(sb.listeners, ln)
	sb.listenersMu.Unlock()
	sb.wg.Add(1)
	go sb.acceptLoop(ln, socketType)
	return nil
}

func (sb *socketBase) acceptLoop(ln net.Listener, socketType string) {
	defer sb.wg.Done()
	defer ln.Close()
	for {
		raw, err := ln.Accept()
		if err != nil {
			select {
			case <-sb.closeCh:
				// Normal shutdown — listener was closed by close(); no event.
			default:
				sb.emit(SocketEvent{Type: EventAcceptFailed, Endpoint: ln.Addr().String(), Err: err})
			}
			return
		}
		sb.wg.Add(1)
		go sb.doServerHandshake(raw, socketType)
	}
}

func (sb *socketBase) doServerHandshake(raw net.Conn, socketType string) {
	defer sb.wg.Done()
	hsCtx, cancel := context.WithTimeout(context.Background(), sb.cfg.handshakeTimeout)
	defer cancel()

	addr := raw.RemoteAddr().String()
	sb.emit(SocketEvent{Type: EventAccepted, Endpoint: addr})

	mech, err := sb.cfg.serverMechFactory(socketType)
	if err != nil {
		raw.Close()
		return
	}
	if sb.cfg.zapCaller != nil {
		if zc, ok := mech.(security.ZAPConfigurer); ok {
			zc.ConfigureZAP(sb.cfg.zapCaller, sb.cfg.zapDomain)
		}
	}
	if pas, ok := mech.(security.PeerAddrSetter); ok {
		pas.SetPeerAddr(addr)
	}
	c, err := conn.ServerHandshake(hsCtx, raw, mech)
	if err != nil {
		sb.emit(SocketEvent{Type: EventHandshakeFailed, Endpoint: addr, Err: err})
		return // raw already closed by F4 on handshake failure
	}
	sb.emit(SocketEvent{Type: EventHandshakeSucceeded, Endpoint: addr})
	if err := sb.addConn(c, socketType); err != nil {
		c.Close()
	}
}

// connect dials endpoint, runs the ZMTP handshake, and adds the resulting
// pipe. Blocking — returns after handshake succeeds or fails.
func (sb *socketBase) connect(ctx context.Context, endpoint, socketType string) error {
	raw, err := transport.Dial(ctx, endpoint)
	if err != nil {
		sb.emit(SocketEvent{Type: EventConnectFailed, Endpoint: endpoint, Err: err})
		return err
	}
	sb.emit(SocketEvent{Type: EventConnected, Endpoint: endpoint})
	hsCtx, cancel := context.WithTimeout(ctx, sb.cfg.handshakeTimeout)
	defer cancel()

	mech, err := sb.cfg.clientMechFactory(socketType)
	if err != nil {
		raw.Close()
		return err
	}
	c, err := conn.ClientHandshake(hsCtx, raw, mech)
	if err != nil {
		sb.emit(SocketEvent{Type: EventHandshakeFailed, Endpoint: endpoint, Err: err})
		return err
	}
	sb.emit(SocketEvent{Type: EventHandshakeSucceeded, Endpoint: endpoint})
	if err := sb.addConn(c, socketType); err != nil {
		c.Close()
		return err
	}
	return nil
}

// addConn validates socket-type compatibility, creates a pipe, and starts it.
func (sb *socketBase) addConn(c *conn.Conn, localSocketType string) error {
	meta := c.PeerMetadata()
	// Look up Socket-Type in wire.Metadata (a slice of MetadataProperty).
	// Use the Get method for case-insensitive lookup.
	peerTypeBytes, _ := meta.Get("Socket-Type")
	peerType := string(peerTypeBytes)
	if peerType != "" {
		allowed := compatiblePeers[localSocketType]
		if !allowed[peerType] {
			return ErrIncompatiblePeer
		}
	}
	if sb.postHandshake != nil {
		return sb.postHandshake(c)
	}
	identity := peerIdentity(meta)
	p := newPipe(c, identity, sb.cfg.sndHWM, sb.cfg.rcvHWM, sb.cfg.sndOverflow)
	if sb.cfg.monitorCh != nil {
		p.onDisconnect = func(addr string) {
			sb.emit(SocketEvent{Type: EventDisconnected, Endpoint: addr})
		}
	}
	linkOrStorePipe(c, p)
	sb.pipes.add(p)
	p.start(sb.pipes, sb.closeCh)
	return nil
}

// close stops all acceptors and reader goroutines, waits for them to exit.
// Idempotent.
func (sb *socketBase) close() {
	sb.closeOnce.Do(func() {
		close(sb.closeCh)
		if sb.closeFn != nil {
			sb.closeFn()
		}
		sb.listenersMu.Lock()
		for _, ln := range sb.listeners {
			ln.Close()
		}
		sb.listenersMu.Unlock()
		// Wait for all acceptor and handshake goroutines to finish. After
		// this point no new pipes will be added to the pipeSet, so the
		// snapshot below is authoritative. ReadLoops are not tracked by sb.wg
		// and are still blocked on ReadFrame — the pipes remain in pipeSet.
		sb.wg.Wait()
		// Snapshot all live pipes. Emit EventClosed for each before closing
		// the connection so the remote address is still valid.
		// Inproc readLoop does NOT call ps.remove on the closeCh path (it lets
		// close() own cleanup), so inproc pipes are guaranteed to be here.
		closing := sb.pipes.all()
		for _, p := range closing {
			if p.conn != nil { // conn is nil in test-only pipes created without a real connection
				sb.emit(SocketEvent{Type: EventClosed, Endpoint: p.conn.RemoteAddr().String()})
				p.conn.Close()
			}
		}
		// Wait for every snapshotted pipe's reader goroutine to exit.
		for _, p := range closing {
			p.wg.Wait()
		}
		// Seal the monitor channel. Acquire the write lock to block any
		// concurrent emit() calls (e.g. from a readLoop's onDisconnect that
		// fired just before closeCh was observed as closed). Once monitorSealed
		// is set, subsequent emit calls bail out under the read lock, preventing
		// sends to the closed channel.
		if sb.cfg.monitorCh != nil {
			sb.monitorMu.Lock()
			if !sb.monitorSealed {
				select {
				case sb.cfg.monitorCh <- SocketEvent{Type: EventMonitorStopped}:
				default:
				}
				sb.monitorSealed = true
				close(sb.cfg.monitorCh)
			}
			sb.monitorMu.Unlock()
		}
	})
}

// recvAny fair-queues across all pipes. For the common single-peer case it
// uses a plain select to avoid reflect.Select overhead and slice allocation.
func (sb *socketBase) recvAny(ctx context.Context) (Message, *pipe, error) {
	for {
		// Fast path: exactly one connected pipe — direct channel receive,
		// no reflect.Select and no snapshot allocation.
		if p := sb.pipes.singlePipe(); p != nil {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-sb.closeCh:
				return nil, nil, ErrClosed
			case msg, ok := <-p.inCh:
				if ok {
					return msg, p, nil
				}
				// Pipe died. Proactively remove to avoid busy-loop in the
				// inproc case where readLoop's ps.remove may lag behind inCh
				// closure due to goroutine scheduling.
				sb.pipes.remove(p)
				continue
			}
		}

		// Two-pipe fast path: static 4-case select, no reflect.Select and no
		// snapshot allocation.
		if p1, p2 := sb.pipes.twoPipes(); p1 != nil {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-sb.closeCh:
				return nil, nil, ErrClosed
			case msg, ok := <-p1.inCh:
				if ok {
					return msg, p1, nil
				}
				sb.pipes.remove(p1)
				continue
			case msg, ok := <-p2.inCh:
				if ok {
					return msg, p2, nil
				}
				sb.pipes.remove(p2)
				continue
			}
		}

		// General path: 0 or ≥3 pipes.
		pipes := sb.pipes.all()
		if len(pipes) == 0 {
			select {
			case <-sb.pipes.currentAdded():
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-sb.closeCh:
				return nil, nil, ErrClosed
			}
			continue
		}
		msg, p, err := recvFromPipes(ctx, pipes, sb.closeCh)
		if err != nil {
			return nil, nil, err
		}
		if msg == nil {
			// Dead pipe — proactively remove in case readLoop's ps.remove
			// hasn't fired yet (inproc scheduling window).
			sb.pipes.remove(p)
			continue
		}
		return msg, p, nil
	}
}

// recvFromPipes fair-queues across a snapshot of pipes using reflect.Select.
func recvFromPipes(ctx context.Context, pipes []*pipe, closeCh <-chan struct{}) (Message, *pipe, error) {
	cases := make([]reflect.SelectCase, 2+len(pipes))
	// ctx.Done() returns nil for context.Background(); a nil channel in
	// reflect.Select blocks forever, which is the correct behavior.
	cases[0] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ctx.Done())}
	cases[1] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(closeCh)}
	for i, p := range pipes {
		cases[2+i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(p.inCh)}
	}
	chosen, recv, ok := reflect.Select(cases)
	switch chosen {
	case 0:
		return nil, nil, ctx.Err()
	case 1:
		return nil, nil, ErrClosed
	default:
		p := pipes[chosen-2]
		if !ok {
			return nil, p, nil // dead pipe — caller retries
		}
		return recv.Interface().(Message), p, nil
	}
}

// sendWaitPipe waits until a pipe is available for sending, then returns it.
func (sb *socketBase) sendWaitPipe(ctx context.Context) (*pipe, error) {
	for {
		// Read the notification channel before next() so any concurrent add()
		// between here and next() closes the channel we wait on — no missed wakeup.
		added := sb.pipes.currentAdded()
		p := sb.pipes.next()
		if p != nil {
			return p, nil
		}
		select {
		case <-added:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-sb.closeCh:
			return nil, ErrClosed
		}
	}
}
