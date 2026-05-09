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

// bind opens a listener on endpoint and launches a background acceptor
// goroutine. Non-blocking after the listener is established.
func (sb *socketBase) bind(ctx context.Context, endpoint, socketType string) error {
	ln, err := transport.Listen(ctx, endpoint)
	if err != nil {
		return err
	}
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
		pas.SetPeerAddr(raw.RemoteAddr().String())
	}
	c, err := conn.ServerHandshake(hsCtx, raw, mech)
	if err != nil {
		return // raw already closed by F4 on handshake failure
	}
	if err := sb.addConn(c, socketType); err != nil {
		c.Close()
	}
}

// connect dials endpoint, runs the ZMTP handshake, and adds the resulting
// pipe. Blocking — returns after handshake succeeds or fails.
func (sb *socketBase) connect(ctx context.Context, endpoint, socketType string) error {
	raw, err := transport.Dial(ctx, endpoint)
	if err != nil {
		return err
	}
	hsCtx, cancel := context.WithTimeout(ctx, sb.cfg.handshakeTimeout)
	defer cancel()

	mech, err := sb.cfg.clientMechFactory(socketType)
	if err != nil {
		raw.Close()
		return err
	}
	c, err := conn.ClientHandshake(hsCtx, raw, mech)
	if err != nil {
		return err
	}
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
		for _, p := range sb.pipes.all() {
			p.conn.Close()
		}
		sb.wg.Wait()
		// Close any pipes that were added after the first snapshot.
		for _, p := range sb.pipes.all() {
			p.conn.Close()
		}
		// Now wait for all reader goroutines to exit.
		for _, p := range sb.pipes.all() {
			p.wg.Wait()
		}
	})
}

// recvAny fair-queues across all pipes using reflect.Select. Retries on dead pipes.
func (sb *socketBase) recvAny(ctx context.Context) (Message, *pipe, error) {
	for {
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
			// Dead pipe — removed by readLoop; retry.
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

