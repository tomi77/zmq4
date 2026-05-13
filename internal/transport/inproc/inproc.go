package inproc

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/tomi77/zmq4/internal/transport/internal/sentinels"
)

// pairIDCounter is incremented for every new net.Pipe pair created by the
// inproc transport. Both halves of a pair carry the same ID so that
// socketBase.addConn can link the two corresponding pipe structs for the
// inproc data fast-path (optimization C).
var pairIDCounter uint64

// inprocNetConn wraps a net.Conn with a pairID identifying which net.Pipe
// pair this end belongs to. Both ends of the same net.Pipe share a pairID.
type inprocNetConn struct {
	net.Conn
	pairID uint64
}

// PairID returns the pair identifier shared by both halves of a net.Pipe.
func (i *inprocNetConn) PairID() uint64 { return i.pairID }

// newPair allocates a fresh net.Pipe and wraps both ends with a shared pairID.
func newPair() (server, client net.Conn) {
	id := atomic.AddUint64(&pairIDCounter, 1)
	a, b := net.Pipe()
	return &inprocNetConn{Conn: a, pairID: id}, &inprocNetConn{Conn: b, pairID: id}
}

// Listen registers name in the inproc registry and returns a net.Listener.
// If the name is already bound, returns ErrInprocAlreadyBound.
//
// Listen drains any pending Dialers on the same name in FIFO order,
// pairing each with a fresh net.Pipe. The drain runs after registry.mu is
// released so it never blocks under the global lock.
//
// ctx is currently unused — Listen does not block.
func Listen(_ context.Context, name string) (net.Listener, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: empty inproc name", sentinels.ErrEndpointMalformed)
	}

	registry.mu.Lock()
	if _, exists := registry.bound[name]; exists {
		registry.mu.Unlock()
		return nil, fmt.Errorf("%w: %q", sentinels.ErrInprocAlreadyBound, name)
	}
	lis := newInprocListener(name)
	registry.bound[name] = lis
	drainSnap := registry.pending[name]
	delete(registry.pending, name)

	// Pair every pending dialer with a fresh net.Pipe and deliver the
	// dial-side conn via pd.ready BEFORE releasing registry.mu. The
	// cap-1 buffered channel guarantees the send is non-blocking, and
	// committing it under the lock closes the cancel-vs-drain race
	// (spec §7.5): once a Dial cancellation reacquires registry.mu and
	// finds pd absent from pending, pd.ready is guaranteed to hold the
	// orphan conn for it to drain and close.
	accepts := make([]net.Conn, 0, len(drainSnap))
	for _, pd := range drainSnap {
		serverConn, clientConn := newPair()
		pd.ready <- acceptResult{conn: clientConn} // cap-1, non-blocking
		accepts = append(accepts, serverConn)
	}
	registry.mu.Unlock()

	// Enqueue accept-sides off-lock (qmu acquired here; never co-held
	// with registry.mu per §7.8). FIFO order preserved.
	for _, a := range accepts {
		lis.enqueue(a)
	}

	return lis, nil
}

// Close, Accept, Addr methods.

func (l *inprocListener) Close() error {
	registry.mu.Lock()
	if registry.bound[l.name] == l {
		delete(registry.bound, l.name)
	}
	registry.mu.Unlock()
	l.closeOnce.Do(func() {
		close(l.closed)
		select {
		case l.notify <- struct{}{}:
		default:
		}
	})
	return nil
}

func (l *inprocListener) Addr() net.Addr {
	return inprocAddr{l.name}
}

func (l *inprocListener) Accept() (net.Conn, error) {
	for {
		l.qmu.Lock()
		if len(l.queue) > 0 {
			c := l.queue[0]
			l.queue = l.queue[1:]
			l.qmu.Unlock()
			return c, nil
		}
		// queue empty — check closed before parking.
		select {
		case <-l.closed:
			l.qmu.Unlock()
			return nil, net.ErrClosed
		default:
		}
		l.qmu.Unlock()

		// Park until either a notify ping or close.
		select {
		case <-l.notify:
			// loop, re-check queue + closed
		case <-l.closed:
			// loop will observe closed in step 1+2
		}
	}
}

// Dial opens a connection to name. If name is already bound, returns
// immediately with a fresh net.Pipe pair (the accept side is enqueued on
// the listener). If unbound, blocks until either a Listen on the same
// name pairs the dial, or ctx is cancelled.
func Dial(ctx context.Context, name string) (net.Conn, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: empty inproc name", sentinels.ErrEndpointMalformed)
	}

	registry.mu.Lock()
	if lis, ok := registry.bound[name]; ok {
		serverConn, clientConn := newPair()
		registry.mu.Unlock()
		lis.enqueue(serverConn)
		return clientConn, nil
	}

	pd := &pendingDial{ready: make(chan acceptResult, 1)}
	registry.pending[name] = append(registry.pending[name], pd)
	registry.mu.Unlock()

	select {
	case res := <-pd.ready:
		return res.conn, nil
	case <-ctx.Done():
		registry.mu.Lock()
		found := removeFromPending(name, pd)
		registry.mu.Unlock()
		if !found {
			// Listen-drain already delivered. Drain pd.ready and close
			// the orphaned dial-side conn so the listener observes EOF.
			select {
			case res := <-pd.ready:
				_ = res.conn.Close()
			default:
			}
		}
		return nil, ctx.Err()
	}
}
