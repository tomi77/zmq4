package inproc

import (
	"net"
	"sync"
)

// inprocAddr satisfies net.Addr for inproc connections.
type inprocAddr struct{ name string }

func (a inprocAddr) Network() string { return "inproc" }
func (a inprocAddr) String() string  { return a.name }

// inprocListener is the live-listener side of a bound inproc name.
// queue is appended-to under qmu by both Listen-drain and post-bind
// Dials. Accept consumes from queue under qmu; if the queue is empty
// it parks on notify (or on closed).
type inprocListener struct {
	name string

	qmu    sync.Mutex
	queue  []net.Conn
	notify chan struct{} // cap 1; signalled on enqueue or on Close

	closed    chan struct{}
	closeOnce sync.Once
}

// pendingDial is the waiter side of a Dial-before-bind. ready is cap-1
// buffered so Listen-drain can deliver without blocking; if Dial cancels
// concurrently, the cancellation path drains ready (see §7.5).
type pendingDial struct {
	ready chan acceptResult
}

type acceptResult struct {
	conn net.Conn // dial-side end of a fresh net.Pipe pair
}

// registry is package-global state.
var registry = struct {
	mu      sync.Mutex
	bound   map[string]*inprocListener
	pending map[string][]*pendingDial // FIFO order — oldest at index 0
}{
	bound:   make(map[string]*inprocListener),
	pending: make(map[string][]*pendingDial),
}

// newInprocListener allocates a bound listener for name (caller MUST hold
// registry.mu and have already verified the name is unbound).
func newInprocListener(name string) *inprocListener {
	return &inprocListener{
		name:   name,
		notify: make(chan struct{}, 1),
		closed: make(chan struct{}),
	}
}

// enqueue appends conn to the listener's queue and pings notify.
func (l *inprocListener) enqueue(c net.Conn) {
	l.qmu.Lock()
	l.queue = append(l.queue, c)
	l.qmu.Unlock()
	select {
	case l.notify <- struct{}{}:
	default:
	}
}

// removeFromPending finds and removes pd from registry.pending[name].
// Returns true if pd was present. Caller MUST hold registry.mu.
func removeFromPending(name string, pd *pendingDial) bool {
	list := registry.pending[name]
	for i, p := range list {
		if p == pd {
			registry.pending[name] = append(list[:i], list[i+1:]...)
			if len(registry.pending[name]) == 0 {
				delete(registry.pending, name)
			}
			return true
		}
	}
	return false
}
