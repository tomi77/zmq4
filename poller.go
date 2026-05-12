package zmq4

// Events is a bitmask of polling readiness events.
type Events uint32

const (
	POLLIN  Events = 1 // socket has at least one message ready to receive
	POLLOUT Events = 2 // socket can accept at least one outbound message
)

// Event is returned by Poller.Poll for each socket that matched its mask.
type Event struct {
	Socket any    // the value passed to Poller.Add
	Events Events // subset of registered mask that fired
}

type pollEntry struct {
	socket any
	events Events
	base   *socketBase
}

// Poller groups sockets and blocks until one or more are ready.
// Not thread-safe.
type Poller struct {
	items []pollEntry
}

// NewPoller returns an empty Poller.
func NewPoller() *Poller { return &Poller{} }

// asPollBase returns the *socketBase for any concrete zmq4 socket type.
// Named-field embedding prevents interface promotion, so a type switch is used.
func asPollBase(s any) (*socketBase, bool) {
	switch v := s.(type) {
	case *REQ:    return &v.base, true
	case *REP:    return &v.base, true
	case *DEALER: return &v.base, true
	case *ROUTER: return &v.base, true
	case *PUB:    return &v.base, true
	case *SUB:    return &v.base, true
	case *XPUB:   return &v.base, true
	case *XSUB:   return &v.base, true
	case *PUSH:   return &v.base, true
	case *PULL:   return &v.base, true
	case *PAIR:   return &v.base, true
	default:      return nil, false
	}
}

// Add registers s with event mask e.
func (p *Poller) Add(s any, e Events) error {
	if e == 0 {
		return ErrInvalidEvents
	}
	sb, ok := asPollBase(s)
	if !ok {
		return ErrNotSocket
	}
	for _, item := range p.items {
		if item.socket == s {
			return ErrAlreadyRegistered
		}
	}
	p.items = append(p.items, pollEntry{socket: s, events: e, base: sb})
	return nil
}

// Remove unregisters s.
func (p *Poller) Remove(s any) error {
	for i, item := range p.items {
		if item.socket == s {
			p.items = append(p.items[:i], p.items[i+1:]...)
			return nil
		}
	}
	return ErrNotRegistered
}

// Update replaces the event mask for an already-registered socket.
func (p *Poller) Update(s any, e Events) error {
	if e == 0 {
		return ErrInvalidEvents
	}
	for i, item := range p.items {
		if item.socket == s {
			p.items[i].events = e
			return nil
		}
	}
	return ErrNotRegistered
}
