package zmq4

import (
	"reflect"
	"time"
)

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
	case *REQ:
		return &v.base, true
	case *REP:
		return &v.base, true
	case *DEALER:
		return &v.base, true
	case *ROUTER:
		return &v.base, true
	case *PUB:
		return &v.base, true
	case *SUB:
		return &v.base, true
	case *XPUB:
		return &v.base, true
	case *XSUB:
		return &v.base, true
	case *PUSH:
		return &v.base, true
	case *PULL:
		return &v.base, true
	case *PAIR:
		return &v.base, true
	default:
		return nil, false
	}
}

// Add registers s with event mask e.
// Returns ErrInvalidEvents if e is zero.
// Returns ErrNotSocket if s is not a zmq4 socket type.
// Returns ErrAlreadyRegistered if s is already registered.
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
// Returns ErrNotRegistered if s was never added.
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
// Returns ErrNotRegistered if s was never added.
// Returns ErrInvalidEvents if e is zero.
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

type caseTag int

const (
	tagTimeout caseTag = iota
	tagClose
	tagRebuild
	tagWakeup
)

// phase1 does a non-blocking scan across all registered entries.
// Returns all sockets that satisfy their event mask right now.
func phase1(items []pollEntry) []Event {
	var ready []Event
	for _, item := range items {
		pipes := item.base.pipes.all()
		var got Events
		if item.events&POLLIN != 0 {
			for _, pp := range pipes {
				if len(pp.inCh) > 0 {
					got |= POLLIN
					break
				}
			}
		}
		if item.events&POLLOUT != 0 {
			for _, pp := range pipes {
				if len(pp.outCh) < cap(pp.outCh) {
					got |= POLLOUT
					break
				}
			}
		}
		if got != 0 {
			ready = append(ready, Event{Socket: item.socket, Events: got})
		}
	}
	return ready
}

// Poll blocks until at least one registered socket satisfies its event mask,
// then returns all currently-ready sockets.
//
//	timeout < 0  → block indefinitely
//	timeout = 0  → non-blocking snapshot
//	timeout > 0  → block up to timeout; (nil, nil) when expired
//
// Returns (nil, ErrClosed) if any registered socket is closed during the call.
// Returns (nil, nil) immediately when no sockets are registered.
func (p *Poller) Poll(timeout time.Duration) ([]Event, error) {
	if len(p.items) == 0 {
		return nil, nil
	}

	ready := phase1(p.items)
	if len(ready) > 0 || timeout == 0 {
		return ready, nil
	}

	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}

	for {
		var timerCh <-chan time.Time // nil when timeout < 0 → blocks forever
		if timeout > 0 {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, nil
			}
			timerCh = time.After(remaining)
		}

		cases, tags := buildCases(p.items, timerCh)
		chosen, _, _ := reflect.Select(cases)

		switch tags[chosen] {
		case tagTimeout:
			return nil, nil
		case tagClose:
			return nil, ErrClosed
		case tagRebuild:
			// new peer connected; rebuild cases on next loop iteration
		case tagWakeup:
			ready = phase1(p.items)
			if len(ready) > 0 {
				return ready, nil
			}
			// stale signal from dead pipe; rebuild and retry
		}
	}
}

// buildCases constructs the reflect.SelectCase slice for Phase 2.
// Slot 0 is always the timeout (nil chan = block forever when timeout < 0).
// Each subsequent slot is tagged so Poll knows what action to take on wakeup.
func buildCases(items []pollEntry, timerCh <-chan time.Time) ([]reflect.SelectCase, []caseTag) {
	var cases []reflect.SelectCase
	var tags []caseTag

	appendCase := func(chanVal reflect.Value, tag caseTag) {
		cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: chanVal})
		tags = append(tags, tag)
	}

	// Slot 0: timeout (nil channel blocks forever → correct for timeout < 0).
	appendCase(reflect.ValueOf(timerCh), tagTimeout)

	// Signal cases: one group per registered socket.
	for _, item := range items {
		pipes := item.base.pipes.all()
		if len(pipes) == 0 {
			// No peers yet — wake up when the first one connects.
			appendCase(reflect.ValueOf(item.base.pipes.currentAdded()), tagRebuild)
			continue
		}
		if item.events&POLLIN != 0 {
			for _, pp := range pipes {
				appendCase(reflect.ValueOf(pp.inReady), tagWakeup)
			}
		}
		if item.events&POLLOUT != 0 {
			for _, pp := range pipes {
				appendCase(reflect.ValueOf(pp.outReady), tagWakeup)
			}
		}
	}

	// Close cases: one per registered socket (any one closing terminates Poll).
	for _, item := range items {
		appendCase(reflect.ValueOf(item.base.closeCh), tagClose)
	}

	return cases, tags
}
