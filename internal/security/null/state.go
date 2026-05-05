package null

import (
	"fmt"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/seccommon"
	"github.com/tomi77/zmq4/internal/wire"
)

// State drives one side of a ZMTP 3.1 NULL handshake. It is single-shot,
// not safe for concurrent use, and not reusable: create a new State for
// each connection attempt.
type State struct {
	local    wire.Metadata
	peer     wire.Metadata // populated by Receive on a valid peer READY
	started  bool
	received bool
	failed   bool
}

// New constructs a State that will advertise localMetadata in our
// outbound READY. localMetadata is referenced, not copied; the caller
// must not mutate it after passing it in.
func New(localMetadata wire.Metadata) *State {
	return &State{local: localMetadata}
}

// Done reports whether the handshake has completed successfully.
func (s *State) Done() bool { return s.received && !s.failed }

// Start produces the initial outbound READY. It must be called exactly
// once, before any Receive call.
func (s *State) Start() (wire.Command, error) {
	if s.failed {
		return wire.Command{}, ErrAlreadyFailed
	}
	if s.started {
		return wire.Command{}, ErrAlreadyStarted
	}
	rc := wire.ReadyCommand{Metadata: s.local}
	cmd, err := rc.Encode()
	if err != nil {
		s.failed = true
		return wire.Command{}, fmt.Errorf("null: encode READY: %w", err)
	}
	s.started = true
	return cmd, nil
}

// Receive consumes one command from the peer and advances the state
// machine. See package doc and 02a spec for the contract.
func (s *State) Receive(cmd wire.Command) (out *wire.Command, done bool, err error) {
	if s.failed {
		return nil, false, ErrAlreadyFailed
	}
	if !s.started {
		s.failed = true
		return nil, false, ErrNotStarted
	}
	if s.received {
		s.failed = true
		return nil, false, ErrAlreadyDone
	}
	switch cmd.Name {
	case wire.ReadyCommandName:
		rc, perr := wire.ParseReady(cmd)
		if perr != nil {
			s.failed = true
			return nil, false, fmt.Errorf("%w: %v", ErrMalformedReady, perr)
		}
		s.peer = seccommon.CloneMetadata(rc.Metadata)
		s.received = true
		return nil, true, nil
	case wire.ErrorCommandName:
		s.failed = true
		ec, perr := wire.ParseError(cmd)
		if perr != nil {
			return nil, false, fmt.Errorf("%w: malformed ERROR: %v", ErrPeerError, perr)
		}
		return nil, false, fmt.Errorf("%w: %s", ErrPeerError, ec.Reason)
	}
	s.failed = true
	return nil, false, fmt.Errorf("%w: %q", ErrUnexpectedCommand, cmd.Name)
}

// PeerMetadata returns the metadata the peer advertised in its READY
// command. Valid only after Receive returned done=true. The returned
// slice is owned by the State and lives until the State is discarded;
// callers must not mutate it.
func (s *State) PeerMetadata() wire.Metadata { return s.peer }

// Wrap returns f unchanged. NULL does no traffic encapsulation.
// Returns security.ErrNotDone if called before the handshake completes.
func (s *State) Wrap(f wire.Frame) (wire.Frame, error) {
	if !s.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}

// Unwrap returns f unchanged. NULL does no traffic encapsulation.
// Returns security.ErrNotDone if called before the handshake completes.
func (s *State) Unwrap(f wire.Frame) (wire.Frame, error) {
	if !s.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}
