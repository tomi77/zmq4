package null

import (
	"fmt"

	"github.com/tomi77/zmq4/internal/wire"
)

// State drives one side of a ZMTP 3.1 NULL handshake. It is single-shot
// and not safe for concurrent use.
type State struct {
	local    wire.Metadata
	peer     wire.Metadata
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
