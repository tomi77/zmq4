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

	// ZAP — set by ConfigureZAP; only used on the server side.
	zap      security.ZAPCaller
	domain   string
	peerAddr string
	zapMeta  wire.Metadata
}

// New constructs a State that will advertise localMetadata in our
// outbound READY. localMetadata is referenced, not copied; the caller
// must not mutate it after passing it in.
func New(localMetadata wire.Metadata) *State {
	return &State{local: localMetadata}
}

// ConfigureZAP injects a ZAP client and domain. Called by base.go on the
// server side immediately after mechanism creation. Satisfies security.ZAPConfigurer.
func (s *State) ConfigureZAP(caller security.ZAPCaller, domain string) {
	s.zap = caller
	s.domain = domain
}

// SetPeerAddr stores the peer's network address for inclusion in ZAP requests.
// Called by base.go on the server side before the handshake. Satisfies security.PeerAddrSetter.
func (s *State) SetPeerAddr(addr string) { s.peerAddr = addr }

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
		if s.zap != nil {
			code, _, zapMeta, zapErr := s.zap.Authenticate(
				s.domain, s.peerAddr, "", "NULL", nil,
			)
			if zapErr != nil || code != "200" {
				return s.failZAPDenied(code)
			}
			s.zapMeta = zapMeta
		}
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

func (s *State) failZAPDenied(statusCode string) (*wire.Command, bool, error) {
	s.failed = true
	reason := seccommon.SanitizeReason("ZAP " + statusCode)
	errCmd, encErr := wire.ErrorCommand{Reason: reason}.Encode()
	if encErr != nil {
		return nil, false, fmt.Errorf("null: encode ERROR: %w", encErr)
	}
	return &errCmd, false, fmt.Errorf("%w: status %s", security.ErrZAPDenied, statusCode)
}

// PeerMetadata returns the peer's READY metadata merged with any ZAP reply
// metadata. Valid only after Receive returned done=true.
// The returned slice is owned by the State; callers MUST NOT mutate it.
func (s *State) PeerMetadata() wire.Metadata {
	if len(s.zapMeta) == 0 {
		return s.peer
	}
	merged := seccommon.CloneMetadata(s.peer)
	return append(merged, s.zapMeta...)
}

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

// Name returns "NULL". See security.Mechanism.Name.
func (s *State) Name() string { return "NULL" }
