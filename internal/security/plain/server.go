package plain

import (
	"fmt"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/seccommon"
	"github.com/tomi77/zmq4/internal/wire"
)

// ServerState drives the server side of a ZMTP 3.1 PLAIN handshake.
// Single-shot; not safe for concurrent use.
type ServerState struct {
	auth  Authenticator
	local wire.Metadata // metadata for READY
	peer  wire.Metadata // metadata from peer INITIATE (defensively copied)

	helloProcessed bool
	done           bool
	failed         bool
}

// Authenticator decides whether to accept a (username, password) pair.
// Returning nil ⇒ WELCOME. Returning non-nil ⇒ ERROR (reason = err.Error()
// after sanitization). Runs synchronously; must not do I/O or take
// locks held elsewhere.
type Authenticator func(username, password []byte) error

// NewServer constructs a server. auth must not be nil; passing nil is
// a programming error and panics. localMetadata is sent in READY at the
// end of the handshake; referenced, not copied.
func NewServer(auth Authenticator, localMetadata wire.Metadata) *ServerState {
	if auth == nil {
		panic("plain: NewServer requires a non-nil Authenticator")
	}
	return &ServerState{auth: auth, local: localMetadata}
}

// Done reports whether the handshake has completed successfully.
func (s *ServerState) Done() bool { return s.done && !s.failed }

// PeerMetadata returns the metadata the client sent in INITIATE. Valid
// only after Receive returned done=true.
func (s *ServerState) PeerMetadata() wire.Metadata { return s.peer }

// Wrap returns f unchanged. PLAIN does no traffic encapsulation.
// Returns security.ErrNotDone if called before the handshake completes.
func (s *ServerState) Wrap(f wire.Frame) (wire.Frame, error) {
	if !s.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}

// Unwrap returns f unchanged. PLAIN does no traffic encapsulation.
// Returns security.ErrNotDone if called before the handshake completes.
func (s *ServerState) Unwrap(f wire.Frame) (wire.Frame, error) {
	if !s.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}

// Receive consumes one peer command and advances the state machine.
// See spec §4.2 for the contract.
func (s *ServerState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error) {
	if s.failed {
		return nil, false, ErrAlreadyFailed
	}
	if s.done {
		s.failed = true
		return nil, false, ErrAlreadyDone
	}

	if !s.helloProcessed {
		// Expecting HELLO.
		switch cmd.Name {
		case helloCommandName:
			body, perr := parseHello(cmd)
			if perr != nil {
				s.failed = true
				return nil, false, perr
			}
			if authErr := s.auth(body.Username, body.Password); authErr != nil {
				return s.failAuthRejected(authErr)
			}
			welcome := encodeWelcome()
			s.helloProcessed = true
			return &welcome, false, nil
		case wire.ErrorCommandName:
			return nil, false, s.failPeerError(cmd)
		}
		s.failed = true
		return nil, false, fmt.Errorf("%w: %q (expected HELLO)", ErrUnexpectedCommand, cmd.Name)
	}

	// Expecting INITIATE.
	switch cmd.Name {
	case initiateCommandName:
		md, perr := wire.ParseMetadata(cmd.Data)
		if perr != nil {
			s.failed = true
			return nil, false, fmt.Errorf("%w: %v", ErrMalformedInitiate, perr)
		}
		s.peer = seccommon.CloneMetadata(md)
		ready, encErr := wire.ReadyCommand{Metadata: s.local}.Encode()
		if encErr != nil {
			s.failed = true
			return nil, false, fmt.Errorf("plain: encode READY: %w", encErr)
		}
		s.done = true
		return &ready, true, nil
	case wire.ErrorCommandName:
		return nil, false, s.failPeerError(cmd)
	}
	s.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected INITIATE)", ErrUnexpectedCommand, cmd.Name)
}

// failAuthRejected encodes an ERROR command carrying the authenticator's
// reason and marks the state as failed. The caller MUST send the
// returned out command before closing the connection.
func (s *ServerState) failAuthRejected(authErr error) (*wire.Command, bool, error) {
	s.failed = true
	reason := seccommon.SanitizeReason(authErr.Error())
	errCmd, encErr := wire.ErrorCommand{Reason: reason}.Encode()
	if encErr != nil {
		return nil, false, fmt.Errorf("plain: encode ERROR: %w", encErr)
	}
	return &errCmd, false, fmt.Errorf("%w: %s", ErrAuthRejected, reason)
}

func (s *ServerState) failPeerError(cmd wire.Command) error {
	s.failed = true
	ec, perr := wire.ParseError(cmd)
	if perr != nil {
		return fmt.Errorf("%w: malformed ERROR: %v", ErrPeerError, perr)
	}
	return fmt.Errorf("%w: %s", ErrPeerError, ec.Reason)
}
