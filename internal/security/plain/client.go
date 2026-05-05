package plain

import (
	"fmt"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/seccommon"
	"github.com/tomi77/zmq4/internal/wire"
)

// ClientState drives the client side of a ZMTP 3.1 PLAIN handshake.
// Single-shot; not safe for concurrent use.
type ClientState struct {
	username []byte
	password []byte
	local    wire.Metadata // metadata for INITIATE
	peer     wire.Metadata // metadata from peer READY (defensively copied)

	started         bool
	welcomeReceived bool
	done            bool
	failed          bool
}

// NewClient constructs a client. username and password are referenced,
// not copied; callers must not mutate them after passing them in. Each
// must be ≤255 bytes per RFC 37 §3.2.
//
// localMetadata is sent in INITIATE (step 3); referenced, not copied.
func NewClient(username, password []byte, localMetadata wire.Metadata) (*ClientState, error) {
	if len(username) > 255 {
		return nil, fmt.Errorf("%w: username %d bytes", ErrCredentialsTooLong, len(username))
	}
	if len(password) > 255 {
		return nil, fmt.Errorf("%w: password %d bytes", ErrCredentialsTooLong, len(password))
	}
	return &ClientState{
		username: username,
		password: password,
		local:    localMetadata,
	}, nil
}

// Done reports whether the handshake has completed successfully.
func (c *ClientState) Done() bool { return c.done && !c.failed }

// Start emits HELLO. Must be called exactly once before Receive.
func (c *ClientState) Start() (wire.Command, error) {
	if c.failed {
		return wire.Command{}, ErrAlreadyFailed
	}
	if c.started {
		return wire.Command{}, ErrAlreadyStarted
	}
	cmd, err := encodeHello(helloBody{Username: c.username, Password: c.password})
	if err != nil {
		c.failed = true
		return wire.Command{}, fmt.Errorf("plain: encode HELLO: %w", err)
	}
	c.started = true
	return cmd, nil
}

// Receive consumes one peer command and advances the state machine.
//
//	step 2: cmd=WELCOME ⇒ out=INITIATE, done=false
//	step 4: cmd=READY   ⇒ out=nil,      done=true
//	any:    cmd=ERROR   ⇒ err=ErrPeerError(reason)
func (c *ClientState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error) {
	if c.failed {
		return nil, false, ErrAlreadyFailed
	}
	if !c.started {
		c.failed = true
		return nil, false, ErrNotStarted
	}
	if c.done {
		c.failed = true
		return nil, false, ErrAlreadyDone
	}

	if !c.welcomeReceived {
		// Expecting WELCOME.
		switch cmd.Name {
		case welcomeCommandName:
			if perr := parseWelcome(cmd); perr != nil {
				c.failed = true
				return nil, false, perr
			}
			initiate := &wire.Command{
				Name: initiateCommandName,
				Data: wire.EncodeMetadata(c.local),
			}
			c.welcomeReceived = true
			return initiate, false, nil
		case wire.ErrorCommandName:
			return nil, false, c.failPeerError(cmd)
		}
		c.failed = true
		return nil, false, fmt.Errorf("%w: %q (expected WELCOME)", ErrUnexpectedCommand, cmd.Name)
	}

	// Expecting READY.
	switch cmd.Name {
	case wire.ReadyCommandName:
		rc, perr := wire.ParseReady(cmd)
		if perr != nil {
			c.failed = true
			return nil, false, fmt.Errorf("%w: %v", ErrMalformedReady, perr)
		}
		c.peer = seccommon.CloneMetadata(rc.Metadata)
		c.done = true
		return nil, true, nil
	case wire.ErrorCommandName:
		return nil, false, c.failPeerError(cmd)
	}
	c.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected READY)", ErrUnexpectedCommand, cmd.Name)
}

// failPeerError marks the state failed and returns an ErrPeerError-wrapped
// reason extracted from the peer's ERROR command.
func (c *ClientState) failPeerError(cmd wire.Command) error {
	c.failed = true
	ec, perr := wire.ParseError(cmd)
	if perr != nil {
		return fmt.Errorf("%w: malformed ERROR: %v", ErrPeerError, perr)
	}
	return fmt.Errorf("%w: %s", ErrPeerError, ec.Reason)
}

// PeerMetadata returns the metadata the server advertised in its READY
// command. Valid only after Receive returned done=true. The slice
// aliases an internal buffer; callers must NOT mutate it.
func (c *ClientState) PeerMetadata() wire.Metadata { return c.peer }

// Wrap returns f unchanged. PLAIN does no traffic encapsulation.
// Returns security.ErrNotDone if called before the handshake completes.
func (c *ClientState) Wrap(f wire.Frame) (wire.Frame, error) {
	if !c.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}

// Unwrap returns f unchanged. PLAIN does no traffic encapsulation.
// Returns security.ErrNotDone if called before the handshake completes.
func (c *ClientState) Unwrap(f wire.Frame) (wire.Frame, error) {
	if !c.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}
