package plain

import (
	"fmt"

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
