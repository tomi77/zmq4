package null

import "errors"

var (
	// ErrAlreadyStarted is returned by Start when called more than once.
	ErrAlreadyStarted = errors.New("null: handshake already started")

	// ErrNotStarted is returned by Receive when called before Start.
	ErrNotStarted = errors.New("null: handshake not started")

	// ErrAlreadyDone is returned when any method is called after a
	// previous Receive returned done=true.
	ErrAlreadyDone = errors.New("null: handshake already complete")

	// ErrAlreadyFailed is returned when any method is called after a
	// previous error.
	ErrAlreadyFailed = errors.New("null: handshake already failed")

	// ErrUnexpectedCommand is returned when the peer sends a command
	// whose name is neither READY nor ERROR during the handshake.
	ErrUnexpectedCommand = errors.New("null: unexpected command")

	// ErrPeerError is returned when the peer sends an ERROR command.
	// The wrapped error includes the peer's reason string.
	ErrPeerError = errors.New("null: peer sent ERROR")

	// ErrMalformedReady is returned when the peer's READY command-data
	// fails to parse as metadata.
	ErrMalformedReady = errors.New("null: malformed READY")
)
