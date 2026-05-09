package plain

import (
	"errors"

	"github.com/tomi77/zmq4/internal/security"
)

var (
	// ErrCredentialsTooLong is returned by NewClient when username or
	// password exceeds 255 bytes (RFC 37 §3.2 ABNF limit).
	ErrCredentialsTooLong = errors.New("plain: credentials too long")

	// ErrAlreadyStarted is returned by ClientState.Start on second call.
	ErrAlreadyStarted = errors.New("plain: handshake already started")

	// ErrNotStarted is returned by ClientState.Receive before Start.
	ErrNotStarted = errors.New("plain: handshake not started")

	// ErrAlreadyDone is returned when any method is called after the
	// handshake completed successfully.
	ErrAlreadyDone = errors.New("plain: handshake already complete")

	// ErrAlreadyFailed is returned when any method is called after a
	// previous error has put the state into the failed state.
	ErrAlreadyFailed = errors.New("plain: handshake already failed")

	// ErrUnexpectedCommand is returned when the peer sends a command
	// whose name is not the one expected in the current state (and is
	// not ERROR).
	ErrUnexpectedCommand = errors.New("plain: unexpected command")

	// ErrPeerError is returned when the peer sends an ERROR command.
	// The wrapped error includes the peer's reason string.
	ErrPeerError = errors.New("plain: peer sent ERROR")

	// ErrAuthRejected is returned by ServerState.Receive when the
	// Authenticator callback returned a non-nil error for HELLO.
	// Returned alongside a non-nil out *wire.Command containing the
	// ERROR command the caller MUST send before closing the connection.
	ErrAuthRejected = errors.New("plain: authenticator rejected credentials")

	// ErrMalformedHello is returned when HELLO body fails to parse as
	// "username password" per RFC 37 §3.2.
	ErrMalformedHello = errors.New("plain: malformed HELLO")

	// ErrMalformedWelcome is returned when WELCOME has a non-empty body.
	ErrMalformedWelcome = errors.New("plain: malformed WELCOME")

	// ErrMalformedInitiate is returned when INITIATE body fails
	// wire.ParseMetadata.
	ErrMalformedInitiate = errors.New("plain: malformed INITIATE")

	// ErrMalformedReady is returned when READY body fails
	// wire.ParseMetadata.
	ErrMalformedReady = errors.New("plain: malformed READY")
)

// ErrZAPDenied is returned by ServerState.Receive when the ZAP handler rejects
// the connection. Alias of security.ErrZAPDenied.
var ErrZAPDenied = security.ErrZAPDenied
