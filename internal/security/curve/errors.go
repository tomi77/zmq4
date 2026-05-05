package curve

import "errors"

var (
	// ErrInvalidOptions is returned by NewClient/NewServer when the
	// caller passes a zero ServerKey/OurPublicKey or a nil OurSecretKey
	// pointer. NewServer with a nil Authorizer panics rather than
	// returning this error — see NewServer godoc.
	ErrInvalidOptions = errors.New("curve: invalid options")

	// ErrCryptoRand is returned when the configured Rand source's Read
	// method fails (transient keypair generation, nonce randomization,
	// cookie-key generation).
	ErrCryptoRand = errors.New("curve: rand read failed")

	// ErrAlreadyStarted is returned by ClientState.Start on second call.
	ErrAlreadyStarted = errors.New("curve: handshake already started")

	// ErrNotStarted is returned by ClientState.Receive before Start.
	ErrNotStarted = errors.New("curve: handshake not started")

	// ErrAlreadyDone is returned when Start or Receive is called after
	// a previous successful completion. Wrap and Unwrap remain valid
	// after Done — that is the whole point of post-handshake encryption.
	ErrAlreadyDone = errors.New("curve: handshake already complete")

	// ErrAlreadyFailed is returned when any method is called after a
	// previous error has put the state into the failed state.
	ErrAlreadyFailed = errors.New("curve: handshake already failed")

	// ErrUnexpectedCommand is returned when the peer sends a command
	// whose name is not the one expected in the current state (and is
	// not ERROR).
	ErrUnexpectedCommand = errors.New("curve: unexpected command")

	// ErrPeerError is returned when the peer sends an ERROR command.
	// The wrapped string includes the peer's reason as received; bytes
	// outside %x21..%x7E are not stripped before wrapping. Loggers and
	// UIs SHOULD treat the reason as untrusted, peer-controlled input.
	ErrPeerError = errors.New("curve: peer sent ERROR")

	// ErrAuthRejected is returned by ServerState.Receive on the
	// INITIATE step when the Authorizer callback returned a non-nil
	// error. Returned alongside a non-nil out *wire.Command containing
	// the ERROR command the caller MUST send before closing the
	// connection.
	ErrAuthRejected = errors.New("curve: authorizer rejected client")

	// ErrMalformedHello is returned when HELLO does not parse per
	// RFC 26 §5.2 (wrong size, bad version, non-zero padding).
	ErrMalformedHello = errors.New("curve: malformed HELLO")

	// ErrMalformedWelcome is returned when WELCOME does not parse per
	// RFC 26 §5.3 (wrong size).
	ErrMalformedWelcome = errors.New("curve: malformed WELCOME")

	// ErrMalformedInitiate is returned when INITIATE outer structure
	// does not parse per RFC 26 §5.4.
	ErrMalformedInitiate = errors.New("curve: malformed INITIATE")

	// ErrMalformedReady is returned when READY outer structure does
	// not parse per RFC 26 §5.5.
	ErrMalformedReady = errors.New("curve: malformed READY")

	// ErrMalformedMessage is returned when MESSAGE structure (size,
	// command name) does not parse per RFC 26 §6.
	ErrMalformedMessage = errors.New("curve: malformed MESSAGE")

	// ErrBoxOpen is returned when a NaCl box (or secretbox) Open
	// returned false — the auth tag did not verify. Wraps a description
	// of which box failed (HELLO outer, WELCOME outer, INITIATE outer,
	// vouch, READY, MESSAGE, cookie).
	ErrBoxOpen = errors.New("curve: box authentication failed")

	// ErrCookieMismatch is returned when an INITIATE cookie opens
	// cleanly but its inner (C', s') does not match the server's
	// recorded handshake state — indicates a forged or replayed
	// INITIATE.
	ErrCookieMismatch = errors.New("curve: cookie mismatch")

	// ErrNonceReused is returned when an incoming MESSAGE short-nonce
	// is ≤ the last accepted receive nonce — a replay or out-of-order
	// delivery.
	ErrNonceReused = errors.New("curve: nonce reused")

	// ErrNonceExhausted is returned when an outgoing MESSAGE send nonce
	// would wrap past 2^64-1.
	ErrNonceExhausted = errors.New("curve: nonce exhausted")
)
