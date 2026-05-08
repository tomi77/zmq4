package conn

import (
	"errors"
	"fmt"
)

// Sentinels returned by ClientHandshake / ServerHandshake. Every sentinel
// is wrapped via fmt.Errorf("%w: …", sentinel, …) with context (mechanism
// name, side, raw conn RemoteAddr) before being returned. F5 uses
// errors.Is to discriminate.
var (
	// ErrNoDeadline is returned before the constructor touches raw when
	// the supplied ctx carries no deadline. Spec §6.6.
	ErrNoDeadline = errors.New("conn: ctx must carry a deadline")

	// ErrInvalidGreeting is returned when the peer's ZMTP greeting fails
	// signature validation. Spec §6.1 step 2.
	ErrInvalidGreeting = errors.New("conn: invalid ZMTP greeting")

	// ErrMechanismMismatch is returned when the peer-advertised mechanism
	// in the greeting does not match our local Mechanism.Name(). Spec §6.1
	// step 5. RFC 23 §3.3: "If the mechanisms don't match, the connection
	// MUST be closed."
	ErrMechanismMismatch = errors.New("conn: mechanism mismatch with peer")

	// ErrRoleConflict is returned for asymmetric mechanisms (PLAIN, CURVE)
	// when both peers advertise the same as-server bit. NULL is symmetric
	// and ignores the bit. Spec §6.1 step 6.
	ErrRoleConflict = errors.New("conn: as-server role conflict with peer")

	// ErrHandshakeFail wraps any non-sentinel reason a handshake aborted —
	// peer-emitted ERROR, local mech.Receive / mech.Start error, malformed
	// command body, mid-handshake EOF. Spec §6.2 / §6.3.
	ErrHandshakeFail = errors.New("conn: handshake aborted")

	// ErrMetadataTooLarge is returned when a metadata-bearing handshake
	// command body (READY for NULL/PLAIN/CURVE; INITIATE for PLAIN/CURVE)
	// exceeds the configured cap. Spec §6.2.
	ErrMetadataTooLarge = errors.New("conn: handshake metadata exceeds cap")

	// ErrCommandTooLarge is returned when any single handshake command
	// frame exceeds the configured per-command cap. Spec §6.2.
	ErrCommandTooLarge = errors.New("conn: handshake command exceeds cap")

	// ErrUnexpectedFrame is returned during the handshake when the peer
	// sends a FrameMessage instead of a FrameCommand. Spec §6.2.
	ErrUnexpectedFrame = errors.New("conn: unexpected frame kind during handshake")
)

// ErrPeerError carries the reason from a peer-emitted ERROR command on
// the post-handshake stream. Surfaced as a pointer so errors.As can
// recover the Reason. The in-handshake equivalent (peer ERROR during
// handshake) does not use *ErrPeerError; it returns ErrHandshakeFail
// wrapping a string with the reason embedded — F5 reacts differently.
type ErrPeerError struct {
	Reason string
}

func (e *ErrPeerError) Error() string {
	return fmt.Sprintf("conn: peer ERROR: %q", e.Reason)
}
