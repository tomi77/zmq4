package security

import "github.com/tomi77/zmq4/internal/wire"

// Mechanism drives one side of a ZMTP 3.1 security handshake and
// post-handshake traffic encapsulation. Single-shot per connection:
// once Done() returns true (or any method returns an error), the
// Mechanism must not be reused.
//
// All methods are NOT goroutine-safe. F4 owns sequencing.
type Mechanism interface {
	// Receive consumes one peer command and advances the handshake.
	// After Done(), Receive MUST NOT be called.
	Receive(cmd wire.Command) (out *wire.Command, done bool, err error)

	// Wrap transforms one outgoing application frame into its on-wire
	// form. Valid only after Done(); otherwise returns ErrNotDone.
	//
	// NULL/PLAIN return f unchanged. CURVE returns a FrameCommand whose
	// Body is the encoded MESSAGE command carrying the encrypted
	// (flags||payload) under the CURVE session keys. f.More is preserved
	// inside the encrypted payload as the inner flags byte (bit 0 ==
	// MORE); the outer wire.Frame.More is always false.
	//
	// Wrap operates on a single frame. Multi-frame logical messages
	// (linked via MORE) are wrapped one frame at a time: each frame
	// becomes its own MESSAGE command with its own short-nonce.
	//
	// For pass-through mechanisms (NULL, PLAIN), the returned Frame
	// aliases f. For mechanisms that perform encapsulation (CURVE), the
	// returned Frame's Body is freshly allocated and independent of f.
	// In all cases the State retains no reference to f. Wrap consumes f
	// synchronously: it MUST read whatever it needs from f.Body before
	// returning and MUST NOT retain or mutate any reference to f. The
	// caller is therefore free to reuse, mutate, or release f.Body the
	// instant Wrap returns; the only constraint is that the caller must
	// not mutate f.Body while the returned Frame is still in use.
	Wrap(f wire.Frame) (wire.Frame, error)

	// Unwrap inverts Wrap. NULL/PLAIN return f unchanged. CURVE expects
	// f to be a FrameCommand whose body parses as a MESSAGE command;
	// the box is opened, the inner flags byte is split out, and a
	// wire.Frame is returned whose Kind is FrameMessage, More is
	// recovered from the inner flags byte (bit 0), and Body is the
	// decrypted payload.
	//
	// For pass-through mechanisms (NULL, PLAIN), the returned Frame
	// aliases f. For mechanisms that perform encapsulation (CURVE), the
	// returned Frame's Body is freshly allocated and independent of f.
	// In all cases the State retains no reference to f. Unwrap consumes
	// f synchronously: it MUST read whatever it needs from f.Body before
	// returning and MUST NOT retain or mutate any reference to f. The
	// caller is therefore free to reuse, mutate, or release f.Body the
	// instant Unwrap returns; the only constraint is that the caller
	// must not mutate f.Body while the returned Frame is still in use.
	Unwrap(f wire.Frame) (wire.Frame, error)

	// Done reports whether the handshake completed successfully.
	Done() bool

	// PeerMetadata returns the metadata advertised by the peer in its
	// handshake. Valid only after Done(). The returned slice is owned
	// by the Mechanism and remains valid until the Mechanism is
	// discarded; callers MUST NOT mutate it.
	PeerMetadata() wire.Metadata

	// Name returns the wire mechanism name advertised in the ZMTP
	// greeting — one of "NULL", "PLAIN", "CURVE". Stable for the
	// lifetime of the Mechanism. Used by F4 (connection layer) to
	// populate the greeting's mechanism field and to validate the
	// peer-advertised mechanism matches.
	Name() string
}

// ClientMechanism is a Mechanism with an active-side initialization
// step. Implemented by null.State, plain.ClientState, and
// curve.ClientState. Server-side states (plain.ServerState,
// curve.ServerState) implement only Mechanism.
//
// F4 obtains a Mechanism / ClientMechanism by calling the per-package
// constructor; the active side calls Start() exactly once before
// entering the Receive loop.
type ClientMechanism interface {
	Mechanism
	Start() (wire.Command, error)
}

// ZAPCaller is satisfied by *zap.Client. Server-side mechanisms receive it
// via ConfigureZAP and call it during the authentication step of the handshake.
type ZAPCaller interface {
	// Authenticate sends a ZAP request and returns (statusCode, userID, metadata, err).
	// Only statusCode "200" indicates acceptance; all other codes ("300", "400", "500")
	// are treated as denial. err is non-nil only for transport/handler errors, not for
	// auth failures — auth failures are expressed via statusCode.
	Authenticate(domain, address, identity, mechanism string, credentials [][]byte) (statusCode, userID string, metadata wire.Metadata, err error)
}

// ZAPConfigurer is implemented by server-side mechanisms that support ZAP.
// base.go calls ConfigureZAP immediately after mechanism creation when the
// socket was configured with WithZAPDomain.
type ZAPConfigurer interface {
	ConfigureZAP(caller ZAPCaller, domain string)
}

// PeerAddrSetter is implemented by server-side mechanisms to receive the
// peer's network address before the handshake begins. base.go always calls
// SetPeerAddr on accepted connections.
type PeerAddrSetter interface {
	SetPeerAddr(addr string)
}
