package curve

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/wire"
)

// ClientOptions configures a CURVE ClientState.
type ClientOptions struct {
	// ServerKey is the server's long-term public key. Required.
	ServerKey PublicKey

	// OurPublicKey is this client's long-term public key. Required.
	OurPublicKey PublicKey

	// OurSecretKey is this client's long-term secret key. Required.
	// Referenced (not copied); the caller owns its lifetime. ClientState
	// does NOT zero OurSecretKey on Close — the caller decides when the
	// long-term secret is no longer needed.
	OurSecretKey *SecretKey

	// LocalMetadata is sent in INITIATE. Referenced, not copied; same
	// lifetime rules as plain.NewClient.
	LocalMetadata wire.Metadata

	// Rand supplies entropy for the transient keypair, vouch nonce, and
	// MESSAGE nonce randomization. Pass nil to use crypto/rand.Reader.
	// Tests may inject a deterministic source for byte-exact vector
	// tests.
	Rand io.Reader
}

// ClientState drives the client side of a CURVE handshake and traffic
// encapsulation. Single-shot; not safe for concurrent use.
type ClientState struct {
	// Long-term identity (caller-owned ourLongSec).
	serverPub  PublicKey
	ourLongPub PublicKey
	ourLongSec *SecretKey

	// Transient identity (owned by ClientState; zeroed on Close).
	transPub PublicKey
	transSec SecretKey

	// Precomputed shared keys.
	handshakeShared *SharedKey // c' × S
	afterReady      *SharedKey // c' × S' (filled in Receive(WELCOME))
	vouchShared     *SharedKey // c × S; zeroed after vouch is sealed

	// Local & peer metadata.
	local wire.Metadata
	peer  wire.Metadata

	// Nonce counters.
	sendNonce     uint64
	recvNonce     uint64
	helloNonce    uint64
	initiateNonce uint64

	// Lifecycle.
	started, welcomeReceived, done, failed, closed bool

	rand io.Reader
}

// NewClient constructs a CURVE ClientState. Errors:
//
//	ErrInvalidOptions  — zero ServerKey/OurPublicKey, nil OurSecretKey.
//
// Key generation and precomputation happen in Start, not here.
// crypto/rand.Reader is used if opts.Rand is nil.
func NewClient(opts ClientOptions) (*ClientState, error) {
	if opts.ServerKey == (PublicKey{}) {
		return nil, fmt.Errorf("%w: zero ServerKey", ErrInvalidOptions)
	}
	if opts.OurPublicKey == (PublicKey{}) {
		return nil, fmt.Errorf("%w: zero OurPublicKey", ErrInvalidOptions)
	}
	if opts.OurSecretKey == nil {
		return nil, fmt.Errorf("%w: nil OurSecretKey", ErrInvalidOptions)
	}
	rng := opts.Rand
	if rng == nil {
		rng = rand.Reader
	}
	return &ClientState{
		serverPub:     opts.ServerKey,
		ourLongPub:    opts.OurPublicKey,
		ourLongSec:    opts.OurSecretKey,
		local:         opts.LocalMetadata,
		helloNonce:    1,
		initiateNonce: 1,
		sendNonce:     1,
		rand:          rng,
	}, nil
}

// Done reports whether the handshake completed successfully.
func (c *ClientState) Done() bool { return c.done && !c.failed && !c.closed }

// Start generates the transient keypair, precomputes handshakeShared
// and vouchShared, emits HELLO, and transitions to AWAIT_WELCOME. Must
// be called exactly once before Receive.
func (c *ClientState) Start() (wire.Command, error) {
	switch {
	case c.closed:
		return wire.Command{}, security.ErrClosed
	case c.failed:
		return wire.Command{}, ErrAlreadyFailed
	case c.started:
		return wire.Command{}, ErrAlreadyStarted
	}

	transPubArr, transSecArr, err := box.GenerateKey(c.rand)
	if err != nil {
		c.failed = true
		return wire.Command{}, fmt.Errorf("%w: transient keypair: %v", ErrCryptoRand, err)
	}
	copy(c.transPub[:], transPubArr[:])
	copy(c.transSec[:], transSecArr[:])

	c.handshakeShared = precompute(c.serverPub, &c.transSec) // c' × S
	c.vouchShared = precompute(c.serverPub, c.ourLongSec)    // c × S — long-term secret touched ONCE here.

	hello, err := encodeHello(c.transPub, c.handshakeShared, c.helloNonce, c.rand)
	if err != nil {
		c.failed = true
		return wire.Command{}, fmt.Errorf("curve: encode HELLO: %w", err)
	}
	c.helloNonce++
	c.started = true
	return hello, nil
}
