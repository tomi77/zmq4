package curve

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/seccommon"
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

// Receive consumes one peer command and advances the state machine.
func (c *ClientState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error) {
	switch {
	case c.closed:
		return nil, false, security.ErrClosed
	case c.failed:
		return nil, false, ErrAlreadyFailed
	case !c.started:
		c.failed = true
		return nil, false, ErrNotStarted
	case c.done:
		c.failed = true
		return nil, false, ErrAlreadyDone
	}

	if !c.welcomeReceived {
		switch cmd.Name {
		case welcomeCommandName:
			return c.handleWelcome(cmd)
		case wire.ErrorCommandName:
			return nil, false, c.failPeerError(cmd)
		}
		c.failed = true
		return nil, false, fmt.Errorf("%w: %q (expected WELCOME)", ErrUnexpectedCommand, cmd.Name)
	}

	// AWAIT_READY.
	switch cmd.Name {
	case readyCommandName:
		return c.handleReady(cmd)
	case wire.ErrorCommandName:
		return nil, false, c.failPeerError(cmd)
	}
	c.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected READY)", ErrUnexpectedCommand, cmd.Name)
}

func (c *ClientState) handleReady(cmd wire.Command) (*wire.Command, bool, error) {
	md, perr := parseReady(cmd, c.afterReady)
	if perr != nil {
		c.failed = true
		return nil, false, perr
	}
	c.peer = seccommon.CloneMetadata(md)
	c.done = true
	return nil, true, nil
}

// PeerMetadata returns the metadata the server advertised in READY.
// Valid only after Done(). Aliases an internal buffer; callers MUST
// NOT mutate it.
func (c *ClientState) PeerMetadata() wire.Metadata { return c.peer }

// PeerPublicKey returns the server's long-term public key (== ServerKey
// from ClientOptions). Provided for symmetry with ServerState.
func (c *ClientState) PeerPublicKey() PublicKey { return c.serverPub }

func (c *ClientState) handleWelcome(cmd wire.Command) (*wire.Command, bool, error) {
	serverTransPub, ck, perr := parseWelcome(cmd, c.handshakeShared)
	if perr != nil {
		c.failed = true
		return nil, false, perr
	}
	c.afterReady = precompute(serverTransPub, &c.transSec) // c' × S'

	v, vErr := encodeVouch(c.transPub, c.serverPub, c.vouchShared, c.rand)
	if vErr != nil {
		c.failed = true
		return nil, false, fmt.Errorf("curve: encode vouch: %w", vErr)
	}
	// vouchShared is no longer needed; zero immediately so a later bug
	// cannot re-derive the long-term × long-term key.
	c.vouchShared.Zero()
	c.vouchShared = nil

	initiate, iErr := encodeInitiate(ck, v, c.ourLongPub, c.local, c.afterReady, c.initiateNonce, c.rand)
	if iErr != nil {
		c.failed = true
		return nil, false, fmt.Errorf("curve: encode INITIATE: %w", iErr)
	}
	c.initiateNonce++
	c.welcomeReceived = true
	return &initiate, false, nil
}

// failPeerError marks the state failed and wraps the peer's ERROR
// reason. Reason bytes are returned as-received; callers SHOULD treat
// them as untrusted.
func (c *ClientState) failPeerError(cmd wire.Command) error {
	c.failed = true
	ec, perr := wire.ParseError(cmd)
	if perr != nil {
		return fmt.Errorf("%w: malformed ERROR: %v", ErrPeerError, perr)
	}
	return fmt.Errorf("%w: %s", ErrPeerError, ec.Reason)
}

// Wrap encapsulates an outgoing frame as MESSAGE. See
// security.Mechanism.Wrap. Each call advances the send-nonce counter.
// Returns ErrNonceExhausted if the counter would wrap past 2^64-1.
func (c *ClientState) Wrap(f wire.Frame) (wire.Frame, error) {
	switch {
	case c.closed:
		return wire.Frame{}, security.ErrClosed
	case !c.Done():
		return wire.Frame{}, security.ErrNotDone
	}
	if c.sendNonce == ^uint64(0) {
		return wire.Frame{}, ErrNonceExhausted
	}
	flags := byte(0)
	if f.More {
		flags = 0x01
	}
	cmd, err := encodeMessage(flags, f.Body, c.afterReady, messageClientPrefix, c.sendNonce)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("curve: encode MESSAGE: %w", err)
	}
	c.sendNonce++

	body, err := wire.EncodeCommand(cmd)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("curve: encode command: %w", err)
	}
	return wire.Frame{Kind: wire.FrameCommand, More: false, Body: body}, nil
}

// Unwrap decrypts an incoming MESSAGE. Each successful call advances
// recvNonce and rejects strictly-non-monotonic nonces with
// ErrNonceReused.
func (c *ClientState) Unwrap(f wire.Frame) (wire.Frame, error) {
	switch {
	case c.closed:
		return wire.Frame{}, security.ErrClosed
	case !c.Done():
		return wire.Frame{}, security.ErrNotDone
	}
	if f.Kind != wire.FrameCommand {
		return wire.Frame{}, fmt.Errorf("%w: kind %v", ErrMalformedMessage, f.Kind)
	}
	cmd, perr := wire.ParseCommand(f.Body)
	if perr != nil {
		return wire.Frame{}, fmt.Errorf("%w: %v", ErrMalformedMessage, perr)
	}
	flags, payload, nonce, perr := parseMessage(cmd, c.afterReady, messageServerPrefix)
	if perr != nil {
		return wire.Frame{}, perr
	}
	if nonce <= c.recvNonce {
		return wire.Frame{}, fmt.Errorf("%w: incoming=%d last=%d", ErrNonceReused, nonce, c.recvNonce)
	}
	c.recvNonce = nonce
	return wire.Frame{Kind: wire.FrameMessage, More: flags&0x01 == 0x01, Body: payload}, nil
}

// Close zeros the transient secret and any retained shared keys.
// Idempotent. After Close, every method returns security.ErrClosed.
// Long-term keys passed in via ClientOptions are NOT zeroed — the
// caller owns that lifetime.
func (c *ClientState) Close() {
	if c.closed {
		return
	}
	c.closed = true
	c.transSec.Zero()
	if c.handshakeShared != nil {
		c.handshakeShared.Zero()
	}
	if c.afterReady != nil {
		c.afterReady.Zero()
	}
	if c.vouchShared != nil {
		c.vouchShared.Zero()
	}
}
