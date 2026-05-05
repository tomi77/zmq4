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

// Authorizer decides whether a client's long-term public key is allowed
// to connect. See docs/specs/02c-security-curve.md §4.4 for the full
// contract.
type Authorizer func(clientPublicKey PublicKey, peerMetadata wire.Metadata) error

// ServerOptions configures a CURVE ServerState.
type ServerOptions struct {
	OurPublicKey  PublicKey
	OurSecretKey  *SecretKey // referenced; caller owns lifetime
	LocalMetadata wire.Metadata

	// Authorizer is required; NewServer panics if nil.
	Authorizer Authorizer

	// Rand supplies entropy for the transient keypair, cookie key,
	// cookie nonce, welcome nonce, ready nonce, and MESSAGE nonces.
	// Pass nil for crypto/rand.Reader.
	Rand io.Reader
}

// ServerState drives the server side of a CURVE handshake and traffic
// encapsulation. Single-shot; not safe for concurrent use.
type ServerState struct {
	ourLongPub PublicKey
	ourLongSec *SecretKey

	transPub PublicKey
	transSec SecretKey

	cookieKey SecretKey

	authorizer Authorizer

	handshakeShared *SharedKey // s × C'
	afterReady      *SharedKey // s' × C'

	peerLongPub  PublicKey
	peerTransPub PublicKey

	local wire.Metadata
	peer  wire.Metadata

	sendNonce  uint64
	recvNonce  uint64
	readyNonce uint64

	helloProcessed, done, failed, closed bool

	rand io.Reader
}

// NewServer constructs a CURVE ServerState. Panics if opts.Authorizer
// is nil. Returns ErrInvalidOptions for zero OurPublicKey / nil
// OurSecretKey, ErrCryptoRand for entropy failures (transient keypair
// + cookie key generation happen here).
func NewServer(opts ServerOptions) (*ServerState, error) {
	if opts.Authorizer == nil {
		panic("curve: NewServer requires a non-nil Authorizer")
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
	transPubArr, transSecArr, err := box.GenerateKey(rng)
	if err != nil {
		return nil, fmt.Errorf("%w: transient keypair: %v", ErrCryptoRand, err)
	}
	var transPub PublicKey
	var transSec SecretKey
	copy(transPub[:], transPubArr[:])
	copy(transSec[:], transSecArr[:])

	var cookieKey SecretKey
	if _, err := io.ReadFull(rng, cookieKey[:]); err != nil {
		return nil, fmt.Errorf("%w: cookie key: %v", ErrCryptoRand, err)
	}

	return &ServerState{
		ourLongPub: opts.OurPublicKey,
		ourLongSec: opts.OurSecretKey,
		transPub:   transPub,
		transSec:   transSec,
		cookieKey:  cookieKey,
		authorizer: opts.Authorizer,
		local:      opts.LocalMetadata,
		readyNonce: 1,
		sendNonce:  1,
		rand:       rng,
	}, nil
}

// Done reports whether the handshake completed successfully.
func (s *ServerState) Done() bool { return s.done && !s.failed && !s.closed }

// Receive consumes one peer command and advances the state machine.
// Server has no Start — it is purely reactive (HELLO arrives first).
func (s *ServerState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error) {
	switch {
	case s.closed:
		return nil, false, security.ErrClosed
	case s.failed:
		return nil, false, ErrAlreadyFailed
	case s.done:
		s.failed = true
		return nil, false, ErrAlreadyDone
	}

	if !s.helloProcessed {
		switch cmd.Name {
		case helloCommandName:
			return s.handleHello(cmd)
		case wire.ErrorCommandName:
			return nil, false, s.failPeerError(cmd)
		}
		s.failed = true
		return nil, false, fmt.Errorf("%w: %q (expected HELLO)", ErrUnexpectedCommand, cmd.Name)
	}

	// AWAIT_INITIATE — fleshed out in Task 19/20.
	s.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected INITIATE)", ErrUnexpectedCommand, cmd.Name)
}

func (s *ServerState) handleHello(cmd wire.Command) (*wire.Command, bool, error) {
	// HELLO is sealed under c'×S = box(serverLongSec, peerTransPub). The
	// server can only compute the shared key after it reads peerTransPub
	// from the cleartext part of HELLO — so we extract C' first, then
	// precompute s×C', then call parseHello to verify the box.
	if len(cmd.Data) != helloBodyLen {
		s.failed = true
		return nil, false, fmt.Errorf("%w: body size %d, want %d", ErrMalformedHello, len(cmd.Data), helloBodyLen)
	}
	var peerTransPub PublicKey
	copy(peerTransPub[:], cmd.Data[2+72:2+72+32])

	openShared := precompute(peerTransPub, s.ourLongSec) // s × C'
	if _, perr := parseHello(cmd, openShared); perr != nil {
		s.failed = true
		return nil, false, perr
	}
	s.peerTransPub = peerTransPub
	s.handshakeShared = openShared
	s.afterReady = precompute(peerTransPub, &s.transSec) // s' × C'

	// Seal cookie binding (C' || s') under cookieKey.
	ck, cErr := sealCookie(peerTransPub, s.transSec, &s.cookieKey, s.rand)
	if cErr != nil {
		s.failed = true
		return nil, false, fmt.Errorf("curve: seal cookie: %w", cErr)
	}
	welcome, wErr := encodeWelcome(s.transPub, ck, s.handshakeShared, s.rand)
	if wErr != nil {
		s.failed = true
		return nil, false, fmt.Errorf("curve: encode WELCOME: %w", wErr)
	}
	s.helloProcessed = true
	return &welcome, false, nil
}

// failPeerError mirrors ClientState.failPeerError.
func (s *ServerState) failPeerError(cmd wire.Command) error {
	s.failed = true
	ec, perr := wire.ParseError(cmd)
	if perr != nil {
		return fmt.Errorf("%w: malformed ERROR: %v", ErrPeerError, perr)
	}
	return fmt.Errorf("%w: %s", ErrPeerError, ec.Reason)
}

// PeerPublicKey returns the client's long-term public key (the value
// passed to the Authorizer). Valid only after Done().
func (s *ServerState) PeerPublicKey() PublicKey { return s.peerLongPub }

// PeerMetadata returns the metadata the client sent in INITIATE. Valid
// only after Done().
func (s *ServerState) PeerMetadata() wire.Metadata { return s.peer }

// Wrap encapsulates an outgoing frame as MESSAGE under
// messageServerPrefix. See ClientState.Wrap for the contract.
func (s *ServerState) Wrap(f wire.Frame) (wire.Frame, error) {
	switch {
	case s.closed:
		return wire.Frame{}, security.ErrClosed
	case !s.Done():
		return wire.Frame{}, security.ErrNotDone
	}
	if s.sendNonce == ^uint64(0) {
		return wire.Frame{}, ErrNonceExhausted
	}
	flags := byte(0)
	if f.More {
		flags = 0x01
	}
	cmd, err := encodeMessage(flags, f.Body, s.afterReady, messageServerPrefix, s.sendNonce)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("curve: encode MESSAGE: %w", err)
	}
	s.sendNonce++
	body, err := wire.EncodeCommand(cmd)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("curve: encode command: %w", err)
	}
	return wire.Frame{Kind: wire.FrameCommand, More: false, Body: body}, nil
}

// Unwrap inverts Wrap, opening peer MESSAGE under messageClientPrefix.
func (s *ServerState) Unwrap(f wire.Frame) (wire.Frame, error) {
	switch {
	case s.closed:
		return wire.Frame{}, security.ErrClosed
	case !s.Done():
		return wire.Frame{}, security.ErrNotDone
	}
	if f.Kind != wire.FrameCommand {
		return wire.Frame{}, fmt.Errorf("%w: kind %v", ErrMalformedMessage, f.Kind)
	}
	cmd, perr := wire.ParseCommand(f.Body)
	if perr != nil {
		return wire.Frame{}, fmt.Errorf("%w: %v", ErrMalformedMessage, perr)
	}
	flags, payload, nonce, perr := parseMessage(cmd, s.afterReady, messageClientPrefix)
	if perr != nil {
		return wire.Frame{}, perr
	}
	if nonce <= s.recvNonce {
		return wire.Frame{}, fmt.Errorf("%w: incoming=%d last=%d", ErrNonceReused, nonce, s.recvNonce)
	}
	s.recvNonce = nonce
	return wire.Frame{Kind: wire.FrameMessage, More: flags&0x01 == 0x01, Body: payload}, nil
}

// Close zeros transient secret + handshakeShared + afterReady +
// cookieKey. Idempotent; long-term secret is NOT zeroed.
func (s *ServerState) Close() {
	if s.closed {
		return
	}
	s.closed = true
	s.transSec.Zero()
	s.cookieKey.Zero()
	if s.handshakeShared != nil {
		s.handshakeShared.Zero()
	}
	if s.afterReady != nil {
		s.afterReady.Zero()
	}
}

// Compile-time assertion: ServerState implements security.Mechanism.
// (ClientState also implements security.ClientMechanism — that
// assertion lives in interfaces_conformance_test.go to avoid a cycle.)
var _ security.Mechanism = (*ServerState)(nil)

// Workaround for the unused-import warning if seccommon is not yet
// referenced in this file. Removed when handleInitiate (Task 19) lands.
var _ = seccommon.CloneMetadata
