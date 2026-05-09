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

	// ZAP — set by ConfigureZAP; only used on the server side.
	zap      security.ZAPCaller
	domain   string
	peerAddr string
	zapMeta  wire.Metadata
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

// ConfigureZAP injects a ZAP client and domain. Satisfies security.ZAPConfigurer.
func (s *ServerState) ConfigureZAP(caller security.ZAPCaller, domain string) {
	s.zap = caller
	s.domain = domain
}

// SetPeerAddr stores the peer's network address for ZAP requests.
// Satisfies security.PeerAddrSetter.
func (s *ServerState) SetPeerAddr(addr string) { s.peerAddr = addr }

// Done reports whether the handshake completed successfully.
func (s *ServerState) Done() bool { return s.done && !s.failed && !s.closed }

// Name returns "CURVE". See security.Mechanism.Name.
func (s *ServerState) Name() string { return "CURVE" }

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

	// AWAIT_INITIATE.
	switch cmd.Name {
	case initiateCommandName:
		return s.handleInitiate(cmd)
	case wire.ErrorCommandName:
		return nil, false, s.failPeerError(cmd)
	}
	s.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected INITIATE)", ErrUnexpectedCommand, cmd.Name)
}

func (s *ServerState) handleInitiate(cmd wire.Command) (*wire.Command, bool, error) {
	ck, v, peerLongPub, md, perr := parseInitiate(cmd, s.afterReady)
	if perr != nil {
		s.failed = true
		return nil, false, perr
	}
	// Open cookie under cookieKey. The inner (C', s') MUST match the
	// values we recorded in handleHello.
	ckC1, ckSPrimeSec, cErr := openCookie(ck, &s.cookieKey)
	if cErr != nil {
		s.failed = true
		return nil, false, cErr
	}
	if ckC1 != s.peerTransPub {
		s.failed = true
		return nil, false, fmt.Errorf("%w: cookie C' mismatch", ErrCookieMismatch)
	}
	if ckSPrimeSec != s.transSec {
		s.failed = true
		return nil, false, fmt.Errorf("%w: cookie s' mismatch", ErrCookieMismatch)
	}
	// Open vouch under (clientLongPub × ourLongSec) and verify the
	// inner (C' || S) matches our recorded values.
	vC1, vS, vErr := openVouch(v, peerLongPub, s.ourLongSec)
	if vErr != nil {
		s.failed = true
		return nil, false, vErr
	}
	if vC1 != s.peerTransPub {
		s.failed = true
		return nil, false, fmt.Errorf("%w: vouch C'", ErrBoxOpen)
	}
	if vS != s.ourLongPub {
		s.failed = true
		return nil, false, fmt.Errorf("%w: vouch S", ErrBoxOpen)
	}

	// Defensive copy of metadata before passing to Authorizer.
	clonedMd := seccommon.CloneMetadata(md)

	if s.zap != nil {
		code, _, zapMeta, zapErr := s.zap.Authenticate(
			s.domain, s.peerAddr, "",
			"CURVE", [][]byte{peerLongPub[:]},
		)
		if zapErr != nil || code != "200" {
			return s.failZAPDenied(code)
		}
		s.zapMeta = zapMeta
	} else if authErr := s.authorizer(peerLongPub, clonedMd); authErr != nil {
		return s.failAuthRejected(authErr)
	}

	s.peerLongPub = peerLongPub
	s.peer = clonedMd

	ready, rErr := encodeReady(s.local, s.afterReady, s.readyNonce, s.rand)
	if rErr != nil {
		s.failed = true
		return nil, false, fmt.Errorf("curve: encode READY: %w", rErr)
	}
	s.readyNonce++
	s.done = true
	return &ready, true, nil
}

func (s *ServerState) failAuthRejected(authErr error) (*wire.Command, bool, error) {
	s.failed = true
	reason := seccommon.SanitizeReason(authErr.Error())
	errCmd, encErr := wire.ErrorCommand{Reason: reason}.Encode()
	if encErr != nil {
		return nil, false, fmt.Errorf("curve: encode ERROR: %w", encErr)
	}
	return &errCmd, false, fmt.Errorf("%w: %s", ErrAuthRejected, reason)
}

func (s *ServerState) failZAPDenied(statusCode string) (*wire.Command, bool, error) {
	s.failed = true
	reason := seccommon.SanitizeReason("ZAP " + statusCode)
	errCmd, encErr := wire.ErrorCommand{Reason: reason}.Encode()
	if encErr != nil {
		return nil, false, fmt.Errorf("curve: encode ERROR: %w", encErr)
	}
	return &errCmd, false, fmt.Errorf("%w: status %s", security.ErrZAPDenied, statusCode)
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

// PeerMetadata returns the peer's READY metadata merged with any ZAP reply
// metadata. Valid only after Receive returned done=true.
// The returned slice is owned by the State; callers MUST NOT mutate it.
func (s *ServerState) PeerMetadata() wire.Metadata {
	if len(s.zapMeta) == 0 {
		return s.peer
	}
	merged := seccommon.CloneMetadata(s.peer)
	return append(merged, s.zapMeta...)
}

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
