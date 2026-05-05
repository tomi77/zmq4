package curve

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/tomi77/zmq4/internal/wire"
)

const (
	helloCommandName    = "HELLO"
	welcomeCommandName  = "WELCOME"
	initiateCommandName = "INITIATE"
	readyCommandName    = "READY"
	messageCommandName  = "MESSAGE"
	// errorCommandName is shared with NULL/PLAIN; we reference
	// wire.ErrorCommandName directly rather than redeclare it.
)

// Nonce prefixes (RFC 26 §3). Two shapes:
//
//   - Short-nonce prefixes are 16 B; on the wire the full 24-byte NaCl
//     nonce is prefix||short-nonce(8 B big-endian counter).
//   - Long-nonce prefixes are 8 B; on the wire the full 24-byte NaCl
//     nonce is prefix||long-nonce(16 B random).
//
// Trailing letter on MESSAGE prefixes encodes the SENDER role: "C" for
// client-sent, "S" for server-sent (per RFC 26 §6).
var (
	helloNoncePrefix    = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'H', 'E', 'L', 'L', 'O', '-', '-', '-'}
	welcomeNoncePrefix  = [8]byte{'W', 'E', 'L', 'C', 'O', 'M', 'E', '-'}
	cookieNoncePrefix   = [8]byte{'C', 'O', 'O', 'K', 'I', 'E', '-', '-'}
	vouchNoncePrefix    = [8]byte{'V', 'O', 'U', 'C', 'H', '-', '-', '-'}
	initiateNoncePrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'I', 'N', 'I', 'T', 'I', 'A', 'T', 'E'}
	readyNoncePrefix    = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'R', 'E', 'A', 'D', 'Y', '-', '-', '-'}
	messageClientPrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'M', 'E', 'S', 'S', 'A', 'G', 'E', 'C'}
	messageServerPrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'M', 'E', 'S', 'S', 'A', 'G', 'E', 'S'}
)

// HELLO wire layout (RFC 26 §5.2):
//
//	%x01 %x00 (version major=1 minor=0)         2 B
//	72 zero bytes (padding)                     72 B
//	C' (client transient public)                32 B
//	hello-nonce                                  8 B
//	hello-box (NaCl box of 64 zero bytes)       80 B  (= 64+16 overhead)
//
// Total body: 194 B.
const helloBodyLen = 2 + 72 + 32 + 8 + 80

// encodeHello builds a HELLO command. clientTransPub is the client's
// fresh transient public key (C'). sharedKey is precompute(serverLongPub,
// clientTransSec) = c' × S. nonce is the per-handshake short-nonce
// counter (starts at 1, monotonically increasing). rand is currently
// unused by encodeHello (the wire format only requires a counter
// short-nonce here) but accepted for symmetry with other encoders that
// emit long-nonces — pass nil if you do not have one. Returns the
// fully-formed wire.Command ready for the caller to send.
func encodeHello(clientTransPub PublicKey, sharedKey *SharedKey, nonce uint64, rand io.Reader) (wire.Command, error) {
	_ = rand // unused; reserved for symmetry with long-nonce encoders.

	data := make([]byte, helloBodyLen)
	data[0] = 0x01 // version major
	data[1] = 0x00 // version minor
	// 72-byte padding stays zero by virtue of make().
	copy(data[2+72:2+72+32], clientTransPub[:])

	binary.BigEndian.PutUint64(data[2+72+32:2+72+32+8], nonce)

	var nacl [24]byte
	copy(nacl[:16], helloNoncePrefix[:])
	binary.BigEndian.PutUint64(nacl[16:], nonce)

	// hello-box content is 64 zero bytes (the "signature" payload).
	var zeros [64]byte
	out := box.SealAfterPrecomputation(nil, zeros[:], &nacl, (*[32]byte)(sharedKey))
	if len(out) != 80 {
		return wire.Command{}, fmt.Errorf("curve: internal: hello-box len=%d want 80", len(out))
	}
	copy(data[2+72+32+8:], out)

	return wire.Command{Name: helloCommandName, Data: data}, nil
}

// parseHello opens a peer HELLO and returns the client's transient
// public key. sharedKey must be precompute(clientTransPub, serverLongSec)
// = s × C' for the server side (note: NaCl box DH is symmetric in the
// pair, so c'×S and s×C' yield the same bytes — but the server, which
// does not yet know C', cannot use this until after parsing C' from
// the cleartext part of HELLO; sharedKey should therefore be computed
// AFTER C' is read out of the body).
func parseHello(cmd wire.Command, sharedKey *SharedKey) (PublicKey, error) {
	if cmd.Name != helloCommandName {
		return PublicKey{}, fmt.Errorf("%w: command name %q", ErrMalformedHello, cmd.Name)
	}
	if len(cmd.Data) != helloBodyLen {
		return PublicKey{}, fmt.Errorf("%w: body size %d, want %d", ErrMalformedHello, len(cmd.Data), helloBodyLen)
	}
	if cmd.Data[0] != 0x01 || cmd.Data[1] != 0x00 {
		return PublicKey{}, fmt.Errorf("%w: bad version %x %x", ErrMalformedHello, cmd.Data[0], cmd.Data[1])
	}
	for i := 0; i < 72; i++ {
		if cmd.Data[2+i] != 0 {
			return PublicKey{}, fmt.Errorf("%w: non-zero padding at byte %d", ErrMalformedHello, 2+i)
		}
	}
	var clientTransPub PublicKey
	copy(clientTransPub[:], cmd.Data[2+72:2+72+32])

	var nacl [24]byte
	copy(nacl[:16], helloNoncePrefix[:])
	copy(nacl[16:], cmd.Data[2+72+32:2+72+32+8])

	box64 := cmd.Data[2+72+32+8:]
	if _, ok := box.OpenAfterPrecomputation(nil, box64, &nacl, (*[32]byte)(sharedKey)); !ok {
		return PublicKey{}, fmt.Errorf("%w: hello-box", ErrBoxOpen)
	}
	return clientTransPub, nil
}

// WELCOME wire layout (RFC 26 §5.3):
//
//	welcome-nonce        16 B (random long-nonce)
//	welcome-box         144 B (= 32 + 96 + 16 overhead)
//	  plaintext: S' (32) || cookie (96)
//
// Total body: 160 B.
const welcomeBodyLen = 16 + 144

// Cookie wire layout (RFC 26 §5):
//
//	cookie-nonce         16 B (random long-nonce)
//	secretbox            80 B (= 64 + 16 overhead)
//	  plaintext: C' (32) || s' (32)
//
// Total cookie: 96 B.
type cookie [96]byte

// sealCookie produces an opaque 96-byte cookie that the client echoes
// back inside INITIATE. The cookie binds (C', s') to the per-handshake
// cookieKey so the server need not retain handshake state between
// WELCOME and INITIATE.
func sealCookie(clientTransPub PublicKey, serverTransSec SecretKey, cookieKey *SecretKey, rng io.Reader) (cookie, error) {
	if rng == nil {
		rng = rand.Reader
	}
	var c cookie
	if _, err := io.ReadFull(rng, c[:16]); err != nil {
		return cookie{}, fmt.Errorf("%w: %v", ErrCryptoRand, err)
	}
	var nacl [24]byte
	copy(nacl[:8], cookieNoncePrefix[:])
	copy(nacl[8:], c[:16])

	var plaintext [64]byte
	copy(plaintext[:32], clientTransPub[:])
	copy(plaintext[32:], serverTransSec[:])

	out := secretbox.Seal(nil, plaintext[:], &nacl, (*[32]byte)(cookieKey))
	if len(out) != 80 {
		return cookie{}, fmt.Errorf("curve: internal: cookie box len=%d want 80", len(out))
	}
	copy(c[16:], out)
	return c, nil
}

// openCookie inverts sealCookie. Returns ErrBoxOpen if the secretbox
// auth tag does not verify (wrong key, tampered ciphertext).
func openCookie(c cookie, cookieKey *SecretKey) (PublicKey, SecretKey, error) {
	var nacl [24]byte
	copy(nacl[:8], cookieNoncePrefix[:])
	copy(nacl[8:], c[:16])

	plain, ok := secretbox.Open(nil, c[16:], &nacl, (*[32]byte)(cookieKey))
	if !ok {
		return PublicKey{}, SecretKey{}, fmt.Errorf("%w: cookie", ErrBoxOpen)
	}
	if len(plain) != 64 {
		return PublicKey{}, SecretKey{}, fmt.Errorf("curve: internal: cookie plaintext len=%d want 64", len(plain))
	}
	var pub PublicKey
	var sec SecretKey
	copy(pub[:], plain[:32])
	copy(sec[:], plain[32:])
	return pub, sec, nil
}

// encodeWelcome builds a WELCOME command. sharedKey is
// precompute(clientTransPub, serverLongSec) = s × C'.
func encodeWelcome(serverTransPub PublicKey, ck cookie, sharedKey *SharedKey, rng io.Reader) (wire.Command, error) {
	if rng == nil {
		rng = rand.Reader
	}
	data := make([]byte, welcomeBodyLen)
	if _, err := io.ReadFull(rng, data[:16]); err != nil {
		return wire.Command{}, fmt.Errorf("%w: %v", ErrCryptoRand, err)
	}

	var nacl [24]byte
	copy(nacl[:8], welcomeNoncePrefix[:])
	copy(nacl[8:], data[:16])

	var plaintext [128]byte
	copy(plaintext[:32], serverTransPub[:])
	copy(plaintext[32:], ck[:])

	out := box.SealAfterPrecomputation(nil, plaintext[:], &nacl, (*[32]byte)(sharedKey))
	if len(out) != 144 {
		return wire.Command{}, fmt.Errorf("curve: internal: welcome-box len=%d want 144", len(out))
	}
	copy(data[16:], out)

	return wire.Command{Name: welcomeCommandName, Data: data}, nil
}

// parseWelcome inverts encodeWelcome. sharedKey is
// precompute(serverLongPub, clientTransSec) = c' × S.
func parseWelcome(cmd wire.Command, sharedKey *SharedKey) (PublicKey, cookie, error) {
	if cmd.Name != welcomeCommandName {
		return PublicKey{}, cookie{}, fmt.Errorf("%w: command name %q", ErrMalformedWelcome, cmd.Name)
	}
	if len(cmd.Data) != welcomeBodyLen {
		return PublicKey{}, cookie{}, fmt.Errorf("%w: body size %d, want %d", ErrMalformedWelcome, len(cmd.Data), welcomeBodyLen)
	}
	var nacl [24]byte
	copy(nacl[:8], welcomeNoncePrefix[:])
	copy(nacl[8:], cmd.Data[:16])

	plain, ok := box.OpenAfterPrecomputation(nil, cmd.Data[16:], &nacl, (*[32]byte)(sharedKey))
	if !ok {
		return PublicKey{}, cookie{}, fmt.Errorf("%w: welcome", ErrBoxOpen)
	}
	if len(plain) != 128 {
		return PublicKey{}, cookie{}, fmt.Errorf("%w: welcome plaintext len=%d", ErrMalformedWelcome, len(plain))
	}
	var serverTransPub PublicKey
	copy(serverTransPub[:], plain[:32])
	var ck cookie
	copy(ck[:], plain[32:])
	return serverTransPub, ck, nil
}

// vouch is the 96-byte authenticator embedded inside INITIATE.
type vouch [96]byte

// encodeVouch builds the vouch box that goes inside INITIATE.
// vouchShared is precompute(serverLongPub, clientLongSec) = c × S — the
// long-term × long-term shared key. ClientState.Start computes this
// eagerly so the long-term secret is touched once at construction;
// vouchShared is then zeroed by ClientState.Receive(WELCOME) right
// after this function returns.
//
// serverLongPub is passed alongside vouchShared because it is part of
// the box plaintext (vouch authenticates the bond between C' and S).
// rng supplies the 16-byte long-nonce; pass nil for crypto/rand.Reader.
func encodeVouch(clientTransPub, serverLongPub PublicKey, vouchShared *SharedKey, rng io.Reader) (vouch, error) {
	if rng == nil {
		rng = rand.Reader
	}
	var v vouch
	if _, err := io.ReadFull(rng, v[:16]); err != nil {
		return vouch{}, fmt.Errorf("%w: %v", ErrCryptoRand, err)
	}
	var nacl [24]byte
	copy(nacl[:8], vouchNoncePrefix[:])
	copy(nacl[8:], v[:16])

	var plaintext [64]byte
	copy(plaintext[:32], clientTransPub[:])
	copy(plaintext[32:], serverLongPub[:])

	out := box.SealAfterPrecomputation(nil, plaintext[:], &nacl, (*[32]byte)(vouchShared))
	if len(out) != 80 {
		return vouch{}, fmt.Errorf("curve: internal: vouch-box len=%d want 80", len(out))
	}
	copy(v[16:], out)
	return v, nil
}

// openVouch inverts encodeVouch. The server uses the client's long-term
// public (which it has just learned from INITIATE) and its own
// long-term secret. Returns the inner (C', S) that must match the
// values the server already knows; failure to match indicates an
// impersonation attempt and returns ErrBoxOpen.
func openVouch(v vouch, clientLongPub PublicKey, serverLongSec *SecretKey) (PublicKey, PublicKey, error) {
	var nacl [24]byte
	copy(nacl[:8], vouchNoncePrefix[:])
	copy(nacl[8:], v[:16])

	plain, ok := box.Open(nil, v[16:], &nacl, (*[32]byte)(&clientLongPub), (*[32]byte)(serverLongSec))
	if !ok {
		return PublicKey{}, PublicKey{}, fmt.Errorf("%w: vouch", ErrBoxOpen)
	}
	if len(plain) != 64 {
		return PublicKey{}, PublicKey{}, fmt.Errorf("curve: internal: vouch plaintext len=%d", len(plain))
	}
	var c1 PublicKey
	var s PublicKey
	copy(c1[:], plain[:32])
	copy(s[:], plain[32:])
	return c1, s, nil
}
