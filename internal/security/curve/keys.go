package curve

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// PublicKey is a 32-byte Curve25519 public key. Values are safe to
// log, store, and transmit.
type PublicKey [32]byte

// SecretKey is a 32-byte Curve25519 secret key. Sensitive material;
// callers SHOULD call Zero() when no longer needed. Implements
// fmt.Stringer returning "[REDACTED]" so accidental %v formatting does
// not leak the bytes (also implements GoString for %#v).
//
// String/GoString use POINTER receivers so a formatting call never
// triggers an implicit value copy of the 32 bytes onto another stack.
type SecretKey [32]byte

// Zero overwrites the key bytes with zero. Idempotent.
func (s *SecretKey) Zero() { clear(s[:]) }

// String returns a redacted placeholder. Pointer receiver on purpose —
// calling %v on a SecretKey value would otherwise copy the 32 bytes.
func (*SecretKey) String() string { return "[REDACTED]" }

// GoString returns a redacted placeholder for %#v.
func (*SecretKey) GoString() string { return "curve.SecretKey([REDACTED])" }

// SharedKey is a 32-byte precomputed NaCl box key (the X25519 shared
// secret) ready for nacl/box.SealAfterPrecomputation. Same redaction
// and Zero() semantics as SecretKey, including pointer-receiver
// formatting.
type SharedKey [32]byte

// Zero overwrites the key bytes with zero. Idempotent.
func (s *SharedKey) Zero() { clear(s[:]) }

// String returns a redacted placeholder. Pointer receiver — see
// SecretKey.String.
func (*SharedKey) String() string { return "[REDACTED]" }

// GoString returns a redacted placeholder for %#v.
func (*SharedKey) GoString() string { return "curve.SharedKey([REDACTED])" }

// GenerateKeyPair returns a freshly generated long-term Curve25519
// keypair. rng supplies entropy; pass nil to use crypto/rand.Reader.
// The only error path is rng.Read failing.
func GenerateKeyPair(rng io.Reader) (PublicKey, SecretKey, error) {
	if rng == nil {
		rng = rand.Reader
	}
	pubArr, secArr, err := box.GenerateKey(rng)
	if err != nil {
		return PublicKey{}, SecretKey{}, fmt.Errorf("%w: %v", ErrCryptoRand, err)
	}
	var pub PublicKey
	var sec SecretKey
	copy(pub[:], pubArr[:])
	copy(sec[:], secArr[:])
	return pub, sec, nil
}

// precompute wraps nacl/box.Precompute with the typed key wrappers.
// Used by ClientState/ServerState; not exported because production
// callers don't need to drive precomputation themselves.
func precompute(peerPub PublicKey, ourSec *SecretKey) *SharedKey {
	var out SharedKey
	box.Precompute((*[32]byte)(&out), (*[32]byte)(&peerPub), (*[32]byte)(ourSec))
	return &out
}
