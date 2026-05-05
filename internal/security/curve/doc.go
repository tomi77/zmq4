// Package curve implements the ZMTP 3.1 CURVE security mechanism
// (RFC 37 §3.3 / RFC 26).
//
// CURVE provides mutual peer authentication via Curve25519 long-term
// keypairs and confidentiality+integrity for both the four-step
// handshake (HELLO → WELCOME → INITIATE → READY) and the post-
// handshake application traffic (MESSAGE commands carrying NaCl
// box-encrypted frames).
//
// The handshake is asymmetric. ClientState drives the active side;
// ServerState drives the reactive side. Server-side authorization is
// delegated to a caller-supplied Authorizer callback that decides
// whether a verified client long-term public key is allowed to connect
// — F6 will provide a ZAP-backed Authorizer.
//
// This package is pure: it does no I/O, allocates no goroutines, and
// reads no clocks. Entropy is supplied through an injectable
// io.Reader (defaults to crypto/rand.Reader); tests inject a
// deterministic source for byte-exact vectors.
//
// Long-term SecretKey buffers passed in via ClientOptions/ServerOptions
// are referenced — the caller owns their lifetime and Close() does not
// zero them. Transient secrets, shared keys, and the cookie key are
// owned by ClientState/ServerState and zeroed on Close().
//
// See docs/specs/02c-security-curve.md for the full specification.
package curve
