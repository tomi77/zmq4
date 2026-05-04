// Package plain implements the ZMTP 3.1 PLAIN security handshake.
//
// PLAIN authenticates a peer with a clear-text username/password pair.
// It provides no confidentiality and is appropriate only over already-
// secured transports (TLS-tunnelled TCP, trusted IPC, authenticated VPN)
// or in development.
//
// The handshake is asymmetric. ClientState drives the client side
// (HELLO → WELCOME → INITIATE → READY); ServerState drives the server
// side (the same exchange, in reverse). The two state machines are
// independent — neither is an alias for the other and there is (yet)
// no shared Mechanism interface (deferred to F2c).
//
// Server-side authentication is delegated to a caller-supplied
// Authenticator callback. F6 will provide a ZAP-backed authenticator
// that satisfies the same callback shape.
//
// This package is pure: it does no I/O, allocates no goroutines, and
// reads no clocks. It consumes and produces wire.Command values on
// behalf of the caller.
//
// See docs/specs/02b-security-plain.md for the full specification.
package plain
