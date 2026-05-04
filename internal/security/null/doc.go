// Package null implements the ZMTP 3.1 NULL security handshake.
//
// NULL provides no authentication and no confidentiality. After the
// greeting completes with mechanism="NULL", both peers exchange a
// READY command containing their metadata, and the handshake is done.
//
// This package is pure: it does no I/O, allocates no goroutines, and
// reads no clocks. It consumes and produces wire.Command values on
// behalf of the caller.
//
// State is not reusable. A new State instance MUST be created for each
// connection attempt; there is no reset mechanism.
//
// See docs/specs/02a-security-null.md for the full specification.
package null
