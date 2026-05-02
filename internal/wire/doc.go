// Package wire implements the ZMTP 3.1 wire protocol codec.
//
// This package performs no I/O of its own beyond what the caller's
// io.Reader / io.Writer does. It defines no state machine, no
// goroutines, no timers. It is the lowest layer of the zmq4
// implementation and is consumed by internal/conn (Phase 4) and above.
//
// See docs/specs/01-zmtp-wire-protocol.md for the full design and
// docs/specs/00-meta-overview.md for the project layering.
package wire
