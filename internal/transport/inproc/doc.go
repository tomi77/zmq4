// Package inproc implements the inproc:// transport for F3 — an
// in-process namespace of net.Pipe-backed connections.
//
// The registry is per-OS-process; subprocesses do not share an inproc
// namespace.
//
// Dial blocks on ctx until a matching Listen on the same name completes
// the pairing. Pending dialers survive Listener.Close → re-Listen
// cycles; closing a listener releases the name without aborting
// in-flight dialers.
//
// See docs/specs/03-transports.md §5.4 / §7 for the data structures and
// state machine.
package inproc
