// Package zmq4 provides a pure-Go implementation of the ZeroMQ core protocol
// stack (ZMTP 3.1).
//
// # Memory ownership
//
// The library follows a two-tier memory contract.
//
// Safe default (all methods without a "Frame" suffix): every value returned to
// the caller is owned by the caller.  It may be retained, mutated, or freed
// without affecting the socket's internal state.
//
// Opt-in zero-copy (methods whose name ends in "Frame"): the returned
// [wire.Frame].Body aliases the socket's internal read buffer.  It is valid
// only until the next *Frame call on the same socket.  Call [wire.Frame.Clone]
// to detach the body into a fresh, caller-owned slice before that point.
//
// Every upward layer boundary passes owned data.  Aliasing is an internal
// implementation detail that only surfaces through the explicitly named *Frame
// methods.
package zmq4
