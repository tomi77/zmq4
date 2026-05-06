// Package transport implements the F3 transport layer for ZMTP.
//
// It provides pure-Go listener and dialer abstractions for the three
// ZMTP-supported transports — tcp, ipc (Unix domain sockets), and
// inproc (in-process pipes) — over the standard net package.
//
// The public surface is two opener functions plus a URI parser:
//
//	func Listen(ctx, endpoint) (net.Listener, error)
//	func Dial(ctx, endpoint) (net.Conn, error)
//	func ParseEndpoint(endpoint) (scheme, addr, err)
//
// All callers receive stdlib net.Conn / net.Listener. The concrete
// types per scheme are documented at the call sites but MUST NOT be
// type-switched for behaviour.
//
// See docs/specs/03-transports.md for the full specification.
package transport
