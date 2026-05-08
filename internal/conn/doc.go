// Package conn implements the F4 connection layer for ZMTP 3.1.
//
// It takes a raw net.Conn (typically from internal/transport via F5)
// plus a configured security.Mechanism (from internal/security) and
// produces a *Conn after a successful greeting + handshake. The *Conn
// exposes blocking ReadFrame / WriteFrame on the post-handshake byte
// stream.
//
// F4 owns no transport plumbing (F5 calls transport.Dial / Listen),
// no socket-type semantics (F5), no reconnect (F5), no operational
// heartbeat (F6), and no long-lived goroutines after handshake.
//
// See docs/specs/04-connection-layer.md for the full specification.
package conn
