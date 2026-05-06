// Package tcp implements the tcp:// transport for F3.
//
// Listen translates an address ("host:port"; host may be "*" for
// wildcard, port may be "*" for ephemeral) into a *net.TCPListener
// whose Accept method returns conns with TCP_NODELAY set.
//
// Dial honours the supplied context for DNS lookup and connect.
//
// Address grammar is the per-scheme subset of docs/specs/03-transports.md
// §3 (no URI prefix, no scheme); URI parsing lives in the parent
// transport package.
package tcp
