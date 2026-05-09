// Package zmq4 provides a pure-Go implementation of the ZeroMQ core protocol
// stack (ZMTP 3.1).
//
// # Socket types
//
// Request-reply pattern (RFC 28):
//
//   - [REQ] — request socket (alternating Send→Recv)
//   - [REP] — reply socket (alternating Recv→Send)
//   - [DEALER] — async request socket (round-robin send, fair-queue recv)
//   - [ROUTER] — identity-routing socket (msg[0] is always the peer identity)
//
// Publish-subscribe pattern (RFC 29):
//
//   - [PUB] — publish socket (topic-filtered broadcast; drop on slow peers)
//   - [SUB] — subscribe socket (Subscribe/Unsubscribe + fair-queue recv)
//   - [XPUB] — extended publish (like PUB; Recv returns subscription frames)
//   - [XSUB] — extended subscribe (like SUB; Send forwards raw sub frames)
//
// Pipeline pattern (RFC 30):
//
//   - [PUSH] — push socket (round-robin send; blocks until a peer is ready)
//   - [PULL] — pull socket (fair-queue recv; no send)
//
// Exclusive-pair pattern (RFC 31):
//
//   - [PAIR] — exclusive-pair socket (single peer; bidirectional)
//
// # Creating a socket
//
//	push := zmq4.NewPUSH()
//	if err := push.Bind(ctx, "tcp://127.0.0.1:5555"); err != nil { ... }
//	defer push.Close()
//
//	pull := zmq4.NewPULL()
//	if err := pull.Connect(ctx, "tcp://127.0.0.1:5555"); err != nil { ... }
//	msg, err := pull.Recv(ctx)
//
// # Security
//
// Select a security mechanism via constructor options:
//
//	zmq4.WithNULL()                       // no authentication (default)
//	zmq4.WithPLAIN(username, password)    // PLAIN credentials (Connect side)
//	zmq4.WithPLAINServer(auth)            // PLAIN authentication (Bind side)
//	zmq4.WithCURVE(clientOptions)         // CURVE encryption (Connect side)
//	zmq4.WithCURVEServer(serverOptions)   // CURVE encryption (Bind side)
//
// # Memory ownership
//
// Every [Message] returned by Recv is caller-owned: parts may be retained
// and mutated freely without affecting the socket's internal state.
package zmq4
