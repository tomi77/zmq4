// Package zmq4 provides a pure-Go implementation of the ZeroMQ core protocol
// stack (ZMTP 3.1).
//
// # Socket types
//
// F5a provides four socket types for the request-reply pattern (RFC 28):
//
//   - [REQ] — request socket (alternating Send→Recv)
//   - [REP] — reply socket (alternating Recv→Send)
//   - [DEALER] — async request socket (round-robin send, fair-queue recv)
//   - [ROUTER] — identity-routing socket (msg[0] is always the peer identity)
//
// # Creating a socket
//
//	req := zmq4.NewREQ(zmq4.WithNULL())
//	if err := req.Connect(ctx, "tcp://127.0.0.1:5555"); err != nil { ... }
//	defer req.Close()
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
