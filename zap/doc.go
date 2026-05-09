// Package zap implements the ZeroMQ Authentication Protocol (ZAP, RFC 27).
//
// A ZAP Handler is a [Router] that runs in its own goroutine and dispatches
// authentication requests to a user-supplied [Handler]. A [Client] connects
// to the Router and is injected into server-side security mechanisms via
// [github.com/tomi77/zmq4.WithZAPDomain].
//
// Typical use:
//
//	router := zap.NewRouter(myHandler)
//	defer router.Close()
//
//	rep := zmq4.NewREP(zmq4.WithPLAINServer(myAuth), zmq4.WithZAPDomain(router, "global"))
//
// The ZAP handler runs exclusively in-process over Go channels (not over the
// wire). Authentication is performed synchronously during the ZMTP handshake
// for every incoming connection.
package zap
