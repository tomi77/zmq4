package zmq4

import "errors"

var (
	// ErrClosed is returned by any socket operation after the socket is closed.
	ErrClosed = errors.New("zmq4: socket closed")

	// ErrState is returned when an operation is called out of sequence
	// (e.g. REQ sends twice without an intervening Recv).
	ErrState = errors.New("zmq4: operation out of sequence")

	// ErrNoRoute is returned when no connected peer is available for routing.
	ErrNoRoute = errors.New("zmq4: no route to peer")

	// ErrIncompatiblePeer is returned when the remote socket type is not
	// compatible with the local socket type.
	ErrIncompatiblePeer = errors.New("zmq4: incompatible peer socket type")

	// ErrSecurityMismatch is returned when a security option is not valid for
	// the socket's role (e.g. a client-side option on a Bind socket).
	ErrSecurityMismatch = errors.New("zmq4: security option not valid for this role")

	// ErrNoIdentity is returned by ROUTER.Send when msg[0] (the identity frame)
	// is empty.
	ErrNoIdentity = errors.New("zmq4: ROUTER Send requires non-empty msg[0]")

	// ErrNoTopic is returned by PUB/XPUB.Send when the message has no frames
	// (a topic prefix is required).
	ErrNoTopic = errors.New("zmq4: PUB/XPUB Send requires at least one frame (topic)")

	// ErrPairAlreadyConnected is returned when a second peer tries to connect
	// to a PAIR socket that already has an active peer.
	ErrPairAlreadyConnected = errors.New("zmq4: PAIR socket already has a peer")

	// ErrNotSocket is returned by Poller methods when the value passed is not
	// a recognised zmq4 socket type.
	ErrNotSocket = errors.New("zmq4: value is not a zmq4 socket")

	// ErrAlreadyRegistered is returned by Poller.Add when the socket is already
	// registered with this Poller.
	ErrAlreadyRegistered = errors.New("zmq4: socket already registered with poller")

	// ErrNotRegistered is returned by Poller.Remove and Poller.Update when the
	// socket is not registered with this Poller.
	ErrNotRegistered = errors.New("zmq4: socket not registered with poller")

	// ErrInvalidEvents is returned by Poller.Add and Poller.Update when the
	// event mask is zero.
	ErrInvalidEvents = errors.New("zmq4: event mask must not be zero")
)
