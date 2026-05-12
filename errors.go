package zmq4

import "errors"

var (
	ErrClosed               = errors.New("zmq4: socket closed")
	ErrState                = errors.New("zmq4: operation out of sequence")
	ErrNoRoute              = errors.New("zmq4: no route to peer")
	ErrIncompatiblePeer     = errors.New("zmq4: incompatible peer socket type")
	ErrSecurityMismatch     = errors.New("zmq4: security option not valid for this role")
	ErrNoIdentity           = errors.New("zmq4: ROUTER Send requires non-empty msg[0]")
	ErrNoTopic              = errors.New("zmq4: PUB/XPUB Send requires at least one frame (topic)")
	ErrPairAlreadyConnected = errors.New("zmq4: PAIR socket already has a peer")
	ErrNotSocket            = errors.New("zmq4: value is not a zmq4 socket")
	ErrAlreadyRegistered    = errors.New("zmq4: socket already registered with poller")
	ErrNotRegistered        = errors.New("zmq4: socket not registered with poller")
	ErrInvalidEvents        = errors.New("zmq4: event mask must not be zero")
)
