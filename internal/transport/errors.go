package transport

import "github.com/tomi77/zmq4/internal/transport/internal/sentinels"

// ErrEndpointMalformed is returned by ParseEndpoint and the subpackage
// openers when the endpoint URI or scheme-native address is syntactically
// invalid.
var ErrEndpointMalformed = sentinels.ErrEndpointMalformed

// ErrSchemeUnknown is returned by ParseEndpoint for any scheme outside
// {tcp, ipc, inproc}, and by the ipc subpackage on Windows where ipc is
// not implemented.
var ErrSchemeUnknown = sentinels.ErrSchemeUnknown

// ErrInprocAlreadyBound is returned by the inproc subpackage's Listen when
// the requested name is already bound by another live listener.
var ErrInprocAlreadyBound = sentinels.ErrInprocAlreadyBound
