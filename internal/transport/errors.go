package transport

import "errors"

// ErrEndpointMalformed is returned by ParseEndpoint and the subpackage
// openers when the endpoint URI or scheme-native address is syntactically
// invalid.
var ErrEndpointMalformed = errors.New("transport: malformed endpoint")

// ErrSchemeUnknown is returned by ParseEndpoint for any scheme outside
// {tcp, ipc, inproc}, and by the ipc subpackage on Windows where ipc is
// not implemented.
var ErrSchemeUnknown = errors.New("transport: unknown scheme")

// ErrInprocAlreadyBound is returned by the inproc subpackage's Listen when
// the requested name is already bound by another live listener.
var ErrInprocAlreadyBound = errors.New("transport: inproc name already bound")
