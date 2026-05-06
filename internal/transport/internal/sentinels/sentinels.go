// Package sentinels holds shared error sentinels for the F3 transport
// layer. It is a leaf package: it imports nothing from sibling transport
// packages, so it can be imported by both the transport facade and each
// scheme-specific subpackage without creating a cycle.
//
// Application code MUST NOT import this package directly. The public
// surface lives in package transport, which re-exports each sentinel
// as an alias.
package sentinels

import "errors"

// ErrEndpointMalformed: see transport.ErrEndpointMalformed.
var ErrEndpointMalformed = errors.New("transport: malformed endpoint")

// ErrSchemeUnknown: see transport.ErrSchemeUnknown.
var ErrSchemeUnknown = errors.New("transport: unknown scheme")

// ErrInprocAlreadyBound: see transport.ErrInprocAlreadyBound.
var ErrInprocAlreadyBound = errors.New("transport: inproc name already bound")
