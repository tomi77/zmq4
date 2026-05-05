package security

import "errors"

// ErrNotDone is returned by Wrap/Unwrap if the handshake has not
// completed.
var ErrNotDone = errors.New("security: handshake not done")

// ErrClosed is returned by every method after Close has been called
// (CURVE-only; NULL/PLAIN have no Close).
var ErrClosed = errors.New("security: state closed")
