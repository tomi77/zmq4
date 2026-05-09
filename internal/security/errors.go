package security

import "errors"

// ErrNotDone is returned by Wrap/Unwrap if the handshake has not
// completed.
var ErrNotDone = errors.New("security: handshake not done")

// ErrClosed is returned by every method after Close has been called
// (CURVE-only; NULL/PLAIN have no Close).
var ErrClosed = errors.New("security: state closed")

// ErrZAPDenied is returned by server-side Mechanism.Receive when the ZAP
// handler rejected the connection (status code 400 or 500, or an error from
// the Handler). The Receive method returns this error together with a non-nil
// output command containing the ERROR frame that MUST be sent before closing
// the connection.
var ErrZAPDenied = errors.New("security: ZAP denied connection")
