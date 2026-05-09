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
// the Handler). Callers receive it alongside a non-nil *wire.Command containing
// the ERROR frame that MUST be sent before closing the connection.
var ErrZAPDenied = errors.New("security: ZAP denied connection")
