package wire

import "errors"

var (
	// ErrShortBuffer indicates the supplied buffer is shorter than the
	// minimum required to encode or decode the value.
	ErrShortBuffer = errors.New("zmq4/wire: buffer too short")

	// ErrInvalidSignature indicates the greeting signature bytes do not
	// match the required 0xFF...0x7F marker.
	ErrInvalidSignature = errors.New("zmq4/wire: invalid greeting signature")

	// ErrUnsupportedVersion indicates the greeting version is not 3.1.
	ErrUnsupportedVersion = errors.New("zmq4/wire: unsupported ZMTP version (only 3.1 is supported)")

	// ErrInvalidMechanism indicates the mechanism field is malformed
	// (oversized, contains disallowed characters, or not NUL-padded).
	ErrInvalidMechanism = errors.New("zmq4/wire: invalid mechanism field")

	// ErrReservedFlags indicates a frame's flags byte sets reserved bits 3..7.
	ErrReservedFlags = errors.New("zmq4/wire: frame uses reserved flag bits")

	// ErrCommandHasMore indicates a command frame has the MORE flag set,
	// which is forbidden by RFC 37.
	ErrCommandHasMore = errors.New("zmq4/wire: command frame has MORE flag set")

	// ErrInvalidCommand indicates a command body is malformed (bad name
	// length, non-letter chars in name, etc.).
	ErrInvalidCommand = errors.New("zmq4/wire: malformed command")

	// ErrFrameTooLarge indicates a frame size exceeds 2^63-1 octets.
	ErrFrameTooLarge = errors.New("zmq4/wire: frame size exceeds 2^63-1")
)
