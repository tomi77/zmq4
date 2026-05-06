package transport

import (
	"fmt"
	"strings"
)

// ParseEndpoint splits a ZMTP endpoint URI of the form "<scheme>://<addr>"
// into its scheme and scheme-native address parts.
//
// The scheme MUST be one of "tcp", "ipc", "inproc". The addr is returned
// verbatim; per-scheme validation (port range, path/name non-emptiness,
// IPv6 brackets) is the subpackage's responsibility.
//
// Returns ErrEndpointMalformed for missing "://", empty scheme, or empty
// addr. Returns ErrSchemeUnknown for any other scheme.
func ParseEndpoint(endpoint string) (scheme, addr string, err error) {
	i := strings.Index(endpoint, "://")
	if i <= 0 || i+3 == len(endpoint) {
		return "", "", fmt.Errorf("%w: %q", ErrEndpointMalformed, endpoint)
	}
	scheme, addr = endpoint[:i], endpoint[i+3:]
	switch scheme {
	case "tcp", "ipc", "inproc":
		return scheme, addr, nil
	default:
		return "", "", fmt.Errorf("%w: scheme %q", ErrSchemeUnknown, scheme)
	}
}
