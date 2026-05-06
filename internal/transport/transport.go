package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/tomi77/zmq4/internal/transport/inproc"
	"github.com/tomi77/zmq4/internal/transport/ipc"
	"github.com/tomi77/zmq4/internal/transport/tcp"
)

// Listen opens a listener for endpoint, parsing the URI per ParseEndpoint
// and dispatching to the appropriate scheme-specific subpackage.
func Listen(ctx context.Context, endpoint string) (net.Listener, error) {
	scheme, addr, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	switch scheme {
	case "tcp":
		return tcp.Listen(ctx, addr)
	case "ipc":
		return ipc.Listen(ctx, addr)
	case "inproc":
		return inproc.Listen(ctx, addr)
	default:
		// ParseEndpoint already filtered, but be defensive.
		return nil, fmt.Errorf("%w: %q", ErrSchemeUnknown, scheme)
	}
}

// Dial opens a connection for endpoint, parsing the URI per ParseEndpoint
// and dispatching to the appropriate scheme-specific subpackage.
func Dial(ctx context.Context, endpoint string) (net.Conn, error) {
	scheme, addr, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	switch scheme {
	case "tcp":
		return tcp.Dial(ctx, addr)
	case "ipc":
		return ipc.Dial(ctx, addr)
	case "inproc":
		return inproc.Dial(ctx, addr)
	default:
		return nil, fmt.Errorf("%w: %q", ErrSchemeUnknown, scheme)
	}
}
