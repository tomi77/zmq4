//go:build windows

package ipc

import (
	"context"
	"fmt"
	"net"

	"github.com/tomi77/zmq4/internal/transport"
)

// Listen returns ErrSchemeUnknown on Windows. ipc is not implemented;
// see docs/specs/03-transports.md §9 Open Question 7.
func Listen(_ context.Context, _ string) (*net.UnixListener, error) {
	return nil, fmt.Errorf("%w: ipc on windows", transport.ErrSchemeUnknown)
}

// Dial returns ErrSchemeUnknown on Windows.
func Dial(_ context.Context, _ string) (*net.UnixConn, error) {
	return nil, fmt.Errorf("%w: ipc on windows", transport.ErrSchemeUnknown)
}
