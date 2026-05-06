//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/tomi77/zmq4/internal/transport"
)

// Listen opens a Unix domain socket listener at path. After bind the
// socket file is chmod'd to 0600. SetUnlinkOnClose(true) is enabled so
// Close removes the file. ctx is currently unused (Unix bind does not
// resolve names).
func Listen(_ context.Context, path string) (*net.UnixListener, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty ipc path", transport.ErrEndpointMalformed)
	}
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	lis, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/ipc: listen %q: %w", path, err)
	}
	lis.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("transport/ipc: chmod %q: %w", path, err)
	}
	return lis, nil
}

// Dial opens a Unix domain connection to path. ctx bounds the connect.
func Dial(ctx context.Context, path string) (*net.UnixConn, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty ipc path", transport.ErrEndpointMalformed)
	}
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("transport/ipc: dial %q: %w", path, err)
	}
	return c.(*net.UnixConn), nil
}
