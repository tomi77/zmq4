package tcp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/tomi77/zmq4/internal/transport/internal/sentinels"
)

// Listen opens a TCP listener for addr. addr is "host:port"; host may be
// "*" (rewritten to "0.0.0.0") and port may be "*" (rewritten to "0",
// i.e. ephemeral; read the actual port via lis.Addr()).
//
// The returned listener wraps *net.TCPListener so that every accepted
// connection has TCP_NODELAY set.
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	resolved, err := resolveBindAddr(addr)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", resolved)
	if err != nil {
		return nil, fmt.Errorf("transport/tcp: listen %q: %w", addr, err)
	}
	tl, ok := lis.(*net.TCPListener)
	if !ok {
		// net.ListenConfig should always return *net.TCPListener for tcp;
		// be defensive in case stdlib changes.
		return lis, nil
	}
	return &nodelayListener{TCPListener: tl}, nil
}

// Dial opens a TCP connection to addr ("host:port") with TCP_NODELAY set.
// ctx bounds DNS resolution and connect.
func Dial(ctx context.Context, addr string) (net.Conn, error) {
	if err := validateDialAddr(addr); err != nil {
		return nil, err
	}
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/tcp: dial %q: %w", addr, err)
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return c, nil
}

// nodelayListener is a *net.TCPListener wrapper whose Accept applies
// SetNoDelay(true) before returning.
type nodelayListener struct {
	*net.TCPListener
}

func (l *nodelayListener) Accept() (net.Conn, error) {
	c, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = c.SetNoDelay(true)
	return c, nil
}

func resolveBindAddr(addr string) (string, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "*" {
		host = "0.0.0.0"
	}
	if port == "*" {
		port = "0"
	} else {
		// Validate numeric port; reject 0 (only "*" denotes ephemeral)
		// and out-of-range values.
		n, perr := strconv.Atoi(port)
		if perr != nil || n <= 0 || n > 65535 {
			return "", fmt.Errorf("%w: tcp port %q", sentinels.ErrEndpointMalformed, port)
		}
	}
	if host == "" {
		return "", fmt.Errorf("%w: tcp host empty in %q", sentinels.ErrEndpointMalformed, addr)
	}
	return net.JoinHostPort(host, port), nil
}

func validateDialAddr(addr string) error {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "*" {
		return fmt.Errorf("%w: tcp dial host %q", sentinels.ErrEndpointMalformed, host)
	}
	if port == "*" {
		return fmt.Errorf("%w: tcp dial port may not be wildcard in %q", sentinels.ErrEndpointMalformed, addr)
	}
	n, perr := strconv.Atoi(port)
	if perr != nil || n <= 0 || n > 65535 {
		return fmt.Errorf("%w: tcp port %q", sentinels.ErrEndpointMalformed, port)
	}
	return nil
}

// splitHostPort handles bracketed IPv6 ("[::1]:5555") and bare host:port.
func splitHostPort(addr string) (host, port string, err error) {
	if strings.HasPrefix(addr, "[") {
		// Bracketed IPv6: "[v6]:port"
		end := strings.LastIndex(addr, "]")
		if end < 0 || end+1 >= len(addr) || addr[end+1] != ':' {
			return "", "", fmt.Errorf("%w: malformed IPv6 in %q", sentinels.ErrEndpointMalformed, addr)
		}
		return addr[1:end], addr[end+2:], nil
	}
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", "", fmt.Errorf("%w: missing :port in %q", sentinels.ErrEndpointMalformed, addr)
	}
	return addr[:i], addr[i+1:], nil
}
