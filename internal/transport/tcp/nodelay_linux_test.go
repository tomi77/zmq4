//go:build linux

package tcp

import (
	"context"
	"net"
	"syscall"
	"testing"
)

func tcpNoDelay(c *net.TCPConn) (bool, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return false, err
	}
	var v int
	var serr error
	cerr := rc.Control(func(fd uintptr) {
		v, serr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY)
	})
	if cerr != nil {
		return false, cerr
	}
	if serr != nil {
		return false, serr
	}
	return v != 0, nil
}

func TestNoDelaySetOnDial(t *testing.T) {
	ctx := context.Background()
	lis, _ := Listen(ctx, "127.0.0.1:*")
	defer lis.Close()
	go func() {
		c, _ := lis.Accept()
		if c != nil {
			c.Close()
		}
	}()
	dc, err := Dial(ctx, lis.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dc.Close()
	tc := dc.(*net.TCPConn)
	on, err := tcpNoDelay(tc)
	if err != nil {
		t.Fatalf("tcpNoDelay: %v", err)
	}
	if !on {
		t.Fatalf("TCP_NODELAY not set after Dial")
	}
}

func TestNoDelaySetOnAccept(t *testing.T) {
	ctx := context.Background()
	lis, _ := Listen(ctx, "127.0.0.1:*")
	defer lis.Close()
	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()
	dc, _ := Dial(ctx, lis.Addr().String())
	defer dc.Close()
	got := <-ch
	if got.e != nil {
		t.Fatalf("Accept: %v", got.e)
	}
	defer got.c.Close()
	tc := got.c.(*net.TCPConn)
	on, err := tcpNoDelay(tc)
	if err != nil {
		t.Fatalf("tcpNoDelay: %v", err)
	}
	if !on {
		t.Fatalf("TCP_NODELAY not set on accepted conn")
	}
}
