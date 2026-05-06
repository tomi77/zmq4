package inproc

import (
	"context"
	"errors"
	"testing"

	"github.com/tomi77/zmq4/internal/transport"
)

func TestListenEmptyName(t *testing.T) {
	_, err := Listen(context.Background(), "")
	if !errors.Is(err, transport.ErrEndpointMalformed) {
		t.Fatalf("Listen(\"\") err = %v, want ErrEndpointMalformed", err)
	}
}

func TestListenAlreadyBound(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()

	lis1, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis1.Close()

	_, err = Listen(ctx, name)
	if !errors.Is(err, transport.ErrInprocAlreadyBound) {
		t.Fatalf("second Listen err = %v, want ErrInprocAlreadyBound", err)
	}
}

func TestListenAddr(t *testing.T) {
	name := "test/" + t.Name()
	lis, err := Listen(context.Background(), name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()
	a := lis.Addr()
	if a.Network() != "inproc" {
		t.Fatalf("Addr.Network() = %q, want \"inproc\"", a.Network())
	}
	if a.String() != name {
		t.Fatalf("Addr.String() = %q, want %q", a.String(), name)
	}
}
