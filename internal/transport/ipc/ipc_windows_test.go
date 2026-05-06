//go:build windows

package ipc

import (
	"context"
	"errors"
	"testing"

	"github.com/tomi77/zmq4/internal/transport"
)

func TestListenWindowsStub(t *testing.T) {
	_, err := Listen(context.Background(), "ignored")
	if !errors.Is(err, transport.ErrSchemeUnknown) {
		t.Fatalf("Listen err = %v, want ErrSchemeUnknown", err)
	}
}

func TestDialWindowsStub(t *testing.T) {
	_, err := Dial(context.Background(), "ignored")
	if !errors.Is(err, transport.ErrSchemeUnknown) {
		t.Fatalf("Dial err = %v, want ErrSchemeUnknown", err)
	}
}
