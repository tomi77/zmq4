package security_test

import (
	"errors"
	"testing"

	"github.com/tomi77/zmq4/internal/security"
)

func TestErrNotDoneIsDistinct(t *testing.T) {
	if errors.Is(security.ErrNotDone, security.ErrClosed) {
		t.Fatalf("ErrNotDone matches ErrClosed; sentinels must be distinct")
	}
	if errors.Is(security.ErrClosed, security.ErrNotDone) {
		t.Fatalf("ErrClosed matches ErrNotDone; sentinels must be distinct")
	}
}
