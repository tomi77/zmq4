package zmq4

import (
	"testing"
	"time"
)

// TestPubPipeMatchesDoesNotBlockDuringWrite verifies that matches() is lock-free:
// it must return immediately even while a write lock is held by addSub/removeSub.
func TestPubPipeMatchesDoesNotBlockDuringWrite(t *testing.T) {
	pp := newPubPipe(nil, nil, 100)
	pp.addSub([]byte("topic"))

	// Hold the write lock to simulate an in-progress addSub.
	pp.mu.Lock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = pp.matches([]byte("topic"))
	}()

	select {
	case <-done:
		// Correct: matches() returned without waiting for the write lock.
	case <-time.After(100 * time.Millisecond):
		t.Fatal("matches() blocked waiting for write lock; must be lock-free via atomic.Pointer")
	}

	pp.mu.Unlock()
}
