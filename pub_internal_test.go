package zmq4

import (
	"testing"
	"time"
)

// TestPubPipeSetAllAllocsZero: all() is called on every PUB.Send — must be zero-alloc.
func TestPubPipeSetAllAllocsZero(t *testing.T) {
	ps := newPubPipeSet()
	for range 3 {
		ps.add(newPubPipe(nil, nil, 100))
	}
	got := testing.AllocsPerRun(100, func() {
		_ = ps.all()
	})
	if got > 0 {
		t.Fatalf("pubPipeSet.all() with 3 pipes: %.0f allocs/op, want 0", got)
	}
}

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
