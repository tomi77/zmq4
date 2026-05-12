package zmq4

import "testing"

// TestSplitEnvelopeAllocsZero verifies that splitEnvelope makes no heap
// allocations — it returns sub-slices of the input rather than copies.
func TestSplitEnvelopeAllocsZero(t *testing.T) {
	msg := Message{[]byte("id"), nil, []byte("payload")}
	got := testing.AllocsPerRun(100, func() {
		env, pay := splitEnvelope(msg)
		_ = env
		_ = pay
	})
	if got > 0 {
		t.Fatalf("splitEnvelope: %.0f allocs/op, want 0", got)
	}
}

// TestSplitEnvelopeEnvelopeIsolatedFromPayloadAppend verifies that appending
// to the payload after splitEnvelope does not corrupt the envelope. This is
// the key correctness property of the 3-index-slice optimisation.
func TestSplitEnvelopeEnvelopeIsolatedFromPayloadAppend(t *testing.T) {
	msg := Message{[]byte("id"), nil, []byte("data")}
	env, pay := splitEnvelope(msg)

	// Append a new frame to payload — must not overwrite env[1] (the delimiter).
	pay = append(pay, []byte("extra"))

	if len(env) != 2 {
		t.Fatalf("env len = %d, want 2", len(env))
	}
	if len(env[1]) != 0 {
		t.Fatalf("env[1] (delimiter) corrupted after payload append: %q", env[1])
	}
	_ = pay
}
