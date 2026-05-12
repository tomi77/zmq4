package zmq4

import "testing"

func TestEventTypeValues(t *testing.T) {
	if EventListening != 1 {
		t.Fatalf("EventListening = %d, want 1", EventListening)
	}
	if EventMonitorStopped != 11 {
		t.Fatalf("EventMonitorStopped = %d, want 11", EventMonitorStopped)
	}
}
