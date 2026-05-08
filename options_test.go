package zmq4

import (
	"testing"
	"time"
)

func TestNewSocketConfigDefaults(t *testing.T) {
	cfg := newSocketConfig(nil)
	if cfg.handshakeTimeout != 5*time.Second {
		t.Fatalf("default timeout: got %v, want 5s", cfg.handshakeTimeout)
	}
	if cfg.clientMechFactory == nil {
		t.Fatal("clientMechFactory must not be nil")
	}
	if cfg.serverMechFactory == nil {
		t.Fatal("serverMechFactory must not be nil")
	}
}

func TestWithHandshakeTimeoutPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for d<=0")
		}
	}()
	WithHandshakeTimeout(0)
}

func TestWithIdentityPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty identity")
		}
	}()
	WithIdentity(nil)
}

func TestWithIdentityTooLongPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for identity > 255 bytes")
		}
	}()
	WithIdentity(make([]byte, 256))
}

func TestWithNULLClientFactory(t *testing.T) {
	cfg := newSocketConfig([]Option{WithNULL()})
	mech, err := cfg.clientMechFactory("REQ")
	if err != nil {
		t.Fatalf("clientMechFactory: %v", err)
	}
	if mech == nil {
		t.Fatal("got nil mechanism")
	}
}

func TestWithIdentityAppearsInMeta(t *testing.T) {
	id := []byte("myid")
	cfg := newSocketConfig([]Option{WithNULL(), WithIdentity(id)})
	meta := cfg.localMeta("REQ")
	if got := meta["Identity"]; got != "myid" {
		t.Fatalf("Identity in meta: got %q, want %q", got, "myid")
	}
}
