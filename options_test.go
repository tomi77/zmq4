package zmq4

import (
	"errors"
	"testing"
	"time"

	"github.com/tomi77/zmq4/internal/security/plain"
	"github.com/tomi77/zmq4/zap"
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

func TestWithPLAINServerMechMismatch(t *testing.T) {
	cfg := newSocketConfig([]Option{WithPLAIN("u", "p")})
	_, err := cfg.serverMechFactory("REQ")
	if !errors.Is(err, ErrSecurityMismatch) {
		t.Fatalf("want ErrSecurityMismatch, got %v", err)
	}
}

func TestWithPLAINClientMechMismatch(t *testing.T) {
	auth := plain.Authenticator(func(user, pass []byte) error { return nil })
	cfg := newSocketConfig([]Option{WithPLAINServer(auth)})
	_, err := cfg.clientMechFactory("REQ")
	if !errors.Is(err, ErrSecurityMismatch) {
		t.Fatalf("want ErrSecurityMismatch, got %v", err)
	}
}

func TestNewSocketConfigHWMDefaults(t *testing.T) {
	cfg := newSocketConfig(nil)
	if cfg.sndHWM != 1000 {
		t.Fatalf("sndHWM default: got %d, want 1000", cfg.sndHWM)
	}
	if cfg.rcvHWM != 1000 {
		t.Fatalf("rcvHWM default: got %d, want 1000", cfg.rcvHWM)
	}
	if cfg.sndOverflow != Block {
		t.Fatalf("sndOverflow default: got %v, want Block", cfg.sndOverflow)
	}
}

func TestWithSndHWMPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for n<=0")
		}
	}()
	WithSndHWM(0)
}

func TestWithRcvHWMPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for n<=0")
		}
	}()
	WithRcvHWM(0)
}

func TestWithSndHWMOption(t *testing.T) {
	cfg := newSocketConfig([]Option{WithSndHWM(42)})
	if cfg.sndHWM != 42 {
		t.Fatalf("got %d, want 42", cfg.sndHWM)
	}
}

func TestWithRcvHWMOption(t *testing.T) {
	cfg := newSocketConfig([]Option{WithRcvHWM(7)})
	if cfg.rcvHWM != 7 {
		t.Fatalf("got %d, want 7", cfg.rcvHWM)
	}
}

func TestWithSndHWMPolicyOption(t *testing.T) {
	cfg := newSocketConfig([]Option{WithSndHWMPolicy(Drop)})
	if cfg.sndOverflow != Drop {
		t.Fatalf("got %v, want Drop", cfg.sndOverflow)
	}
}

func TestWithSndOverflowInternal(t *testing.T) {
	cfg := newSocketConfig([]Option{withSndOverflow(Drop)})
	if cfg.sndOverflow != Drop {
		t.Fatalf("got %v, want Drop", cfg.sndOverflow)
	}
}

func TestWithSndHWMPolicyOverridesInternal(t *testing.T) {
	// User-supplied policy wins over socket-type internal default.
	cfg := newSocketConfig([]Option{withSndOverflow(Drop), WithSndHWMPolicy(Block)})
	if cfg.sndOverflow != Block {
		t.Fatalf("got %v, want Block", cfg.sndOverflow)
	}
}

func TestWithZAPDomainSetsConfig(t *testing.T) {
	h := zap.HandlerFunc(func(r zap.Request) (zap.Reply, error) {
		return zap.Reply{StatusCode: zap.StatusOK}, nil
	})
	router := zap.NewRouter(h)
	defer router.Close()

	cfg := newSocketConfig([]Option{WithZAPDomain(router, "test-domain")})
	if cfg.zapCaller == nil {
		t.Fatal("zapCaller = nil, want non-nil")
	}
	if cfg.zapDomain != "test-domain" {
		t.Fatalf("zapDomain = %q, want %q", cfg.zapDomain, "test-domain")
	}
}

func TestWithMonitorStoresChannel(t *testing.T) {
	ch := make(chan SocketEvent, 1)
	cfg := newSocketConfig([]Option{WithMonitor(ch)})
	if cfg.monitorCh != ch {
		t.Fatal("monitorCh not set")
	}
}

func TestWithMonitorNilIsNoop(t *testing.T) {
	cfg := newSocketConfig([]Option{WithMonitor(nil)})
	if cfg.monitorCh != nil {
		t.Fatal("nil channel should leave monitorCh nil")
	}
}
