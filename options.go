package zmq4

import (
	"slices"
	"time"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/curve"
	"github.com/tomi77/zmq4/internal/security/null"
	"github.com/tomi77/zmq4/internal/security/plain"
	"github.com/tomi77/zmq4/internal/wire"
	zmqzap "github.com/tomi77/zmq4/zap"
)

// OverflowPolicy specifies what happens when a pipe's send queue (SNDHWM) is full.
type OverflowPolicy int

const (
	// Block causes the sender to wait until space is available or the socket closes.
	Block OverflowPolicy = iota
	// Drop silently discards the message without blocking.
	Drop
)

const defaultHandshakeTimeout = 5 * time.Second

// socketConfig holds per-socket configuration built from Option functions.
type socketConfig struct {
	// clientMechFactory builds a fresh ClientMechanism for Connect paths.
	clientMechFactory func(socketType string) (security.ClientMechanism, error)
	// serverMechFactory builds a fresh Mechanism for Bind/Accept paths.
	serverMechFactory func(socketType string) (security.Mechanism, error)
	// identity is the local Identity metadata value; nil = omit.
	identity         []byte
	handshakeTimeout time.Duration
	sndHWM           int                // outbound pipe queue capacity; default 1000
	rcvHWM           int                // inbound pipe queue capacity; default 1000
	sndOverflow      OverflowPolicy     // behaviour when sndHWM is reached; default Block
	zapCaller        security.ZAPCaller // non-nil when WithZAPDomain is used
	zapDomain        string
	monitorCh        chan<- SocketEvent // non-nil when WithMonitor is used
}

// localMeta returns the metadata this socket advertises in handshake as
// a map[string]string. Always includes Socket-Type; includes Identity
// only if set.
func (cfg *socketConfig) localMeta(socketType string) map[string]string {
	m := map[string]string{"Socket-Type": socketType}
	if len(cfg.identity) > 0 {
		m["Identity"] = string(cfg.identity)
	}
	return m
}

// toWireMetadata converts a map[string]string to wire.Metadata, placing
// Socket-Type first (as required by ZMTP) and then remaining keys sorted
// alphabetically to ensure deterministic ordering.
func toWireMetadata(m map[string]string) wire.Metadata {
	md := make(wire.Metadata, 0, len(m))
	// Socket-Type first per convention.
	if v, ok := m["Socket-Type"]; ok {
		md = append(md, wire.MetadataProperty{
			Name:  []byte("Socket-Type"),
			Value: []byte(v),
		})
	}
	// Collect remaining keys and sort them for deterministic output.
	rest := make([]wire.MetadataProperty, 0, len(m)-1)
	for k, v := range m {
		if k == "Socket-Type" {
			continue
		}
		rest = append(rest, wire.MetadataProperty{
			Name:  []byte(k),
			Value: []byte(v),
		})
	}
	slices.SortFunc(rest, func(a, b wire.MetadataProperty) int {
		switch {
		case string(a.Name) < string(b.Name):
			return -1
		case string(a.Name) > string(b.Name):
			return 1
		default:
			return 0
		}
	})
	return append(md, rest...)
}

// Option configures a socket at construction time.
type Option func(*socketConfig)

func newSocketConfig(opts []Option) *socketConfig {
	cfg := &socketConfig{
		handshakeTimeout: defaultHandshakeTimeout,
		sndHWM:           1000,
		rcvHWM:           1000,
		sndOverflow:      Block,
	}
	// Default: NULL mechanism. Factory closures capture cfg pointer so
	// WithIdentity applied later is picked up at connection time.
	cfg.clientMechFactory = func(socketType string) (security.ClientMechanism, error) {
		return null.New(toWireMetadata(cfg.localMeta(socketType))), nil
	}
	cfg.serverMechFactory = func(socketType string) (security.Mechanism, error) {
		return null.New(toWireMetadata(cfg.localMeta(socketType))), nil
	}
	for _, o := range opts {
		o(cfg)
	}
	return cfg
}

// WithNULL selects the NULL security mechanism (default if no security
// option is provided).
func WithNULL() Option {
	return func(cfg *socketConfig) {
		cfg.clientMechFactory = func(socketType string) (security.ClientMechanism, error) {
			return null.New(toWireMetadata(cfg.localMeta(socketType))), nil
		}
		cfg.serverMechFactory = func(socketType string) (security.Mechanism, error) {
			return null.New(toWireMetadata(cfg.localMeta(socketType))), nil
		}
	}
}

// WithPLAIN configures PLAIN client-side credentials (Connect side).
func WithPLAIN(username, password string) Option {
	return func(cfg *socketConfig) {
		cfg.clientMechFactory = func(socketType string) (security.ClientMechanism, error) {
			return plain.NewClient([]byte(username), []byte(password), toWireMetadata(cfg.localMeta(socketType)))
		}
		cfg.serverMechFactory = func(socketType string) (security.Mechanism, error) {
			return nil, ErrSecurityMismatch
		}
	}
}

// WithPLAINServer configures PLAIN server-side authentication (Bind side).
func WithPLAINServer(auth plain.Authenticator) Option {
	return func(cfg *socketConfig) {
		cfg.serverMechFactory = func(socketType string) (security.Mechanism, error) {
			return plain.NewServer(auth, toWireMetadata(cfg.localMeta(socketType))), nil
		}
		cfg.clientMechFactory = func(socketType string) (security.ClientMechanism, error) {
			return nil, ErrSecurityMismatch
		}
	}
}

// WithCURVE configures CURVE client-side keys (Connect side).
func WithCURVE(opts curve.ClientOptions) Option {
	return func(cfg *socketConfig) {
		cfg.clientMechFactory = func(socketType string) (security.ClientMechanism, error) {
			o := opts
			o.LocalMetadata = toWireMetadata(cfg.localMeta(socketType))
			return curve.NewClient(o)
		}
		cfg.serverMechFactory = func(socketType string) (security.Mechanism, error) {
			return nil, ErrSecurityMismatch
		}
	}
}

// WithCURVEServer configures CURVE server-side keys (Bind side).
func WithCURVEServer(opts curve.ServerOptions) Option {
	return func(cfg *socketConfig) {
		cfg.serverMechFactory = func(socketType string) (security.Mechanism, error) {
			o := opts
			o.LocalMetadata = toWireMetadata(cfg.localMeta(socketType))
			return curve.NewServer(o)
		}
		cfg.clientMechFactory = func(socketType string) (security.ClientMechanism, error) {
			return nil, ErrSecurityMismatch
		}
	}
}

// WithIdentity sets the local socket identity (Identity metadata property).
// Panics if len(id) == 0 or len(id) > 255.
func WithIdentity(id []byte) Option {
	if len(id) == 0 || len(id) > 255 {
		panic("zmq4: WithIdentity: id must be 1..255 bytes")
	}
	idCopy := append([]byte(nil), id...)
	return func(cfg *socketConfig) {
		cfg.identity = idCopy
	}
}

// WithHandshakeTimeout sets the per-connection handshake deadline.
// Default: 5 s. Panics if d <= 0.
func WithHandshakeTimeout(d time.Duration) Option {
	if d <= 0 {
		panic("zmq4: WithHandshakeTimeout: duration must be > 0")
	}
	return func(cfg *socketConfig) {
		cfg.handshakeTimeout = d
	}
}

// WithSndHWM sets the outbound pipe queue capacity. Panics if n <= 0.
func WithSndHWM(n int) Option {
	if n <= 0 {
		panic("zmq4: WithSndHWM: n must be > 0")
	}
	return func(cfg *socketConfig) { cfg.sndHWM = n }
}

// WithRcvHWM sets the inbound pipe queue capacity. Panics if n <= 0.
func WithRcvHWM(n int) Option {
	if n <= 0 {
		panic("zmq4: WithRcvHWM: n must be > 0")
	}
	return func(cfg *socketConfig) { cfg.rcvHWM = n }
}

// WithSndHWMPolicy overrides the default overflow policy for this socket type.
func WithSndHWMPolicy(p OverflowPolicy) Option {
	return func(cfg *socketConfig) { cfg.sndOverflow = p }
}

// withSndOverflow is an internal option used by socket-type constructors
// (e.g. NewPUB) to set a type-appropriate default before user opts are applied.
func withSndOverflow(p OverflowPolicy) Option {
	return func(cfg *socketConfig) { cfg.sndOverflow = p }
}

// WithZAPDomain configures ZAP authentication for this socket's server side.
// r must be started (via zap.NewRouter) before passing it here, and must
// outlive the socket. domain is a string identifying the security domain
// sent to the ZAP handler; use "" for the default domain.
//
// WithZAPDomain is additive: it may be combined with WithPLAINServer,
// WithCURVEServer, or WithNULL (the default). When ZAP is configured, it
// takes precedence over any local Authenticator / Authorizer callback.
func WithZAPDomain(r *zmqzap.Router, domain string) Option {
	return func(cfg *socketConfig) {
		cfg.zapCaller = zmqzap.NewClient(r)
		cfg.zapDomain = domain
	}
}

// WithMonitor wires ch as the monitoring channel for this socket. The socket
// emits a SocketEvent for each lifecycle transition (bind, connect, handshake,
// disconnect, close). When the socket closes it emits EventMonitorStopped and
// then closes ch, so consumers may use:
//
//	for ev := range ch { … }
//
// The caller owns ch and must not close it. Events are dropped without blocking
// when ch is full; use a buffered channel sized to the expected burst. A nil ch
// is a no-op.
func WithMonitor(ch chan<- SocketEvent) Option {
	return func(cfg *socketConfig) { cfg.monitorCh = ch }
}
