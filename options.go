package zmq4

import (
	"time"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/curve"
	"github.com/tomi77/zmq4/internal/security/null"
	"github.com/tomi77/zmq4/internal/security/plain"
	"github.com/tomi77/zmq4/internal/wire"
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
// Socket-Type first (as required by ZMTP) and then remaining keys in
// iteration order.
func toWireMetadata(m map[string]string) wire.Metadata {
	md := make(wire.Metadata, 0, len(m))
	// Socket-Type first per convention.
	if v, ok := m["Socket-Type"]; ok {
		md = append(md, wire.MetadataProperty{
			Name:  []byte("Socket-Type"),
			Value: []byte(v),
		})
	}
	for k, v := range m {
		if k == "Socket-Type" {
			continue
		}
		md = append(md, wire.MetadataProperty{
			Name:  []byte(k),
			Value: []byte(v),
		})
	}
	return md
}

// Option configures a socket at construction time.
type Option func(*socketConfig)

func newSocketConfig(opts []Option) *socketConfig {
	cfg := &socketConfig{
		handshakeTimeout: defaultHandshakeTimeout,
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
