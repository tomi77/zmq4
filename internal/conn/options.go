package conn

import "github.com/tomi77/zmq4/internal/wire"

// config holds resolved F4 limits for one handshake. Built from defaults
// and Option callbacks at the entry of ClientHandshake / ServerHandshake.
type config struct {
	maxMetadataSize         int
	maxHandshakeCommandSize int
	maxFrameBodySize        int64
}

// Defaults match spec §3.2.
const (
	defaultMaxMetadataSize         = 8 * 1024
	defaultMaxHandshakeCommandSize = 64 * 1024
)

// newConfig builds a config from defaults plus opts. Each Option
// receives the partially-built config and mutates it in place.
func newConfig(opts []Option) *config {
	c := &config{
		maxMetadataSize:         defaultMaxMetadataSize,
		maxHandshakeCommandSize: defaultMaxHandshakeCommandSize,
		maxFrameBodySize:        wire.MaxFrameBodySize,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Option configures a handshake. Defaults: max-metadata=8 KiB,
// max-handshake-cmd=64 KiB, max-frame-body=wire.MaxFrameBodySize.
type Option func(*config)

// WithMaxMetadataSize caps the total wire-level body of metadata-bearing
// handshake commands (READY for all mechanisms; INITIATE for
// PLAIN/CURVE). Default 8192. Panics if n <= 0. Spec §6.2.
func WithMaxMetadataSize(n int) Option {
	if n <= 0 {
		panic("conn: WithMaxMetadataSize: n must be positive")
	}
	return func(c *config) { c.maxMetadataSize = n }
}

// WithMaxHandshakeCommandSize caps the body of any single handshake
// command frame. Default 65536. Panics if n <= 0. Plumbed into the
// transient handshake FrameReader. Spec §4.2.
func WithMaxHandshakeCommandSize(n int) Option {
	if n <= 0 {
		panic("conn: WithMaxHandshakeCommandSize: n must be positive")
	}
	return func(c *config) { c.maxHandshakeCommandSize = n }
}

// WithMaxFrameBodySize caps the body of post-handshake frames. Default
// wire.MaxFrameBodySize. Plumbed into the persistent post-handshake
// FrameReader. Panics if n <= 0. Spec §4.2.
func WithMaxFrameBodySize(n int64) Option {
	if n <= 0 {
		panic("conn: WithMaxFrameBodySize: n must be positive")
	}
	return func(c *config) { c.maxFrameBodySize = n }
}
