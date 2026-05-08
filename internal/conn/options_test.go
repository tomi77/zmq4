package conn

import (
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestNewConfigDefaults(t *testing.T) {
	c := newConfig(nil)
	if c.maxMetadataSize != defaultMaxMetadataSize {
		t.Errorf("maxMetadataSize = %d, want %d", c.maxMetadataSize, defaultMaxMetadataSize)
	}
	if c.maxHandshakeCommandSize != defaultMaxHandshakeCommandSize {
		t.Errorf("maxHandshakeCommandSize = %d, want %d", c.maxHandshakeCommandSize, defaultMaxHandshakeCommandSize)
	}
	if c.maxFrameBodySize != wire.MaxFrameBodySize {
		t.Errorf("maxFrameBodySize = %d, want %d", c.maxFrameBodySize, wire.MaxFrameBodySize)
	}
}

func TestWithMaxMetadataSize(t *testing.T) {
	c := newConfig([]Option{WithMaxMetadataSize(1024)})
	if c.maxMetadataSize != 1024 {
		t.Errorf("maxMetadataSize = %d, want 1024", c.maxMetadataSize)
	}
}

func TestWithMaxHandshakeCommandSize(t *testing.T) {
	c := newConfig([]Option{WithMaxHandshakeCommandSize(2048)})
	if c.maxHandshakeCommandSize != 2048 {
		t.Errorf("maxHandshakeCommandSize = %d, want 2048", c.maxHandshakeCommandSize)
	}
}

func TestWithMaxFrameBodySize(t *testing.T) {
	c := newConfig([]Option{WithMaxFrameBodySize(int64(1 << 20))})
	if c.maxFrameBodySize != int64(1<<20) {
		t.Errorf("maxFrameBodySize = %d, want %d", c.maxFrameBodySize, 1<<20)
	}
}

func TestOptionsPanicOnNonPositive(t *testing.T) {
	cases := []struct {
		name string
		fn   func()
	}{
		{"WithMaxMetadataSize(0)", func() { WithMaxMetadataSize(0) }},
		{"WithMaxMetadataSize(-1)", func() { WithMaxMetadataSize(-1) }},
		{"WithMaxHandshakeCommandSize(0)", func() { WithMaxHandshakeCommandSize(0) }},
		{"WithMaxHandshakeCommandSize(-1)", func() { WithMaxHandshakeCommandSize(-1) }},
		{"WithMaxFrameBodySize(0)", func() { WithMaxFrameBodySize(0) }},
		{"WithMaxFrameBodySize(-1)", func() { WithMaxFrameBodySize(-1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected panic, got none")
				}
			}()
			tc.fn()
		})
	}
}
