package wire

import "testing"

func TestFrameWireSize(t *testing.T) {
	cases := []struct {
		name string
		f    Frame
		want int
	}{
		{"empty-message", Frame{Kind: FrameMessage, Body: nil}, 2},                       // 1 flag + 1 size
		{"short-message-1", Frame{Kind: FrameMessage, Body: []byte{0xAA}}, 3},            // 1+1+1
		{"short-boundary-255", Frame{Kind: FrameMessage, Body: make([]byte, 255)}, 257},  // 1+1+255
		{"long-boundary-256", Frame{Kind: FrameMessage, Body: make([]byte, 256)}, 265},   // 1+8+256
		{"empty-command", Frame{Kind: FrameCommand, Body: nil}, 2},
		{"short-command-1", Frame{Kind: FrameCommand, Body: []byte{0xAA}}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.f.WireSize(); got != c.want {
				t.Fatalf("got %d, want %d", got, c.want)
			}
		})
	}
}
