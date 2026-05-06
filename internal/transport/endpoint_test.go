package transport

import (
	"errors"
	"strings"
	"testing"
)

func TestParseEndpointValid(t *testing.T) {
	cases := []struct {
		in           string
		wantScheme   string
		wantAddr     string
	}{
		{"tcp://127.0.0.1:5555", "tcp", "127.0.0.1:5555"},
		{"tcp://[::1]:5555", "tcp", "[::1]:5555"},
		{"tcp://*:5555", "tcp", "*:5555"},
		{"tcp://*:*", "tcp", "*:*"},
		{"tcp://example.com:80", "tcp", "example.com:80"},
		{"ipc:///tmp/zmq.sock", "ipc", "/tmp/zmq.sock"},
		{"ipc://relative/path.sock", "ipc", "relative/path.sock"},
		{"inproc://my-service", "inproc", "my-service"},
		{"inproc://x", "inproc", "x"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			s, a, err := ParseEndpoint(tc.in)
			if err != nil {
				t.Fatalf("ParseEndpoint(%q) error = %v", tc.in, err)
			}
			if s != tc.wantScheme || a != tc.wantAddr {
				t.Fatalf("ParseEndpoint(%q) = (%q,%q), want (%q,%q)",
					tc.in, s, a, tc.wantScheme, tc.wantAddr)
			}
		})
	}
}

func TestParseEndpointInvalid(t *testing.T) {
	cases := []struct {
		in     string
		wantIs error
	}{
		{"", ErrEndpointMalformed},
		{"no-scheme", ErrEndpointMalformed},
		{"://addr", ErrEndpointMalformed},
		{"tcp://", ErrEndpointMalformed},
		{"unknown://addr", ErrSchemeUnknown},
		{"http://example.com", ErrSchemeUnknown},
		{"TCP://127.0.0.1:5555", ErrSchemeUnknown}, // case-sensitive
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			_, _, err := ParseEndpoint(tc.in)
			if err == nil {
				t.Fatalf("ParseEndpoint(%q) = nil, want error", tc.in)
			}
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("ParseEndpoint(%q) err = %v, want errors.Is(%v)", tc.in, err, tc.wantIs)
			}
			if !strings.HasPrefix(err.Error(), "transport:") {
				t.Fatalf("err = %q; want prefix \"transport:\"", err.Error())
			}
		})
	}
}
