//go:build !linux

package tcp

import "testing"

// TCP_NODELAY syscall introspection is only verified on Linux. On other
// platforms we trust that SetNoDelay(true) was called; behavioural
// timing tests are too flaky for CI.
func TestNoDelayPlatformSkip(t *testing.T) {
	t.Skip("TCP_NODELAY syscall verification is Linux-only")
}
