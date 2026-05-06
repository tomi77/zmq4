# F3 Transports Implementation Plan

> **For Claude:** REQUIRED: Use `superpowers:subagent-driven-development` to implement this plan. Steps use checkbox (`- [x]`) syntax for tracking. Each task is one commit.

**Goal:** Implement `internal/transport` per `docs/specs/03-transports.md`: pure-Go listener and dialer abstractions for `tcp`, `ipc` (Unix domain sockets), and `inproc` (in-process pipes via `net.Pipe`). No I/O is performed at higher layers in this phase — only `net.Conn`-class transport plumbing.

**Architecture:** L3 sits below F1 (wire) and F2 (security) and is consumed by F4 (connection layer). Public surface is two opener functions (`transport.Listen`, `transport.Dial`) plus `transport.ParseEndpoint`, all returning stdlib `net.Conn` / `net.Listener`. Per-scheme logic is isolated in `internal/transport/{tcp,ipc,inproc}` subpackages, each callable directly with a scheme-native address (no URI dependency). The top-level package owns URI parsing and dispatch.

**Tech Stack:** Pure Go 1.26, stdlib only — `net`, `context`, `sync`, `os`, `errors`, `fmt`, `strings`, `strconv`, `syscall` (only inside test helpers). No external deps. No long-lived goroutines except what `net.Pipe` itself spawns; one-shot test goroutines are fine.

**Decisions baked into the plan:**
- inproc `Dial` blocks on `ctx` until a matching `Listen`. FIFO drain order on bind.
- inproc backed by `net.Pipe()`; deadline support is first-class via stdlib.
- `TCP_NODELAY` set unconditionally on every dialed and accepted TCP conn.
- `ipc` package source files guarded by `//go:build !windows`; sibling `ipc_windows.go` returns `ErrSchemeUnknown` from both openers.
- IPC mode `0600` post-`Listen`; `SetUnlinkOnClose(true)` always.
- Three sentinels (`ErrEndpointMalformed`, `ErrSchemeUnknown`, `ErrInprocAlreadyBound`) live at the top-level facade. Subpackages wrap with these via `fmt.Errorf("...: %w", err)`.
- **Do NOT run `modernize -fix` per task.** Only at the final done-criteria sweep (Task 18) before tagging. The plan's per-task verification steps stop at `go vet` + `go test -race`.
- Phase tag: `phase-3-transport-complete` after Task 18.
- Test fixtures use `t.TempDir()` (ipc paths) and `t.Name()`-derived strings (inproc names) to avoid cross-test collisions.
- Time-based assertions use generous bounds to keep tests stable on slow CI; the inproc "blocks until bind" case uses 50 ms guard, deadline checks use 25 ms grace.

---

## Chunk 1: Package skeleton, sentinels, endpoint parser

### Task 1: Package skeleton + sentinels + parser

**Files:**
- Create: `internal/transport/doc.go`
- Create: `internal/transport/errors.go`
- Create: `internal/transport/endpoint.go`
- Create: `internal/transport/endpoint_test.go`

- [x] **Step 1: Write `internal/transport/doc.go`**

```go
// Package transport implements the F3 transport layer for ZMTP.
//
// It provides pure-Go listener and dialer abstractions for the three
// ZMTP-supported transports — tcp, ipc (Unix domain sockets), and
// inproc (in-process pipes) — over the standard net package.
//
// The public surface is two opener functions plus a URI parser:
//
//	func Listen(ctx, endpoint) (net.Listener, error)
//	func Dial(ctx, endpoint) (net.Conn, error)
//	func ParseEndpoint(endpoint) (scheme, addr, err)
//
// All callers receive stdlib net.Conn / net.Listener. The concrete
// types per scheme are documented at the call sites but MUST NOT be
// type-switched for behaviour.
//
// See docs/specs/03-transports.md for the full specification.
package transport
```

- [x] **Step 2: Write `internal/transport/errors.go`**

```go
package transport

import "errors"

// ErrEndpointMalformed is returned by ParseEndpoint and the subpackage
// openers when the endpoint URI or scheme-native address is syntactically
// invalid.
var ErrEndpointMalformed = errors.New("transport: malformed endpoint")

// ErrSchemeUnknown is returned by ParseEndpoint for any scheme outside
// {tcp, ipc, inproc}, and by the ipc subpackage on Windows where ipc is
// not implemented.
var ErrSchemeUnknown = errors.New("transport: unknown scheme")

// ErrInprocAlreadyBound is returned by the inproc subpackage's Listen when
// the requested name is already bound by another live listener.
var ErrInprocAlreadyBound = errors.New("transport: inproc name already bound")
```

- [x] **Step 3: Write `internal/transport/endpoint.go`**

```go
package transport

import (
	"fmt"
	"strings"
)

// ParseEndpoint splits a ZMTP endpoint URI of the form "<scheme>://<addr>"
// into its scheme and scheme-native address parts.
//
// The scheme MUST be one of "tcp", "ipc", "inproc". The addr is returned
// verbatim; per-scheme validation (port range, path/name non-emptiness,
// IPv6 brackets) is the subpackage's responsibility.
//
// Returns ErrEndpointMalformed for missing "://", empty scheme, or empty
// addr. Returns ErrSchemeUnknown for any other scheme.
func ParseEndpoint(endpoint string) (scheme, addr string, err error) {
	i := strings.Index(endpoint, "://")
	if i <= 0 || i+3 == len(endpoint) {
		return "", "", fmt.Errorf("%w: %q", ErrEndpointMalformed, endpoint)
	}
	scheme, addr = endpoint[:i], endpoint[i+3:]
	switch scheme {
	case "tcp", "ipc", "inproc":
		return scheme, addr, nil
	default:
		return "", "", fmt.Errorf("%w: scheme %q", ErrSchemeUnknown, scheme)
	}
}
```

- [x] **Step 4: Write `internal/transport/endpoint_test.go`**

```go
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
```

- [x] **Step 5: Run tests**

Run: `go test -race ./internal/transport/...`

Expected: PASS (all `TestParseEndpoint*` subtests).

- [x] **Step 6: `go vet`**

Run: `go vet ./internal/transport/...`

Expected: no output.

- [x] **Step 7: Commit**

```bash
git add internal/transport/doc.go internal/transport/errors.go \
        internal/transport/endpoint.go internal/transport/endpoint_test.go
git commit -m "transport: package skeleton + endpoint parser"
```

---

## Chunk 2: TCP subpackage

### Task 2: TCP package — Listen / Dial round-trip

**Files:**
- Create: `internal/transport/tcp/doc.go`
- Create: `internal/transport/tcp/tcp.go`
- Create: `internal/transport/tcp/tcp_test.go`

- [x] **Step 1: Write `internal/transport/tcp/doc.go`**

```go
// Package tcp implements the tcp:// transport for F3.
//
// Listen translates an address ("host:port"; host may be "*" for
// wildcard, port may be "*" for ephemeral) into a *net.TCPListener
// whose Accept method returns conns with TCP_NODELAY set.
//
// Dial honours the supplied context for DNS lookup and connect.
//
// Address grammar is the per-scheme subset of docs/specs/03-transports.md
// §3 (no URI prefix, no scheme); URI parsing lives in the parent
// transport package.
package tcp
```

- [x] **Step 2: Write `internal/transport/tcp/tcp.go`**

```go
package tcp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/tomi77/zmq4/internal/transport"
)

// Listen opens a TCP listener for addr. addr is "host:port"; host may be
// "*" (rewritten to "0.0.0.0") and port may be "*" (rewritten to "0",
// i.e. ephemeral; read the actual port via lis.Addr()).
//
// The returned listener wraps *net.TCPListener so that every accepted
// connection has TCP_NODELAY set.
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	resolved, err := resolveBindAddr(addr)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", resolved)
	if err != nil {
		return nil, fmt.Errorf("transport/tcp: listen %q: %w", addr, err)
	}
	tl, ok := lis.(*net.TCPListener)
	if !ok {
		// net.ListenConfig should always return *net.TCPListener for tcp;
		// be defensive in case stdlib changes.
		return lis, nil
	}
	return &nodelayListener{TCPListener: tl}, nil
}

// Dial opens a TCP connection to addr ("host:port") with TCP_NODELAY set.
// ctx bounds DNS resolution and connect.
func Dial(ctx context.Context, addr string) (net.Conn, error) {
	if err := validateDialAddr(addr); err != nil {
		return nil, err
	}
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/tcp: dial %q: %w", addr, err)
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return c, nil
}

// nodelayListener is a *net.TCPListener wrapper whose Accept applies
// SetNoDelay(true) before returning.
type nodelayListener struct {
	*net.TCPListener
}

func (l *nodelayListener) Accept() (net.Conn, error) {
	c, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = c.SetNoDelay(true)
	return c, nil
}

func resolveBindAddr(addr string) (string, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "*" {
		host = "0.0.0.0"
	}
	if port == "*" {
		port = "0"
	} else {
		// Validate numeric port; reject 0 (only "*" denotes ephemeral)
		// and out-of-range values.
		n, perr := strconv.Atoi(port)
		if perr != nil || n <= 0 || n > 65535 {
			return "", fmt.Errorf("%w: tcp port %q", transport.ErrEndpointMalformed, port)
		}
	}
	if host == "" {
		return "", fmt.Errorf("%w: tcp host empty in %q", transport.ErrEndpointMalformed, addr)
	}
	return net.JoinHostPort(host, port), nil
}

func validateDialAddr(addr string) error {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "*" {
		return fmt.Errorf("%w: tcp dial host %q", transport.ErrEndpointMalformed, host)
	}
	if port == "*" {
		return fmt.Errorf("%w: tcp dial port may not be wildcard in %q", transport.ErrEndpointMalformed, addr)
	}
	n, perr := strconv.Atoi(port)
	if perr != nil || n <= 0 || n > 65535 {
		return fmt.Errorf("%w: tcp port %q", transport.ErrEndpointMalformed, port)
	}
	return nil
}

// splitHostPort handles bracketed IPv6 ("[::1]:5555") and bare host:port.
func splitHostPort(addr string) (host, port string, err error) {
	if strings.HasPrefix(addr, "[") {
		// Bracketed IPv6: "[v6]:port"
		end := strings.LastIndex(addr, "]")
		if end < 0 || end+1 >= len(addr) || addr[end+1] != ':' {
			return "", "", fmt.Errorf("%w: malformed IPv6 in %q", transport.ErrEndpointMalformed, addr)
		}
		return addr[:end+1], addr[end+2:], nil
	}
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", "", fmt.Errorf("%w: missing :port in %q", transport.ErrEndpointMalformed, addr)
	}
	return addr[:i], addr[i+1:], nil
}
```

- [x] **Step 3: Write baseline test `internal/transport/tcp/tcp_test.go`**

```go
package tcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestListenDialRoundTrip(t *testing.T) {
	ctx := context.Background()
	lis, err := Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	addr := lis.Addr().String()
	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, e := lis.Accept()
		ch <- accepted{c, e}
	}()

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	dc, err := Dial(dialCtx, addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dc.Close()

	got := <-ch
	if got.err != nil {
		t.Fatalf("Accept: %v", got.err)
	}
	defer got.c.Close()

	want := []byte("hello over tcp")
	if _, err := dc.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(got.c, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("recv = %q, want %q", buf, want)
	}
}

func TestCloseUnblocksAccept(t *testing.T) {
	ctx := context.Background()
	lis, err := Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, e := lis.Accept()
		errCh <- e
	}()

	time.Sleep(20 * time.Millisecond) // let Accept park
	if err := lis.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case e := <-errCh:
		if e == nil {
			t.Fatalf("Accept after Close = nil error, want non-nil")
		}
	case <-time.After(time.Second):
		t.Fatalf("Accept did not unblock within 1s")
	}
}

func TestListenAlreadyBound(t *testing.T) {
	ctx := context.Background()
	lis1, err := Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	defer lis1.Close()
	addr := lis1.Addr().String()

	_, err = Listen(ctx, addr)
	if err == nil {
		t.Fatalf("second Listen on %s = nil error, want EADDRINUSE-class", addr)
	}
	// Wrapped via fmt.Errorf("transport/tcp: listen ...: %w", ...).
	// We don't pin syscall.EADDRINUSE because OS-level errno wrapping
	// varies; just verify the wrapper prefix.
	if !strings.Contains(err.Error(), "transport/tcp:") {
		t.Fatalf("err = %q, want \"transport/tcp:\" prefix", err.Error())
	}
}

func TestCloseUnblocksRead(t *testing.T) {
	ctx := context.Background()
	lis, _ := Listen(ctx, "127.0.0.1:0")
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()
	dc, _ := Dial(ctx, lis.Addr().String())
	got := <-ch

	// Peer (got.c) closes; reader on dc must observe EOF.
	_ = got.c.Close()
	buf := make([]byte, 4)
	_, err := dc.Read(buf)
	if err == nil {
		t.Fatalf("Read after peer close = nil, want EOF")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read err = %v, want io.EOF", err)
	}
	dc.Close()
}

func TestReadDeadline(t *testing.T) {
	ctx := context.Background()
	lis, _ := Listen(ctx, "127.0.0.1:0")
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()

	dc, _ := Dial(ctx, lis.Addr().String())
	defer dc.Close()
	got := <-ch
	defer got.c.Close()

	_ = dc.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buf := make([]byte, 4)
	_, err := dc.Read(buf)
	if err == nil {
		t.Fatalf("Read with past deadline = nil, want timeout")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read err = %v, want net.Error{Timeout=true}", err)
	}
}
```

- [x] **Step 4: Run tests**

Run: `go test -race ./internal/transport/tcp/...`

Expected: PASS (5 tests: round-trip, AlreadyBound, CloseUnblocksAccept, CloseUnblocksRead, ReadDeadline).

- [x] **Step 5: `go vet`**

Run: `go vet ./internal/transport/tcp/...`

Expected: no output.

- [x] **Step 6: Commit**

```bash
git add internal/transport/tcp/
git commit -m "transport/tcp: Listen + Dial baseline (round-trip, already-bound, close-unblocks)"
```

---

### Task 3: TCP wildcard host, ephemeral port, IPv6

**Files:**
- Modify: `internal/transport/tcp/tcp_test.go` (append new tests)

- [x] **Step 1: Append `TestListenWildcardHost`**

```go
func TestListenWildcardHost(t *testing.T) {
	ctx := context.Background()
	lis, err := Listen(ctx, "*:0")
	if err != nil {
		t.Fatalf("Listen(*:0): %v", err)
	}
	defer lis.Close()
	a, ok := lis.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Addr type = %T, want *net.TCPAddr", lis.Addr())
	}
	if !a.IP.IsUnspecified() {
		t.Fatalf("bind IP = %v, want 0.0.0.0", a.IP)
	}
	if a.Port == 0 {
		t.Fatalf("ephemeral port not assigned: %v", a)
	}
}
```

- [x] **Step 2: Append `TestListenWildcardPort`**

```go
func TestListenWildcardPort(t *testing.T) {
	ctx := context.Background()
	lis, err := Listen(ctx, "127.0.0.1:*")
	if err != nil {
		t.Fatalf("Listen(127.0.0.1:*): %v", err)
	}
	defer lis.Close()
	a := lis.Addr().(*net.TCPAddr)
	if a.Port == 0 {
		t.Fatalf("ephemeral port = 0; expected non-zero")
	}
}
```

- [x] **Step 3: Append `TestListenIPv6Bracket` and `TestDialIPv6`**

```go
func TestListenIPv6Bracket(t *testing.T) {
	ctx := context.Background()
	lis, err := Listen(ctx, "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 not available on this host: %v", err)
	}
	defer lis.Close()
	a := lis.Addr().(*net.TCPAddr)
	if !a.IP.Equal(net.ParseIP("::1")) {
		t.Fatalf("bind IP = %v, want ::1", a.IP)
	}
}

func TestDialIPv6(t *testing.T) {
	ctx := context.Background()
	lis, err := Listen(ctx, "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 not available on this host: %v", err)
	}
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()

	dc, err := Dial(ctx, lis.Addr().String())
	if err != nil {
		t.Fatalf("Dial(%s): %v", lis.Addr(), err)
	}
	defer dc.Close()
	got := <-ch
	if got.err != nil {
		t.Fatalf("Accept: %v", got.err)
	}
	got.c.Close()
}
```

- [x] **Step 4: Append `TestDialMalformed`**

```go
func TestDialMalformed(t *testing.T) {
	cases := []string{
		"",                   // empty
		"127.0.0.1",          // no port
		"127.0.0.1:0",        // numeric 0 port (only "*" denotes ephemeral)
		"127.0.0.1:99999",    // out of range
		"127.0.0.1:abc",      // non-numeric
		"*:5555",             // wildcard host on Dial
		"127.0.0.1:*",        // wildcard port on Dial
		"[::1:5555",          // unclosed bracket
	}
	ctx := context.Background()
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			_, err := Dial(ctx, in)
			if err == nil {
				t.Fatalf("Dial(%q) = nil error, want ErrEndpointMalformed", in)
			}
			if !errors.Is(err, transport.ErrEndpointMalformed) {
				t.Fatalf("err = %v, want errors.Is(ErrEndpointMalformed)", err)
			}
		})
	}
}
```

- [x] **Step 5: Update imports**

Test file should now import `"github.com/tomi77/zmq4/internal/transport"`.

- [x] **Step 6: Run tests**

Run: `go test -race ./internal/transport/tcp/...`

Expected: PASS (TestDialMalformed has 8 subtests; IPv6 tests may skip on hosts without IPv6).

- [x] **Step 7: Commit**

```bash
git add internal/transport/tcp/tcp_test.go
git commit -m "transport/tcp: wildcard host/port, IPv6, malformed-addr coverage"
```

---

### Task 4: TCP `TCP_NODELAY` assertion

**Files:**
- Create: `internal/transport/tcp/nodelay_linux_test.go`
- Create: `internal/transport/tcp/nodelay_other_test.go`

- [x] **Step 1: Linux-tagged test asserting `TCP_NODELAY` flag**

`internal/transport/tcp/nodelay_linux_test.go`:

```go
//go:build linux

package tcp

import (
	"context"
	"net"
	"syscall"
	"testing"
)

func tcpNoDelay(c *net.TCPConn) (bool, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return false, err
	}
	var v int
	var serr error
	cerr := rc.Control(func(fd uintptr) {
		v, serr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY)
	})
	if cerr != nil {
		return false, cerr
	}
	if serr != nil {
		return false, serr
	}
	return v != 0, nil
}

func TestNoDelaySetOnDial(t *testing.T) {
	ctx := context.Background()
	lis, _ := Listen(ctx, "127.0.0.1:0")
	defer lis.Close()
	go func() {
		c, _ := lis.Accept()
		if c != nil {
			c.Close()
		}
	}()
	dc, err := Dial(ctx, lis.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dc.Close()
	tc := dc.(*net.TCPConn)
	on, err := tcpNoDelay(tc)
	if err != nil {
		t.Fatalf("tcpNoDelay: %v", err)
	}
	if !on {
		t.Fatalf("TCP_NODELAY not set after Dial")
	}
}

func TestNoDelaySetOnAccept(t *testing.T) {
	ctx := context.Background()
	lis, _ := Listen(ctx, "127.0.0.1:0")
	defer lis.Close()
	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()
	dc, _ := Dial(ctx, lis.Addr().String())
	defer dc.Close()
	got := <-ch
	if got.err != nil {
		t.Fatalf("Accept: %v", got.err)
	}
	defer got.c.Close()
	tc := got.c.(*net.TCPConn)
	on, err := tcpNoDelay(tc)
	if err != nil {
		t.Fatalf("tcpNoDelay: %v", err)
	}
	if !on {
		t.Fatalf("TCP_NODELAY not set on accepted conn")
	}
}
```

- [x] **Step 2: Non-Linux placeholder**

`internal/transport/tcp/nodelay_other_test.go`:

```go
//go:build !linux

package tcp

import "testing"

// TCP_NODELAY syscall introspection is only verified on Linux. On other
// platforms we trust that SetNoDelay(true) was called; behavioural
// timing tests are too flaky for CI.
func TestNoDelayPlatformSkip(t *testing.T) {
	t.Skip("TCP_NODELAY syscall verification is Linux-only")
}
```

- [x] **Step 3: Run tests**

Run: `go test -race ./internal/transport/tcp/...`

Expected: PASS on Linux (2 NODELAY tests run); SKIP on non-Linux.

- [x] **Step 4: Commit**

```bash
git add internal/transport/tcp/nodelay_linux_test.go internal/transport/tcp/nodelay_other_test.go
git commit -m "transport/tcp: TCP_NODELAY syscall assertions (linux)"
```

---

## Chunk 3: IPC subpackage

### Task 5: IPC package — Listen / Dial round-trip (`!windows`)

**Files:**
- Create: `internal/transport/ipc/doc.go`
- Create: `internal/transport/ipc/ipc.go`
- Create: `internal/transport/ipc/ipc_test.go`

- [x] **Step 1: Write `internal/transport/ipc/doc.go`**

```go
// Package ipc implements the ipc:// transport for F3 — Unix domain
// sockets on Unix platforms.
//
// On Windows the package compiles to stubs returning
// transport.ErrSchemeUnknown; a real Windows implementation (Named
// Pipes) is deferred — see docs/specs/03-transports.md §9 Open
// Question 7.
//
// Listen creates the socket file with mode 0600 and SetUnlinkOnClose(true).
// A small chmod-window between bind and chmod is documented in the spec.
package ipc
```

- [x] **Step 2: Write `internal/transport/ipc/ipc.go` (Unix)**

```go
//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/tomi77/zmq4/internal/transport"
)

// Listen opens a Unix domain socket listener at path. After bind the
// socket file is chmod'd to 0600. SetUnlinkOnClose(true) is enabled so
// Close removes the file. ctx is currently unused (Unix bind does not
// resolve names).
func Listen(_ context.Context, path string) (*net.UnixListener, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty ipc path", transport.ErrEndpointMalformed)
	}
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	lis, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/ipc: listen %q: %w", path, err)
	}
	lis.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("transport/ipc: chmod %q: %w", path, err)
	}
	return lis, nil
}

// Dial opens a Unix domain connection to path. ctx bounds the connect.
func Dial(ctx context.Context, path string) (*net.UnixConn, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty ipc path", transport.ErrEndpointMalformed)
	}
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("transport/ipc: dial %q: %w", path, err)
	}
	return c.(*net.UnixConn), nil
}
```

- [x] **Step 3: Write `internal/transport/ipc/ipc_test.go` (Unix)**

```go
//go:build !windows

package ipc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomi77/zmq4/internal/transport"
)

func newSocketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "zmq.sock")
}

func TestListenDialRoundTrip(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, err := Listen(ctx, path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()

	dc, err := Dial(ctx, path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dc.Close()
	got := <-ch
	if got.err != nil {
		t.Fatalf("Accept: %v", got.err)
	}
	defer got.c.Close()

	want := []byte("hello over ipc")
	if _, err := dc.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(got.c, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("recv = %q, want %q", buf, want)
	}
}

func TestListenEmptyPath(t *testing.T) {
	ctx := context.Background()
	_, err := Listen(ctx, "")
	if !errors.Is(err, transport.ErrEndpointMalformed) {
		t.Fatalf("Listen(\"\") err = %v, want ErrEndpointMalformed", err)
	}
}

func TestDialEmptyPath(t *testing.T) {
	ctx := context.Background()
	_, err := Dial(ctx, "")
	if !errors.Is(err, transport.ErrEndpointMalformed) {
		t.Fatalf("Dial(\"\") err = %v, want ErrEndpointMalformed", err)
	}
}

func TestDeadline(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, _ := Listen(ctx, path)
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()
	dc, _ := Dial(ctx, path)
	defer dc.Close()
	got := <-ch
	defer got.c.Close()

	_ = dc.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buf := make([]byte, 4)
	_, err := dc.Read(buf)
	if err == nil {
		t.Fatalf("Read with past deadline = nil, want timeout")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read err = %v, want net.Error{Timeout=true}", err)
	}
	_ = os.Stat(path) // touch to silence unused-import vet on go1.x; harmless
}
```

- [x] **Step 4: Run tests**

Run: `go test -race ./internal/transport/ipc/...`

Expected: PASS on Unix.

- [x] **Step 5: Commit**

```bash
git add internal/transport/ipc/
git commit -m "transport/ipc: Listen + Dial round-trip (!windows)"
```

---

### Task 6: IPC unlink-on-close + chmod 0600

**Files:**
- Modify: `internal/transport/ipc/ipc_test.go` (append)

- [x] **Step 1: Append `TestUnlinkOnClose`**

```go
func TestUnlinkOnClose(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, err := Listen(ctx, path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("socket file missing after Listen: %v", err)
	}
	if err := lis.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket file still exists after Close: stat err = %v", err)
	}
}
```

- [x] **Step 2: Append `TestFileMode0600`**

```go
func TestFileMode0600(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, err := Listen(ctx, path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode = %o, want 0600", mode)
	}
}
```

- [x] **Step 3: Append `TestStaleSocketRebind`**

Add `"strings"` to the imports of `ipc_test.go`, then append:

```go
func TestStaleSocketRebind(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)

	// Simulate stale socket by creating a regular file at the path (a
	// crashed process would leave the actual socket node behind; for our
	// purposes a regular file produces the same EADDRINUSE-class failure
	// from net.ListenUnix).
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create stale: %v", err)
	}
	f.Close()

	_, err = Listen(ctx, path)
	if err == nil {
		t.Fatalf("Listen on stale path = nil, want bind failure")
	}
	if !strings.Contains(err.Error(), "transport/ipc:") {
		t.Fatalf("err = %q, want \"transport/ipc:\" prefix", err.Error())
	}
}
```

- [x] **Step 4: Append `TestCloseUnblocksRead`**

```go
func TestCloseUnblocksRead(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, _ := Listen(ctx, path)
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()
	dc, _ := Dial(ctx, path)
	got := <-ch

	_ = got.c.Close()
	buf := make([]byte, 4)
	_, err := dc.Read(buf)
	if err == nil {
		t.Fatalf("Read after peer close = nil, want EOF")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read err = %v, want io.EOF", err)
	}
	dc.Close()
}
```

- [x] **Step 5: Append `TestCloseUnblocksAccept`**

```go
func TestCloseUnblocksAccept(t *testing.T) {
	ctx := context.Background()
	path := newSocketPath(t)
	lis, err := Listen(ctx, path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, e := lis.Accept()
		errCh <- e
	}()
	time.Sleep(20 * time.Millisecond)
	_ = lis.Close()
	select {
	case e := <-errCh:
		if e == nil {
			t.Fatalf("Accept after Close = nil, want error")
		}
	case <-time.After(time.Second):
		t.Fatalf("Accept did not unblock within 1s")
	}
}
```

- [x] **Step 6: Run tests**

Run: `go test -race ./internal/transport/ipc/...`

Expected: PASS.

- [x] **Step 7: Commit**

```bash
git add internal/transport/ipc/ipc_test.go
git commit -m "transport/ipc: unlink, mode 0600, stale-rebind, close-unblocks-{accept,read}"
```

---

### Task 7: IPC Windows stub

**Files:**
- Create: `internal/transport/ipc/ipc_windows.go`
- Create: `internal/transport/ipc/ipc_windows_test.go`

- [x] **Step 1: Write Windows stub**

`internal/transport/ipc/ipc_windows.go`:

```go
//go:build windows

package ipc

import (
	"context"
	"fmt"
	"net"

	"github.com/tomi77/zmq4/internal/transport"
)

// Listen returns ErrSchemeUnknown on Windows. ipc is not implemented;
// see docs/specs/03-transports.md §9 Open Question 7.
func Listen(_ context.Context, _ string) (*net.UnixListener, error) {
	return nil, fmt.Errorf("%w: ipc on windows", transport.ErrSchemeUnknown)
}

// Dial returns ErrSchemeUnknown on Windows.
func Dial(_ context.Context, _ string) (*net.UnixConn, error) {
	return nil, fmt.Errorf("%w: ipc on windows", transport.ErrSchemeUnknown)
}
```

- [x] **Step 2: Write Windows stub test**

`internal/transport/ipc/ipc_windows_test.go`:

```go
//go:build windows

package ipc

import (
	"context"
	"errors"
	"testing"

	"github.com/tomi77/zmq4/internal/transport"
)

func TestListenWindowsStub(t *testing.T) {
	_, err := Listen(context.Background(), "ignored")
	if !errors.Is(err, transport.ErrSchemeUnknown) {
		t.Fatalf("Listen err = %v, want ErrSchemeUnknown", err)
	}
}

func TestDialWindowsStub(t *testing.T) {
	_, err := Dial(context.Background(), "ignored")
	if !errors.Is(err, transport.ErrSchemeUnknown) {
		t.Fatalf("Dial err = %v, want ErrSchemeUnknown", err)
	}
}
```

- [x] **Step 3: Verify build on Linux + (optionally) Windows**

Run: `GOOS=windows GOARCH=amd64 go build ./internal/transport/ipc/`

Expected: build succeeds (no test execution).

Run: `go test -race ./internal/transport/ipc/...`

Expected: PASS on Linux (Windows tests excluded by build tag).

- [x] **Step 4: Commit**

```bash
git add internal/transport/ipc/ipc_windows.go internal/transport/ipc/ipc_windows_test.go
git commit -m "transport/ipc: Windows stub returning ErrSchemeUnknown"
```

---

## Chunk 4: inproc subpackage

### Task 8: inproc registry + Listen + AlreadyBound

**Files:**
- Create: `internal/transport/inproc/doc.go`
- Create: `internal/transport/inproc/registry.go`
- Create: `internal/transport/inproc/inproc.go`
- Create: `internal/transport/inproc/inproc_test.go`

- [x] **Step 1: Write `inproc/doc.go`**

```go
// Package inproc implements the inproc:// transport for F3 — an
// in-process namespace of net.Pipe-backed connections.
//
// The registry is per-OS-process; subprocesses do not share an inproc
// namespace.
//
// Dial blocks on ctx until a matching Listen on the same name completes
// the pairing. Pending dialers survive Listener.Close → re-Listen
// cycles; closing a listener releases the name without aborting
// in-flight dialers.
//
// See docs/specs/03-transports.md §5.4 / §7 for the data structures and
// state machine.
package inproc
```

- [x] **Step 2: Write `inproc/registry.go`**

```go
package inproc

import (
	"net"
	"sync"
)

// inprocAddr satisfies net.Addr for inproc connections.
type inprocAddr struct{ name string }

func (a inprocAddr) Network() string { return "inproc" }
func (a inprocAddr) String() string  { return a.name }

// inprocListener is the live-listener side of a bound inproc name.
// queue is appended-to under qmu by both Listen-drain and post-bind
// Dials. Accept consumes from queue under qmu; if the queue is empty
// it parks on notify (or on closed).
type inprocListener struct {
	name string

	qmu    sync.Mutex
	queue  []net.Conn
	notify chan struct{} // cap 1; signalled on enqueue or on Close

	closed     chan struct{}
	closeOnce  sync.Once
}

// pendingDial is the waiter side of a Dial-before-bind. ready is cap-1
// buffered so Listen-drain can deliver without blocking; if Dial cancels
// concurrently, the cancellation path drains ready (see §7.5).
type pendingDial struct {
	ready chan acceptResult
}

type acceptResult struct {
	conn net.Conn // dial-side end of a fresh net.Pipe pair
}

// registry is package-global state.
var registry = struct {
	mu      sync.Mutex
	bound   map[string]*inprocListener
	pending map[string][]*pendingDial // FIFO order — oldest at index 0
}{
	bound:   make(map[string]*inprocListener),
	pending: make(map[string][]*pendingDial),
}

// newInprocListener allocates a bound listener for name (caller MUST hold
// registry.mu and have already verified the name is unbound).
func newInprocListener(name string) *inprocListener {
	return &inprocListener{
		name:   name,
		notify: make(chan struct{}, 1),
		closed: make(chan struct{}),
	}
}

// enqueue appends conn to the listener's queue and pings notify.
func (l *inprocListener) enqueue(c net.Conn) {
	l.qmu.Lock()
	l.queue = append(l.queue, c)
	l.qmu.Unlock()
	select {
	case l.notify <- struct{}{}:
	default:
	}
}

// removeFromPending finds and removes pd from registry.pending[name].
// Returns true if pd was present. Caller MUST hold registry.mu.
func removeFromPending(name string, pd *pendingDial) bool {
	list := registry.pending[name]
	for i, p := range list {
		if p == pd {
			registry.pending[name] = append(list[:i], list[i+1:]...)
			if len(registry.pending[name]) == 0 {
				delete(registry.pending, name)
			}
			return true
		}
	}
	return false
}
```

> **Forward-reference note:** `Listen` (Step 3) drains `pending[name]` and
> sends to `pd.ready` channels owned by `pendingDial` values. `pendingDial`
> instances are only created by `Dial`, which is added in Task 9. In Task 8
> the drain path is therefore dead (the snapshot is always empty). This is
> intentional — splitting Listen and Dial across two commits keeps each
> task's diff small and bisectable.

- [x] **Step 3: Write `inproc/inproc.go` (Listen only for this task)**

```go
package inproc

import (
	"context"
	"fmt"
	"net"

	"github.com/tomi77/zmq4/internal/transport"
)

// Listen registers name in the inproc registry and returns a net.Listener.
// If the name is already bound, returns ErrInprocAlreadyBound.
//
// Listen drains any pending Dialers on the same name in FIFO order,
// pairing each with a fresh net.Pipe. The drain runs after registry.mu is
// released so it never blocks under the global lock.
//
// ctx is currently unused — Listen does not block.
func Listen(_ context.Context, name string) (net.Listener, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: empty inproc name", transport.ErrEndpointMalformed)
	}

	registry.mu.Lock()
	if _, exists := registry.bound[name]; exists {
		registry.mu.Unlock()
		return nil, fmt.Errorf("%w: %q", transport.ErrInprocAlreadyBound, name)
	}
	lis := newInprocListener(name)
	registry.bound[name] = lis
	drainSnap := registry.pending[name]
	delete(registry.pending, name)
	registry.mu.Unlock()

	// Drain off-lock. FIFO order preserved by slice traversal.
	for _, pd := range drainSnap {
		a, b := net.Pipe()
		lis.enqueue(a)
		// cap-1 send — non-blocking by construction.
		pd.ready <- acceptResult{conn: b}
	}

	return lis, nil
}

// Close, Accept, Addr methods.

func (l *inprocListener) Close() error {
	registry.mu.Lock()
	if registry.bound[l.name] == l {
		delete(registry.bound, l.name)
	}
	registry.mu.Unlock()
	l.closeOnce.Do(func() {
		close(l.closed)
		select {
		case l.notify <- struct{}{}:
		default:
		}
	})
	return nil
}

func (l *inprocListener) Addr() net.Addr {
	return inprocAddr{l.name}
}

func (l *inprocListener) Accept() (net.Conn, error) {
	for {
		l.qmu.Lock()
		if len(l.queue) > 0 {
			c := l.queue[0]
			l.queue = l.queue[1:]
			l.qmu.Unlock()
			return c, nil
		}
		// queue empty — check closed before parking.
		select {
		case <-l.closed:
			l.qmu.Unlock()
			return nil, net.ErrClosed
		default:
		}
		l.qmu.Unlock()

		// Park until either a notify ping or close.
		select {
		case <-l.notify:
			// loop, re-check queue + closed
		case <-l.closed:
			// loop will observe closed in step 1+2
		}
	}
}
```

- [x] **Step 4: Write `inproc/inproc_test.go` (Listen-only tests for this task)**

```go
package inproc

import (
	"context"
	"errors"
	"testing"

	"github.com/tomi77/zmq4/internal/transport"
)

func TestListenEmptyName(t *testing.T) {
	_, err := Listen(context.Background(), "")
	if !errors.Is(err, transport.ErrEndpointMalformed) {
		t.Fatalf("Listen(\"\") err = %v, want ErrEndpointMalformed", err)
	}
}

func TestListenAlreadyBound(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()

	lis1, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis1.Close()

	_, err = Listen(ctx, name)
	if !errors.Is(err, transport.ErrInprocAlreadyBound) {
		t.Fatalf("second Listen err = %v, want ErrInprocAlreadyBound", err)
	}
}

func TestListenAddr(t *testing.T) {
	name := "test/" + t.Name()
	lis, err := Listen(context.Background(), name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()
	a := lis.Addr()
	if a.Network() != "inproc" {
		t.Fatalf("Addr.Network() = %q, want \"inproc\"", a.Network())
	}
	if a.String() != name {
		t.Fatalf("Addr.String() = %q, want %q", a.String(), name)
	}
}
```

- [x] **Step 5: Run tests**

Run: `go test -race ./internal/transport/inproc/...`

Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add internal/transport/inproc/
git commit -m "transport/inproc: registry + Listen + AlreadyBound"
```

---

### Task 9: inproc Dial (post-bind path) + round-trip

**Files:**
- Modify: `internal/transport/inproc/inproc.go` (add Dial)
- Modify: `internal/transport/inproc/inproc_test.go` (append tests)

- [x] **Step 1: Append Dial to `inproc.go`**

```go
// Dial opens a connection to name. If name is already bound, returns
// immediately with a fresh net.Pipe pair (the accept side is enqueued on
// the listener). If unbound, blocks until either a Listen on the same
// name pairs the dial, or ctx is cancelled.
func Dial(ctx context.Context, name string) (net.Conn, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: empty inproc name", transport.ErrEndpointMalformed)
	}

	registry.mu.Lock()
	if lis, ok := registry.bound[name]; ok {
		a, b := net.Pipe()
		registry.mu.Unlock()
		lis.enqueue(a)
		return b, nil
	}

	pd := &pendingDial{ready: make(chan acceptResult, 1)}
	registry.pending[name] = append(registry.pending[name], pd)
	registry.mu.Unlock()

	select {
	case res := <-pd.ready:
		return res.conn, nil
	case <-ctx.Done():
		registry.mu.Lock()
		found := removeFromPending(name, pd)
		registry.mu.Unlock()
		if !found {
			// Listen-drain already delivered. Drain pd.ready and close
			// the orphaned dial-side conn so the listener observes EOF.
			select {
			case res := <-pd.ready:
				_ = res.conn.Close()
			default:
			}
		}
		return nil, ctx.Err()
	}
}
```

- [x] **Step 2: Append `TestDialPostBindRoundTrip`**

```go
import (
	"bytes"
	"io"
	"net"
)

func TestDialPostBindRoundTrip(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()
	lis, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()

	dc, err := Dial(ctx, name)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dc.Close()
	got := <-ch
	if got.err != nil {
		t.Fatalf("Accept: %v", got.err)
	}
	defer got.c.Close()

	want := []byte("hello over inproc")
	go func() {
		_, _ = dc.Write(want)
	}()
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(got.c, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("recv = %q, want %q", buf, want)
	}
}
```

- [x] **Step 3: Run tests**

Run: `go test -race ./internal/transport/inproc/...`

Expected: PASS.

- [x] **Step 4: Commit**

```bash
git add internal/transport/inproc/inproc.go internal/transport/inproc/inproc_test.go
git commit -m "transport/inproc: Dial post-bind + round-trip"
```

---

### Task 10: inproc connect-blocks-until-bind

**Files:**
- Modify: `internal/transport/inproc/inproc_test.go` (append)

- [x] **Step 1: Append `TestConnectBlocksUntilBind`**

```go
import "time"

func TestConnectBlocksUntilBind(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := Dial(ctx, name)
		ch <- p{c, e}
	}()

	// Give Dial time to block.
	select {
	case got := <-ch:
		t.Fatalf("Dial returned before Listen: conn=%v err=%v", got.c, got.e)
	case <-time.After(50 * time.Millisecond):
		// Expected: still blocked.
	}

	lis, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	// Accept the paired conn.
	ach := make(chan net.Conn, 1)
	go func() {
		c, _ := lis.Accept()
		ach <- c
	}()

	select {
	case got := <-ch:
		if got.e != nil {
			t.Fatalf("Dial after Listen err = %v", got.e)
		}
		defer got.c.Close()
		ac := <-ach
		defer ac.Close()
		// Round-trip a tiny payload.
		want := []byte("paired")
		go func() { _, _ = got.c.Write(want) }()
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(ac, buf); err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
		if !bytes.Equal(buf, want) {
			t.Fatalf("recv = %q, want %q", buf, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("Dial did not unblock after Listen within 1s")
	}
}
```

- [x] **Step 2: Run tests**

Run: `go test -race -run TestConnectBlocksUntilBind ./internal/transport/inproc/...`

Expected: PASS.

- [x] **Step 3: Commit**

```bash
git add internal/transport/inproc/inproc_test.go
git commit -m "transport/inproc: connect-blocks-until-bind"
```

---

### Task 11: inproc Dial cancellation

**Files:**
- Modify: `internal/transport/inproc/inproc_test.go` (append)

- [x] **Step 1: Append `TestConnectCancelledByContext`**

```go
func TestConnectCancelledByContext(t *testing.T) {
	parent := context.Background()
	name := "test/" + t.Name()
	ctx, cancel := context.WithTimeout(parent, 25*time.Millisecond)
	defer cancel()

	c, err := Dial(ctx, name)
	if err == nil {
		c.Close()
		t.Fatalf("Dial = %v, want context error", c)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial err = %v, want errors.Is(context.DeadlineExceeded)", err)
	}

	// Verify pending entry is cleaned up.
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if list, ok := registry.pending[name]; ok && len(list) > 0 {
		t.Fatalf("pending[%q] = %d entries after cancel, want 0", name, len(list))
	}
}

func TestConnectCancelledManually(t *testing.T) {
	parent := context.Background()
	name := "test/" + t.Name()
	ctx, cancel := context.WithCancel(parent)

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := Dial(ctx, name)
		ch <- p{c, e}
	}()
	time.Sleep(20 * time.Millisecond) // let Dial enqueue
	cancel()

	got := <-ch
	if got.e == nil {
		t.Fatalf("Dial = %v, want cancel error", got.c)
	}
	if !errors.Is(got.e, context.Canceled) {
		t.Fatalf("err = %v, want errors.Is(context.Canceled)", got.e)
	}
}
```

- [x] **Step 2: Run tests**

Run: `go test -race -run TestConnectCancelled ./internal/transport/inproc/...`

Expected: PASS.

- [x] **Step 3: Commit**

```bash
git add internal/transport/inproc/inproc_test.go
git commit -m "transport/inproc: Dial cancellation by context"
```

---

### Task 12: inproc Listener.Close + Accept lifecycle + bind/rebind

**Files:**
- Modify: `internal/transport/inproc/inproc_test.go` (append)

- [x] **Step 1: Append `TestCloseUnblocksAccept`**

```go
func TestCloseUnblocksAccept(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()
	lis, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, e := lis.Accept()
		errCh <- e
	}()
	time.Sleep(20 * time.Millisecond) // let Accept park

	if err := lis.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case e := <-errCh:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatalf("Accept err = %v, want net.ErrClosed", e)
		}
	case <-time.After(time.Second):
		t.Fatalf("Accept did not unblock within 1s")
	}
}
```

- [x] **Step 2: Append `TestBindRebindAfterClose`**

```go
func TestBindRebindAfterClose(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()

	lis1, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	if err := lis1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	lis2, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("second Listen: %v", err)
	}
	defer lis2.Close()
}
```

- [x] **Step 3: Append `TestPendingDialBetweenCloseAndRebind`**

This is the spec §7.2 invariant test: after a `Listener.Close()`, the name
is released — a subsequent `Dial` on the same name blocks (no tombstone)
and pairs only with the next `Listen` on that name.

```go
func TestPendingDialBetweenCloseAndRebind(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()

	// First lifecycle: Listen + Close immediately, no Dial in between.
	lis1, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	if err := lis1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Now Dial: name is unbound; Dial must block.
	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := Dial(ctx, name)
		ch <- p{c, e}
	}()
	select {
	case got := <-ch:
		t.Fatalf("Dial returned without Listen: conn=%v err=%v", got.c, got.e)
	case <-time.After(50 * time.Millisecond):
		// expected: blocked
	}

	// Second Listen — pairs the pending Dial via Listen-drain.
	lis2, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("second Listen: %v", err)
	}
	defer lis2.Close()
	go func() {
		c, _ := lis2.Accept()
		if c != nil {
			c.Close()
		}
	}()
	select {
	case got := <-ch:
		if got.e != nil {
			t.Fatalf("Dial err = %v", got.e)
		}
		got.c.Close()
	case <-time.After(time.Second):
		t.Fatalf("Dial did not pair with second Listen within 1s")
	}
}
```

- [x] **Step 4: Append `TestQueuedConnsDeliveredAfterClose`** — verifies that conns enqueued before Close still get delivered:

```go
func TestQueuedConnsDeliveredAfterClose(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()
	lis, err := Listen(ctx, name)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// Dial creates a pair, enqueues the accept side; Accept is not yet
	// called. Then Close.
	dc, err := Dial(ctx, name)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dc.Close()
	if err := lis.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// First Accept should still deliver the queued conn.
	ac, err := lis.Accept()
	if err != nil {
		t.Fatalf("Accept after Close (queue non-empty) err = %v, want conn", err)
	}
	ac.Close()

	// Second Accept must return ErrClosed.
	if _, err := lis.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after queue drained err = %v, want net.ErrClosed", err)
	}
}
```

- [x] **Step 5: Run tests**

Run: `go test -race ./internal/transport/inproc/...`

Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add internal/transport/inproc/inproc_test.go
git commit -m "transport/inproc: Listener.Close + Accept lifecycle + rebind"
```

---

### Task 13: inproc cancel-vs-drain race resolution

**Files:**
- Modify: `internal/transport/inproc/inproc_test.go` (append)

- [x] **Step 1: Append `TestCancelRacingDrain` — exercises the §7.5 race**

```go
// TestCancelRacingDrain stresses the case where ctx fires concurrently
// with Listen-drain. Either Dial wins the conn (drain raced first) or
// Dial returns ctx.Err and the orphan conn is closed. Both outcomes are
// valid; what's invalid is goroutine/fd leak or panic.
func TestCancelRacingDrain(t *testing.T) {
	parent := context.Background()
	for i := 0; i < 200; i++ {
		name := "test/race/" + t.Name() + "/" + strconv.Itoa(i)
		ctx, cancel := context.WithCancel(parent)

		type p struct {
			c net.Conn
			e error
		}
		ch := make(chan p, 1)
		go func() {
			c, e := Dial(ctx, name)
			ch <- p{c, e}
		}()
		// Schedule cancel and Listen at "the same time" — Go scheduler
		// arbitrates which goroutine wins.
		go cancel()
		lis, err := Listen(parent, name)
		if err != nil {
			t.Fatalf("[%d] Listen: %v", i, err)
		}
		// Drain Accept regardless of Dial outcome.
		go func() {
			c, _ := lis.Accept()
			if c != nil {
				c.Close()
			}
		}()

		got := <-ch
		switch {
		case got.e == nil && got.c != nil:
			got.c.Close() // Dial won the race
		case got.e != nil && got.c == nil:
			if !errors.Is(got.e, context.Canceled) && !errors.Is(got.e, context.DeadlineExceeded) {
				t.Fatalf("[%d] Dial err = %v, want context error", i, got.e)
			}
		default:
			t.Fatalf("[%d] inconsistent Dial result: c=%v err=%v", i, got.c, got.e)
		}

		_ = lis.Close()
	}
}
```

> Add `"strconv"` to the imports of `inproc_test.go`.

- [x] **Step 2: Run tests**

Run: `go test -race -count=2 -run TestCancelRacingDrain ./internal/transport/inproc/...`

Expected: PASS, no race reports across 2×200=400 iterations.

- [x] **Step 3: Commit**

```bash
git add internal/transport/inproc/inproc_test.go
git commit -m "transport/inproc: cancel-vs-drain race resolution"
```

---

### Task 14: inproc 100-cycle race stress

**Files:**
- Create: `internal/transport/inproc/race_test.go`

- [x] **Step 1: Write race stress test**

```go
package inproc

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
)

func TestRaceDetectorClean(t *testing.T) {
	const cycles = 100
	const dialers = 4
	ctx := context.Background()

	for c := 0; c < cycles; c++ {
		name := "test/race/" + t.Name() + "/" + strconv.Itoa(c)
		var wg sync.WaitGroup

		dialChan := make(chan net.Conn, dialers)
		for d := 0; d < dialers; d++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dc, err := Dial(ctx, name)
				if err != nil {
					return
				}
				dialChan <- dc
			}()
		}

		lis, err := Listen(ctx, name)
		if err != nil {
			t.Fatalf("[%d] Listen: %v", c, err)
		}

		// Accept drainers.
		var accepted []net.Conn
		var amu sync.Mutex
		var awg sync.WaitGroup
		for a := 0; a < dialers; a++ {
			awg.Add(1)
			go func() {
				defer awg.Done()
				ac, err := lis.Accept()
				if err != nil {
					return
				}
				amu.Lock()
				accepted = append(accepted, ac)
				amu.Unlock()
			}()
		}

		wg.Wait()
		close(dialChan)
		_ = lis.Close()
		// Closing should unblock any still-parked Accepts.
		awg.Wait()

		for ac := range accepted {
			_ = accepted[ac].Close()
		}
		for dc := range dialChan {
			_ = dc.Close()
		}
	}
}
```

- [x] **Step 2: Run with `-race`**

Run: `go test -race -count=1 -run TestRaceDetectorClean ./internal/transport/inproc/...`

Expected: PASS, no race reports.

- [x] **Step 3: Commit**

```bash
git add internal/transport/inproc/race_test.go
git commit -m "transport/inproc: 100-cycle race stress"
```

---

### Task 15: inproc Read/Write deadline + EOF semantics

**Files:**
- Modify: `internal/transport/inproc/inproc_test.go` (append)

- [x] **Step 1: Append `TestDeadline`**

```go
func TestDeadline(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()
	lis, _ := Listen(ctx, name)
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()
	dc, _ := Dial(ctx, name)
	defer dc.Close()
	got := <-ch
	defer got.c.Close()

	_ = dc.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buf := make([]byte, 4)
	_, err := dc.Read(buf)
	if err == nil {
		t.Fatalf("Read with past deadline = nil, want timeout")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read err = %v, want net.Error{Timeout=true}", err)
	}
}
```

- [x] **Step 2: Append `TestPeerCloseEOF`**

```go
func TestPeerCloseEOF(t *testing.T) {
	ctx := context.Background()
	name := "test/" + t.Name()
	lis, _ := Listen(ctx, name)
	defer lis.Close()

	type p struct {
		c net.Conn
		e error
	}
	ch := make(chan p, 1)
	go func() {
		c, e := lis.Accept()
		ch <- p{c, e}
	}()
	dc, _ := Dial(ctx, name)
	got := <-ch

	_ = dc.Close()
	buf := make([]byte, 4)
	_, err := got.c.Read(buf)
	if err == nil {
		t.Fatalf("Read after peer close = nil, want EOF")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read err = %v, want io.EOF", err)
	}
	got.c.Close()
}
```

- [x] **Step 3: Run tests**

Run: `go test -race ./internal/transport/inproc/...`

Expected: PASS.

- [x] **Step 4: Commit**

```bash
git add internal/transport/inproc/inproc_test.go
git commit -m "transport/inproc: deadline and peer-close EOF semantics"
```

---

## Chunk 5: Top-level facade + cross-scheme conformance

### Task 16: Facade `Listen` / `Dial` dispatcher

**Files:**
- Create: `internal/transport/transport.go`

- [x] **Step 1: Write `transport.go`**

```go
package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/tomi77/zmq4/internal/transport/inproc"
	"github.com/tomi77/zmq4/internal/transport/ipc"
	"github.com/tomi77/zmq4/internal/transport/tcp"
)

// Listen opens a listener for endpoint, parsing the URI per ParseEndpoint
// and dispatching to the appropriate scheme-specific subpackage.
func Listen(ctx context.Context, endpoint string) (net.Listener, error) {
	scheme, addr, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	switch scheme {
	case "tcp":
		return tcp.Listen(ctx, addr)
	case "ipc":
		return ipc.Listen(ctx, addr)
	case "inproc":
		return inproc.Listen(ctx, addr)
	default:
		// ParseEndpoint already filtered, but be defensive.
		return nil, fmt.Errorf("%w: %q", ErrSchemeUnknown, scheme)
	}
}

// Dial opens a connection for endpoint, parsing the URI per ParseEndpoint
// and dispatching to the appropriate scheme-specific subpackage.
func Dial(ctx context.Context, endpoint string) (net.Conn, error) {
	scheme, addr, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	switch scheme {
	case "tcp":
		return tcp.Dial(ctx, addr)
	case "ipc":
		return ipc.Dial(ctx, addr)
	case "inproc":
		return inproc.Dial(ctx, addr)
	default:
		return nil, fmt.Errorf("%w: %q", ErrSchemeUnknown, scheme)
	}
}
```

- [x] **Step 2: Run build**

Run: `go build ./internal/transport/...`

Expected: builds without errors.

- [x] **Step 3: Run all transport tests**

Run: `go test -race ./internal/transport/...`

Expected: PASS (everything from Tasks 1–15 plus existing).

- [x] **Step 4: Commit**

```bash
git add internal/transport/transport.go
git commit -m "transport: facade Listen/Dial dispatcher"
```

---

### Task 17: Cross-scheme conformance table

**Files:**
- Create: `internal/transport/transport_test.go`

- [x] **Step 1: Write cross-scheme table-driven tests**

```go
package transport_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/tomi77/zmq4/internal/transport"
)

type schemeFactory struct {
	name         string
	bindEndpoint func(t *testing.T) string
	dialEndpoint func(lis net.Listener) string
	skipReason   string // non-empty => Skip with this reason
}

func schemes(t *testing.T) []schemeFactory {
	t.Helper()
	ipcSkip := ""
	if runtime.GOOS == "windows" {
		ipcSkip = "ipc not implemented on windows (transport.ErrSchemeUnknown)"
	}
	return []schemeFactory{
		{
			name:         "tcp",
			bindEndpoint: func(t *testing.T) string { return "tcp://127.0.0.1:0" },
			dialEndpoint: func(lis net.Listener) string { return "tcp://" + lis.Addr().String() },
		},
		{
			name: "ipc",
			bindEndpoint: func(t *testing.T) string {
				return "ipc://" + filepath.Join(t.TempDir(), "zmq.sock")
			},
			dialEndpoint: func(lis net.Listener) string { return "ipc://" + lis.Addr().String() },
			skipReason:   ipcSkip,
		},
		{
			name:         "inproc",
			bindEndpoint: func(t *testing.T) string { return "inproc://crossscheme/" + t.Name() },
			dialEndpoint: func(lis net.Listener) string { return "inproc://" + lis.Addr().String() },
		},
	}
}

func TestCrossSchemeRoundTrip(t *testing.T) {
	for _, sc := range schemes(t) {
		t.Run(sc.name, func(t *testing.T) {
			if sc.skipReason != "" {
				t.Skip(sc.skipReason)
			}
			ctx := context.Background()
			lis, err := transport.Listen(ctx, sc.bindEndpoint(t))
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer lis.Close()

			type p struct {
				c net.Conn
				e error
			}
			ch := make(chan p, 1)
			go func() {
				c, e := lis.Accept()
				ch <- p{c, e}
			}()

			dc, err := transport.Dial(ctx, sc.dialEndpoint(lis))
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer dc.Close()
			got := <-ch
			if got.e != nil {
				t.Fatalf("Accept: %v", got.e)
			}
			defer got.c.Close()

			payloads := [][]byte{
				bytes.Repeat([]byte("a"), 1024),
				bytes.Repeat([]byte("b"), 1<<20), // 1 MiB
			}
			var wg sync.WaitGroup
			for _, want := range payloads {
				want := want
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, _ = dc.Write(want)
				}()
				buf := make([]byte, len(want))
				if _, err := io.ReadFull(got.c, buf); err != nil {
					t.Fatalf("ReadFull(%d): %v", len(want), err)
				}
				if !bytes.Equal(buf, want) {
					t.Fatalf("recv mismatch (len=%d)", len(want))
				}
			}
			wg.Wait()
		})
	}
}

func TestCrossSchemeCloseUnblocksAccept(t *testing.T) {
	for _, sc := range schemes(t) {
		t.Run(sc.name, func(t *testing.T) {
			if sc.skipReason != "" {
				t.Skip(sc.skipReason)
			}
			ctx := context.Background()
			lis, err := transport.Listen(ctx, sc.bindEndpoint(t))
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			errCh := make(chan error, 1)
			go func() {
				_, e := lis.Accept()
				errCh <- e
			}()
			time.Sleep(20 * time.Millisecond)
			_ = lis.Close()

			select {
			case e := <-errCh:
				if !errors.Is(e, net.ErrClosed) {
					t.Fatalf("Accept err = %v, want net.ErrClosed", e)
				}
			case <-time.After(time.Second):
				t.Fatalf("Accept did not unblock within 1s")
			}
		})
	}
}

func TestCrossSchemePeerCloseEOF(t *testing.T) {
	for _, sc := range schemes(t) {
		t.Run(sc.name, func(t *testing.T) {
			if sc.skipReason != "" {
				t.Skip(sc.skipReason)
			}
			ctx := context.Background()
			lis, err := transport.Listen(ctx, sc.bindEndpoint(t))
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer lis.Close()

			type p struct {
				c net.Conn
				e error
			}
			ch := make(chan p, 1)
			go func() {
				c, e := lis.Accept()
				ch <- p{c, e}
			}()
			dc, _ := transport.Dial(ctx, sc.dialEndpoint(lis))
			got := <-ch

			_ = dc.Close()
			buf := make([]byte, 4)
			_, err = got.c.Read(buf)
			if err == nil {
				t.Fatalf("Read after peer close = nil, want EOF")
			}
			if !errors.Is(err, io.EOF) {
				t.Fatalf("Read err = %v, want io.EOF", err)
			}
			got.c.Close()
		})
	}
}
```

- [x] **Step 2: Append `TestCrossSchemeDialAfterClose` (per-scheme)**

Spec §8.5 requires per-scheme assertions for Dial after listener Close.
Each scheme has its own observable: tcp returns ECONNREFUSED-class, ipc
ENOENT-class, inproc blocks (we use a short ctx and assert the cancel
error).

```go
func TestCrossSchemeDialAfterClose(t *testing.T) {
	for _, sc := range schemes(t) {
		t.Run(sc.name, func(t *testing.T) {
			if sc.skipReason != "" {
				t.Skip(sc.skipReason)
			}
			ctx := context.Background()
			lis, err := transport.Listen(ctx, sc.bindEndpoint(t))
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			ep := sc.dialEndpoint(lis)
			_ = lis.Close()

			switch sc.name {
			case "tcp", "ipc":
				// Both report a connect-refused or no-such-file error.
				dialCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()
				dc, derr := transport.Dial(dialCtx, ep)
				if derr == nil {
					dc.Close()
					t.Fatalf("Dial after Close = nil error, want %s-class failure", sc.name)
				}
			case "inproc":
				// Name was released; Dial blocks until ctx fires.
				dialCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
				dc, derr := transport.Dial(dialCtx, ep)
				if derr == nil {
					dc.Close()
					t.Fatalf("inproc Dial after Close = nil error, want context error")
				}
				if !errors.Is(derr, context.DeadlineExceeded) {
					t.Fatalf("inproc Dial err = %v, want context.DeadlineExceeded", derr)
				}
			default:
				t.Fatalf("unknown scheme %q in cross-scheme test", sc.name)
			}
		})
	}
}
```

- [x] **Step 3: Run cross-scheme tests**

Run: `go test -race ./internal/transport/...`

Expected: PASS for all three scheme subtests on Linux/macOS; ipc subtests SKIP on Windows.

- [x] **Step 4: Commit**

```bash
git add internal/transport/transport_test.go
git commit -m "transport: cross-scheme conformance table"
```

---

## Chunk 6: Done-criteria sweep + spec status flip + tag

### Task 18: Done-criteria sweep + spec status + meta-overview update + tag

**Files:**
- Modify: `docs/specs/03-transports.md` (Status header)
- Modify: `docs/specs/00-meta-overview.md` (F3 row + status banner)
- Modify: `docs/plans/03-transports-implementation.md` (mark all checkboxes)

- [x] **Step 1: `go vet`**

Run: `go vet ./...`

Expected: no output.

- [x] **Step 2: `staticcheck`**

Run: `staticcheck ./...`

Expected: no output. (Install if missing: `go install honnef.co/go/tools/cmd/staticcheck@latest`.)

- [x] **Step 3: `-race` full project**

Run: `go test -race -count=1 ./...`

Expected: PASS. No race reports.

- [x] **Step 4: Cross-compile Windows**

Run: `GOOS=windows GOARCH=amd64 go build ./...`

Expected: builds.

- [x] **Step 5: `modernize -fix`** (memory feedback: only at phase end)

Use the same `modernize` invocation the project used at the previous
phase tag (`phase-2c-curve-complete`). Inspect `git log -p phase-2c-curve-complete~..phase-2c-curve-complete -- '**/*.go'` for the canonical command and target paths if uncertain.

Expected: no diff.

- [x] **Step 6: Flip spec status**

Edit `docs/specs/03-transports.md` header from:

```
> **Status:** pre-implementation, awaiting approval.
```

to:

```
> **Status:** implemented, frozen for F4+.
```

- [x] **Step 7: Update `docs/specs/00-meta-overview.md`**

In the status banner at the top, add `phase-3-transport-complete` to the list of tagged phases. In the §4 phase table, change the F3 row's Status column from `Pending.` to `**Complete** — tagged \`phase-3-transport-complete\`.`.

- [x] **Step 8: Mark plan checkboxes**

In `docs/plans/03-transports-implementation.md`, replace all `- [x]` with `- [x]` for tasks 1–17 (Task 18 is in progress).

- [x] **Step 9: Commit doc updates**

```bash
git add docs/specs/03-transports.md docs/specs/00-meta-overview.md docs/plans/03-transports-implementation.md
git commit -m "transport: mark Phase 3 (transport layer) complete"
```

- [x] **Step 10: Tag**

```bash
git tag phase-3-transport-complete
```

- [x] **Step 11: Final verification**

Run: `git tag --sort=-creatordate | head`

Expected: `phase-3-transport-complete` at top.

Run: `go test -race -count=1 ./...`

Expected: PASS.

- [x] **Step 12: Mark Task 18 done**

In the plan, replace this task's last open `- [x]` with `- [x]` and add a final commit:

```bash
git add docs/plans/03-transports-implementation.md
git commit -m "transport: F3 plan — mark done-criteria sweep complete"
```

---

## Done

After Task 18, F3 is complete. Working tree is clean, all tests pass under `-race`, the spec is frozen for F4+, the meta-overview reflects F3 status, and `phase-3-transport-complete` is tagged.

F4 (connection layer) consumes this layer via `transport.Listen` / `transport.Dial`; it will set deadlines, drive F1+F2 on top of returned `net.Conn`s, and is the first phase to interop with libzmq.
