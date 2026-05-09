# F6b ZAP — ZeroMQ Authentication Protocol Implementation Plan

> **For Claude:** REQUIRED: Use `superpowers:subagent-driven-development` to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking. Each task is one commit.

**Goal:** Implement the ZeroMQ Authentication Protocol (RFC 27) for all three ZMTP mechanisms (NULL, PLAIN, CURVE) using an in-process channel-based dispatcher, exposed via a public `zap/` package.

**Architecture:** A `zap.Router` runs a goroutine that serialises `Handler.Authenticate()` calls received through an internal channel. A `zap.Client` (satisfying `security.ZAPCaller`) enqueues requests and blocks until a reply arrives. Server-side security mechanisms receive ZAP configuration via two new interfaces: `ZAPConfigurer` (called by `base.go` after mechanism creation when `zapCaller` is set in socket config) and `PeerAddrSetter` (always called on server-side mechanisms so ZAP requests include the peer's network address). The root package adds `WithZAPDomain(r *zap.Router, domain string)` and stores `zapCaller`/`zapDomain` in `socketConfig`.

**Tech Stack:** Pure Go 1.26, stdlib only. No new external deps.

**Decisions baked into the plan:**
- ZAP identity field is always empty (all three mechanisms). Documented limitation.
- When ZAP is configured, it supersedes the local `Authenticator`/`Authorizer` callback for the decision. The local callback is still accepted by the constructor and may co-exist; ZAP simply takes precedence.
- `ErrZAPDenied` lives in `internal/security/errors.go` (shared sentinel).
- ZAP metadata from reply is appended to peer ZMTP metadata in `PeerMetadata()`.
- **No `modernize -fix` per task.** Run only at Task 9 (done-criteria sweep).
- **Phase tag:** `phase-6b-zap-complete` after Task 9.

---

## Chunk 1: `zap/` package

### Task 1: `zap/` — types, errors, doc

**Files:**
- Create: `zap/doc.go`
- Create: `zap/handler.go`
- Create: `zap/errors.go`

- [ ] **Step 1: Create `zap/doc.go`**

```go
// Package zap implements the ZeroMQ Authentication Protocol (ZAP, RFC 27).
//
// A ZAP Handler is a [Router] that runs in its own goroutine and dispatches
// authentication requests to a user-supplied [Handler]. A [Client] connects
// to the Router and is injected into server-side security mechanisms via
// [github.com/tomi77/zmq4.WithZAPDomain].
//
// Typical use:
//
//	router := zap.NewRouter(myHandler)
//	defer router.Close()
//
//	rep := zmq4.NewREP(zmq4.WithPLAINServer(myAuth), zmq4.WithZAPDomain(router, "global"))
//
// The ZAP handler runs exclusively in-process over Go channels (not over the
// wire). Authentication is performed synchronously during the ZMTP handshake
// for every incoming connection.
package zap
```

- [ ] **Step 2: Create `zap/handler.go`**

```go
package zap

// Status codes defined by RFC 27 §7.
const (
	StatusOK          = "200"
	StatusTemporary   = "300"
	StatusDenied      = "400"
	StatusInternalErr = "500"
)

// Handler decides whether to accept an incoming connection.
// Authenticate is called synchronously during the ZMTP handshake;
// it must not block indefinitely.
type Handler interface {
	Authenticate(r Request) (Reply, error)
}

// Request is the ZAP authentication request (RFC 27 §7).
type Request struct {
	Version     string   // always "1.0"
	RequestID   []byte   // 8 random bytes; opaque to the handler
	Domain      string   // security domain configured on the socket
	Address     string   // peer network address, e.g. "192.0.2.1:40000"
	Identity    []byte   // always empty in this implementation
	Mechanism   string   // "NULL", "PLAIN", or "CURVE"
	Credentials [][]byte // NULL: nil; PLAIN: [username, password]; CURVE: [clientPublicKey]
}

// Reply is the ZAP handler's response (RFC 27 §7).
type Reply struct {
	StatusCode string            // "200", "300", "400", or "500"
	StatusText string            // human-readable status description
	UserID     string            // application-level user identifier (may be empty)
	Metadata   map[string]string // additional properties merged into PeerMetadata()
}
```

- [ ] **Step 3: Create `zap/errors.go`**

```go
package zap

import "errors"

// ErrRouterClosed is returned by Client.Authenticate when the Router
// has been closed before or during the request.
var ErrRouterClosed = errors.New("zap: router closed")
```

- [ ] **Step 4: Run full suite — confirm no regressions**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go build ./zap/... && go test ./...
```

Expected: `zap/` compiles (empty-ish package); all existing tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add zap/doc.go zap/handler.go zap/errors.go && git commit -m "feat(F6b): zap/ — Handler interface, Request/Reply types, status constants"
```

---

### Task 2: `zap/` — Router, Client, tests

**Files:**
- Create: `zap/router.go`
- Create: `zap/client.go`
- Create: `zap/zap_test.go`

- [ ] **Step 1: Write failing tests in `zap/zap_test.go`**

```go
package zap_test

import (
	"errors"
	"testing"

	zmqzap "github.com/tomi77/zmq4/zap"
)

// handlerFunc is a test helper that adapts a function to the Handler interface.
type handlerFunc func(r zmqzap.Request) (zmqzap.Reply, error)

func (f handlerFunc) Authenticate(r zmqzap.Request) (zmqzap.Reply, error) { return f(r) }

func TestRouterCallsHandler(t *testing.T) {
	called := make(chan zmqzap.Request, 1)
	h := handlerFunc(func(r zmqzap.Request) (zmqzap.Reply, error) {
		called <- r
		return zmqzap.Reply{StatusCode: zmqzap.StatusOK}, nil
	})
	r := zmqzap.NewRouter(h)
	defer r.Close()

	c := zmqzap.NewClient(r)
	code, _, _, err := c.Authenticate("dom", "1.2.3.4:5000", "", "NULL", nil)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if code != zmqzap.StatusOK {
		t.Fatalf("status = %q, want %q", code, zmqzap.StatusOK)
	}
	req := <-called
	if req.Domain != "dom" {
		t.Fatalf("Domain = %q, want %q", req.Domain, "dom")
	}
	if req.Address != "1.2.3.4:5000" {
		t.Fatalf("Address = %q, want %q", req.Address, "1.2.3.4:5000")
	}
	if req.Mechanism != "NULL" {
		t.Fatalf("Mechanism = %q, want %q", req.Mechanism, "NULL")
	}
}

func TestRouterReturnsReplyFields(t *testing.T) {
	h := handlerFunc(func(r zmqzap.Request) (zmqzap.Reply, error) {
		return zmqzap.Reply{
			StatusCode: zmqzap.StatusOK,
			StatusText: "OK",
			UserID:     "alice",
			Metadata:   map[string]string{"X-Role": "admin"},
		}, nil
	})
	r := zmqzap.NewRouter(h)
	defer r.Close()

	c := zmqzap.NewClient(r)
	code, userID, meta, err := c.Authenticate("", "", "", "NULL", nil)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if code != zmqzap.StatusOK {
		t.Fatalf("code = %q, want %q", code, zmqzap.StatusOK)
	}
	if userID != "alice" {
		t.Fatalf("userID = %q, want %q", userID, "alice")
	}
	if meta == nil {
		t.Fatal("metadata nil, want non-nil")
	}
}

func TestRouterDenyReturns400(t *testing.T) {
	h := handlerFunc(func(r zmqzap.Request) (zmqzap.Reply, error) {
		return zmqzap.Reply{StatusCode: zmqzap.StatusDenied, StatusText: "no"}, nil
	})
	r := zmqzap.NewRouter(h)
	defer r.Close()

	c := zmqzap.NewClient(r)
	code, _, _, err := c.Authenticate("", "", "", "NULL", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != zmqzap.StatusDenied {
		t.Fatalf("code = %q, want %q", code, zmqzap.StatusDenied)
	}
}

func TestClientOnClosedRouterReturnsErr(t *testing.T) {
	h := handlerFunc(func(r zmqzap.Request) (zmqzap.Reply, error) {
		return zmqzap.Reply{StatusCode: zmqzap.StatusOK}, nil
	})
	r := zmqzap.NewRouter(h)
	r.Close()

	c := zmqzap.NewClient(r)
	_, _, _, err := c.Authenticate("", "", "", "NULL", nil)
	if !errors.Is(err, zmqzap.ErrRouterClosed) {
		t.Fatalf("err = %v, want ErrRouterClosed", err)
	}
}

func TestRouterPLAINCredentials(t *testing.T) {
	var gotCreds [][]byte
	h := handlerFunc(func(r zmqzap.Request) (zmqzap.Reply, error) {
		gotCreds = r.Credentials
		return zmqzap.Reply{StatusCode: zmqzap.StatusOK}, nil
	})
	r := zmqzap.NewRouter(h)
	defer r.Close()

	c := zmqzap.NewClient(r)
	_, _, _, err := c.Authenticate("", "", "", "PLAIN", [][]byte{[]byte("user"), []byte("pass")})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(gotCreds) != 2 || string(gotCreds[0]) != "user" || string(gotCreds[1]) != "pass" {
		t.Fatalf("credentials = %v, want [user pass]", gotCreds)
	}
}
```

- [ ] **Step 2: Run tests — confirm compile failure**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./zap/... 2>&1 | head -20
```

Expected: compile errors (undefined `NewRouter`, `NewClient`).

- [ ] **Step 3: Create `zap/router.go`**

```go
package zap

import "sync"

// zapEnvelope carries a request and its reply channel through the Router loop.
type zapEnvelope struct {
	req     Request
	replyCh chan zapResult
}

type zapResult struct {
	reply Reply
	err   error
}

// Router serialises authentication requests to a Handler in a dedicated
// goroutine. Create with NewRouter; close with Close.
type Router struct {
	handler   Handler
	reqCh     chan zapEnvelope
	closeCh   chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewRouter starts a Router goroutine backed by h. h must not be nil.
func NewRouter(h Handler) *Router {
	r := &Router{
		handler: h,
		reqCh:   make(chan zapEnvelope, 16),
		closeCh: make(chan struct{}),
	}
	r.wg.Add(1)
	go r.loop()
	return r
}

// Close stops the Router goroutine and waits for it to exit.
// Idempotent — safe to call multiple times.
// Subsequent Client.Authenticate calls return ErrRouterClosed.
func (r *Router) Close() error {
	r.closeOnce.Do(func() { close(r.closeCh) })
	r.wg.Wait()
	return nil
}

func (r *Router) loop() {
	defer r.wg.Done()
	for {
		select {
		case env := <-r.reqCh:
			reply, err := r.handler.Authenticate(env.req)
			env.replyCh <- zapResult{reply: reply, err: err}
		case <-r.closeCh:
			// Drain requests that arrived before shutdown to unblock callers.
			for {
				select {
				case env := <-r.reqCh:
					env.replyCh <- zapResult{err: ErrRouterClosed}
				default:
					return
				}
			}
		}
	}
}

// dispatch enqueues env for the handler goroutine.
func (r *Router) dispatch(env zapEnvelope) error {
	select {
	case r.reqCh <- env:
		return nil
	case <-r.closeCh:
		return ErrRouterClosed
	}
}
```

- [ ] **Step 4: Create `zap/client.go`**

```go
package zap

import (
	"crypto/rand"
	"fmt"

	"github.com/tomi77/zmq4/internal/wire"
)

// Client sends ZAP authentication requests to a Router. Obtain via NewClient.
// Client is safe for concurrent use by multiple goroutines (each handshake
// goroutine calls Authenticate independently).
type Client struct {
	router *Router
}

// NewClient creates a Client backed by r. r must not be nil.
func NewClient(r *Router) *Client {
	return &Client{router: r}
}

// Authenticate sends a ZAP REQUEST to the Router and waits for a REPLY.
// Returns (statusCode, userID, zapMetadata, error).
// statusCode is one of the Status* constants ("200", "300", "400", "500").
// Returns ErrRouterClosed if the Router has been shut down.
func (c *Client) Authenticate(domain, address, identity, mechanism string, credentials [][]byte) (statusCode, userID string, metadata wire.Metadata, err error) {
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", "", nil, fmt.Errorf("zap: generate request ID: %w", err)
	}
	replyCh := make(chan zapResult, 1)
	env := zapEnvelope{
		req: Request{
			Version:     "1.0",
			RequestID:   id[:],
			Domain:      domain,
			Address:     address,
			Identity:    []byte(identity),
			Mechanism:   mechanism,
			Credentials: credentials,
		},
		replyCh: replyCh,
	}
	if dispErr := c.router.dispatch(env); dispErr != nil {
		return "", "", nil, dispErr
	}
	result := <-replyCh
	if result.err != nil {
		return "", "", nil, result.err
	}
	return result.reply.StatusCode, result.reply.UserID, convertMetadata(result.reply.Metadata), nil
}

func convertMetadata(m map[string]string) wire.Metadata {
	if len(m) == 0 {
		return nil
	}
	md := make(wire.Metadata, 0, len(m))
	for k, v := range m {
		md = append(md, wire.MetadataProperty{Name: []byte(k), Value: []byte(v)})
	}
	return md
}
```

- [ ] **Step 5: Run tests — confirm pass**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestRouter|TestClient' ./zap/... -v
```

Expected: all 5 tests PASS.

- [ ] **Step 6: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add zap/router.go zap/client.go zap/zap_test.go && git commit -m "feat(F6b): zap/ — Router (channel dispatch) + Client (ZAPCaller impl)"
```

---

## Chunk 2: Security interfaces + NULL ZAP

### Task 3: `internal/security` — new interfaces + `ErrZAPDenied`

**Files:**
- Modify: `internal/security/interfaces.go`
- Modify: `internal/security/errors.go`

- [ ] **Step 1: Add `ErrZAPDenied` to `internal/security/errors.go`**

Append after the existing `ErrClosed` line:

```go
// ErrZAPDenied is returned by server-side Mechanism.Receive when the ZAP
// handler rejected the connection (status code 400 or 500, or an error from
// the Handler). Callers receive it alongside a non-nil *wire.Command containing
// the ERROR frame that MUST be sent before closing the connection.
var ErrZAPDenied = errors.New("security: ZAP denied connection")
```

- [ ] **Step 2: Add `ZAPCaller`, `ZAPConfigurer`, `PeerAddrSetter` to `internal/security/interfaces.go`**

Append after the closing brace of the `ClientMechanism` interface:

```go
// ZAPCaller is satisfied by *zap.Client. Server-side mechanisms receive it
// via ConfigureZAP and call it during the authentication step of the handshake.
type ZAPCaller interface {
	// Authenticate sends a ZAP request and returns (statusCode, userID, metadata, err).
	// statusCode is one of "200", "300", "400", "500" (see zap.Status* constants).
	// err is non-nil only for transport/handler errors, not for auth failures —
	// auth failures are expressed via statusCode.
	Authenticate(domain, address, identity, mechanism string, credentials [][]byte) (statusCode, userID string, metadata wire.Metadata, err error)
}

// ZAPConfigurer is implemented by server-side mechanisms that support ZAP.
// base.go calls ConfigureZAP immediately after mechanism creation when the
// socket was configured with WithZAPDomain.
type ZAPConfigurer interface {
	ConfigureZAP(caller ZAPCaller, domain string)
}

// PeerAddrSetter is implemented by server-side mechanisms to receive the
// peer's network address before the handshake begins. base.go always calls
// SetPeerAddr on accepted connections.
type PeerAddrSetter interface {
	SetPeerAddr(addr string)
}
```

- [ ] **Step 3: Run full suite — confirm no regressions**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS (additive only).

- [ ] **Step 4: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add internal/security/interfaces.go internal/security/errors.go && git commit -m "feat(F6b): security — ZAPCaller/ZAPConfigurer/PeerAddrSetter interfaces + ErrZAPDenied"
```

---

### Task 4: NULL — ZAP support

**Files:**
- Modify: `internal/security/null/state.go`
- Modify: `internal/security/null/errors.go`
- Modify: `internal/security/null/state_test.go`

- [ ] **Step 1: Add `ErrZAPDenied` alias to `null/errors.go`**

The existing `null/errors.go` imports only `"errors"`. Add the `security` import and the alias.

Add `"github.com/tomi77/zmq4/internal/security"` to the import block in `null/errors.go`, then append after the existing var block:

```go
// ErrZAPDenied is returned by State.Receive when the ZAP handler rejects
// the connection. Alias of security.ErrZAPDenied.
var ErrZAPDenied = security.ErrZAPDenied
```

The updated import block in `null/errors.go` becomes:

```go
import (
	"errors"

	"github.com/tomi77/zmq4/internal/security"
)
```

- [ ] **Step 2: Write failing tests in `null/state_test.go`**

Add at the bottom of the file. Note `mockZAP` must be in `package null` to access `security.ZAPCaller`:

```go
// --- ZAP tests ---

type mockZAP struct {
	code string
	uid  string
	meta wire.Metadata
	err  error
}

func (m *mockZAP) Authenticate(domain, address, identity, mechanism string, credentials [][]byte) (string, string, wire.Metadata, error) {
	return m.code, m.uid, m.meta, m.err
}

func TestNullServerZAPAllow(t *testing.T) {
	s := New(nil)
	s.ConfigureZAP(&mockZAP{code: "200", uid: "alice"}, "test")
	s.SetPeerAddr("1.2.3.4:9000")

	// Server must Start() first.
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	peerReady, _ := wire.ReadyCommand{}.Encode()
	out, done, err := s.Receive(peerReady)
	if err != nil {
		t.Fatalf("Receive: unexpected error %v", err)
	}
	if out != nil {
		t.Fatalf("out = %v, want nil", out)
	}
	if !done {
		t.Fatal("done = false, want true")
	}
}

func TestNullServerZAPDeny(t *testing.T) {
	s := New(nil)
	s.ConfigureZAP(&mockZAP{code: "400"}, "test")
	s.SetPeerAddr("1.2.3.4:9000")

	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	peerReady, _ := wire.ReadyCommand{}.Encode()
	out, done, err := s.Receive(peerReady)
	if !errors.Is(err, security.ErrZAPDenied) {
		t.Fatalf("err = %v, want ErrZAPDenied", err)
	}
	if done {
		t.Fatal("done = true, want false")
	}
	if out == nil {
		t.Fatal("out = nil, want ERROR command")
	}
	if out.Name != wire.ErrorCommandName {
		t.Fatalf("out.Name = %q, want ERROR", out.Name)
	}
}

func TestNullServerZAPMetadataMerge(t *testing.T) {
	zapMeta := wire.Metadata{
		{Name: []byte("X-Role"), Value: []byte("admin")},
	}
	s := New(nil)
	s.ConfigureZAP(&mockZAP{code: "200", meta: zapMeta}, "test")
	s.SetPeerAddr("127.0.0.1:1")

	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	peerReady, _ := wire.ReadyCommand{
		Metadata: wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("PUSH")}},
	}.Encode()
	_, done, err := s.Receive(peerReady)
	if err != nil || !done {
		t.Fatalf("Receive: done=%v err=%v", done, err)
	}

	meta := s.PeerMetadata()
	v, ok := meta.Get("X-Role")
	if !ok || string(v) != "admin" {
		t.Fatalf("PeerMetadata X-Role = %q ok=%v, want admin", v, ok)
	}
	v, ok = meta.Get("Socket-Type")
	if !ok || string(v) != "PUSH" {
		t.Fatalf("PeerMetadata Socket-Type = %q ok=%v, want PUSH", v, ok)
	}
}

func TestNullServerNoZAPUnchanged(t *testing.T) {
	// Without ZAP, existing behaviour unchanged.
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	peerReady, _ := wire.ReadyCommand{}.Encode()
	_, done, err := s.Receive(peerReady)
	if err != nil || !done {
		t.Fatalf("Receive: done=%v err=%v", done, err)
	}
}
```

Add missing imports to the test file if needed. Current imports are `"bytes"`, `"errors"`, `"strings"`, `"testing"`, `security`, `wire`. Add `"errors"` if not present (it's already there).

- [ ] **Step 3: Run tests — confirm compile failure**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestNullServerZAP|TestNullServerNoZAP' ./internal/security/null/... 2>&1 | head -20
```

Expected: compile error — undefined `ConfigureZAP`, `SetPeerAddr`.

- [ ] **Step 4: Implement ZAP support in `null/state.go`**

**4a. Add ZAP fields to `State`:**

```go
type State struct {
	local    wire.Metadata
	peer     wire.Metadata
	started  bool
	received bool
	failed   bool

	// ZAP — set by ConfigureZAP; only used on the server side.
	zap      security.ZAPCaller
	domain   string
	peerAddr string
	zapMeta  wire.Metadata
}
```

**4b. Add `ConfigureZAP` and `SetPeerAddr` methods after `New`:**

```go
// ConfigureZAP injects a ZAP client and domain. Called by base.go on the
// server side immediately after mechanism creation. Satisfies security.ZAPConfigurer.
func (s *State) ConfigureZAP(caller security.ZAPCaller, domain string) {
	s.zap = caller
	s.domain = domain
}

// SetPeerAddr stores the peer's network address for inclusion in ZAP requests.
// Called by base.go on the server side before the handshake. Satisfies security.PeerAddrSetter.
func (s *State) SetPeerAddr(addr string) { s.peerAddr = addr }
```

**4c. Update the `wire.ReadyCommandName` branch in `Receive()` to call ZAP:**

Replace the existing branch:
```go
case wire.ReadyCommandName:
    rc, perr := wire.ParseReady(cmd)
    if perr != nil {
        s.failed = true
        return nil, false, fmt.Errorf("%w: %v", ErrMalformedReady, perr)
    }
    s.peer = seccommon.CloneMetadata(rc.Metadata)
    s.received = true
    return nil, true, nil
```

With:
```go
case wire.ReadyCommandName:
    rc, perr := wire.ParseReady(cmd)
    if perr != nil {
        s.failed = true
        return nil, false, fmt.Errorf("%w: %v", ErrMalformedReady, perr)
    }
    s.peer = seccommon.CloneMetadata(rc.Metadata)
    if s.zap != nil {
        code, _, zapMeta, zapErr := s.zap.Authenticate(
            s.domain, s.peerAddr, "", "NULL", nil,
        )
        if zapErr != nil || code != "200" {
            return s.failZAPDenied(code)
        }
        s.zapMeta = zapMeta
    }
    s.received = true
    return nil, true, nil
```

**4d. Add `failZAPDenied` helper after `Receive`:**

```go
func (s *State) failZAPDenied(statusCode string) (*wire.Command, bool, error) {
    s.failed = true
    reason := seccommon.SanitizeReason("ZAP " + statusCode)
    errCmd, encErr := wire.ErrorCommand{Reason: reason}.Encode()
    if encErr != nil {
        return nil, false, fmt.Errorf("null: encode ERROR: %w", encErr)
    }
    return &errCmd, false, fmt.Errorf("%w: status %s", security.ErrZAPDenied, statusCode)
}
```

**4e. Update `PeerMetadata()` to merge ZAP metadata:**

Replace:
```go
func (s *State) PeerMetadata() wire.Metadata { return s.peer }
```

With:
```go
// PeerMetadata returns the peer's READY metadata merged with any ZAP reply
// metadata. Valid only after Receive returned done=true.
func (s *State) PeerMetadata() wire.Metadata {
    if len(s.zapMeta) == 0 {
        return s.peer
    }
    merged := seccommon.CloneMetadata(s.peer)
    return append(merged, s.zapMeta...)
}
```

- [ ] **Step 5: Run tests — confirm pass**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestNullServerZAP|TestNullServerNoZAP' ./internal/security/null/... -v
```

Expected: all 4 new tests PASS.

- [ ] **Step 6: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add internal/security/null/state.go internal/security/null/errors.go internal/security/null/state_test.go && git commit -m "feat(F6b): null — ZAP support (ConfigureZAP, SetPeerAddr, failZAPDenied)"
```

---

## Chunk 3: PLAIN ZAP support

### Task 5: `plain` — ZAP support

**Files:**
- Modify: `internal/security/plain/server.go`
- Modify: `internal/security/plain/errors.go`
- Modify: `internal/security/plain/server_test.go`

- [ ] **Step 1: Add `ErrZAPDenied` alias to `plain/errors.go`**

The existing `plain/errors.go` imports only `"errors"`. Add the `security` import and the alias.

Add `"github.com/tomi77/zmq4/internal/security"` to the import block, then append after the existing var block:

```go
// ErrZAPDenied is returned by ServerState.Receive when the ZAP handler rejects
// the connection. Alias of security.ErrZAPDenied.
var ErrZAPDenied = security.ErrZAPDenied
```

The updated import block in `plain/errors.go` becomes:

```go
import (
	"errors"

	"github.com/tomi77/zmq4/internal/security"
)
```

- [ ] **Step 2: Write failing tests in `plain/server_test.go`**

Check the existing test file for its package declaration and imports, then add at the bottom:

```go
// --- ZAP tests ---

type mockZAP struct {
	code string
	meta wire.Metadata
	err  error
}

func (m *mockZAP) Authenticate(domain, address, identity, mechanism string, credentials [][]byte) (string, string, wire.Metadata, error) {
	return m.code, "", m.meta, m.err
}

func alwaysAllow(username, password []byte) error { return nil }
func alwaysDeny(username, password []byte) error  { return errors.New("denied") }

func TestPlainServerZAPAllowOverridesLocalCallback(t *testing.T) {
	// ZAP "200" — local deny callback is NOT called (ZAP takes precedence).
	s := NewServer(alwaysDeny, nil)
	s.ConfigureZAP(&mockZAP{code: "200"}, "dom")
	s.SetPeerAddr("1.2.3.4:1")

	hello := encodeHelloForTest(t, []byte("user"), []byte("pass"))
	out, done, err := s.Receive(hello)
	if err != nil {
		t.Fatalf("Receive: unexpected error %v", err)
	}
	if done {
		t.Fatal("done = true after HELLO, want false")
	}
	if out == nil || out.Name != welcomeCommandName {
		t.Fatalf("out.Name = %q, want WELCOME", out.Name)
	}
}

func TestPlainServerZAPDenySends400(t *testing.T) {
	s := NewServer(alwaysAllow, nil)
	s.ConfigureZAP(&mockZAP{code: "400"}, "dom")
	s.SetPeerAddr("1.2.3.4:1")

	hello := encodeHelloForTest(t, []byte("user"), []byte("pass"))
	out, done, err := s.Receive(hello)
	if !errors.Is(err, security.ErrZAPDenied) {
		t.Fatalf("err = %v, want ErrZAPDenied", err)
	}
	if done {
		t.Fatal("done = true, want false")
	}
	if out == nil || out.Name != wire.ErrorCommandName {
		t.Fatalf("out.Name = %q, want ERROR", out.Name)
	}
}

func TestPlainServerZAPMetadataMerge(t *testing.T) {
	zapMeta := wire.Metadata{
		{Name: []byte("X-Tenant"), Value: []byte("acme")},
	}
	s := NewServer(alwaysAllow, nil)
	s.ConfigureZAP(&mockZAP{code: "200", meta: zapMeta}, "dom")
	s.SetPeerAddr("127.0.0.1:1")

	hello := encodeHelloForTest(t, []byte("u"), []byte("p"))
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("HELLO Receive: %v", err)
	}

	initiate := encodeInitiateForTest(t, wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("REQ")}})
	_, done, err := s.Receive(initiate)
	if err != nil || !done {
		t.Fatalf("INITIATE Receive: done=%v err=%v", done, err)
	}

	v, ok := s.PeerMetadata().Get("X-Tenant")
	if !ok || string(v) != "acme" {
		t.Fatalf("PeerMetadata X-Tenant = %q ok=%v, want acme", v, ok)
	}
}

func TestPlainServerNoZAPUnchanged(t *testing.T) {
	// Without ZAP, local callback is invoked as before.
	s := NewServer(alwaysDeny, nil)
	hello := encodeHelloForTest(t, []byte("u"), []byte("p"))
	_, _, err := s.Receive(hello)
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("err = %v, want ErrAuthRejected", err)
	}
}
```

`encodeHelloForTest` and `encodeInitiateForTest` are helpers. Check if they already exist in `server_test.go`. If not, look in the package for how HELLO/INITIATE are encoded (the package must export or have internal helpers). Since the tests are `package plain` (internal), they can call internal encode helpers. Check:

```bash
grep -n "encodeHello\|encodeInitiate\|makeHello\|buildHello" /Users/tomaszrup/Projects/github.com/tomi77/zmq4/internal/security/plain/server_test.go | head -10
```

If no helper exists, find the HELLO encoder in the package:

```bash
grep -rn "func.*hello\|func.*Hello\|func.*HELLO" /Users/tomaszrup/Projects/github.com/tomi77/zmq4/internal/security/plain/ | head -10
```

Adapt the test helpers to use whatever encoding functions exist in the package. The pattern from existing tests (line 58 area) likely constructs commands directly. Mirror that pattern.

- [ ] **Step 3: Run tests — confirm compile failure**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestPlainServerZAP|TestPlainServerNoZAP' ./internal/security/plain/... 2>&1 | head -20
```

Expected: compile error — undefined `ConfigureZAP`, `SetPeerAddr`.

- [ ] **Step 4: Implement ZAP support in `plain/server.go`**

**4a. Add ZAP fields to `ServerState`:**

```go
type ServerState struct {
	auth  Authenticator
	local wire.Metadata
	peer  wire.Metadata

	helloProcessed bool
	done           bool
	failed         bool

	// ZAP — set by ConfigureZAP; only used on the server side.
	zap      security.ZAPCaller
	domain   string
	peerAddr string
	zapMeta  wire.Metadata
}
```

**4b. Add `ConfigureZAP` and `SetPeerAddr` methods after `NewServer`:**

```go
// ConfigureZAP injects a ZAP client and domain. Satisfies security.ZAPConfigurer.
func (s *ServerState) ConfigureZAP(caller security.ZAPCaller, domain string) {
	s.zap = caller
	s.domain = domain
}

// SetPeerAddr stores the peer's network address for ZAP requests.
// Satisfies security.PeerAddrSetter.
func (s *ServerState) SetPeerAddr(addr string) { s.peerAddr = addr }
```

**4c. In `Receive()`, replace the auth call on HELLO with ZAP-aware logic:**

Replace:
```go
if authErr := s.auth(body.Username, body.Password); authErr != nil {
    return s.failAuthRejected(authErr)
}
```

With:
```go
if s.zap != nil {
    code, _, zapMeta, zapErr := s.zap.Authenticate(
        s.domain, s.peerAddr, "", "PLAIN",
        [][]byte{body.Username, body.Password},
    )
    if zapErr != nil || code != "200" {
        return s.failZAPDenied(code)
    }
    s.zapMeta = zapMeta
} else if authErr := s.auth(body.Username, body.Password); authErr != nil {
    return s.failAuthRejected(authErr)
}
```

**4d. Add `failZAPDenied` helper after `failAuthRejected`:**

```go
func (s *ServerState) failZAPDenied(statusCode string) (*wire.Command, bool, error) {
	s.failed = true
	reason := seccommon.SanitizeReason("ZAP " + statusCode)
	errCmd, encErr := wire.ErrorCommand{Reason: reason}.Encode()
	if encErr != nil {
		return nil, false, fmt.Errorf("plain: encode ERROR: %w", encErr)
	}
	return &errCmd, false, fmt.Errorf("%w: status %s", security.ErrZAPDenied, statusCode)
}
```

**4e. Update `PeerMetadata()` to merge ZAP metadata:**

Replace:
```go
func (s *ServerState) PeerMetadata() wire.Metadata { return s.peer }
```

With:
```go
func (s *ServerState) PeerMetadata() wire.Metadata {
	if len(s.zapMeta) == 0 {
		return s.peer
	}
	merged := seccommon.CloneMetadata(s.peer)
	return append(merged, s.zapMeta...)
}
```

- [ ] **Step 5: Add test helpers to `server_test.go`**

The internal `encodeHello` function takes a `helloBody` struct (not bare bytes). Add these two helpers to `server_test.go` just before the ZAP test block:

```go
func encodeHelloForTest(t *testing.T, username, password []byte) wire.Command {
	t.Helper()
	cmd, err := encodeHello(helloBody{Username: username, Password: password})
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	return cmd
}

func encodeInitiateForTest(t *testing.T, md wire.Metadata) wire.Command {
	t.Helper()
	return wire.Command{Name: initiateCommandName, Data: wire.EncodeMetadata(md)}
}
```

- [ ] **Step 6: Run tests — confirm pass**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestPlainServerZAP|TestPlainServerNoZAP' ./internal/security/plain/... -v
```

Expected: all 4 tests PASS.

- [ ] **Step 7: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add internal/security/plain/server.go internal/security/plain/errors.go internal/security/plain/server_test.go && git commit -m "feat(F6b): plain — ZAP support (ConfigureZAP, SetPeerAddr, failZAPDenied)"
```

---

## Chunk 4: CURVE ZAP support

### Task 6: `curve` — ZAP support

**Files:**
- Modify: `internal/security/curve/server.go`
- Modify: `internal/security/curve/errors.go`
- Modify: `internal/security/curve/server_test.go`

- [ ] **Step 1: Add `ErrZAPDenied` alias to `curve/errors.go`**

The existing `curve/errors.go` imports only `"errors"`. Add the `security` import and the alias.

Add `"github.com/tomi77/zmq4/internal/security"` to the import block, then append after the existing var block:

```go
// ErrZAPDenied is returned by ServerState.Receive when the ZAP handler rejects
// the connection. Alias of security.ErrZAPDenied.
var ErrZAPDenied = security.ErrZAPDenied
```

The updated import block in `curve/errors.go` becomes:

```go
import (
	"errors"

	"github.com/tomi77/zmq4/internal/security"
)
```

- [ ] **Step 2: Write failing tests in `curve/server_test.go`**

Add at the bottom of `curve/server_test.go`. The existing package uses `makePair(t)` (defined in `codec_test.go`, same package) returning `(PublicKey, SecretKey)`.

First define the `runCurveServerSideExchange` helper and `mockZAP` struct, then the three tests:

```go
// mockZAP is a ZAPCaller stub for testing.
type mockZAP struct {
	code string
	meta wire.Metadata
}

func (m *mockZAP) Authenticate(domain, address, identity, mechanism string, credentials [][]byte) (string, string, wire.Metadata, error) {
	return m.code, "", m.meta, nil
}

// runCurveServerSideExchange drives a full HELLO→WELCOME→INITIATE exchange
// using a real ClientState. Returns the server error from the INITIATE step
// (nil on success, non-nil on auth/ZAP rejection).
func runCurveServerSideExchange(t *testing.T, srv *ServerState, serverPub PublicKey, clientPub PublicKey, clientSec SecretKey) error {
	t.Helper()
	c, err := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	welcome, _, err := srv.Receive(hello)
	if err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	initiate, _, err := c.Receive(*welcome)
	if err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	_, _, srvErr := srv.Receive(*initiate)
	return srvErr
}

func TestCurveServerZAPAllowOverridesAuthorizer(t *testing.T) {
	serverPub, serverSec := makePair(t)
	clientPub, clientSec := makePair(t)

	denyAll := Authorizer(func(_ PublicKey, _ wire.Metadata) error {
		return errors.New("deny")
	})
	srv, err := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: denyAll, Rand: rand.Reader,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.ConfigureZAP(&mockZAP{code: "200"}, "dom")
	srv.SetPeerAddr("127.0.0.1:1")

	if err := runCurveServerSideExchange(t, srv, serverPub, clientPub, clientSec); err != nil {
		t.Fatalf("CURVE exchange with ZAP allow: %v", err)
	}
	if !srv.Done() {
		t.Fatal("Done() = false, want true")
	}
}

func TestCurveServerZAPDenySendsError(t *testing.T) {
	serverPub, serverSec := makePair(t)
	clientPub, clientSec := makePair(t)

	allowAll := Authorizer(func(_ PublicKey, _ wire.Metadata) error { return nil })
	srv, err := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: allowAll, Rand: rand.Reader,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.ConfigureZAP(&mockZAP{code: "400"}, "dom")
	srv.SetPeerAddr("127.0.0.1:1")

	err = runCurveServerSideExchange(t, srv, serverPub, clientPub, clientSec)
	if !errors.Is(err, security.ErrZAPDenied) {
		t.Fatalf("err = %v, want ErrZAPDenied", err)
	}
}

func TestCurveServerNoZAPUnchanged(t *testing.T) {
	serverPub, serverSec := makePair(t)
	clientPub, clientSec := makePair(t)

	denyAll := Authorizer(func(_ PublicKey, _ wire.Metadata) error {
		return errors.New("deny")
	})
	srv, err := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: denyAll, Rand: rand.Reader,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	err = runCurveServerSideExchange(t, srv, serverPub, clientPub, clientSec)
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("err = %v, want ErrAuthRejected", err)
	}
}
```

Note: `rand.Reader` is from `"crypto/rand"` — check that `curve/server_test.go` already imports it (it does, per existing tests).

- [ ] **Step 3: Run tests — confirm compile failure**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestCurveServerZAP|TestCurveServerNoZAP' ./internal/security/curve/... 2>&1 | head -20
```

Expected: compile error — undefined `ConfigureZAP`, `SetPeerAddr`.

- [ ] **Step 4: Implement ZAP support in `curve/server.go`**

**4a. Add ZAP fields to `ServerState`** (after the `rand io.Reader` field):

```go
// ZAP — set by ConfigureZAP; only used on the server side.
zap      security.ZAPCaller
domain   string
peerAddr string
zapMeta  wire.Metadata
```

**4b. Add `ConfigureZAP` and `SetPeerAddr` methods after `NewServer`:**

```go
// ConfigureZAP injects a ZAP client and domain. Satisfies security.ZAPConfigurer.
func (s *ServerState) ConfigureZAP(caller security.ZAPCaller, domain string) {
	s.zap = caller
	s.domain = domain
}

// SetPeerAddr stores the peer's network address for ZAP requests.
// Satisfies security.PeerAddrSetter.
func (s *ServerState) SetPeerAddr(addr string) { s.peerAddr = addr }
```

**4c. In `handleInitiate`, replace the authorizer call with ZAP-aware logic:**

Find the line (approximately 193):
```go
if authErr := s.authorizer(peerLongPub, clonedMd); authErr != nil {
    return s.failAuthRejected(authErr)
}
```

Replace with:
```go
if s.zap != nil {
    code, _, zapMeta, zapErr := s.zap.Authenticate(
        s.domain, s.peerAddr, "",
        "CURVE", [][]byte{peerLongPub[:]},
    )
    if zapErr != nil || code != "200" {
        return s.failZAPDenied(code)
    }
    s.zapMeta = zapMeta
} else if authErr := s.authorizer(peerLongPub, clonedMd); authErr != nil {
    return s.failAuthRejected(authErr)
}
```

**4d. Add `failZAPDenied` helper after `failAuthRejected`:**

```go
func (s *ServerState) failZAPDenied(statusCode string) (*wire.Command, bool, error) {
	s.failed = true
	reason := seccommon.SanitizeReason("ZAP " + statusCode)
	errCmd, encErr := wire.ErrorCommand{Reason: reason}.Encode()
	if encErr != nil {
		return nil, false, fmt.Errorf("curve: encode ERROR: %w", encErr)
	}
	return &errCmd, false, fmt.Errorf("%w: status %s", security.ErrZAPDenied, statusCode)
}
```

**4e. Update `PeerMetadata()` to merge ZAP metadata:**

Replace:
```go
func (s *ServerState) PeerMetadata() wire.Metadata { return s.peer }
```

With:
```go
func (s *ServerState) PeerMetadata() wire.Metadata {
	if len(s.zapMeta) == 0 {
		return s.peer
	}
	merged := seccommon.CloneMetadata(s.peer)
	return append(merged, s.zapMeta...)
}
```

- [ ] **Step 5: Run tests — confirm pass**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestCurveServerZAP|TestCurveServerNoZAP' ./internal/security/curve/... -v
```

Expected: all 3 tests PASS.

- [ ] **Step 6: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add internal/security/curve/server.go internal/security/curve/errors.go internal/security/curve/server_test.go && git commit -m "feat(F6b): curve — ZAP support (ConfigureZAP, SetPeerAddr, failZAPDenied)"
```

---

## Chunk 5: Root package wiring + integration tests

### Task 7: `options.go` + `base.go` wiring

**Files:**
- Modify: `options.go`
- Modify: `options_test.go`
- Modify: `base.go`

- [ ] **Step 1: Write failing tests in `options_test.go`**

Add at the bottom:

```go
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
```

Before writing this test, do three things:

**A) Add `HandlerFunc` adapter to `zap/handler.go`:**

```go
// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(r Request) (Reply, error)

func (f HandlerFunc) Authenticate(r Request) (Reply, error) { return f(r) }
```

**B) Update `zap/zap_test.go`:** Replace the local `handlerFunc` adapter type and its method (added in Task 2 Step 1) with `zap.HandlerFunc`. Delete these lines from `zap/zap_test.go`:

```go
// handlerFunc is a test helper that adapts a function to the Handler interface.
type handlerFunc func(r zmqzap.Request) (zmqzap.Reply, error)

func (f handlerFunc) Authenticate(r zmqzap.Request) (zmqzap.Reply, error) { return f(r) }
```

Then replace every `handlerFunc(func(...)` with `zmqzap.HandlerFunc(func(...)` in the test file.

**C) Add the `zap` import to `options_test.go`** (bare, no alias — there is no conflict with stdlib in this file):

```go
"github.com/tomi77/zmq4/zap"
```

The test uses `zap.HandlerFunc`, `zap.NewRouter`, `zap.Request`, `zap.Reply`, `zap.StatusOK` — all with bare `zap.` prefix, which matches the bare import.

- [ ] **Step 2: Run tests — confirm compile failure**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestWithZAPDomain' ./... 2>&1 | head -20
```

Expected: compile error — undefined `WithZAPDomain`.

- [ ] **Step 3: Add `zapCaller` + `zapDomain` to `socketConfig` and add `WithZAPDomain` to `options.go`**

**3a. Add fields to `socketConfig` struct** (after `sndOverflow OverflowPolicy`):

```go
zapCaller security.ZAPCaller // non-nil when WithZAPDomain is used
zapDomain string
```

**3b. Add import** for the `zap` package (using alias to avoid shadowing):

```go
zmqzap "github.com/tomi77/zmq4/zap"
```

**3c. Add `WithZAPDomain` option at the bottom of `options.go`:**

```go
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
```

- [ ] **Step 4: Update `base.go` — inject ZAP and peer address after mechanism creation**

In `doServerHandshake`, after the `mech, err := sb.cfg.serverMechFactory(socketType)` block, add:

```go
if sb.cfg.zapCaller != nil {
    if zc, ok := mech.(security.ZAPConfigurer); ok {
        zc.ConfigureZAP(sb.cfg.zapCaller, sb.cfg.zapDomain)
    }
}
if pas, ok := mech.(security.PeerAddrSetter); ok {
    pas.SetPeerAddr(raw.RemoteAddr().String())
}
```

The full updated `doServerHandshake`:

```go
func (sb *socketBase) doServerHandshake(raw net.Conn, socketType string) {
	defer sb.wg.Done()
	hsCtx, cancel := context.WithTimeout(context.Background(), sb.cfg.handshakeTimeout)
	defer cancel()

	mech, err := sb.cfg.serverMechFactory(socketType)
	if err != nil {
		raw.Close()
		return
	}
	if sb.cfg.zapCaller != nil {
		if zc, ok := mech.(security.ZAPConfigurer); ok {
			zc.ConfigureZAP(sb.cfg.zapCaller, sb.cfg.zapDomain)
		}
	}
	if pas, ok := mech.(security.PeerAddrSetter); ok {
		pas.SetPeerAddr(raw.RemoteAddr().String())
	}
	c, err := conn.ServerHandshake(hsCtx, raw, mech)
	if err != nil {
		return
	}
	if err := sb.addConn(c, socketType); err != nil {
		c.Close()
	}
}
```

- [ ] **Step 5: Run tests — confirm pass**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestWithZAPDomain' ./... -v
```

Expected: PASS.

- [ ] **Step 6: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add options.go options_test.go base.go zap/handler.go zap/zap_test.go && git commit -m "feat(F6b): wire WithZAPDomain option + base.go ZAPConfigurer/PeerAddrSetter injection"
```

---

### Task 8: Integration tests — ZAP with NULL and PLAIN

**Files:**
- Modify: `integration_test.go`

Integration tests use `inproc://` for synchronous in-process communication (no Docker). Package is `zmq4_test`.

- [ ] **Step 1: Write the tests**

Add at the bottom of `integration_test.go`:

```go
func TestNULLZAPAllow(t *testing.T) {
	// NULL mechanism + ZAP allow-all: connection succeeds, message delivered.
	endpoint := "inproc://TestNULLZAPAllow"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	router := zap.NewRouter(zap.HandlerFunc(func(r zap.Request) (zap.Reply, error) {
		if r.Mechanism != "NULL" {
			return zap.Reply{StatusCode: zap.StatusDenied, StatusText: "wrong mechanism"}, nil
		}
		return zap.Reply{StatusCode: zap.StatusOK, UserID: "anonymous"}, nil
	}))
	defer router.Close()

	push := zmq4.NewPUSH()
	pull := zmq4.NewPULL(zmq4.WithZAPDomain(router, ""))
	defer push.Close()
	defer pull.Close()

	if err := pull.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := push.Connect(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)

	if err := push.Send(ctx, zmq4.Message{[]byte("hello")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msg, err := pull.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(msg[0]) != "hello" {
		t.Fatalf("msg = %q, want hello", msg[0])
	}
}

func TestNULLZAPDenyBlocksConnection(t *testing.T) {
	// NULL mechanism + ZAP deny-all: connection is rejected at handshake.
	endpoint := "inproc://TestNULLZAPDenyBlocksConnection"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	router := zap.NewRouter(zap.HandlerFunc(func(r zap.Request) (zap.Reply, error) {
		return zap.Reply{StatusCode: zap.StatusDenied, StatusText: "denied"}, nil
	}))
	defer router.Close()

	push := zmq4.NewPUSH()
	pull := zmq4.NewPULL(zmq4.WithZAPDomain(router, "secure"))
	defer push.Close()
	defer pull.Close()

	if err := pull.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	// Connect succeeds at transport level; handshake failure happens async.
	if err := push.Connect(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	// Send should time out because no pipe was established.
	sendCtx, sendCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer sendCancel()
	err := push.Send(sendCtx, zmq4.Message{[]byte("blocked")})
	if err == nil {
		t.Fatal("Send succeeded, want error (no pipe established after ZAP denial)")
	}
}

func TestPLAINZAPAllow(t *testing.T) {
	// PLAIN mechanism + ZAP allow: connection succeeds.
	endpoint := "inproc://TestPLAINZAPAllow"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	router := zap.NewRouter(zap.HandlerFunc(func(r zap.Request) (zap.Reply, error) {
		if r.Mechanism != "PLAIN" || len(r.Credentials) < 2 {
			return zap.Reply{StatusCode: zap.StatusDenied}, nil
		}
		if string(r.Credentials[0]) == "alice" && string(r.Credentials[1]) == "secret" {
			return zap.Reply{StatusCode: zap.StatusOK, UserID: "alice"}, nil
		}
		return zap.Reply{StatusCode: zap.StatusDenied}, nil
	}))
	defer router.Close()

	// Local auth callback always denies — ZAP takes precedence.
	localDeny := plain.Authenticator(func(u, p []byte) error { return fmt.Errorf("local deny") })

	rep := zmq4.NewREP(zmq4.WithPLAINServer(localDeny), zmq4.WithZAPDomain(router, ""))
	req := zmq4.NewREQ(zmq4.WithPLAIN("alice", "secret"))
	defer rep.Close()
	defer req.Close()

	if err := rep.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := req.Connect(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)

	if err := req.Send(ctx, zmq4.Message{[]byte("ping")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msg, err := rep.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(msg[0]) != "ping" {
		t.Fatalf("msg = %q, want ping", msg[0])
	}
}

func TestPLAINZAPDenyRejectsConnection(t *testing.T) {
	// PLAIN mechanism + ZAP deny: wrong password is rejected.
	endpoint := "inproc://TestPLAINZAPDenyRejectsConnection"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	router := zap.NewRouter(zap.HandlerFunc(func(r zap.Request) (zap.Reply, error) {
		return zap.Reply{StatusCode: zap.StatusDenied, StatusText: "bad credentials"}, nil
	}))
	defer router.Close()

	localAllow := plain.Authenticator(func(u, p []byte) error { return nil })

	rep := zmq4.NewREP(zmq4.WithPLAINServer(localAllow), zmq4.WithZAPDomain(router, ""))
	req := zmq4.NewREQ(zmq4.WithPLAIN("alice", "wrong"))
	defer rep.Close()
	defer req.Close()

	if err := rep.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := req.Connect(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	sendCtx, sendCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer sendCancel()
	err := req.Send(sendCtx, zmq4.Message{[]byte("blocked")})
	if err == nil {
		t.Fatal("Send succeeded, want timeout (no pipe after ZAP denial)")
	}
}
```

`integration_test.go` already imports `"github.com/tomi77/zmq4/internal/security/plain"`. Add only:

```go
"github.com/tomi77/zmq4/zap"
```

Use the bare `zap` import name (no alias). The test bodies use `zap.NewRouter`, `zap.HandlerFunc`, `zap.StatusOK`, `zap.StatusDenied`, `zap.Reply`, `zap.Request` — all with the bare `zap.` prefix.

- [ ] **Step 2: Run the new tests**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test -run 'TestNULLZAP|TestPLAINZAP' -v ./...
```

Expected: all 4 PASS.

- [ ] **Step 3: Run full suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add integration_test.go && git commit -m "test(F6b): integration tests — ZAP allow/deny for NULL and PLAIN"
```

---

## Chunk 6: Done-criteria sweep

### Task 9: Done-criteria sweep

**Files:**
- Read-only tooling pass + meta-overview update.

- [ ] **Step 1: Run full test suite**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./...
```

Expected: all PASS, zero failures.

- [ ] **Step 2: Run staticcheck**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && staticcheck ./...
```

Expected: no output. Fix any findings before continuing.

- [ ] **Step 3: Run modernize**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && modernize -fix ./...
```

If any files changed, re-run tests and commit:

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && go test ./... && git add -u && git commit -m "chore(F6b): modernize sweep"
```

- [ ] **Step 4: Update meta-overview**

In `docs/specs/00-meta-overview.md`:

1. Update the Status line at the top — add F6b to the completed list:
```
F1, F2a, F2b, F2c, F3, F4, F5a, F5b, F5c, F6a, and F6b complete
```
Also add `phase-6b-zap-complete` to the tags list.

2. Split the F6b row (currently a combined F6b row) into F6b / F6c / F6d:

Replace:
```markdown
| F6b | `06-zap-monitoring.md` | ZAP auth, socket monitoring events, polling. | Interop and full integration. | Pending. |
```

With:
```markdown
| F6b | — | ZAP auth (RFC 27) for NULL/PLAIN/CURVE — in-process channel-based handler. | Unit + integration. | **Complete** — tagged `phase-6b-zap-complete`. |
| F6c | — | Socket monitoring events. | Unit + integration. | Pending. |
| F6d | — | Polling (zmq_poll equivalent). | Unit + integration. | Pending. |
```

- [ ] **Step 5: Commit meta-overview**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git add docs/specs/00-meta-overview.md && git commit -m "docs(F6b): update meta-overview — F6b complete, add F6c/F6d rows"
```

- [ ] **Step 6: Tag the phase**

```bash
cd /Users/tomaszrup/Projects/github.com/tomi77/zmq4 && git tag phase-6b-zap-complete
```
