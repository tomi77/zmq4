# F2a NULL Security Implementation Plan

> **For Claude:** REQUIRED: Use superpowers:subagent-driven-development to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking. Each task is one commit.

**Goal:** Implement `internal/security/null` per `docs/specs/02a-security-null.md`: a pure, I/O-free state machine for the ZMTP 3.1 NULL handshake.

**Architecture:** L2 layer above `internal/wire` (F1). Single concrete type `null.State`; no shared `Mechanism` interface yet (deferred to F2c). Metadata is parsed via F1's `wire.ParseReady`, then defensively copied so peer metadata lifetime is independent of the caller's frame buffer.

**Tech Stack:** Pure Go 1.26, stdlib only, depends on `github.com/tomi77/zmq4/internal/wire`. No I/O, no goroutines, no time. Allocations: single defensive copy of peer metadata per handshake; everything else borrows from F1.

**Decisions baked into the plan:**
- `null.State` is symmetric — same type for client and server. The greeting's `as-server` byte is informational only for NULL.
- `Receive` copies peer metadata (Name + Value bytes) into a fresh buffer so `PeerMetadata()` survives F4 reusing its frame buffer.
- ERROR receive: handled. ERROR send: not in scope (no rejection criteria for NULL without ZAP).
- `out *wire.Command` return from `Receive` is always nil for NULL — kept in the API for forward compatibility with PLAIN/CURVE.

---

## Chunk 1: Package skeleton, errors, state machine, tests

### Task 1: Package skeleton

**Files:**
- Create: `internal/security/doc.go`
- Create: `internal/security/null/doc.go`
- Create: `internal/security/null/errors.go`

- [ ] **Step 1: Write `internal/security/doc.go`**

```go
// Package security holds ZMTP 3.1 security mechanism state machines.
//
// Each mechanism (NULL, PLAIN, CURVE) lives in its own subpackage and
// implements a pure, I/O-free state machine consumed by the connection
// layer (F4). No package in security/ depends on net, time, or
// goroutines.
package security
```

- [ ] **Step 2: Write `internal/security/null/doc.go`**

```go
// Package null implements the ZMTP 3.1 NULL security handshake.
//
// NULL provides no authentication and no confidentiality. After the
// greeting completes with mechanism="NULL", both peers exchange a
// READY command containing their metadata, and the handshake is done.
//
// This package is pure: it does no I/O, allocates no goroutines, and
// reads no clocks. It consumes and produces wire.Command values on
// behalf of the caller.
//
// See docs/specs/02a-security-null.md for the full specification.
package null
```

- [ ] **Step 3: Write `internal/security/null/errors.go`**

```go
package null

import "errors"

var (
	// ErrAlreadyStarted is returned by Start when called more than once.
	ErrAlreadyStarted = errors.New("null: handshake already started")

	// ErrNotStarted is returned by Receive when called before Start.
	ErrNotStarted = errors.New("null: handshake not started")

	// ErrAlreadyDone is returned when any method is called after a
	// previous Receive returned done=true.
	ErrAlreadyDone = errors.New("null: handshake already complete")

	// ErrAlreadyFailed is returned when any method is called after a
	// previous error.
	ErrAlreadyFailed = errors.New("null: handshake already failed")

	// ErrUnexpectedCommand is returned when the peer sends a command
	// whose name is neither READY nor ERROR during the handshake.
	ErrUnexpectedCommand = errors.New("null: unexpected command")

	// ErrPeerError is returned when the peer sends an ERROR command.
	// The wrapped error includes the peer's reason string.
	ErrPeerError = errors.New("null: peer sent ERROR")

	// ErrMalformedReady is returned when the peer's READY command-data
	// fails to parse as metadata.
	ErrMalformedReady = errors.New("null: malformed READY")
)
```

- [ ] **Step 4: Verify package compiles**

Run: `go build ./internal/security/...`
Expected: success, no output.

- [ ] **Step 5: Commit**

```bash
git add internal/security/doc.go internal/security/null/doc.go internal/security/null/errors.go
git commit -m "security/null: package skeleton and sentinel errors"
```

---

### Task 2: State struct, New, Start

**Files:**
- Create: `internal/security/null/state.go`
- Create: `internal/security/null/state_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package null

import (
	"errors"
	"strings"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestNewReturnsNotDone(t *testing.T) {
	s := New(nil)
	if s.Done() {
		t.Fatalf("new state must not be Done")
	}
}

func TestStartEmitsReadyWithLocalMetadata(t *testing.T) {
	md := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REQ")},
	}
	s := New(md)
	cmd, err := s.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if cmd.Name != wire.ReadyCommandName {
		t.Fatalf("Start emitted command %q, want READY", cmd.Name)
	}
	rc, err := wire.ParseReady(cmd)
	if err != nil {
		t.Fatalf("ParseReady on Start output: %v", err)
	}
	if len(rc.Metadata) != 1 ||
		string(rc.Metadata[0].Name) != "Socket-Type" ||
		string(rc.Metadata[0].Value) != "REQ" {
		t.Fatalf("Start metadata = %+v, want Socket-Type=REQ", rc.Metadata)
	}
}

func TestStartTwiceReturnsAlreadyStarted(t *testing.T) {
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	_, err := s.Start()
	if !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start error = %v, want ErrAlreadyStarted", err)
	}
}

func TestStartWithEmptyMetadata(t *testing.T) {
	s := New(nil)
	cmd, err := s.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	rc, err := wire.ParseReady(cmd)
	if err != nil {
		t.Fatalf("ParseReady: %v", err)
	}
	if len(rc.Metadata) != 0 {
		t.Fatalf("expected empty metadata, got %+v", rc.Metadata)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/null/...`
Expected: FAIL (`undefined: New`, `undefined: State`).

- [ ] **Step 3: Write `internal/security/null/state.go`**

```go
package null

import (
	"fmt"

	"github.com/tomi77/zmq4/internal/wire"
)

// State drives one side of a ZMTP 3.1 NULL handshake. It is single-shot
// and not safe for concurrent use.
type State struct {
	local    wire.Metadata
	peer     wire.Metadata
	started  bool
	received bool
	failed   bool
}

// New constructs a State that will advertise localMetadata in our
// outbound READY. localMetadata is referenced, not copied; the caller
// must not mutate it after passing it in.
func New(localMetadata wire.Metadata) *State {
	return &State{local: localMetadata}
}

// Done reports whether the handshake has completed successfully.
func (s *State) Done() bool { return s.received && !s.failed }

// Start produces the initial outbound READY. It must be called exactly
// once, before any Receive call.
func (s *State) Start() (wire.Command, error) {
	if s.failed {
		return wire.Command{}, ErrAlreadyFailed
	}
	if s.started {
		return wire.Command{}, ErrAlreadyStarted
	}
	rc := wire.ReadyCommand{Metadata: s.local}
	cmd, err := rc.Encode()
	if err != nil {
		s.failed = true
		return wire.Command{}, fmt.Errorf("null: encode READY: %w", err)
	}
	s.started = true
	return cmd, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/null/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/null/state.go internal/security/null/state_test.go
git commit -m "security/null: State, New, Start"
```

---

### Task 3: Receive — happy path (peer's READY)

**Files:**
- Modify: `internal/security/null/state.go`
- Modify: `internal/security/null/state_test.go`

- [ ] **Step 1: Write the failing test**

Append to `state_test.go`:

```go
func TestReceivePeerReadyCompletesHandshake(t *testing.T) {
	peerCmd, err := wire.ReadyCommand{
		Metadata: wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("REP")},
			{Name: []byte("Identity"), Value: []byte("peer-1")},
		},
	}.Encode()
	if err != nil {
		t.Fatalf("encode peer READY: %v", err)
	}

	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	out, done, err := s.Receive(peerCmd)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if out != nil {
		t.Fatalf("Receive returned non-nil out=%+v, want nil for NULL", out)
	}
	if !done {
		t.Fatalf("Receive done=false, want true after peer READY")
	}
	if !s.Done() {
		t.Fatalf("Done() = false after successful Receive")
	}
	pm := s.PeerMetadata()
	if len(pm) != 2 ||
		string(pm[0].Name) != "Socket-Type" || string(pm[0].Value) != "REP" ||
		string(pm[1].Name) != "Identity" || string(pm[1].Value) != "peer-1" {
		t.Fatalf("PeerMetadata = %+v, want Socket-Type=REP,Identity=peer-1", pm)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/security/null/... -run TestReceivePeerReadyCompletesHandshake`
Expected: FAIL (`undefined: (*State).Receive`, `undefined: (*State).PeerMetadata`).

- [ ] **Step 3: Add `Receive` and `PeerMetadata` to `state.go`**

```go
// Receive consumes one command from the peer and advances the state
// machine. See package doc and 02a spec for the contract.
func (s *State) Receive(cmd wire.Command) (out *wire.Command, done bool, err error) {
	if s.failed {
		return nil, false, ErrAlreadyFailed
	}
	if !s.started {
		s.failed = true
		return nil, false, ErrNotStarted
	}
	if s.received {
		s.failed = true
		return nil, false, ErrAlreadyDone
	}
	switch cmd.Name {
	case wire.ReadyCommandName:
		rc, perr := wire.ParseReady(cmd)
		if perr != nil {
			s.failed = true
			return nil, false, fmt.Errorf("%w: %v", ErrMalformedReady, perr)
		}
		s.peer = copyMetadata(rc.Metadata)
		s.received = true
		return nil, true, nil
	}
	s.failed = true
	return nil, false, fmt.Errorf("%w: %q", ErrUnexpectedCommand, cmd.Name)
}

// PeerMetadata returns the metadata the peer advertised in its READY
// command. Valid only after Receive returned done=true. The returned
// slice is owned by the State and lives until the State is discarded;
// callers must not mutate it.
func (s *State) PeerMetadata() wire.Metadata { return s.peer }

// copyMetadata returns a deep copy: a fresh Metadata slice plus fresh
// Name/Value backing arrays for each property. This decouples
// PeerMetadata's lifetime from the input frame buffer that backed cmd.
func copyMetadata(src wire.Metadata) wire.Metadata {
	if len(src) == 0 {
		return nil
	}
	dst := make(wire.Metadata, len(src))
	for i, p := range src {
		name := make([]byte, len(p.Name))
		copy(name, p.Name)
		value := make([]byte, len(p.Value))
		copy(value, p.Value)
		dst[i] = wire.MetadataProperty{Name: name, Value: value}
	}
	return dst
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/null/...`
Expected: PASS (all four tests now green).

- [ ] **Step 5: Commit**

```bash
git add internal/security/null/state.go internal/security/null/state_test.go
git commit -m "security/null: Receive happy path with metadata copy"
```

---

### Task 4: Receive — ERROR command rejection

**Files:**
- Modify: `internal/security/null/state.go`
- Modify: `internal/security/null/state_test.go`

- [ ] **Step 1: Write the failing test**

Append to `state_test.go`:

```go
func TestReceiveErrorWrapsReason(t *testing.T) {
	errCmd, err := wire.ErrorCommand{Reason: "Invalid client"}.Encode()
	if err != nil {
		t.Fatalf("encode ERROR: %v", err)
	}

	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	_, done, err := s.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("Receive(ERROR) error = %v, want ErrPeerError", err)
	}
	if done {
		t.Fatalf("Receive(ERROR) done=true, want false")
	}
	if !strings.Contains(err.Error(), "Invalid client") {
		t.Fatalf("error %q does not include peer reason", err)
	}
	if s.Done() {
		t.Fatalf("Done()=true after ERROR")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/security/null/... -run TestReceiveErrorWrapsReason`
Expected: FAIL (Receive treats ERROR as ErrUnexpectedCommand).

- [ ] **Step 3: Extend the switch in `Receive`**

Add a case before the default in `Receive`:

```go
case wire.ErrorCommandName:
	ec, perr := wire.ParseError(cmd)
	if perr != nil {
		s.failed = true
		return nil, false, fmt.Errorf("%w: malformed ERROR: %v", ErrPeerError, perr)
	}
	s.failed = true
	return nil, false, fmt.Errorf("%w: %s", ErrPeerError, ec.Reason)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/null/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/null/state.go internal/security/null/state_test.go
git commit -m "security/null: Receive treats ERROR as peer rejection"
```

---

### Task 5: Receive — malformed/unexpected/lifecycle errors

**Files:**
- Modify: `internal/security/null/state_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `state_test.go`:

```go
func TestReceiveBeforeStart(t *testing.T) {
	s := New(nil)
	cmd, _ := wire.ReadyCommand{}.Encode()
	_, _, err := s.Receive(cmd)
	if !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Receive before Start = %v, want ErrNotStarted", err)
	}
}

func TestReceiveMalformedReady(t *testing.T) {
	bad := wire.Command{
		Name: wire.ReadyCommandName,
		// Truncated metadata: nameLen=5 but only 2 bytes follow.
		Data: []byte{0x05, 'A', 'B'},
	}
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := s.Receive(bad)
	if !errors.Is(err, ErrMalformedReady) {
		t.Fatalf("Receive(malformed) = %v, want ErrMalformedReady", err)
	}
}

func TestReceiveUnexpectedCommand(t *testing.T) {
	cmd := wire.Command{Name: "PING", Data: nil}
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := s.Receive(cmd)
	if !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("Receive(PING) = %v, want ErrUnexpectedCommand", err)
	}
}

func TestReceiveAfterDone(t *testing.T) {
	peerCmd, _ := wire.ReadyCommand{}.Encode()
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(peerCmd); err != nil {
		t.Fatalf("first Receive: %v", err)
	}
	_, _, err := s.Receive(peerCmd)
	if !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("second Receive = %v, want ErrAlreadyDone", err)
	}
}

func TestReceiveAfterFailed(t *testing.T) {
	cmd := wire.Command{Name: "PING"}
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(cmd); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("first Receive: %v", err)
	}
	_, _, err := s.Receive(cmd)
	if !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Receive after failure = %v, want ErrAlreadyFailed", err)
	}
}

func TestStartAfterFailedReturnsAlreadyFailed(t *testing.T) {
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(wire.Command{Name: "PING"}); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("Receive: %v", err)
	}
	_, err := s.Start()
	if !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Start after failure = %v, want ErrAlreadyFailed", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they pass without further code changes**

Run: `go test ./internal/security/null/...`
Expected: PASS — Tasks 3 and 4 already implemented all the lifecycle branches; this task only widens test coverage.

If any test fails, fix the corresponding lifecycle branch in `Receive` / `Start` and re-run.

- [ ] **Step 3: Commit**

```bash
git add internal/security/null/state_test.go
git commit -m "security/null: state-machine lifecycle tests"
```

---

### Task 6: Buffer-independence test for PeerMetadata

**Files:**
- Modify: `internal/security/null/state_test.go`

- [ ] **Step 1: Write the failing test**

Append:

```go
// TestPeerMetadataIndependentOfInputBuffer verifies that PeerMetadata
// survives the caller mutating (or freeing) the buffer that backed the
// Receive input. F4 will read frames into reusable buffers; null.State
// must not retain pointers into them.
func TestPeerMetadataIndependentOfInputBuffer(t *testing.T) {
	original, err := wire.ReadyCommand{
		Metadata: wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
		},
	}.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Copy into a buffer we own and can clobber afterwards.
	buf := make([]byte, len(original.Data))
	copy(buf, original.Data)
	peerCmd := wire.Command{Name: original.Name, Data: buf}

	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(peerCmd); err != nil {
		t.Fatalf("Receive: %v", err)
	}

	// Clobber the input buffer.
	for i := range buf {
		buf[i] = 0xFF
	}

	pm := s.PeerMetadata()
	if len(pm) != 1 ||
		string(pm[0].Name) != "Socket-Type" ||
		string(pm[0].Value) != "DEALER" {
		t.Fatalf("PeerMetadata after buffer clobber = %+v, want Socket-Type=DEALER", pm)
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./internal/security/null/... -run TestPeerMetadataIndependentOfInputBuffer`
Expected: PASS — Task 3's `copyMetadata` already provides this guarantee; this test pins the contract so a future "optimization" cannot remove the copy without breaking a test.

- [ ] **Step 3: Commit**

```bash
git add internal/security/null/state_test.go
git commit -m "security/null: pin PeerMetadata buffer-independence"
```

---

### Task 7: Property test (testing/quick) — full-duplex round-trip

**Files:**
- Create: `internal/security/null/state_property_test.go`

- [ ] **Step 1: Write the test**

```go
package null

import (
	"bytes"
	"math/rand"
	"testing"
	"testing/quick"

	"github.com/tomi77/zmq4/internal/wire"
)

// TestNullHandshakeProperty: random metadata round-trip via two State
// instances exchanging commands. Covers both lock-step and full-duplex
// orderings.
func TestNullHandshakeProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 1000}

	prop := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		mdA := randMetadata(rng)
		mdB := randMetadata(rng)

		a := New(mdA)
		b := New(mdB)

		cmdA, err := a.Start()
		if err != nil {
			t.Logf("a.Start: %v", err)
			return false
		}
		cmdB, err := b.Start()
		if err != nil {
			t.Logf("b.Start: %v", err)
			return false
		}

		// Order chosen by seed: 0=A receives first, 1=B receives first.
		if rng.Intn(2) == 0 {
			if _, _, err := a.Receive(cmdB); err != nil {
				return false
			}
			if _, _, err := b.Receive(cmdA); err != nil {
				return false
			}
		} else {
			if _, _, err := b.Receive(cmdA); err != nil {
				return false
			}
			if _, _, err := a.Receive(cmdB); err != nil {
				return false
			}
		}

		if !a.Done() || !b.Done() {
			return false
		}
		return metadataEqual(a.PeerMetadata(), mdB) &&
			metadataEqual(b.PeerMetadata(), mdA)
	}

	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

// randMetadata produces a deterministic random Metadata of size 0..6
// with property names from a small allowlist (so we don't violate
// isMetadataName) and value byte-blobs of length 0..32.
func randMetadata(rng *rand.Rand) wire.Metadata {
	names := []string{
		"Socket-Type", "Identity", "Resource",
		"X-Foo", "X-Bar", "X-Baz",
	}
	n := rng.Intn(len(names) + 1) // 0..6
	used := map[string]bool{}
	var md wire.Metadata
	for i := 0; i < n; i++ {
		name := names[rng.Intn(len(names))]
		if used[name] {
			continue
		}
		used[name] = true
		valLen := rng.Intn(33)
		val := make([]byte, valLen)
		rng.Read(val)
		md = append(md, wire.MetadataProperty{
			Name:  []byte(name),
			Value: val,
		})
	}
	return md
}

func metadataEqual(a, b wire.Metadata) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].Name, b[i].Name) ||
			!bytes.Equal(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}
```

- [ ] **Step 2: Run the property test**

Run: `go test ./internal/security/null/... -run TestNullHandshakeProperty -count=1`
Expected: PASS, 1000 iterations.

- [ ] **Step 3: Commit**

```bash
git add internal/security/null/state_property_test.go
git commit -m "security/null: property-based handshake round-trip"
```

---

### Task 8: Vector tests (4 hand-crafted .bin files)

**Files:**
- Create: `internal/security/null/testdata/null-ready-empty.bin`
- Create: `internal/security/null/testdata/null-ready-socket-type-req.bin`
- Create: `internal/security/null/testdata/null-ready-with-identity.bin`
- Create: `internal/security/null/testdata/null-error.bin`
- Create: `internal/security/null/testdata/README.md`
- Create: `internal/security/null/vector_test.go`

> Vectors are hand-crafted from RFC 37 §3 using F1's encoder, the same way F1 vectors were built. The .bin files contain the **command-name + command-data** body (i.e. the payload that goes into a FrameCommand body). Cross-validation against libzmq is deferred to F4 interop, per spec §8.

- [ ] **Step 1: Write a one-off generator at `internal/security/null/gen_vectors.go.tmp`**

```go
//go:build ignore

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tomi77/zmq4/internal/wire"
)

func main() {
	dir := "internal/security/null/testdata"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}

	type vector struct {
		name string
		cmd  wire.Command
	}

	mustEncode := func(rc wire.ReadyCommand) wire.Command {
		c, err := rc.Encode()
		if err != nil {
			panic(err)
		}
		return c
	}
	mustEncodeError := func(reason string) wire.Command {
		c, err := wire.ErrorCommand{Reason: reason}.Encode()
		if err != nil {
			panic(err)
		}
		return c
	}

	vectors := []vector{
		{"null-ready-empty.bin", mustEncode(wire.ReadyCommand{})},
		{"null-ready-socket-type-req.bin", mustEncode(wire.ReadyCommand{
			Metadata: wire.Metadata{
				{Name: []byte("Socket-Type"), Value: []byte("REQ")},
			},
		})},
		{"null-ready-with-identity.bin", mustEncode(wire.ReadyCommand{
			Metadata: wire.Metadata{
				{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
				// 8 bytes of pseudo-random identity, fixed seed for
				// determinism.
				{Name: []byte("Identity"), Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
			},
		})},
		{"null-error.bin", mustEncodeError("Invalid client")},
	}

	for _, v := range vectors {
		body, err := wire.EncodeCommand(v.cmd)
		if err != nil {
			panic(err)
		}
		path := filepath.Join(dir, v.name)
		if err := os.WriteFile(path, body, 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("wrote %s (%d bytes)\n", path, len(body))
	}
}
```

- [ ] **Step 2: Run the generator and remove it**

Run: `go run internal/security/null/gen_vectors.go.tmp && rm internal/security/null/gen_vectors.go.tmp`
Expected: prints four "wrote ..." lines, all four .bin files exist.

- [ ] **Step 3: Write `internal/security/null/testdata/README.md`**

```markdown
# F2a NULL handshake vectors

Hand-crafted from RFC 37 §3 using F1's encoder. Cross-validation against
libzmq is deferred to F4 interop, per `docs/specs/02a-security-null.md`
§8.

| File | Contents |
|------|----------|
| `null-ready-empty.bin` | `READY` with no metadata. |
| `null-ready-socket-type-req.bin` | `READY` with `Socket-Type=REQ`. |
| `null-ready-with-identity.bin` | `READY` with `Socket-Type=ROUTER` and 8-byte `Identity`. |
| `null-error.bin` | `ERROR` with reason `"Invalid client"` (RFC 37 §3.1 example). |

Each file holds the **command body** (command-name + command-data); the
outer FrameCommand framing is L1's concern.
```

- [ ] **Step 4: Write `internal/security/null/vector_test.go`**

```go
package null

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func parseAsCommand(t *testing.T, raw []byte) wire.Command {
	t.Helper()
	cmd, err := wire.ParseCommand(raw)
	if err != nil {
		t.Fatalf("ParseCommand: %v", err)
	}
	return cmd
}

func TestVectorReadyEmpty(t *testing.T) {
	raw := readVector(t, "null-ready-empty.bin")
	cmd := parseAsCommand(t, raw)
	rc, err := wire.ParseReady(cmd)
	if err != nil {
		t.Fatalf("ParseReady: %v", err)
	}
	if len(rc.Metadata) != 0 {
		t.Fatalf("metadata = %+v, want empty", rc.Metadata)
	}
	// Re-encode and compare bytes.
	cmd2, err := rc.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	raw2, err := wire.EncodeCommand(cmd2)
	if err != nil {
		t.Fatalf("EncodeCommand: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("re-encoded bytes differ: got %x want %x", raw2, raw)
	}
}

func TestVectorReadySocketTypeReq(t *testing.T) {
	raw := readVector(t, "null-ready-socket-type-req.bin")
	cmd := parseAsCommand(t, raw)

	// Drive Receive with this command.
	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := s.Receive(cmd); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	pm := s.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "REQ" {
		t.Fatalf("Socket-Type = %q, want REQ", v)
	}
}

func TestVectorReadyWithIdentity(t *testing.T) {
	raw := readVector(t, "null-ready-with-identity.bin")
	cmd := parseAsCommand(t, raw)
	rc, err := wire.ParseReady(cmd)
	if err != nil {
		t.Fatalf("ParseReady: %v", err)
	}
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if v, ok := rc.Metadata.Get("Identity"); !ok || !bytes.Equal(v, want) {
		t.Fatalf("Identity = %x, want %x", v, want)
	}
}

func TestVectorError(t *testing.T) {
	raw := readVector(t, "null-error.bin")
	cmd := parseAsCommand(t, raw)

	s := New(nil)
	if _, err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := s.Receive(cmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("Receive(ERROR) = %v, want ErrPeerError", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("Invalid client")) {
		t.Fatalf("error %q does not contain peer reason", err)
	}
}
```

- [ ] **Step 5: Run all tests + race**

Run: `go test -race ./internal/security/null/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/security/null/testdata internal/security/null/vector_test.go
git commit -m "security/null: hand-crafted handshake vectors"
```

---

### Task 9: Done-criteria sweep

**Files:** none changed; verification only.

- [ ] **Step 1: `go vet`**

Run: `go vet ./...`
Expected: no output.

- [ ] **Step 2: `staticcheck`**

Run: `staticcheck ./...` (install with `go install honnef.co/go/tools/cmd/staticcheck@latest` if missing).
Expected: no output.

- [ ] **Step 3: race-mode tests**

Run: `go test -race -count=1 ./...`
Expected: PASS, no race reports.

- [ ] **Step 4: Commit a handshake benchmark**

Create `internal/security/null/bench_test.go`:

```go
package null

import (
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func BenchmarkHandshake(b *testing.B) {
	md := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REQ")},
	}
	peerCmd, err := wire.ReadyCommand{Metadata: md}.Encode()
	if err != nil {
		b.Fatalf("encode peer: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := New(md)
		if _, err := s.Start(); err != nil {
			b.Fatalf("Start: %v", err)
		}
		if _, _, err := s.Receive(peerCmd); err != nil {
			b.Fatalf("Receive: %v", err)
		}
	}
}
```

Run: `go test -bench BenchmarkHandshake -benchmem -run='^$' ./internal/security/null/...`
Expected: PASS, `allocs/op` reported. The number is informational — it bounds the budget for F2b/F2c regression checks. No assertion gate; the benchmark documents the cost.

Stage and commit alongside the other benchmark file:

```bash
git add internal/security/null/bench_test.go
git commit -m "security/null: handshake benchmark"
```

- [ ] **Step 5: Mark spec as implemented**

Edit `docs/specs/02a-security-null.md`:
- Change status from `draft, awaiting approval before implementation.` to `implemented, frozen for F2b+.`
- For each `- [ ]` checkbox in §8 Done criteria, verify the corresponding evidence (vet output, staticcheck output, race output, vector tests, property test, benchmark) before ticking it. Do not tick anything that wasn't actually verified.

- [ ] **Step 6: Final commit**

```bash
git add docs/specs/02a-security-null.md
git commit -m "security/null: mark Phase 2a (NULL handshake) complete"
```

- [ ] **Step 7: Tag (after orchestrator confirms)**

```bash
git tag phase-2a-null-complete
```

(Push left to user.)
