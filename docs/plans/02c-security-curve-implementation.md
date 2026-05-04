# F2c CURVE Security Implementation Plan

> **For Claude:** REQUIRED: Use superpowers:subagent-driven-development to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking. Each task is one commit.

**Goal:** Implement `internal/security/curve` per `docs/specs/02c-security-curve.md`: a pure, I/O-free pair of state machines (`ClientState`, `ServerState`) for the ZMTP 3.1 CURVE handshake (HELLO ↔ WELCOME ↔ INITIATE ↔ READY) plus post-handshake `MESSAGE` traffic encryption. Also extract the cross-mechanism `Mechanism` / `ClientMechanism` interfaces in `internal/security` (root) and add pass-through `Wrap`/`Unwrap` to F2a/F2b's existing types.

**Architecture:** L2 layer above `internal/wire` (F1). Three concrete mechanisms (NULL, PLAIN, CURVE) now share the `Mechanism` interface in `internal/security` (root). CURVE adds `Wrap`/`Unwrap` for `MESSAGE`-wrapped, `nacl/box`-encrypted application frames; NULL and PLAIN add pass-through implementations. Server-side authorization is delegated to a caller-supplied `Authorizer` callback (F6 will replace with ZAP). Cookie design is RFC-stateless: the server seals `(C', s')` under a per-handshake `cookieKey` so it does not retain per-handshake state between WELCOME and INITIATE. Two new external dependencies — `golang.org/x/crypto/nacl/box` and `golang.org/x/crypto/nacl/secretbox` — both inside the same `golang.org/x/crypto` module.

**Tech Stack:** Pure Go 1.26, stdlib + `golang.org/x/crypto/nacl/box` + `golang.org/x/crypto/nacl/secretbox`. `math/rand/v2.NewChaCha8` for deterministic test entropy. No I/O, no goroutines, no time. Allocations: per `Wrap`/`Unwrap` ≤2 (ciphertext + encoded command body); per handshake step bounded by `testing.AllocsPerRun`.

**Decisions baked into the plan:**
- Two types `ClientState` and `ServerState` per role (same shape as F2b PLAIN). Each in its own file.
- Cross-mechanism interfaces (`Mechanism`, `ClientMechanism`) and shared sentinels (`ErrNotDone`, `ErrClosed`) live in `internal/security` (root).
- `internal/security/metaclone` is renamed to `internal/security/seccommon` and gains `SanitizeReason` (promoted from `plain`). All three mechanisms import `seccommon`. Done in a dedicated migration before any CURVE code lands so the rename is reviewable independently.
- `Authorizer` is `func(clientPublicKey PublicKey, peerMetadata wire.Metadata) error` — not an interface. Same single-callback shape as `plain.Authenticator`; promotion to an interface is mechanical when a third caller appears.
- Server has no `Start` — purely reactive (HELLO arrives first).
- On INITIATE auth-reject the server returns `(out=ERROR_cmd, err=ErrAuthRejected)`; malformed-* and crypto-failure paths return `err` only and let F4 close silently.
- `NewServer(...)` panics if `Authorizer == nil` — programming error caught at construction.
- `Rand` (an `io.Reader`) is injectable; vector tests use a `math/rand/v2.NewChaCha8` seeded with bytes pinned in the test file. Production paths default to `crypto/rand.Reader`.
- Long-term `OurSecretKey` is referenced (caller-owned). `Close()` zeros transient secret and shared keys but never the long-term secret.
- Reasons inside ERROR commands are sanitized via `seccommon.SanitizeReason` (non-VCHAR → `'?'`, then truncate to 255 bytes).
- Short-nonces (HELLO/INITIATE/READY/MESSAGE) are 64-bit counters encoded as **big-endian uint64** on the wire. Long-nonces (WELCOME/cookie/vouch) are 16 bytes of `rand` output.
- MESSAGE counter starts at 1 per direction; `recvNonce` starts at 0 as the "no MESSAGE accepted yet" sentinel; receiver requires strict `incoming > recvNonce` (gaps allowed, duplicates and reorders rejected with `ErrNonceReused`).
- `SecretKey` and `SharedKey` implement `String() = "[REDACTED]"` and `GoString() = "...([REDACTED])"` with **pointer receivers** so a stray `%v` never copies the 32 bytes onto another stack.

**Workflow note (project memory):** after the phase ends (here: end of Chunk 10), run `modernize -fix ./...` — see `MEMORY.md`.

**Phase tag:** `phase-2c-curve-complete` is applied only after every Chunk 10 done-criteria checkbox is verified.

---

## Chunk 1: Pre-CURVE refactor — promote helpers to `internal/security/seccommon`

This chunk does not add functionality. It is a pure rename + relocate so subsequent chunks can import a single shared package for both `CloneMetadata` and `SanitizeReason`. Spec §5.1 calls this out as a "dedicated commit before landing CURVE code".

### Task 1: Rename `internal/security/metaclone` → `internal/security/seccommon` and `Clone` → `CloneMetadata`

**Files:**
- Create: `internal/security/seccommon/doc.go`
- Create: `internal/security/seccommon/clone.go`
- Create: `internal/security/seccommon/clone_test.go`
- Modify: `internal/security/null/state.go` — change import + call site.
- Modify: `internal/security/plain/client.go` — change import + call site.
- Modify: `internal/security/plain/server.go` — change import + call site.
- Delete: `internal/security/metaclone/` (whole directory: `doc.go`, `clone.go`, `clone_test.go`).

- [ ] **Step 1: Write `internal/security/seccommon/doc.go`**

```go
// Package seccommon hosts pure helpers shared by the L2 security
// mechanisms (null, plain, curve):
//
//   - CloneMetadata makes a defensive deep copy of wire.Metadata so
//     PeerMetadata is independent of the input frame buffer.
//   - SanitizeReason makes an arbitrary string safe to embed in a ZMTP
//     ERROR command body (RFC 37 §3 ABNF: 0*255 VCHAR).
//
// Replaces the former internal/security/metaclone package; the rename
// happened in F2c so all three mechanisms could converge on a single
// helper package.
package seccommon
```

- [ ] **Step 2: Write `internal/security/seccommon/clone.go`**

```go
package seccommon

import "github.com/tomi77/zmq4/internal/wire"

// CloneMetadata returns a deep copy of src: a fresh Metadata slice plus
// fresh Name/Value backing arrays for each property. The result aliases
// none of src's backing storage. Empty/nil input returns nil.
func CloneMetadata(src wire.Metadata) wire.Metadata {
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

- [ ] **Step 3: Write `internal/security/seccommon/clone_test.go`**

```go
package seccommon

import (
	"bytes"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestCloneMetadataEmpty(t *testing.T) {
	if got := CloneMetadata(nil); got != nil {
		t.Fatalf("CloneMetadata(nil) = %+v, want nil", got)
	}
	if got := CloneMetadata(wire.Metadata{}); got != nil {
		t.Fatalf("CloneMetadata(empty) = %+v, want nil", got)
	}
}

func TestCloneMetadataIndependentBuffers(t *testing.T) {
	name := []byte("Socket-Type")
	value := []byte("REQ")
	src := wire.Metadata{
		{Name: name, Value: value},
	}
	dst := CloneMetadata(src)

	for i := range name {
		name[i] = 0xFF
	}
	for i := range value {
		value[i] = 0xFF
	}

	if !bytes.Equal(dst[0].Name, []byte("Socket-Type")) {
		t.Fatalf("dst.Name = %x, want unchanged", dst[0].Name)
	}
	if !bytes.Equal(dst[0].Value, []byte("REQ")) {
		t.Fatalf("dst.Value = %x, want unchanged", dst[0].Value)
	}
}
```

- [ ] **Step 4: Run new package tests in isolation**

Run: `go test ./internal/security/seccommon/... -count=1`
Expected: PASS.

- [ ] **Step 5: Replace `metaclone.Clone` with `seccommon.CloneMetadata` in null & plain**

In `internal/security/null/state.go`:
- Replace import path `"github.com/tomi77/zmq4/internal/security/metaclone"` with `"github.com/tomi77/zmq4/internal/security/seccommon"`.
- Replace `metaclone.Clone(rc.Metadata)` with `seccommon.CloneMetadata(rc.Metadata)`.

In `internal/security/plain/client.go` (the line `c.peer = metaclone.Clone(rc.Metadata)`):
- Same import-path swap.
- Replace the call site.

In `internal/security/plain/server.go` (the line `s.peer = metaclone.Clone(md)`):
- Same import-path swap.
- Replace the call site.

- [ ] **Step 6: Update stale `metaclone` comments in `internal/security/null/bench_test.go`**

The bench test contains two stale comment references that name `metaclone.Clone`:
- line ~37: `// allocations from metaclone.Clone (one for the Metadata slice, one Name`
- line ~71: `t.Fatalf("null.State alloc share = %v ... metaclone.Clone budget changed", ...)`

Replace both with `seccommon.CloneMetadata`. The build never broke (these are comments / format strings), but stale wording misleads future readers post-rename.

- [ ] **Step 7: Delete the old metaclone package**

Run: `rm -r internal/security/metaclone`

- [ ] **Step 8: Verify the whole module builds and tests pass**

Run: `go build ./... && go test -race ./internal/security/... -count=1`
Expected: PASS — including the existing `TestPeerMetadataIndependentOfInputBuffer` in null and the equivalent tests in plain.

- [ ] **Step 9: vet / staticcheck**

Run: `go vet ./... && staticcheck ./...`
Expected: no output.

- [ ] **Step 10: Commit**

```bash
git add internal/security/seccommon \
        internal/security/null/state.go \
        internal/security/null/bench_test.go \
        internal/security/plain/client.go \
        internal/security/plain/server.go
git rm -r internal/security/metaclone
git commit -m "$(cat <<'EOF'
security: rename metaclone → seccommon for shared L2 helpers

F2c needs a shared SanitizeReason in addition to CloneMetadata.
Promote both into one package so null/plain/curve import a single
helper module. Function rename Clone → CloneMetadata is the only
visible change; behavior is unchanged.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Move `plain.sanitizeReason` → `seccommon.SanitizeReason`

**Files:**
- Modify: `internal/security/seccommon/clone.go` — split into `clone.go` + `sanitize.go` (logical split; same package).
- Create: `internal/security/seccommon/sanitize.go`
- Create: `internal/security/seccommon/sanitize_test.go`
- Modify: `internal/security/plain/codec.go` — delete `sanitizeReason`.
- Modify: `internal/security/plain/codec_test.go` — delete the three `TestSanitizeReason*` tests (they live in seccommon now).
- Modify: `internal/security/plain/server.go` — call `seccommon.SanitizeReason` instead of `sanitizeReason`.

> **Why this split:** the `plain` package owns no spec-level claim on the reason format — RFC 37 §3 ABNF is generic and applies to every mechanism's ERROR. Moving the helper out of plain prevents curve from re-defining the same function.

- [ ] **Step 1: Write the failing tests in `internal/security/seccommon/sanitize_test.go`**

```go
package seccommon

import (
	"strings"
	"testing"
)

func TestSanitizeReasonReplacesNonVCHAR(t *testing.T) {
	in := "ok\nhuh\x00\tend\x7F\xFF "
	out := SanitizeReason(in)
	if strings.ContainsAny(out, "\n\t\x00\x7F\xFF ") {
		t.Fatalf("SanitizeReason left non-VCHAR bytes in %q", out)
	}
	if len(out) != len(in) {
		t.Fatalf("SanitizeReason length = %d, want %d", len(out), len(in))
	}
}

func TestSanitizeReasonTruncatesTo255(t *testing.T) {
	in := strings.Repeat("a", 300)
	out := SanitizeReason(in)
	if len(out) != 255 {
		t.Fatalf("len = %d, want 255", len(out))
	}
}

func TestSanitizeReasonEmpty(t *testing.T) {
	if out := SanitizeReason(""); out != "" {
		t.Fatalf("SanitizeReason(\"\") = %q, want \"\"", out)
	}
}

func TestSanitizeReasonAllVCHARPassthrough(t *testing.T) {
	in := "ALL_PRINT-Able_!#$%&*+,-./0123456789:;<=>?@ABCDEFG"
	out := SanitizeReason(in)
	if out != in {
		t.Fatalf("SanitizeReason(%q) = %q, want unchanged", in, out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/security/seccommon/... -run TestSanitizeReason -count=1`
Expected: FAIL (`undefined: SanitizeReason`).

- [ ] **Step 3: Write `internal/security/seccommon/sanitize.go`**

```go
package seccommon

// SanitizeReason makes s safe to embed in the body of a ZMTP ERROR
// command (RFC 37 §3 ABNF: error-reason = OCTET 0*255VCHAR). Replaces
// any non-VCHAR byte with '?', then truncates to 255 bytes. VCHAR is
// %x21..%x7E (printable ASCII excluding space).
//
// The empty string is returned unchanged.
func SanitizeReason(s string) string {
	if s == "" {
		return ""
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x21 || c > 0x7E {
			b[i] = '?'
		}
	}
	if len(b) > 255 {
		b = b[:255]
	}
	return string(b)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/security/seccommon/... -count=1`
Expected: PASS — both `CloneMetadata` and the new `SanitizeReason` tests.

- [ ] **Step 5: Delete `sanitizeReason` from `internal/security/plain/codec.go`**

Remove the entire `func sanitizeReason(...)` block (and its leading godoc).

- [ ] **Step 6: Replace the `plain` call site in `server.go`**

In `internal/security/plain/server.go` `failAuthRejected`:
- Add import: `"github.com/tomi77/zmq4/internal/security/seccommon"`.
- Replace `reason := sanitizeReason(authErr.Error())` with `reason := seccommon.SanitizeReason(authErr.Error())`.

- [ ] **Step 7: Remove the now-orphaned tests in `internal/security/plain/codec_test.go`**

Delete `TestSanitizeReasonReplacesNonVCHAR`, `TestSanitizeReasonTruncatesTo255`, `TestSanitizeReasonEmpty`. Their seccommon equivalents already pin the contract. Remove the now-unused `"strings"` import if it has no other consumers in the file.

- [ ] **Step 8: Verify everything still builds and passes**

Run: `go build ./... && go test -race ./... -count=1`
Expected: PASS.

- [ ] **Step 9: vet / staticcheck**

Run: `go vet ./... && staticcheck ./...`
Expected: no output.

- [ ] **Step 10: Commit**

```bash
git add internal/security/seccommon \
        internal/security/plain/codec.go \
        internal/security/plain/codec_test.go \
        internal/security/plain/server.go
git commit -m "$(cat <<'EOF'
security: promote sanitizeReason → seccommon.SanitizeReason

F2c needs the same VCHAR sanitization for CURVE's auth-reject ERROR
reason. Move the helper into seccommon alongside CloneMetadata so all
three mechanisms share one implementation. No behavior change; the
RFC 37 §3 contract is unchanged.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 2: Cross-mechanism interfaces in `internal/security` (root)

Spec §4.1 prescribes the shape. Three implementations exist (after Chunk 3) — that is the threshold for promoting an interface from "speculative" to "load-bearing".

### Task 3: Define `Mechanism`, `ClientMechanism`, `ErrNotDone`, `ErrClosed`

**Files:**
- Create: `internal/security/doc.go`
- Create: `internal/security/interfaces.go`
- Create: `internal/security/errors.go`
- Create: `internal/security/interfaces_test.go` — compile-time guard that the interfaces continue to make sense (no concrete implementer asserted yet — that lands in Chunk 8).

- [ ] **Step 1: Write `internal/security/doc.go`**

```go
// Package security defines cross-mechanism types for the ZMTP 3.1
// security layer (L2). Concrete mechanisms live in subpackages:
//
//   - internal/security/null    — NULL mechanism (RFC 37 §3.1).
//   - internal/security/plain   — PLAIN mechanism (RFC 37 §3.2).
//   - internal/security/curve   — CURVE mechanism (RFC 37 §3.3 / RFC 26).
//
// All three implement Mechanism (and the active side of each
// implements ClientMechanism). The interfaces are consumed by F4
// (connection layer) and tested cross-mechanism in
// interfaces_conformance_test.go.
//
// See docs/specs/02c-security-curve.md §4.1 for the full contract.
package security
```

- [ ] **Step 2: Write `internal/security/interfaces.go`**

```go
package security

import "github.com/tomi77/zmq4/internal/wire"

// Mechanism drives one side of a ZMTP 3.1 security handshake and
// post-handshake traffic encapsulation. Single-shot per connection:
// once Done() returns true (or any method returns an error), the
// Mechanism must not be reused.
//
// All methods are NOT goroutine-safe. F4 owns sequencing.
type Mechanism interface {
	// Receive consumes one peer command and advances the handshake.
	// After Done(), Receive MUST NOT be called.
	Receive(cmd wire.Command) (out *wire.Command, done bool, err error)

	// Wrap transforms one outgoing application frame into its on-wire
	// form. Valid only after Done(); otherwise returns ErrNotDone.
	//
	// NULL/PLAIN return f unchanged. CURVE returns a FrameCommand whose
	// Body is the encoded MESSAGE command carrying the encrypted
	// (flags||payload) under the CURVE session keys. f.More is preserved
	// inside the encrypted payload as the inner flags byte (bit 0 ==
	// MORE); the outer wire.Frame.More is always false.
	//
	// Wrap operates on a single frame. Multi-frame logical messages
	// (linked via MORE) are wrapped one frame at a time: each frame
	// becomes its own MESSAGE command with its own short-nonce.
	//
	// The returned Frame's Body is freshly allocated and owned by the
	// caller. Wrap consumes f synchronously: it MUST read whatever it
	// needs from f.Body before returning and MUST NOT retain or mutate
	// any reference to f. The caller is therefore free to reuse, mutate,
	// or release f.Body the instant Wrap returns.
	Wrap(f wire.Frame) (wire.Frame, error)

	// Unwrap inverts Wrap. NULL/PLAIN return f unchanged. CURVE expects
	// f to be a FrameCommand whose body parses as a MESSAGE command;
	// the box is opened, the inner flags byte is split out, and a
	// wire.Frame is returned whose Kind is FrameMessage, More is
	// recovered from the inner flags byte (bit 0), and Body is the
	// decrypted payload.
	//
	// The returned Frame's Body is freshly allocated and independent of
	// f. Unwrap consumes f synchronously: same lifetime rule as Wrap —
	// the caller may reuse f.Body immediately upon return.
	Unwrap(f wire.Frame) (wire.Frame, error)

	// Done reports whether the handshake completed successfully.
	Done() bool

	// PeerMetadata returns the metadata advertised by the peer in its
	// handshake. Valid only after Done(). The returned Metadata aliases
	// an internal buffer; callers MUST NOT mutate it.
	PeerMetadata() wire.Metadata
}

// ClientMechanism is a Mechanism with an active-side initialization
// step. Implemented by null.State, plain.ClientState, and
// curve.ClientState. Server-side states (plain.ServerState,
// curve.ServerState) implement only Mechanism.
//
// F4 obtains a Mechanism / ClientMechanism by calling the per-package
// constructor; the active side calls Start() exactly once before
// entering the Receive loop.
type ClientMechanism interface {
	Mechanism
	Start() (wire.Command, error)
}
```

- [ ] **Step 3: Write `internal/security/errors.go`**

```go
package security

import "errors"

// ErrNotDone is returned by Wrap/Unwrap if the handshake has not
// completed.
var ErrNotDone = errors.New("security: handshake not done")

// ErrClosed is returned by every method after Close has been called
// (CURVE-only; NULL/PLAIN have no Close).
var ErrClosed = errors.New("security: state closed")
```

- [ ] **Step 4: Write `internal/security/interfaces_test.go` (sanity-only — implementer assertions land in Chunk 8)**

```go
package security_test

import (
	"errors"
	"testing"

	"github.com/tomi77/zmq4/internal/security"
)

func TestErrNotDoneIsDistinct(t *testing.T) {
	if errors.Is(security.ErrNotDone, security.ErrClosed) {
		t.Fatalf("ErrNotDone matches ErrClosed; sentinels must be distinct")
	}
	if errors.Is(security.ErrClosed, security.ErrNotDone) {
		t.Fatalf("ErrClosed matches ErrNotDone; sentinels must be distinct")
	}
}
```

- [ ] **Step 5: Verify package builds and tests pass**

Run: `go test ./internal/security/ -count=1`
Expected: PASS.

- [ ] **Step 6: vet / staticcheck**

Run: `go vet ./internal/security/... && staticcheck ./internal/security/...`
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add internal/security/doc.go internal/security/interfaces.go \
        internal/security/errors.go internal/security/interfaces_test.go
git commit -m "$(cat <<'EOF'
security: extract Mechanism/ClientMechanism interfaces and shared sentinels

Three concrete mechanisms now exist (NULL, PLAIN, CURVE-after-this-phase),
which is the threshold for promoting the shape from speculative to
load-bearing. ErrNotDone and ErrClosed live alongside so every mechanism
references the same sentinel for "Wrap/Unwrap before Done" and post-Close
calls.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 3: F2a/F2b amendments — pass-through `Wrap`/`Unwrap`

Spec §2.1 mandates these methods on every existing state: NULL/PLAIN return frames unchanged; both return `security.ErrNotDone` before `Done()`. Frozen public surface is preserved (no existing fields/funcs change). Phase tags `phase-2a-null-complete` and `phase-2b-plain-complete` are not re-cut; the change is recorded as an amendment note in `00-meta-overview.md` (touched in Chunk 10).

### Task 4: `null.State.Wrap` / `null.State.Unwrap`

**Files:**
- Modify: `internal/security/null/state.go` — add `Wrap`, `Unwrap`.
- Modify: `internal/security/null/state_test.go` — add tests for the new methods.

- [ ] **Step 1: Write the failing tests**

Append to `internal/security/null/state_test.go`:

```go
import (
	"bytes"
	"errors"
	"testing"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/wire"
)

func TestNullWrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	s := New(nil)
	f := wire.Frame{Kind: wire.FrameMessage, Body: []byte("hi")}
	if _, err := s.Wrap(f); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("Wrap before Done = %v, want security.ErrNotDone", err)
	}
}

func TestNullUnwrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	s := New(nil)
	f := wire.Frame{Kind: wire.FrameMessage, Body: []byte("hi")}
	if _, err := s.Unwrap(f); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("Unwrap before Done = %v, want security.ErrNotDone", err)
	}
}

func TestNullWrapPassthrough(t *testing.T) {
	s := newDoneState(t)
	want := wire.Frame{Kind: wire.FrameMessage, More: true, Body: []byte("payload")}
	got, err := s.Wrap(want)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if got.Kind != want.Kind || got.More != want.More || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("Wrap mutated frame: got=%+v want=%+v", got, want)
	}
}

func TestNullUnwrapPassthrough(t *testing.T) {
	s := newDoneState(t)
	want := wire.Frame{Kind: wire.FrameMessage, More: false, Body: []byte("payload")}
	got, err := s.Unwrap(want)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got.Kind != want.Kind || got.More != want.More || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("Unwrap mutated frame: got=%+v want=%+v", got, want)
	}
}

// newDoneState drives the NULL handshake to completion using a paired
// peer-side State so the test does not have to hand-craft READY bytes.
// Helper for the Wrap/Unwrap tests above.
func newDoneState(t *testing.T) *State {
	t.Helper()
	a := New(nil)
	if _, err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	peerReady, err := wire.ReadyCommand{}.Encode()
	if err != nil {
		t.Fatalf("encode peer READY: %v", err)
	}
	if _, _, err := a.Receive(peerReady); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !a.Done() {
		t.Fatalf("not done after Receive(READY)")
	}
	return a
}
```

**Important:** the file already has an import block. Do **not** add a second `import (...)` declaration — merge every new import into the existing block. New imports introduced here include `"bytes"`, `"errors"`, `"testing"`, `"github.com/tomi77/zmq4/internal/wire"`, **and** `"github.com/tomi77/zmq4/internal/security"`. Any of those that already exist should not be duplicated; any that are new must be added to the same block.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/null/... -run TestNullWrap -run TestNullUnwrap -count=1`
Expected: FAIL (`(*null.State).Wrap` undefined / wrong signature).

- [ ] **Step 3: Add `Wrap` and `Unwrap` to `internal/security/null/state.go`**

```go
import (
	// ... existing imports ...
	"github.com/tomi77/zmq4/internal/security"
)

// Wrap returns f unchanged. NULL does no traffic encapsulation.
// Returns security.ErrNotDone if called before the handshake completes.
func (s *State) Wrap(f wire.Frame) (wire.Frame, error) {
	if !s.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}

// Unwrap returns f unchanged. NULL does no traffic encapsulation.
// Returns security.ErrNotDone if called before the handshake completes.
func (s *State) Unwrap(f wire.Frame) (wire.Frame, error) {
	if !s.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}
```

- [ ] **Step 4: Run all null tests**

Run: `go test -race ./internal/security/null/... -count=1`
Expected: PASS — including the existing handshake suite and the four new ones.

- [ ] **Step 5: vet / staticcheck**

Run: `go vet ./internal/security/null/... && staticcheck ./internal/security/null/...`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add internal/security/null/state.go internal/security/null/state_test.go
git commit -m "$(cat <<'EOF'
security/null: add pass-through Wrap/Unwrap (F2c amendment)

Mechanism interface (Chunk 2) requires Wrap/Unwrap on every state.
NULL does no traffic encapsulation; the implementations return frames
unchanged after Done() and security.ErrNotDone before. Additive — no
existing field or function changes; phase-2a-null-complete tag stays
valid.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `plain.ClientState` / `plain.ServerState` `Wrap` / `Unwrap`

**Files:**
- Modify: `internal/security/plain/client.go` — add `Wrap`, `Unwrap`.
- Modify: `internal/security/plain/server.go` — add `Wrap`, `Unwrap`.
- Modify: `internal/security/plain/client_test.go` — add tests.
- Modify: `internal/security/plain/server_test.go` — add tests.

- [ ] **Step 1: Write the failing tests**

Append to `internal/security/plain/client_test.go`:

```go
func TestPlainClientWrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	c, _ := NewClient(nil, nil, nil)
	f := wire.Frame{Kind: wire.FrameMessage, Body: []byte("x")}
	if _, err := c.Wrap(f); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("Wrap before Done = %v, want security.ErrNotDone", err)
	}
}

func TestPlainClientUnwrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	c, _ := NewClient(nil, nil, nil)
	f := wire.Frame{Kind: wire.FrameMessage, Body: []byte("x")}
	if _, err := c.Unwrap(f); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("Unwrap before Done = %v, want security.ErrNotDone", err)
	}
}

func TestPlainClientWrapPassthrough(t *testing.T) {
	c := newPlainClientDone(t)
	want := wire.Frame{Kind: wire.FrameMessage, More: true, Body: []byte("payload")}
	got, err := c.Wrap(want)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if got.Kind != want.Kind || got.More != want.More || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("Wrap mutated frame: got=%+v want=%+v", got, want)
	}
}

func TestPlainClientUnwrapPassthrough(t *testing.T) {
	c := newPlainClientDone(t)
	want := wire.Frame{Kind: wire.FrameMessage, More: false, Body: []byte("payload")}
	got, err := c.Unwrap(want)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got.Kind != want.Kind || got.More != want.More || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("Unwrap mutated frame: got=%+v want=%+v", got, want)
	}
}

func newPlainClientDone(t *testing.T) *ClientState {
	t.Helper()
	c, err := NewClient([]byte("u"), []byte("p"), nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	peerReady, err := wire.ReadyCommand{}.Encode()
	if err != nil {
		t.Fatalf("encode peer READY: %v", err)
	}
	if _, _, err := c.Receive(peerReady); err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}
	if !c.Done() {
		t.Fatalf("not done")
	}
	return c
}
```

Add the import `"github.com/tomi77/zmq4/internal/security"` to the test file.

Append to `internal/security/plain/server_test.go`:

```go
func TestPlainServerWrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	s := NewServer(acceptAll, nil)
	f := wire.Frame{Kind: wire.FrameMessage, Body: []byte("x")}
	if _, err := s.Wrap(f); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("Wrap before Done = %v, want security.ErrNotDone", err)
	}
}

func TestPlainServerUnwrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	s := NewServer(acceptAll, nil)
	f := wire.Frame{Kind: wire.FrameMessage, Body: []byte("x")}
	if _, err := s.Unwrap(f); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("Unwrap before Done = %v, want security.ErrNotDone", err)
	}
}

func TestPlainServerWrapPassthrough(t *testing.T) {
	s := newPlainServerDone(t)
	want := wire.Frame{Kind: wire.FrameMessage, More: true, Body: []byte("payload")}
	got, err := s.Wrap(want)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if got.Kind != want.Kind || got.More != want.More || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("Wrap mutated frame: got=%+v want=%+v", got, want)
	}
}

func TestPlainServerUnwrapPassthrough(t *testing.T) {
	s := newPlainServerDone(t)
	want := wire.Frame{Kind: wire.FrameMessage, More: false, Body: []byte("payload")}
	got, err := s.Unwrap(want)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got.Kind != want.Kind || got.More != want.More || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("Unwrap mutated frame: got=%+v want=%+v", got, want)
	}
}

func newPlainServerDone(t *testing.T) *ServerState {
	t.Helper()
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{Username: []byte("u"), Password: []byte("p")})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	initiate := wire.Command{Name: initiateCommandName, Data: wire.EncodeMetadata(nil)}
	if _, _, err := s.Receive(initiate); err != nil {
		t.Fatalf("Receive(INITIATE): %v", err)
	}
	if !s.Done() {
		t.Fatalf("not done")
	}
	return s
}
```

Add the import `"github.com/tomi77/zmq4/internal/security"` to the test file.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/plain/... -run TestPlain.*Wrap -run TestPlain.*Unwrap -count=1`
Expected: FAIL (`(*ClientState).Wrap` / `(*ServerState).Wrap` undefined).

- [ ] **Step 3: Add `Wrap` and `Unwrap` to `internal/security/plain/client.go`**

```go
import (
	// ... existing imports ...
	"github.com/tomi77/zmq4/internal/security"
)

// Wrap returns f unchanged. PLAIN does no traffic encapsulation.
// Returns security.ErrNotDone if called before the handshake completes.
func (c *ClientState) Wrap(f wire.Frame) (wire.Frame, error) {
	if !c.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}

// Unwrap returns f unchanged. PLAIN does no traffic encapsulation.
// Returns security.ErrNotDone if called before the handshake completes.
func (c *ClientState) Unwrap(f wire.Frame) (wire.Frame, error) {
	if !c.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}
```

- [ ] **Step 4: Add `Wrap` and `Unwrap` to `internal/security/plain/server.go`**

Same shape as `client.go` Step 3 — replace the receiver with `s *ServerState` and the gate with `s.Done()`.

Add the import `"github.com/tomi77/zmq4/internal/security"` to `server.go`. Note: `seccommon` (already imported from Task 2) and `security` (root) are **different** packages — both are needed in this file from now on.

```go
func (s *ServerState) Wrap(f wire.Frame) (wire.Frame, error) {
	if !s.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}

func (s *ServerState) Unwrap(f wire.Frame) (wire.Frame, error) {
	if !s.Done() {
		return wire.Frame{}, security.ErrNotDone
	}
	return f, nil
}
```

- [ ] **Step 5: Run all plain tests**

Run: `go test -race ./internal/security/plain/... -count=1`
Expected: PASS.

- [ ] **Step 6: vet / staticcheck**

Run: `go vet ./internal/security/plain/... && staticcheck ./internal/security/plain/...`
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add internal/security/plain/client.go internal/security/plain/server.go \
        internal/security/plain/client_test.go internal/security/plain/server_test.go
git commit -m "$(cat <<'EOF'
security/plain: add pass-through Wrap/Unwrap (F2c amendment)

Same pattern as null: PLAIN does no traffic encapsulation, so Wrap and
Unwrap return frames unchanged after Done() and security.ErrNotDone
before. Additive only; phase-2b-plain-complete tag stays valid.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 4: CURVE package skeleton — dependency, errors, key types

### Task 6: Add `golang.org/x/crypto` dependency

**Files:**
- Modify: `go.mod` — add `require golang.org/x/crypto vX.Y.Z`.
- Modify: `go.sum` — `go mod tidy` regenerates.

> First non-stdlib dependency in the module. Both `nacl/box` (handshake + traffic) and `nacl/secretbox` (cookie inner) live inside this single module, so one `require` suffices.

- [ ] **Step 1: Resolve the latest released version and pin it**

Run: `go list -m -versions golang.org/x/crypto | tr ' ' '\n' | tail -1`
Expected: prints the most recent published version, e.g. `v0.31.0`. Note this version — write it into the `go get` command in Step 2 instead of `@latest` so the build is reproducible across operators and the spec change is auditable.

If the module list is unreachable (offline / sandboxed dev), ask the operator to make `golang.org/x/crypto` available; this plan does not vendor it manually.

- [ ] **Step 2: Add the dependency at the pinned version**

Run: `go get golang.org/x/crypto@vX.Y.Z` — substitute the exact version printed in Step 1 (do **not** use `@latest`, which would re-resolve on each operator's clock).
Expected: `go.mod` lists `golang.org/x/crypto vX.Y.Z` and `go.sum` has matching `h1:` and `go.mod` lines for that version.

- [ ] **Step 3: Smoke-import the packages we will consume**

Run from the repo root:

```bash
cat > /tmp/curve_smoke.go <<'EOF'
//go:build ignore

package main

import (
	"fmt"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

func main() {
	_ = box.Overhead
	_ = secretbox.Overhead
	fmt.Println("ok")
}
EOF
go run /tmp/curve_smoke.go
rm /tmp/curve_smoke.go
```

Expected: prints `ok`. This proves both subpackages are present at the chosen version. The temp file uses `//go:build ignore` so a stray re-run never picks it up; we delete it immediately.

- [ ] **Step 4: Run the full test suite to confirm nothing else regressed**

Run: `go test -race ./... -count=1`
Expected: PASS — adding a require should not break anything.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum
git commit -m "$(cat <<'EOF'
deps: add golang.org/x/crypto for CURVE (nacl/box + nacl/secretbox)

F2c uses nacl/box for asymmetric authenticated encryption (handshake
boxes + post-handshake MESSAGE traffic) and nacl/secretbox for the
WELCOME cookie inner box. Both subpackages live inside the same
golang.org/x/crypto module — one require directive covers them.

This is the first non-stdlib dependency in the module, sanctioned by
docs/specs/00-meta-overview.md §7.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Package skeleton — `doc.go`, `errors.go`, key types

**Files:**
- Create: `internal/security/curve/doc.go`
- Create: `internal/security/curve/errors.go`
- Create: `internal/security/curve/keys.go`
- Create: `internal/security/curve/keys_test.go`

- [ ] **Step 1: Write `internal/security/curve/doc.go`**

```go
// Package curve implements the ZMTP 3.1 CURVE security mechanism
// (RFC 37 §3.3 / RFC 26).
//
// CURVE provides mutual peer authentication via Curve25519 long-term
// keypairs and confidentiality+integrity for both the four-step
// handshake (HELLO → WELCOME → INITIATE → READY) and the post-
// handshake application traffic (MESSAGE commands carrying NaCl
// box-encrypted frames).
//
// The handshake is asymmetric. ClientState drives the active side;
// ServerState drives the reactive side. Server-side authorization is
// delegated to a caller-supplied Authorizer callback that decides
// whether a verified client long-term public key is allowed to connect
// — F6 will provide a ZAP-backed Authorizer.
//
// This package is pure: it does no I/O, allocates no goroutines, and
// reads no clocks. Entropy is supplied through an injectable
// io.Reader (defaults to crypto/rand.Reader); tests inject a
// deterministic source for byte-exact vectors.
//
// Long-term SecretKey buffers passed in via ClientOptions/ServerOptions
// are referenced — the caller owns their lifetime and Close() does not
// zero them. Transient secrets, shared keys, and the cookie key are
// owned by ClientState/ServerState and zeroed on Close().
//
// See docs/specs/02c-security-curve.md for the full specification.
package curve
```

- [ ] **Step 2: Write `internal/security/curve/errors.go`**

```go
package curve

import "errors"

var (
	// ErrInvalidOptions is returned by NewClient/NewServer when the
	// caller passes a zero ServerKey/OurPublicKey or a nil OurSecretKey
	// pointer. NewServer with a nil Authorizer panics rather than
	// returning this error — see NewServer godoc.
	ErrInvalidOptions = errors.New("curve: invalid options")

	// ErrCryptoRand is returned when the configured Rand source's Read
	// method fails (transient keypair generation, nonce randomization,
	// cookie-key generation).
	ErrCryptoRand = errors.New("curve: rand read failed")

	// ErrAlreadyStarted is returned by ClientState.Start on second call.
	ErrAlreadyStarted = errors.New("curve: handshake already started")

	// ErrNotStarted is returned by ClientState.Receive before Start.
	ErrNotStarted = errors.New("curve: handshake not started")

	// ErrAlreadyDone is returned when Start or Receive is called after
	// a previous successful completion. Wrap and Unwrap remain valid
	// after Done — that is the whole point of post-handshake encryption.
	ErrAlreadyDone = errors.New("curve: handshake already complete")

	// ErrAlreadyFailed is returned when any method is called after a
	// previous error has put the state into the failed state.
	ErrAlreadyFailed = errors.New("curve: handshake already failed")

	// ErrUnexpectedCommand is returned when the peer sends a command
	// whose name is not the one expected in the current state (and is
	// not ERROR).
	ErrUnexpectedCommand = errors.New("curve: unexpected command")

	// ErrPeerError is returned when the peer sends an ERROR command.
	// The wrapped string includes the peer's reason as received; bytes
	// outside %x21..%x7E are not stripped before wrapping. Loggers and
	// UIs SHOULD treat the reason as untrusted, peer-controlled input.
	ErrPeerError = errors.New("curve: peer sent ERROR")

	// ErrAuthRejected is returned by ServerState.Receive on the
	// INITIATE step when the Authorizer callback returned a non-nil
	// error. Returned alongside a non-nil out *wire.Command containing
	// the ERROR command the caller MUST send before closing the
	// connection.
	ErrAuthRejected = errors.New("curve: authorizer rejected client")

	// ErrMalformedHello is returned when HELLO does not parse per
	// RFC 26 §5.2 (wrong size, bad version, non-zero padding).
	ErrMalformedHello = errors.New("curve: malformed HELLO")

	// ErrMalformedWelcome is returned when WELCOME does not parse per
	// RFC 26 §5.3 (wrong size).
	ErrMalformedWelcome = errors.New("curve: malformed WELCOME")

	// ErrMalformedInitiate is returned when INITIATE outer structure
	// does not parse per RFC 26 §5.4.
	ErrMalformedInitiate = errors.New("curve: malformed INITIATE")

	// ErrMalformedReady is returned when READY outer structure does
	// not parse per RFC 26 §5.5.
	ErrMalformedReady = errors.New("curve: malformed READY")

	// ErrMalformedMessage is returned when MESSAGE structure (size,
	// command name) does not parse per RFC 26 §6.
	ErrMalformedMessage = errors.New("curve: malformed MESSAGE")

	// ErrBoxOpen is returned when a NaCl box (or secretbox) Open
	// returned false — the auth tag did not verify. Wraps a description
	// of which box failed (HELLO outer, WELCOME outer, INITIATE outer,
	// vouch, READY, MESSAGE, cookie).
	ErrBoxOpen = errors.New("curve: box authentication failed")

	// ErrCookieMismatch is returned when an INITIATE cookie opens
	// cleanly but its inner (C', s') does not match the server's
	// recorded handshake state — indicates a forged or replayed
	// INITIATE.
	ErrCookieMismatch = errors.New("curve: cookie mismatch")

	// ErrNonceReused is returned when an incoming MESSAGE short-nonce
	// is ≤ the last accepted receive nonce — a replay or out-of-order
	// delivery.
	ErrNonceReused = errors.New("curve: nonce reused")

	// ErrNonceExhausted is returned when an outgoing MESSAGE send nonce
	// would wrap past 2^64-1.
	ErrNonceExhausted = errors.New("curve: nonce exhausted")
)
```

- [ ] **Step 3: Write `internal/security/curve/keys.go`**

```go
package curve

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// PublicKey is a 32-byte Curve25519 public key. Values are safe to
// log, store, and transmit.
type PublicKey [32]byte

// SecretKey is a 32-byte Curve25519 secret key. Sensitive material;
// callers SHOULD call Zero() when no longer needed. Implements
// fmt.Stringer returning "[REDACTED]" so accidental %v formatting does
// not leak the bytes (also implements GoString for %#v).
//
// String/GoString use POINTER receivers so a formatting call never
// triggers an implicit value copy of the 32 bytes onto another stack.
type SecretKey [32]byte

// Zero overwrites the key bytes with zero. Idempotent.
func (s *SecretKey) Zero() { clear(s[:]) }

// String returns a redacted placeholder. Pointer receiver on purpose —
// calling %v on a SecretKey value would otherwise copy the 32 bytes.
func (*SecretKey) String() string { return "[REDACTED]" }

// GoString returns a redacted placeholder for %#v.
func (*SecretKey) GoString() string { return "curve.SecretKey([REDACTED])" }

// SharedKey is a 32-byte precomputed NaCl box key (the X25519 shared
// secret) ready for nacl/box.SealAfterPrecomputation. Same redaction
// and Zero() semantics as SecretKey, including pointer-receiver
// formatting.
type SharedKey [32]byte

// Zero overwrites the key bytes with zero. Idempotent.
func (s *SharedKey) Zero() { clear(s[:]) }

// String returns a redacted placeholder. Pointer receiver — see
// SecretKey.String.
func (*SharedKey) String() string { return "[REDACTED]" }

// GoString returns a redacted placeholder for %#v.
func (*SharedKey) GoString() string { return "curve.SharedKey([REDACTED])" }

// GenerateKeyPair returns a freshly generated long-term Curve25519
// keypair. rng supplies entropy; pass nil to use crypto/rand.Reader.
// The only error path is rng.Read failing.
func GenerateKeyPair(rng io.Reader) (PublicKey, SecretKey, error) {
	if rng == nil {
		rng = rand.Reader
	}
	pubArr, secArr, err := box.GenerateKey(rng)
	if err != nil {
		return PublicKey{}, SecretKey{}, fmt.Errorf("%w: %v", ErrCryptoRand, err)
	}
	var pub PublicKey
	var sec SecretKey
	copy(pub[:], pubArr[:])
	copy(sec[:], secArr[:])
	return pub, sec, nil
}

// precompute wraps nacl/box.Precompute with the typed key wrappers.
// Used by ClientState/ServerState; not exported because production
// callers don't need to drive precomputation themselves.
func precompute(peerPub PublicKey, ourSec *SecretKey) *SharedKey {
	var out SharedKey
	box.Precompute((*[32]byte)(&out), (*[32]byte)(&peerPub), (*[32]byte)(ourSec))
	return &out
}
```

> **Why a typed wrapper around `box.Precompute`:** isolates the unsafe-looking `(*[32]byte)` casts in one place and lets every call site stay in terms of the `PublicKey`/`SecretKey`/`SharedKey` named types.

- [ ] **Step 4: Write the failing tests in `internal/security/curve/keys_test.go`**

```go
package curve

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestGenerateKeyPairWithCryptoRand(t *testing.T) {
	pub, sec, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if pub == (PublicKey{}) {
		t.Fatalf("public key is all zero")
	}
	if sec == (SecretKey{}) {
		t.Fatalf("secret key is all zero")
	}
}

// failingReader returns wantErr on the first Read.
type failingReader struct{ wantErr error }

func (f failingReader) Read(_ []byte) (int, error) { return 0, f.wantErr }

func TestGenerateKeyPairWrapsRandError(t *testing.T) {
	want := errors.New("synthetic")
	_, _, err := GenerateKeyPair(failingReader{want})
	if !errors.Is(err, ErrCryptoRand) {
		t.Fatalf("err = %v, want ErrCryptoRand", err)
	}
}

func TestSecretKeyStringIsRedacted(t *testing.T) {
	var sk SecretKey
	for i := range sk {
		sk[i] = 0xAB
	}
	got := fmt.Sprintf("%v", &sk)
	if got != "[REDACTED]" {
		t.Fatalf("%%v = %q, want \"[REDACTED]\"", got)
	}
	gs := fmt.Sprintf("%#v", &sk)
	if !strings.Contains(gs, "[REDACTED]") {
		t.Fatalf("%%#v = %q, want to contain [REDACTED]", gs)
	}
}

func TestSecretKeyZero(t *testing.T) {
	var sk SecretKey
	for i := range sk {
		sk[i] = 0xAB
	}
	sk.Zero()
	if !bytes.Equal(sk[:], make([]byte, 32)) {
		t.Fatalf("after Zero, key = %x, want all zero", sk[:])
	}
	// Idempotent.
	sk.Zero()
	if !bytes.Equal(sk[:], make([]byte, 32)) {
		t.Fatalf("after second Zero, key changed")
	}
}

func TestSharedKeyStringIsRedacted(t *testing.T) {
	var sk SharedKey
	for i := range sk {
		sk[i] = 0xCD
	}
	got := fmt.Sprintf("%v", &sk)
	if got != "[REDACTED]" {
		t.Fatalf("%%v = %q, want \"[REDACTED]\"", got)
	}
}

func TestSharedKeyZero(t *testing.T) {
	var sk SharedKey
	for i := range sk {
		sk[i] = 0xCD
	}
	sk.Zero()
	if !bytes.Equal(sk[:], make([]byte, 32)) {
		t.Fatalf("after Zero, shared = %x, want all zero", sk[:])
	}
}

func TestPrecomputeIsSymmetric(t *testing.T) {
	// box DH is symmetric: precompute(B, a) == precompute(A, b).
	pubA, secA, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	pubB, secB, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}
	skAB := precompute(pubB, &secA)
	skBA := precompute(pubA, &secB)
	if !bytes.Equal(skAB[:], skBA[:]) {
		t.Fatalf("precompute asymmetry: %x vs %x", skAB[:], skBA[:])
	}
}

// silence unused-import warnings if a refactor removes references.
var _ io.Reader = failingReader{}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 6: vet / staticcheck**

Run: `go vet ./internal/security/curve/... && staticcheck ./internal/security/curve/...`
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add internal/security/curve/doc.go internal/security/curve/errors.go \
        internal/security/curve/keys.go internal/security/curve/keys_test.go
git commit -m "$(cat <<'EOF'
security/curve: package skeleton — sentinels, key types, key gen

PublicKey/SecretKey/SharedKey are all 32-byte arrays; SecretKey and
SharedKey redact %v / %#v output via pointer-receiver String/GoString
so accidental logging never leaks key material. precompute() wraps the
nacl/box.Precompute pointer cast in one place so every call site stays
in named-type terms.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 5: CURVE codec — pure encode/parse + cryptographic primitives

This chunk delivers `internal/security/curve/codec.go`: the stateless wire-format functions that the state machines compose into HELLO/WELCOME/INITIATE/READY/MESSAGE handling. Each task is one or two related codec functions with a paired round-trip test. The state machines (Chunks 6–7) build on top of these without re-deriving the box layouts.

### Task 8: Codec constants, prefixes, and HELLO

**Files:**
- Create: `internal/security/curve/codec.go` — constants + nonce prefixes + `encodeHello` / `parseHello`.
- Create: `internal/security/curve/codec_test.go` — round-trip + tamper tests for HELLO.

> All NaCl nonces are 24 bytes. Short-nonce shape: 16-byte literal prefix || 8-byte big-endian counter. Long-nonce shape: 8-byte literal prefix || 16 random bytes. Trailing letters on MESSAGE prefixes encode the SENDER side: "C" for client→server, "S" for server→client (RFC 26 §6).

- [ ] **Step 1: Write the failing tests in `internal/security/curve/codec_test.go`**

```go
package curve

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func makePair(t *testing.T) (PublicKey, SecretKey) {
	t.Helper()
	pub, sec, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return pub, sec
}

func TestEncodeHelloRoundTrip(t *testing.T) {
	clientPub, clientSec := makePair(t)
	serverPub, serverSec := makePair(t)

	helloShared := precompute(serverPub, &clientSec)   // c' × S
	openShared := precompute(clientPub, &serverSec)    // s × C'

	cmd, err := encodeHello(clientPub, helloShared, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	if cmd.Name != helloCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, helloCommandName)
	}
	got, err := parseHello(cmd, openShared)
	if err != nil {
		t.Fatalf("parseHello: %v", err)
	}
	if got != clientPub {
		t.Fatalf("client transient pub = %x, want %x", got, clientPub)
	}
}

func TestParseHelloRejectsWrongName(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: "READY", Data: make([]byte, 194)}
	if _, err := parseHello(bad, shared); !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestParseHelloRejectsWrongSize(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: helloCommandName, Data: []byte{0x01}}
	if _, err := parseHello(bad, shared); !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestParseHelloRejectsBadVersion(t *testing.T) {
	clientPub, clientSec := makePair(t)
	serverPub, serverSec := makePair(t)
	helloShared := precompute(serverPub, &clientSec)
	openShared := precompute(clientPub, &serverSec)

	cmd, err := encodeHello(clientPub, helloShared, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	cmd.Data[0] = 0x02 // major=2 instead of 1
	if _, err := parseHello(cmd, openShared); !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestParseHelloRejectsNonZeroPadding(t *testing.T) {
	clientPub, clientSec := makePair(t)
	serverPub, serverSec := makePair(t)
	helloShared := precompute(serverPub, &clientSec)
	openShared := precompute(clientPub, &serverSec)

	cmd, err := encodeHello(clientPub, helloShared, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	// padding starts at byte 2 (after version[2]).
	cmd.Data[2] = 0xFF
	if _, err := parseHello(cmd, openShared); !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestParseHelloRejectsTamperedBox(t *testing.T) {
	clientPub, clientSec := makePair(t)
	serverPub, serverSec := makePair(t)
	helloShared := precompute(serverPub, &clientSec)
	openShared := precompute(clientPub, &serverSec)

	cmd, err := encodeHello(clientPub, helloShared, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	// Flip a bit in the trailing 80-byte hello-box ciphertext.
	cmd.Data[len(cmd.Data)-1] ^= 0x01
	if _, err := parseHello(cmd, openShared); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestEncodeHelloDoesNotConsumeRand(t *testing.T) {
	// HELLO uses a counter short-nonce, not a random nonce — so encodeHello
	// must not read from its rand reader at all. (It accepts an io.Reader
	// for symmetry with the long-nonce encoders.) A regression that switches
	// to random nonces would silently weaken determinism for vector tests.
	_, clientSec := makePair(t)
	serverPub, _ := makePair(t)
	shared := precompute(serverPub, &clientSec)

	r := bytes.NewReader(make([]byte, 1<<20))
	if _, err := encodeHello(PublicKey{1, 2, 3}, shared, 1, r); err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	if used := 1<<20 - r.Len(); used != 0 {
		t.Fatalf("encodeHello consumed %d bytes of rand, want 0 (counter short-nonce only)", used)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -count=1`
Expected: FAIL (`undefined: encodeHello`, etc.).

- [ ] **Step 3: Write `internal/security/curve/codec.go` (HELLO portion only — other functions added in later tasks)**

```go
package curve

import (
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"

	"github.com/tomi77/zmq4/internal/wire"
)

const (
	helloCommandName    = "HELLO"
	welcomeCommandName  = "WELCOME"
	initiateCommandName = "INITIATE"
	readyCommandName    = "READY"
	messageCommandName  = "MESSAGE"
	// errorCommandName is shared with NULL/PLAIN; we reference
	// wire.ErrorCommandName directly rather than redeclare it.
)

// Nonce prefixes (RFC 26 §3). Two shapes:
//
//   - Short-nonce prefixes are 16 B; on the wire the full 24-byte NaCl
//     nonce is prefix||short-nonce(8 B big-endian counter).
//   - Long-nonce prefixes are 8 B; on the wire the full 24-byte NaCl
//     nonce is prefix||long-nonce(16 B random).
//
// Trailing letter on MESSAGE prefixes encodes the SENDER role: "C" for
// client-sent, "S" for server-sent (per RFC 26 §6).
var (
	helloNoncePrefix    = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'H', 'E', 'L', 'L', 'O', '-', '-', '-'}
	welcomeNoncePrefix  = [8]byte{'W', 'E', 'L', 'C', 'O', 'M', 'E', '-'}
	cookieNoncePrefix   = [8]byte{'C', 'O', 'O', 'K', 'I', 'E', '-', '-'}
	vouchNoncePrefix    = [8]byte{'V', 'O', 'U', 'C', 'H', '-', '-', '-'}
	initiateNoncePrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'I', 'N', 'I', 'T', 'I', 'A', 'T', 'E'}
	readyNoncePrefix    = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'R', 'E', 'A', 'D', 'Y', '-', '-', '-'}
	messageClientPrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'M', 'E', 'S', 'S', 'A', 'G', 'E', 'C'}
	messageServerPrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'M', 'E', 'S', 'S', 'A', 'G', 'E', 'S'}
)

// HELLO wire layout (RFC 26 §5.2):
//
//	%x01 %x00 (version major=1 minor=0)         2 B
//	72 zero bytes (padding)                     72 B
//	C' (client transient public)                32 B
//	hello-nonce                                  8 B
//	hello-box (NaCl box of 64 zero bytes)       80 B  (= 64+16 overhead)
//
// Total body: 194 B.
const helloBodyLen = 2 + 72 + 32 + 8 + 80

// encodeHello builds a HELLO command. clientTransPub is the client's
// fresh transient public key (C'). sharedKey is precompute(serverLongPub,
// clientTransSec) = c' × S. nonce is the per-handshake short-nonce
// counter (starts at 1, monotonically increasing). rand is currently
// unused by encodeHello (the wire format only requires a counter
// short-nonce here) but accepted for symmetry with other encoders that
// emit long-nonces — pass nil if you do not have one. Returns the
// fully-formed wire.Command ready for the caller to send.
func encodeHello(clientTransPub PublicKey, sharedKey *SharedKey, nonce uint64, rand io.Reader) (wire.Command, error) {
	_ = rand // unused; reserved for symmetry with long-nonce encoders.

	data := make([]byte, helloBodyLen)
	data[0] = 0x01 // version major
	data[1] = 0x00 // version minor
	// 72-byte padding stays zero by virtue of make().
	copy(data[2+72:2+72+32], clientTransPub[:])

	binary.BigEndian.PutUint64(data[2+72+32:2+72+32+8], nonce)

	var nacl [24]byte
	copy(nacl[:16], helloNoncePrefix[:])
	binary.BigEndian.PutUint64(nacl[16:], nonce)

	// hello-box content is 64 zero bytes (the "signature" payload).
	var zeros [64]byte
	out := box.SealAfterPrecomputation(nil, zeros[:], &nacl, (*[32]byte)(sharedKey))
	if len(out) != 80 {
		return wire.Command{}, fmt.Errorf("curve: internal: hello-box len=%d want 80", len(out))
	}
	copy(data[2+72+32+8:], out)

	return wire.Command{Name: helloCommandName, Data: data}, nil
}

// parseHello opens a peer HELLO and returns the client's transient
// public key. sharedKey must be precompute(clientTransPub, serverLongSec)
// = s × C' for the server side (note: NaCl box DH is symmetric in the
// pair, so c'×S and s×C' yield the same bytes — but the server, which
// does not yet know C', cannot use this until after parsing C' from
// the cleartext part of HELLO; sharedKey should therefore be computed
// AFTER C' is read out of the body).
func parseHello(cmd wire.Command, sharedKey *SharedKey) (PublicKey, error) {
	if cmd.Name != helloCommandName {
		return PublicKey{}, fmt.Errorf("%w: command name %q", ErrMalformedHello, cmd.Name)
	}
	if len(cmd.Data) != helloBodyLen {
		return PublicKey{}, fmt.Errorf("%w: body size %d, want %d", ErrMalformedHello, len(cmd.Data), helloBodyLen)
	}
	if cmd.Data[0] != 0x01 || cmd.Data[1] != 0x00 {
		return PublicKey{}, fmt.Errorf("%w: bad version %x %x", ErrMalformedHello, cmd.Data[0], cmd.Data[1])
	}
	for i := 0; i < 72; i++ {
		if cmd.Data[2+i] != 0 {
			return PublicKey{}, fmt.Errorf("%w: non-zero padding at byte %d", ErrMalformedHello, 2+i)
		}
	}
	var clientTransPub PublicKey
	copy(clientTransPub[:], cmd.Data[2+72:2+72+32])

	var nacl [24]byte
	copy(nacl[:16], helloNoncePrefix[:])
	copy(nacl[16:], cmd.Data[2+72+32:2+72+32+8])

	box64 := cmd.Data[2+72+32+8:]
	if _, ok := box.OpenAfterPrecomputation(nil, box64, &nacl, (*[32]byte)(sharedKey)); !ok {
		return PublicKey{}, fmt.Errorf("%w: hello-box", ErrBoxOpen)
	}
	return clientTransPub, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS — including round-trip and the four tamper/format tests.

- [ ] **Step 5: vet / staticcheck**

Run: `go vet ./internal/security/curve/... && staticcheck ./internal/security/curve/...`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add internal/security/curve/codec.go internal/security/curve/codec_test.go
git commit -m "$(cat <<'EOF'
security/curve: HELLO codec (RFC 26 §5.2)

Pure encode/parse functions for the HELLO command. Nonce prefixes are
defined alongside in codec.go since they are shared by every codec
function in this chunk. encodeHello uses NaCl box.SealAfterPrecomputation
on 64 zero bytes; parseHello rejects bad version, non-zero padding,
wrong size, and box-open failure.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: WELCOME + cookie codec

**Files:**
- Modify: `internal/security/curve/codec.go` — add `encodeWelcome` / `parseWelcome` / `sealCookie` / `openCookie`.
- Modify: `internal/security/curve/codec_test.go` — round-trip + tamper tests.

WELCOME wire layout (RFC 26 §5.3): `welcome-nonce(16) || welcome-box(144)`. The plaintext is `S' (32) || cookie (96)`. The cookie is its own structure: `cookie-nonce(16) || secretbox(80) of (C'(32) || s'(32))` — sealed under a per-handshake `cookieKey` that the server keeps in `ServerState`.

- [ ] **Step 1: Append the failing tests**

```go
func TestEncodeWelcomeRoundTrip(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)

	// In the real handshake the server has just generated s'/S' for this
	// connection. We mimic that with a fresh pair.
	serverTransPub, serverTransSec := makePair(t)

	// Cookie key — fresh per ServerState.
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}

	cookie, err := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	if err != nil {
		t.Fatalf("sealCookie: %v", err)
	}

	welcomeShared := precompute(clientTransPub, &serverLongSec) // s × C'
	openShared := precompute(serverLongPub, &clientTransSec)    // c' × S

	cmd, err := encodeWelcome(serverTransPub, cookie, welcomeShared, rand.Reader)
	if err != nil {
		t.Fatalf("encodeWelcome: %v", err)
	}
	if cmd.Name != welcomeCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, welcomeCommandName)
	}
	gotS1, gotCookie, err := parseWelcome(cmd, openShared)
	if err != nil {
		t.Fatalf("parseWelcome: %v", err)
	}
	if gotS1 != serverTransPub {
		t.Fatalf("S' = %x, want %x", gotS1, serverTransPub)
	}
	if gotCookie != cookie {
		t.Fatalf("cookie differs after round-trip")
	}

	// Cookie opens to the original (C', s').
	gotC1, gotSPrimeSec, err := openCookie(gotCookie, &cookieKey)
	if err != nil {
		t.Fatalf("openCookie: %v", err)
	}
	if gotC1 != clientTransPub {
		t.Fatalf("cookie C' = %x, want %x", gotC1, clientTransPub)
	}
	if gotSPrimeSec != serverTransSec {
		t.Fatalf("cookie s' differs from sealed value")
	}
}

func TestParseWelcomeRejectsWrongName(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: "READY", Data: make([]byte, 160)}
	if _, _, err := parseWelcome(bad, shared); !errors.Is(err, ErrMalformedWelcome) {
		t.Fatalf("err = %v, want ErrMalformedWelcome", err)
	}
}

func TestParseWelcomeRejectsWrongSize(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: welcomeCommandName, Data: []byte{0x01}}
	if _, _, err := parseWelcome(bad, shared); !errors.Is(err, ErrMalformedWelcome) {
		t.Fatalf("err = %v, want ErrMalformedWelcome", err)
	}
}

func TestParseWelcomeRejectsTamperedBox(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}

	cookie, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	openShared := precompute(serverLongPub, &clientTransSec)
	cmd, _ := encodeWelcome(serverTransPub, cookie, welcomeShared, rand.Reader)

	cmd.Data[len(cmd.Data)-1] ^= 0x01
	if _, _, err := parseWelcome(cmd, openShared); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestOpenCookieRejectsTampered(t *testing.T) {
	clientTransPub, _ := makePair(t)
	_, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}

	cookie, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	cookie[len(cookie)-1] ^= 0x01
	if _, _, err := openCookie(cookie, &cookieKey); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestOpenCookieRejectsWrongKey(t *testing.T) {
	clientTransPub, _ := makePair(t)
	_, serverTransSec := makePair(t)
	var goodKey, badKey SecretKey
	if _, err := rand.Read(goodKey[:]); err != nil {
		t.Fatalf("rand goodKey: %v", err)
	}
	if _, err := rand.Read(badKey[:]); err != nil {
		t.Fatalf("rand badKey: %v", err)
	}

	cookie, _ := sealCookie(clientTransPub, serverTransSec, &goodKey, rand.Reader)
	if _, _, err := openCookie(cookie, &badKey); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -run TestEncodeWelcome -run TestParseWelcome -run TestOpenCookie -count=1`
Expected: FAIL (`undefined: encodeWelcome`, `sealCookie`, `openCookie`).

- [ ] **Step 3: Append to `internal/security/curve/codec.go`**

```go
import (
	// ... existing imports ...
	"golang.org/x/crypto/nacl/secretbox"
)

// WELCOME wire layout (RFC 26 §5.3):
//
//	welcome-nonce        16 B (random long-nonce)
//	welcome-box         144 B (= 32 + 96 + 16 overhead)
//	  plaintext: S' (32) || cookie (96)
//
// Total body: 160 B.
const welcomeBodyLen = 16 + 144

// Cookie wire layout (RFC 26 §5):
//
//	cookie-nonce         16 B (random long-nonce)
//	secretbox            80 B (= 64 + 16 overhead)
//	  plaintext: C' (32) || s' (32)
//
// Total cookie: 96 B.
type cookie [96]byte

// sealCookie produces an opaque 96-byte cookie that the client echoes
// back inside INITIATE. The cookie binds (C', s') to the per-handshake
// cookieKey so the server need not retain handshake state between
// WELCOME and INITIATE.
func sealCookie(clientTransPub PublicKey, serverTransSec SecretKey, cookieKey *SecretKey, rng io.Reader) (cookie, error) {
	if rng == nil {
		rng = rand.Reader
	}
	var c cookie
	if _, err := io.ReadFull(rng, c[:16]); err != nil {
		return cookie{}, fmt.Errorf("%w: %v", ErrCryptoRand, err)
	}
	var nacl [24]byte
	copy(nacl[:8], cookieNoncePrefix[:])
	copy(nacl[8:], c[:16])

	var plaintext [64]byte
	copy(plaintext[:32], clientTransPub[:])
	copy(plaintext[32:], serverTransSec[:])

	out := secretbox.Seal(nil, plaintext[:], &nacl, (*[32]byte)(cookieKey))
	if len(out) != 80 {
		return cookie{}, fmt.Errorf("curve: internal: cookie box len=%d want 80", len(out))
	}
	copy(c[16:], out)
	return c, nil
}

// openCookie inverts sealCookie. Returns ErrBoxOpen if the secretbox
// auth tag does not verify (wrong key, tampered ciphertext).
func openCookie(c cookie, cookieKey *SecretKey) (PublicKey, SecretKey, error) {
	var nacl [24]byte
	copy(nacl[:8], cookieNoncePrefix[:])
	copy(nacl[8:], c[:16])

	plain, ok := secretbox.Open(nil, c[16:], &nacl, (*[32]byte)(cookieKey))
	if !ok {
		return PublicKey{}, SecretKey{}, fmt.Errorf("%w: cookie", ErrBoxOpen)
	}
	if len(plain) != 64 {
		return PublicKey{}, SecretKey{}, fmt.Errorf("curve: internal: cookie plaintext len=%d want 64", len(plain))
	}
	var pub PublicKey
	var sec SecretKey
	copy(pub[:], plain[:32])
	copy(sec[:], plain[32:])
	return pub, sec, nil
}

// encodeWelcome builds a WELCOME command. sharedKey is
// precompute(clientTransPub, serverLongSec) = s × C'.
func encodeWelcome(serverTransPub PublicKey, ck cookie, sharedKey *SharedKey, rng io.Reader) (wire.Command, error) {
	if rng == nil {
		rng = rand.Reader
	}
	data := make([]byte, welcomeBodyLen)
	if _, err := io.ReadFull(rng, data[:16]); err != nil {
		return wire.Command{}, fmt.Errorf("%w: %v", ErrCryptoRand, err)
	}

	var nacl [24]byte
	copy(nacl[:8], welcomeNoncePrefix[:])
	copy(nacl[8:], data[:16])

	var plaintext [128]byte
	copy(plaintext[:32], serverTransPub[:])
	copy(plaintext[32:], ck[:])

	out := box.SealAfterPrecomputation(nil, plaintext[:], &nacl, (*[32]byte)(sharedKey))
	if len(out) != 144 {
		return wire.Command{}, fmt.Errorf("curve: internal: welcome-box len=%d want 144", len(out))
	}
	copy(data[16:], out)

	return wire.Command{Name: welcomeCommandName, Data: data}, nil
}

// parseWelcome inverts encodeWelcome. sharedKey is
// precompute(serverLongPub, clientTransSec) = c' × S.
func parseWelcome(cmd wire.Command, sharedKey *SharedKey) (PublicKey, cookie, error) {
	if cmd.Name != welcomeCommandName {
		return PublicKey{}, cookie{}, fmt.Errorf("%w: command name %q", ErrMalformedWelcome, cmd.Name)
	}
	if len(cmd.Data) != welcomeBodyLen {
		return PublicKey{}, cookie{}, fmt.Errorf("%w: body size %d, want %d", ErrMalformedWelcome, len(cmd.Data), welcomeBodyLen)
	}
	var nacl [24]byte
	copy(nacl[:8], welcomeNoncePrefix[:])
	copy(nacl[8:], cmd.Data[:16])

	plain, ok := box.OpenAfterPrecomputation(nil, cmd.Data[16:], &nacl, (*[32]byte)(sharedKey))
	if !ok {
		return PublicKey{}, cookie{}, fmt.Errorf("%w: welcome", ErrBoxOpen)
	}
	if len(plain) != 128 {
		return PublicKey{}, cookie{}, fmt.Errorf("%w: welcome plaintext len=%d", ErrMalformedWelcome, len(plain))
	}
	var serverTransPub PublicKey
	copy(serverTransPub[:], plain[:32])
	var ck cookie
	copy(ck[:], plain[32:])
	return serverTransPub, ck, nil
}
```

Add `"crypto/rand"` to the imports if not yet there (it isn't — Task 8's HELLO codec doesn't need it).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 5: vet / staticcheck**

Run: `go vet ./internal/security/curve/... && staticcheck ./internal/security/curve/...`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add internal/security/curve/codec.go internal/security/curve/codec_test.go
git commit -m "$(cat <<'EOF'
security/curve: WELCOME + cookie codec (RFC 26 §5.3 & §5)

Three new pure functions: sealCookie / openCookie wrap the per-
handshake (C' || s') under cookieKey via nacl/secretbox; encodeWelcome
/ parseWelcome carry S' || cookie under c'×S = s×C' via nacl/box.
All four reject tampered ciphertext, wrong size, wrong command name,
and (for openCookie) wrong key.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Vouch codec

**Files:**
- Modify: `internal/security/curve/codec.go` — add `encodeVouch` / `openVouch`.
- Modify: `internal/security/curve/codec_test.go` — round-trip + tamper tests.

The vouch is a 96-byte structure embedded inside INITIATE. It cryptographically proves the peer holds the long-term secret matching the long-term public it claims.

Vouch wire layout (RFC 26 §5.4):
```
vouch-nonce  16 B (random long-nonce)
vouch-box    80 B (= 64 + 16 overhead)
  plaintext: C' (32) || S (32)   sealed under c × S
```

- [ ] **Step 1: Append the failing tests**

```go
func TestEncodeVouchRoundTrip(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	clientTransPub, _ := makePair(t)

	vouchShared := precompute(serverLongPub, &clientLongSec) // c × S
	v, err := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	if err != nil {
		t.Fatalf("encodeVouch: %v", err)
	}
	gotC1, gotS, err := openVouch(v, clientLongPub, &serverLongSec)
	if err != nil {
		t.Fatalf("openVouch: %v", err)
	}
	if gotC1 != clientTransPub {
		t.Fatalf("C' = %x, want %x", gotC1, clientTransPub)
	}
	if gotS != serverLongPub {
		t.Fatalf("S = %x, want %x", gotS, serverLongPub)
	}
}

func TestOpenVouchRejectsTampered(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	clientTransPub, _ := makePair(t)

	vouchShared := precompute(serverLongPub, &clientLongSec)
	v, _ := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	v[len(v)-1] ^= 0x01
	if _, _, err := openVouch(v, clientLongPub, &serverLongSec); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestOpenVouchRejectsWrongClientLongPub(t *testing.T) {
	_, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	clientTransPub, _ := makePair(t)

	vouchShared := precompute(serverLongPub, &clientLongSec)
	v, _ := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	otherPub, _ := makePair(t)
	if _, _, err := openVouch(v, otherPub, &serverLongSec); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -run TestEncodeVouch -run TestOpenVouch -count=1`
Expected: FAIL.

- [ ] **Step 3: Append to `internal/security/curve/codec.go`**

```go
// vouch is the 96-byte authenticator embedded inside INITIATE.
type vouch [96]byte

// encodeVouch builds the vouch box that goes inside INITIATE.
// vouchShared is precompute(serverLongPub, clientLongSec) = c × S — the
// long-term × long-term shared key. ClientState.Start computes this
// eagerly so the long-term secret is touched once at construction;
// vouchShared is then zeroed by ClientState.Receive(WELCOME) right
// after this function returns.
//
// serverLongPub is passed alongside vouchShared because it is part of
// the box plaintext (vouch authenticates the bond between C' and S).
// rng supplies the 16-byte long-nonce; pass nil for crypto/rand.Reader.
func encodeVouch(clientTransPub, serverLongPub PublicKey, vouchShared *SharedKey, rng io.Reader) (vouch, error) {
	if rng == nil {
		rng = rand.Reader
	}
	var v vouch
	if _, err := io.ReadFull(rng, v[:16]); err != nil {
		return vouch{}, fmt.Errorf("%w: %v", ErrCryptoRand, err)
	}
	var nacl [24]byte
	copy(nacl[:8], vouchNoncePrefix[:])
	copy(nacl[8:], v[:16])

	var plaintext [64]byte
	copy(plaintext[:32], clientTransPub[:])
	copy(plaintext[32:], serverLongPub[:])

	out := box.SealAfterPrecomputation(nil, plaintext[:], &nacl, (*[32]byte)(vouchShared))
	if len(out) != 80 {
		return vouch{}, fmt.Errorf("curve: internal: vouch-box len=%d want 80", len(out))
	}
	copy(v[16:], out)
	return v, nil
}

// openVouch inverts encodeVouch. The server uses the client's long-term
// public (which it has just learned from INITIATE) and its own
// long-term secret. Returns the inner (C', S) that must match the
// values the server already knows; failure to match indicates an
// impersonation attempt and returns ErrBoxOpen.
func openVouch(v vouch, clientLongPub PublicKey, serverLongSec *SecretKey) (PublicKey, PublicKey, error) {
	var nacl [24]byte
	copy(nacl[:8], vouchNoncePrefix[:])
	copy(nacl[8:], v[:16])

	plain, ok := box.Open(nil, v[16:], &nacl, (*[32]byte)(&clientLongPub), (*[32]byte)(serverLongSec))
	if !ok {
		return PublicKey{}, PublicKey{}, fmt.Errorf("%w: vouch", ErrBoxOpen)
	}
	if len(plain) != 64 {
		return PublicKey{}, PublicKey{}, fmt.Errorf("curve: internal: vouch plaintext len=%d", len(plain))
	}
	var c1 PublicKey
	var s PublicKey
	copy(c1[:], plain[:32])
	copy(s[:], plain[32:])
	return c1, s, nil
}
```

> **Why a precomputed `vouchShared` parameter:** spec §5.2 mandates that `ClientState.Start` precomputes `vouchShared = c × S` so the long-term `*SecretKey` is dereferenced exactly once at construction. The codec therefore accepts the precomputed `*SharedKey`; `box.SealAfterPrecomputation` is the matching primitive. The server side does not precompute (vouch is opened only once, in `Receive(INITIATE)`), so `openVouch` keeps its `*SecretKey` parameter and uses `box.Open`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/curve/codec.go internal/security/curve/codec_test.go
git commit -m "$(cat <<'EOF'
security/curve: vouch codec (RFC 26 §5.4)

Vouch is the 96-byte authenticator inside INITIATE. encodeVouch seals
(C' || S) under the long-term × long-term key (c × S); openVouch
inverts. Tamper, wrong-key, and wrong-clientLongPub all fail with
ErrBoxOpen.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: INITIATE codec

**Files:**
- Modify: `internal/security/curve/codec.go` — add `encodeInitiate` / `parseInitiate`.
- Modify: `internal/security/curve/codec_test.go` — round-trip + tamper tests.

INITIATE wire layout (RFC 26 §5.4):
```
cookie         96 B (echoed verbatim from welcome)
initiate-nonce  8 B (short-nonce counter)
initiate-box  variable: (96 + 32 + len(metadata) + 16) B
  plaintext: vouch (96) || C (32) || metadata
```
INITIATE outer box is sealed under `c' × S' = afterReady`.

- [ ] **Step 1: Append the failing tests**

```go
func TestEncodeInitiateRoundTrip(t *testing.T) {
	// Set up the post-WELCOME state: client has S' from welcome,
	// server has c' from HELLO.
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)

	afterReadyClient := precompute(serverTransPub, &clientTransSec) // c' × S'
	afterReadyServer := precompute(clientTransPub, &serverTransSec) // s' × C'

	// Sanity: NaCl box DH symmetry.
	if !bytes.Equal(afterReadyClient[:], afterReadyServer[:]) {
		t.Fatalf("afterReady asymmetry: %x vs %x", afterReadyClient[:], afterReadyServer[:])
	}

	vouchShared := precompute(serverLongPub, &clientLongSec)
	v, err := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	if err != nil {
		t.Fatalf("encodeVouch: %v", err)
	}
	cookieValue := cookie{1, 2, 3, 4} // opaque; not opened by INITIATE codec.

	md := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
		{Name: []byte("Identity"), Value: []byte{0xAA, 0xBB}},
	}

	cmd, err := encodeInitiate(cookieValue, v, clientLongPub, md, afterReadyClient, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeInitiate: %v", err)
	}
	if cmd.Name != initiateCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, initiateCommandName)
	}
	gotCookie, gotVouch, gotLongPub, gotMeta, err := parseInitiate(cmd, afterReadyServer)
	if err != nil {
		t.Fatalf("parseInitiate: %v", err)
	}
	if gotCookie != cookieValue {
		t.Fatalf("cookie not echoed verbatim")
	}
	if gotVouch != v {
		t.Fatalf("vouch differs after round-trip")
	}
	if gotLongPub != clientLongPub {
		t.Fatalf("client long-term pub = %x, want %x", gotLongPub, clientLongPub)
	}
	if len(gotMeta) != len(md) ||
		!bytes.Equal(gotMeta[0].Name, md[0].Name) ||
		!bytes.Equal(gotMeta[0].Value, md[0].Value) ||
		!bytes.Equal(gotMeta[1].Name, md[1].Name) ||
		!bytes.Equal(gotMeta[1].Value, md[1].Value) {
		t.Fatalf("metadata differs after round-trip: got=%+v want=%+v", gotMeta, md)
	}
}

func TestEncodeInitiateEmptyMetadataRoundTrip(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	vouchShared := precompute(serverLongPub, &clientLongSec)
	v, err := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	if err != nil {
		t.Fatalf("encodeVouch: %v", err)
	}

	cmd, err := encodeInitiate(cookie{}, v, clientLongPub, nil, afterReadyClient, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeInitiate(nil): %v", err)
	}
	_, _, gotLongPub, gotMeta, err := parseInitiate(cmd, afterReadyServer)
	if err != nil {
		t.Fatalf("parseInitiate: %v", err)
	}
	if gotLongPub != clientLongPub {
		t.Fatalf("clientLongPub = %x, want %x", gotLongPub, clientLongPub)
	}
	if len(gotMeta) != 0 {
		t.Fatalf("metadata = %+v, want empty", gotMeta)
	}
}

func TestParseInitiateRejectsWrongName(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: "READY", Data: make([]byte, 200)}
	if _, _, _, _, err := parseInitiate(bad, shared); !errors.Is(err, ErrMalformedInitiate) {
		t.Fatalf("err = %v, want ErrMalformedInitiate", err)
	}
}

func TestParseInitiateRejectsTooSmall(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: initiateCommandName, Data: []byte{0x01, 0x02}}
	if _, _, _, _, err := parseInitiate(bad, shared); !errors.Is(err, ErrMalformedInitiate) {
		t.Fatalf("err = %v, want ErrMalformedInitiate", err)
	}
}

func TestParseInitiateRejectsTamperedOuterBox(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	vouchShared := precompute(serverLongPub, &clientLongSec)
	v, _ := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	cmd, _ := encodeInitiate(cookie{}, v, clientLongPub, nil, afterReadyClient, 1, rand.Reader)
	cmd.Data[len(cmd.Data)-1] ^= 0x01
	if _, _, _, _, err := parseInitiate(cmd, afterReadyServer); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -run TestEncodeInitiate -run TestParseInitiate -count=1`
Expected: FAIL.

- [ ] **Step 3: Append to `internal/security/curve/codec.go`**

```go
// initiateMinBodyLen is the minimum INITIATE body size:
//   cookie (96) + initiate-nonce (8) + box-overhead (16) + vouch (96) + C (32)
// = 248 B (when metadata is empty).
const initiateMinBodyLen = 96 + 8 + 16 + 96 + 32

// encodeInitiate builds an INITIATE command. sharedKey is
// precompute(serverTransPub, clientTransSec) = c' × S'.
func encodeInitiate(ck cookie, v vouch, clientLongPub PublicKey,
	metadata wire.Metadata, sharedKey *SharedKey, nonce uint64, rng io.Reader,
) (wire.Command, error) {
	_ = rng // unused; INITIATE uses a counter short-nonce, no random bytes.

	mdEnc := wire.EncodeMetadata(metadata)
	body := make([]byte, 96+8+16+96+32+len(mdEnc))
	copy(body[:96], ck[:])
	binary.BigEndian.PutUint64(body[96:96+8], nonce)

	plaintext := make([]byte, 96+32+len(mdEnc))
	copy(plaintext[:96], v[:])
	copy(plaintext[96:96+32], clientLongPub[:])
	copy(plaintext[96+32:], mdEnc)

	var nacl [24]byte
	copy(nacl[:16], initiateNoncePrefix[:])
	binary.BigEndian.PutUint64(nacl[16:], nonce)

	out := box.SealAfterPrecomputation(nil, plaintext, &nacl, (*[32]byte)(sharedKey))
	expected := 96 + 32 + len(mdEnc) + 16
	if len(out) != expected {
		return wire.Command{}, fmt.Errorf("curve: internal: initiate-box len=%d want %d", len(out), expected)
	}
	copy(body[96+8:], out)
	return wire.Command{Name: initiateCommandName, Data: body}, nil
}

// parseInitiate inverts encodeInitiate. sharedKey is
// precompute(clientTransPub, serverTransSec) = s' × C'. Metadata is
// returned aliasing the decrypted plaintext buffer; callers MUST clone
// (via seccommon.CloneMetadata) if they want to retain it past the
// next ServerState.Receive.
func parseInitiate(cmd wire.Command, sharedKey *SharedKey) (cookie, vouch, PublicKey, wire.Metadata, error) {
	if cmd.Name != initiateCommandName {
		return cookie{}, vouch{}, PublicKey{}, nil, fmt.Errorf("%w: command name %q", ErrMalformedInitiate, cmd.Name)
	}
	if len(cmd.Data) < initiateMinBodyLen {
		return cookie{}, vouch{}, PublicKey{}, nil, fmt.Errorf("%w: body size %d, want ≥ %d", ErrMalformedInitiate, len(cmd.Data), initiateMinBodyLen)
	}
	var ck cookie
	copy(ck[:], cmd.Data[:96])

	var nacl [24]byte
	copy(nacl[:16], initiateNoncePrefix[:])
	copy(nacl[16:], cmd.Data[96:96+8])

	plain, ok := box.OpenAfterPrecomputation(nil, cmd.Data[96+8:], &nacl, (*[32]byte)(sharedKey))
	if !ok {
		return cookie{}, vouch{}, PublicKey{}, nil, fmt.Errorf("%w: initiate", ErrBoxOpen)
	}
	if len(plain) < 96+32 {
		return cookie{}, vouch{}, PublicKey{}, nil, fmt.Errorf("%w: plaintext too short (%d)", ErrMalformedInitiate, len(plain))
	}
	var v vouch
	copy(v[:], plain[:96])
	var clientLongPub PublicKey
	copy(clientLongPub[:], plain[96:96+32])

	md, perr := wire.ParseMetadata(plain[96+32:])
	if perr != nil {
		return cookie{}, vouch{}, PublicKey{}, nil, fmt.Errorf("%w: %v", ErrMalformedInitiate, perr)
	}
	return ck, v, clientLongPub, md, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/curve/codec.go internal/security/curve/codec_test.go
git commit -m "$(cat <<'EOF'
security/curve: INITIATE codec (RFC 26 §5.4)

INITIATE outer box is sealed under c'×S' = s'×C' = afterReady. The
plaintext concatenates vouch (96) || C (32) || metadata, with metadata
encoded via wire.EncodeMetadata (the F2b L1 export). Returned metadata
aliases the decrypted buffer — ServerState.Receive clones it via
seccommon.CloneMetadata before exposing through PeerMetadata.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: READY codec

**Files:**
- Modify: `internal/security/curve/codec.go` — add `encodeReady` / `parseReady`.
- Modify: `internal/security/curve/codec_test.go` — round-trip + tamper tests.

READY wire layout (RFC 26 §5.5):
```
ready-nonce  8 B (short-nonce counter)
ready-box   (len(metadata) + 16) B
  plaintext: metadata
```
READY box is sealed under `s' × C' = c' × S' = afterReady` (server seals; client opens).

- [ ] **Step 1: Append the failing tests**

```go
func TestEncodeReadyRoundTrip(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)

	md := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
		{Name: []byte("Identity"), Value: bytes.Repeat([]byte{0x77}, 8)},
	}
	cmd, err := encodeReady(md, afterReadyServer, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeReady: %v", err)
	}
	if cmd.Name != readyCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, readyCommandName)
	}
	got, err := parseReady(cmd, afterReadyClient)
	if err != nil {
		t.Fatalf("parseReady: %v", err)
	}
	if len(got) != len(md) ||
		!bytes.Equal(got[0].Name, md[0].Name) ||
		!bytes.Equal(got[1].Value, md[1].Value) {
		t.Fatalf("metadata differs after round-trip: got=%+v want=%+v", got, md)
	}
}

func TestEncodeReadyEmptyMetadata(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)

	cmd, err := encodeReady(nil, afterReadyServer, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeReady(nil): %v", err)
	}
	got, err := parseReady(cmd, afterReadyClient)
	if err != nil {
		t.Fatalf("parseReady: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("metadata = %+v, want empty", got)
	}
}

func TestParseReadyRejectsWrongName(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: "WELCOME", Data: make([]byte, 24)}
	if _, err := parseReady(bad, shared); !errors.Is(err, ErrMalformedReady) {
		t.Fatalf("err = %v, want ErrMalformedReady", err)
	}
}

func TestParseReadyRejectsTooSmall(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: readyCommandName, Data: []byte{0x01}}
	if _, err := parseReady(bad, shared); !errors.Is(err, ErrMalformedReady) {
		t.Fatalf("err = %v, want ErrMalformedReady", err)
	}
}

func TestParseReadyRejectsTamperedBox(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)

	cmd, _ := encodeReady(nil, afterReadyServer, 1, rand.Reader)
	cmd.Data[len(cmd.Data)-1] ^= 0x01
	if _, err := parseReady(cmd, afterReadyClient); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -run TestEncodeReady -run TestParseReady -count=1`
Expected: FAIL.

- [ ] **Step 3: Append to `internal/security/curve/codec.go`**

```go
// readyMinBodyLen = 8-byte short-nonce + 16-byte box overhead.
const readyMinBodyLen = 8 + 16

// encodeReady builds a READY command. sharedKey is
// precompute(clientTransPub, serverTransSec) = s' × C'.
func encodeReady(metadata wire.Metadata, sharedKey *SharedKey, nonce uint64, rng io.Reader) (wire.Command, error) {
	_ = rng // counter short-nonce; no random bytes.

	mdEnc := wire.EncodeMetadata(metadata)
	body := make([]byte, 8+16+len(mdEnc))
	binary.BigEndian.PutUint64(body[:8], nonce)

	var nacl [24]byte
	copy(nacl[:16], readyNoncePrefix[:])
	binary.BigEndian.PutUint64(nacl[16:], nonce)

	out := box.SealAfterPrecomputation(nil, mdEnc, &nacl, (*[32]byte)(sharedKey))
	if len(out) != len(mdEnc)+16 {
		return wire.Command{}, fmt.Errorf("curve: internal: ready-box len=%d want %d", len(out), len(mdEnc)+16)
	}
	copy(body[8:], out)
	return wire.Command{Name: readyCommandName, Data: body}, nil
}

// parseReady inverts encodeReady. sharedKey is
// precompute(serverTransPub, clientTransSec) = c' × S'. The returned
// Metadata aliases the decrypted plaintext; callers MUST clone via
// seccommon.CloneMetadata to retain it.
func parseReady(cmd wire.Command, sharedKey *SharedKey) (wire.Metadata, error) {
	if cmd.Name != readyCommandName {
		return nil, fmt.Errorf("%w: command name %q", ErrMalformedReady, cmd.Name)
	}
	if len(cmd.Data) < readyMinBodyLen {
		return nil, fmt.Errorf("%w: body size %d, want ≥ %d", ErrMalformedReady, len(cmd.Data), readyMinBodyLen)
	}
	var nacl [24]byte
	copy(nacl[:16], readyNoncePrefix[:])
	copy(nacl[16:], cmd.Data[:8])

	plain, ok := box.OpenAfterPrecomputation(nil, cmd.Data[8:], &nacl, (*[32]byte)(sharedKey))
	if !ok {
		return nil, fmt.Errorf("%w: ready", ErrBoxOpen)
	}
	md, perr := wire.ParseMetadata(plain)
	if perr != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedReady, perr)
	}
	return md, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/curve/codec.go internal/security/curve/codec_test.go
git commit -m "$(cat <<'EOF'
security/curve: READY codec (RFC 26 §5.5)

READY box is sealed under s'×C' = c'×S' = afterReady. The plaintext
is the encoded metadata blob; encodeReady accepts nil metadata and
produces a 24-byte body (8-byte counter nonce + 16-byte overhead).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 13: MESSAGE codec

**Files:**
- Modify: `internal/security/curve/codec.go` — add `encodeMessage` / `parseMessage`.
- Modify: `internal/security/curve/codec_test.go` — round-trip, tamper, MORE-bit tests.

MESSAGE wire layout (RFC 26 §6):
```
message-nonce  8 B (short-nonce counter, monotonic per direction)
message-box   (1 + len(payload) + 16) B
  plaintext: flags (1) || payload
```
MESSAGE is sealed under `afterReady` with a per-direction prefix (`messageClientPrefix` for client→server, `messageServerPrefix` for server→client).

- [ ] **Step 1: Append the failing tests**

```go
func TestEncodeMessageRoundTrip(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	for _, tc := range []struct {
		name    string
		flags   byte
		payload []byte
	}{
		{"empty", 0x00, []byte{}},
		{"more", 0x01, []byte("hi")},
		{"large", 0x00, bytes.Repeat([]byte{0xAB}, 4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := encodeMessage(tc.flags, tc.payload, afterReadyClient, messageClientPrefix, 7)
			if err != nil {
				t.Fatalf("encodeMessage: %v", err)
			}
			if cmd.Name != messageCommandName {
				t.Fatalf("cmd.Name = %q, want %q", cmd.Name, messageCommandName)
			}
			gotFlags, gotPayload, gotNonce, err := parseMessage(cmd, afterReadyServer, messageClientPrefix)
			if err != nil {
				t.Fatalf("parseMessage: %v", err)
			}
			if gotNonce != 7 {
				t.Fatalf("nonce = %d, want 7", gotNonce)
			}
			if gotFlags != tc.flags {
				t.Fatalf("flags = %#x, want %#x", gotFlags, tc.flags)
			}
			if !bytes.Equal(gotPayload, tc.payload) {
				t.Fatalf("payload differs: got %x want %x", gotPayload, tc.payload)
			}
		})
	}
}

func TestParseMessageRejectsWrongName(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: "READY", Data: make([]byte, 25)}
	if _, _, _, err := parseMessage(bad, shared, messageClientPrefix); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("err = %v, want ErrMalformedMessage", err)
	}
}

func TestParseMessageRejectsTooSmall(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: messageCommandName, Data: []byte{0x01}}
	if _, _, _, err := parseMessage(bad, shared, messageClientPrefix); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("err = %v, want ErrMalformedMessage", err)
	}
}

func TestParseMessageRejectsTamperedBox(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	cmd, _ := encodeMessage(0x00, []byte("payload"), afterReadyClient, messageClientPrefix, 1)
	cmd.Data[len(cmd.Data)-1] ^= 0x01
	if _, _, _, err := parseMessage(cmd, afterReadyServer, messageClientPrefix); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestParseMessageRejectsWrongPrefix(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	// Encode with client→server prefix; try to parse with server→client.
	cmd, _ := encodeMessage(0x00, []byte("payload"), afterReadyClient, messageClientPrefix, 1)
	if _, _, _, err := parseMessage(cmd, afterReadyServer, messageServerPrefix); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestEncodeMessageEmptyPayload(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	cmd, err := encodeMessage(0x00, nil, afterReadyClient, messageClientPrefix, 1)
	if err != nil {
		t.Fatalf("encodeMessage(nil): %v", err)
	}
	// Body = 8 (nonce) + 1 (flags) + 0 (payload) + 16 (overhead) = 25.
	if got := len(cmd.Data); got != 25 {
		t.Fatalf("body len = %d, want 25", got)
	}
	gotFlags, gotPayload, _, err := parseMessage(cmd, afterReadyServer, messageClientPrefix)
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	if gotFlags != 0x00 || len(gotPayload) != 0 {
		t.Fatalf("flags=%#x payload=%x, want 0x00 + empty", gotFlags, gotPayload)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -run TestEncodeMessage -run TestParseMessage -count=1`
Expected: FAIL.

- [ ] **Step 3: Append to `internal/security/curve/codec.go`**

```go
// messageMinBodyLen = 8-byte short-nonce + 1-byte flags + 16-byte overhead.
const messageMinBodyLen = 8 + 1 + 16

// encodeMessage seals (flags || payload) under sharedKey with the given
// per-direction prefix. nonce is the short-nonce counter; the caller
// guarantees monotonicity (ClientState/ServerState do this).
func encodeMessage(flags byte, payload []byte, sharedKey *SharedKey, prefix [16]byte, nonce uint64) (wire.Command, error) {
	body := make([]byte, 8+1+len(payload)+16)
	binary.BigEndian.PutUint64(body[:8], nonce)

	plaintext := make([]byte, 1+len(payload))
	plaintext[0] = flags
	copy(plaintext[1:], payload)

	var nacl [24]byte
	copy(nacl[:16], prefix[:])
	binary.BigEndian.PutUint64(nacl[16:], nonce)

	out := box.SealAfterPrecomputation(nil, plaintext, &nacl, (*[32]byte)(sharedKey))
	if len(out) != len(plaintext)+16 {
		return wire.Command{}, fmt.Errorf("curve: internal: message-box len=%d want %d", len(out), len(plaintext)+16)
	}
	copy(body[8:], out)
	return wire.Command{Name: messageCommandName, Data: body}, nil
}

// parseMessage opens a peer MESSAGE. prefix selects the direction
// (caller-supplied; ClientState reads with messageServerPrefix,
// ServerState reads with messageClientPrefix).
func parseMessage(cmd wire.Command, sharedKey *SharedKey, prefix [16]byte) (byte, []byte, uint64, error) {
	if cmd.Name != messageCommandName {
		return 0, nil, 0, fmt.Errorf("%w: command name %q", ErrMalformedMessage, cmd.Name)
	}
	if len(cmd.Data) < messageMinBodyLen {
		return 0, nil, 0, fmt.Errorf("%w: body size %d, want ≥ %d", ErrMalformedMessage, len(cmd.Data), messageMinBodyLen)
	}
	nonce := binary.BigEndian.Uint64(cmd.Data[:8])

	var nacl [24]byte
	copy(nacl[:16], prefix[:])
	binary.BigEndian.PutUint64(nacl[16:], nonce)

	plain, ok := box.OpenAfterPrecomputation(nil, cmd.Data[8:], &nacl, (*[32]byte)(sharedKey))
	if !ok {
		return 0, nil, 0, fmt.Errorf("%w: message", ErrBoxOpen)
	}
	if len(plain) < 1 {
		return 0, nil, 0, fmt.Errorf("%w: plaintext too short", ErrMalformedMessage)
	}
	flags := plain[0]
	return flags, plain[1:], nonce, nil
}
```

> **Why returning `plain[1:]` (no copy):** `box.OpenAfterPrecomputation(nil, ...)` returns a freshly-allocated slice; we slice off the 1-byte flags prefix and hand the tail directly to the state machine, which sets it as `wire.Frame.Body`. That keeps the per-`Unwrap` allocation count at exactly 1, matching spec §5.6's pinned budget. The lifetime contract on `Frame.Body` (caller owns it; ours-to-emit) is satisfied — `plain` is heap-allocated by NaCl and not retained anywhere inside the codec.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/curve/codec.go internal/security/curve/codec_test.go
git commit -m "$(cat <<'EOF'
security/curve: MESSAGE codec (RFC 26 §6)

MESSAGE plaintext is (flags || payload) sealed under afterReady with
a per-direction prefix (messageClientPrefix C→S, messageServerPrefix
S→C). The MORE bit lives in the inner flags byte; parseMessage
returns it separately so ClientState/ServerState can map it to
wire.Frame.More.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 6: ClientState

### Task 14: `NewClient` + `Start` (HELLO emission, eager precompute)

**Files:**
- Create: `internal/security/curve/client.go`
- Create: `internal/security/curve/client_test.go`

`Start` is the only place the client touches its long-term secret: it generates the transient keypair, then precomputes both `handshakeShared = c' × S` (used to seal HELLO and open WELCOME) and `vouchShared = c × S` (used to seal the vouch box once during `Receive(WELCOME)`). After Start returns, the caller's `*SecretKey` is never dereferenced again.

- [ ] **Step 1: Write the failing tests**

```go
package curve

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestNewClientRejectsZeroServerKey(t *testing.T) {
	_, sec := makePair(t)
	_, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{},
		OurPublicKey: PublicKey{1},
		OurSecretKey: &sec,
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewClientRejectsZeroOurPublicKey(t *testing.T) {
	_, sec := makePair(t)
	_, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{1},
		OurPublicKey: PublicKey{},
		OurSecretKey: &sec,
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewClientRejectsNilOurSecretKey(t *testing.T) {
	_, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{1},
		OurPublicKey: PublicKey{1},
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewClientNotDone(t *testing.T) {
	_, sec := makePair(t)
	c, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{1},
		OurPublicKey: PublicKey{1},
		OurSecretKey: &sec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Done() {
		t.Fatalf("new client is Done()")
	}
}

func TestClientStartEmitsValidHello(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)

	c, err := NewClient(ClientOptions{
		ServerKey:    serverLongPub,
		OurPublicKey: clientLongPub,
		OurSecretKey: &clientLongSec,
		Rand:         rand.Reader,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if hello.Name != helloCommandName {
		t.Fatalf("Name = %q, want %q", hello.Name, helloCommandName)
	}

	// Server-side parseHello should accept the produced HELLO.
	// Read C' from the cleartext part first.
	if len(hello.Data) != helloBodyLen {
		t.Fatalf("body len = %d, want %d", len(hello.Data), helloBodyLen)
	}
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	openShared := precompute(clientTransPub, &serverLongSec)
	if _, err := parseHello(hello, openShared); err != nil {
		t.Fatalf("parseHello: %v", err)
	}
}

func TestClientStartTwiceReturnsAlreadyStarted(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, err := NewClient(ClientOptions{
		ServerKey:    serverLongPub,
		OurPublicKey: clientLongPub,
		OurSecretKey: &clientLongSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if _, err := c.Start(); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start = %v, want ErrAlreadyStarted", err)
	}
}

// failingReadOnNthCall returns wantErr on the n-th Read; succeeds before
// that.
type failingReadOnNthCall struct {
	n     int
	calls int
	src   io.Reader
}

func (f *failingReadOnNthCall) Read(p []byte) (int, error) {
	f.calls++
	if f.calls == f.n {
		return 0, errors.New("synthetic")
	}
	return f.src.Read(p)
}

func TestClientStartFailsWhenRandFails(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	rng := &failingReadOnNthCall{n: 1, src: rand.Reader}
	c, err := NewClient(ClientOptions{
		ServerKey:    serverLongPub,
		OurPublicKey: clientLongPub,
		OurSecretKey: &clientLongSec,
		Rand:         rng,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); !errors.Is(err, ErrCryptoRand) {
		t.Fatalf("Start = %v, want ErrCryptoRand", err)
	}
}

// silence unused-import warning if a refactor removes references.
var _ = bytes.Equal
var _ wire.Frame
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -run TestNewClient -run TestClientStart -count=1`
Expected: FAIL (`undefined: NewClient`).

- [ ] **Step 3: Write `internal/security/curve/client.go`**

```go
package curve

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"

	"github.com/tomi77/zmq4/internal/wire"
)

// ClientOptions configures a CURVE ClientState.
type ClientOptions struct {
	// ServerKey is the server's long-term public key. Required.
	ServerKey PublicKey

	// OurPublicKey is this client's long-term public key. Required.
	OurPublicKey PublicKey

	// OurSecretKey is this client's long-term secret key. Required.
	// Referenced (not copied); the caller owns its lifetime. ClientState
	// does NOT zero OurSecretKey on Close — the caller decides when the
	// long-term secret is no longer needed.
	OurSecretKey *SecretKey

	// LocalMetadata is sent in INITIATE. Referenced, not copied; same
	// lifetime rules as plain.NewClient.
	LocalMetadata wire.Metadata

	// Rand supplies entropy for the transient keypair, vouch nonce, and
	// MESSAGE nonce randomization. Pass nil to use crypto/rand.Reader.
	// Tests may inject a deterministic source for byte-exact vector
	// tests.
	Rand io.Reader
}

// ClientState drives the client side of a CURVE handshake and traffic
// encapsulation. Single-shot; not safe for concurrent use.
type ClientState struct {
	// Long-term identity (caller-owned ourLongSec).
	serverPub  PublicKey
	ourLongPub PublicKey
	ourLongSec *SecretKey

	// Transient identity (owned by ClientState; zeroed on Close).
	transPub PublicKey
	transSec SecretKey

	// Precomputed shared keys.
	handshakeShared *SharedKey // c' × S
	afterReady      *SharedKey // c' × S' (filled in Receive(WELCOME))
	vouchShared     *SharedKey // c × S; zeroed after vouch is sealed

	// Local & peer metadata.
	local wire.Metadata
	peer  wire.Metadata

	// Nonce counters.
	sendNonce uint64
	recvNonce uint64
	helloNonce    uint64
	initiateNonce uint64

	// Lifecycle.
	started, welcomeReceived, done, failed, closed bool

	rand io.Reader
}

// NewClient constructs a CURVE ClientState. Errors:
//   ErrInvalidOptions  — zero ServerKey/OurPublicKey, nil OurSecretKey.
//
// Key generation and precomputation happen in Start, not here.
// crypto/rand.Reader is used if opts.Rand is nil.
func NewClient(opts ClientOptions) (*ClientState, error) {
	if opts.ServerKey == (PublicKey{}) {
		return nil, fmt.Errorf("%w: zero ServerKey", ErrInvalidOptions)
	}
	if opts.OurPublicKey == (PublicKey{}) {
		return nil, fmt.Errorf("%w: zero OurPublicKey", ErrInvalidOptions)
	}
	if opts.OurSecretKey == nil {
		return nil, fmt.Errorf("%w: nil OurSecretKey", ErrInvalidOptions)
	}
	rng := opts.Rand
	if rng == nil {
		rng = rand.Reader
	}
	return &ClientState{
		serverPub:     opts.ServerKey,
		ourLongPub:    opts.OurPublicKey,
		ourLongSec:    opts.OurSecretKey,
		local:         opts.LocalMetadata,
		helloNonce:    1,
		initiateNonce: 1,
		sendNonce:     1,
		rand:          rng,
	}, nil
}

// Done reports whether the handshake completed successfully.
func (c *ClientState) Done() bool { return c.done && !c.failed && !c.closed }

// Start generates the transient keypair, precomputes handshakeShared
// and vouchShared, emits HELLO, and transitions to AWAIT_WELCOME. Must
// be called exactly once before Receive.
func (c *ClientState) Start() (wire.Command, error) {
	switch {
	case c.closed:
		return wire.Command{}, ErrClosed
	case c.failed:
		return wire.Command{}, ErrAlreadyFailed
	case c.started:
		return wire.Command{}, ErrAlreadyStarted
	}

	transPubArr, transSecArr, err := box.GenerateKey(c.rand)
	if err != nil {
		c.failed = true
		return wire.Command{}, fmt.Errorf("%w: transient keypair: %v", ErrCryptoRand, err)
	}
	copy(c.transPub[:], transPubArr[:])
	copy(c.transSec[:], transSecArr[:])

	c.handshakeShared = precompute(c.serverPub, &c.transSec) // c' × S
	c.vouchShared = precompute(c.serverPub, c.ourLongSec)    // c × S — long-term secret touched ONCE here.

	hello, err := encodeHello(c.transPub, c.handshakeShared, c.helloNonce, c.rand)
	if err != nil {
		c.failed = true
		return wire.Command{}, fmt.Errorf("curve: encode HELLO: %w", err)
	}
	c.helloNonce++
	c.started = true
	return hello, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 5: vet / staticcheck**

Run: `go vet ./internal/security/curve/... && staticcheck ./internal/security/curve/...`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add internal/security/curve/client.go internal/security/curve/client_test.go
git commit -m "$(cat <<'EOF'
security/curve: ClientState — NewClient + Start (HELLO + eager precompute)

NewClient validates the option set and stashes references; key
generation and shared-key precomputation happen in Start so failure
paths are reproducible from tests. Start touches OurSecretKey exactly
once (to derive vouchShared = c×S) — the caller's *SecretKey is never
dereferenced again during the handshake.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 15: `Receive(WELCOME)` → INITIATE

**Files:**
- Modify: `internal/security/curve/client.go` — add `Receive`, dispatch on `welcomeReceived`.
- Modify: `internal/security/curve/client_test.go` — happy-path test.

- [ ] **Step 1: Append the failing tests**

```go
func TestClientReceiveWelcomeEmitsValidInitiate(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	mdC := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
	}
	c, err := NewClient(ClientOptions{
		ServerKey:     serverLongPub,
		OurPublicKey:  clientLongPub,
		OurSecretKey:  &clientLongSec,
		LocalMetadata: mdC,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Drive the server side manually with codec primitives so we can
	// build a valid WELCOME without depending on ServerState yet.
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	helloOpenShared := precompute(clientTransPub, &serverLongSec) // s × C'
	if _, err := parseHello(hello, helloOpenShared); err != nil {
		t.Fatalf("server-side parseHello: %v", err)
	}

	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, err := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	if err != nil {
		t.Fatalf("sealCookie: %v", err)
	}
	welcomeShared := precompute(clientTransPub, &serverLongSec) // s × C'
	welcome, err := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)
	if err != nil {
		t.Fatalf("encodeWelcome: %v", err)
	}

	out, done, err := c.Receive(welcome)
	if err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	if done {
		t.Fatalf("done=true after WELCOME, want false")
	}
	if out == nil || out.Name != initiateCommandName {
		t.Fatalf("out = %+v, want INITIATE", out)
	}

	// Open INITIATE with the server's afterReady = s' × C'.
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	gotCookie, gotVouch, gotLongPub, gotMeta, err := parseInitiate(*out, afterReadyServer)
	if err != nil {
		t.Fatalf("parseInitiate: %v", err)
	}
	if gotCookie != ck {
		t.Fatalf("cookie not echoed verbatim")
	}
	if gotLongPub != clientLongPub {
		t.Fatalf("client long pub = %x, want %x", gotLongPub, clientLongPub)
	}
	// Vouch authenticates (C' || S) under c × S; we open it via box.Open.
	gotC1, gotS, err := openVouch(gotVouch, clientLongPub, &serverLongSec)
	if err != nil {
		t.Fatalf("openVouch: %v", err)
	}
	if gotC1 != clientTransPub {
		t.Fatalf("vouch C' = %x, want %x", gotC1, clientTransPub)
	}
	if gotS != serverLongPub {
		t.Fatalf("vouch S = %x, want %x", gotS, serverLongPub)
	}
	if v, ok := gotMeta.Get("Socket-Type"); !ok || string(v) != "DEALER" {
		t.Fatalf("INITIATE Socket-Type = %q, want DEALER", v)
	}
}

func TestClientReceiveBeforeStart(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if _, _, err := c.Receive(wire.Command{Name: welcomeCommandName}); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Receive before Start = %v, want ErrNotStarted", err)
	}
}

func TestClientReceiveMalformedWelcome(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	bad := wire.Command{Name: welcomeCommandName, Data: []byte{0x01}}
	if _, _, err := c.Receive(bad); !errors.Is(err, ErrMalformedWelcome) {
		t.Fatalf("err = %v, want ErrMalformedWelcome", err)
	}
}

func TestClientReceiveTamperedWelcome(t *testing.T) {
	// Build a real WELCOME, flip a bit, expect ErrBoxOpen.
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	welcome, _ := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)

	welcome.Data[len(welcome.Data)-1] ^= 0x01
	if _, _, err := c.Receive(welcome); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -run TestClientReceive -count=1`
Expected: FAIL (`(*ClientState).Receive` undefined or wrong dispatch).

- [ ] **Step 3: Add `Receive` to `internal/security/curve/client.go`**

```go
// Receive consumes one peer command and advances the state machine.
func (c *ClientState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error) {
	switch {
	case c.closed:
		return nil, false, ErrClosed
	case c.failed:
		return nil, false, ErrAlreadyFailed
	case !c.started:
		c.failed = true
		return nil, false, ErrNotStarted
	case c.done:
		c.failed = true
		return nil, false, ErrAlreadyDone
	}

	if !c.welcomeReceived {
		switch cmd.Name {
		case welcomeCommandName:
			return c.handleWelcome(cmd)
		case wire.ErrorCommandName:
			return nil, false, c.failPeerError(cmd)
		}
		c.failed = true
		return nil, false, fmt.Errorf("%w: %q (expected WELCOME)", ErrUnexpectedCommand, cmd.Name)
	}

	// AWAIT_READY — fleshed out in Task 16.
	c.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected READY)", ErrUnexpectedCommand, cmd.Name)
}

func (c *ClientState) handleWelcome(cmd wire.Command) (*wire.Command, bool, error) {
	serverTransPub, ck, perr := parseWelcome(cmd, c.handshakeShared)
	if perr != nil {
		c.failed = true
		return nil, false, perr
	}
	c.afterReady = precompute(serverTransPub, &c.transSec) // c' × S'

	v, vErr := encodeVouch(c.transPub, c.serverPub, c.vouchShared, c.rand)
	if vErr != nil {
		c.failed = true
		return nil, false, fmt.Errorf("curve: encode vouch: %w", vErr)
	}
	// vouchShared is no longer needed; zero immediately so a later bug
	// cannot re-derive the long-term × long-term key.
	c.vouchShared.Zero()
	c.vouchShared = nil

	initiate, iErr := encodeInitiate(ck, v, c.ourLongPub, c.local, c.afterReady, c.initiateNonce, c.rand)
	if iErr != nil {
		c.failed = true
		return nil, false, fmt.Errorf("curve: encode INITIATE: %w", iErr)
	}
	c.initiateNonce++
	c.welcomeReceived = true
	return &initiate, false, nil
}

// failPeerError marks the state failed and wraps the peer's ERROR
// reason. Reason bytes are returned as-received; callers SHOULD treat
// them as untrusted.
func (c *ClientState) failPeerError(cmd wire.Command) error {
	c.failed = true
	ec, perr := wire.ParseError(cmd)
	if perr != nil {
		return fmt.Errorf("%w: malformed ERROR: %v", ErrPeerError, perr)
	}
	return fmt.Errorf("%w: %s", ErrPeerError, ec.Reason)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/curve/client.go internal/security/curve/client_test.go
git commit -m "$(cat <<'EOF'
security/curve: ClientState.Receive(WELCOME) → INITIATE

handleWelcome opens WELCOME under handshakeShared, derives afterReady
= c'×S', seals the vouch under vouchShared (then zeros it — long-term
secret is never derivable from the state again), and seals INITIATE
under afterReady. Malformed/tampered WELCOME and unexpected commands
fail per spec §6.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 16: `Receive(READY)` → done; `PeerMetadata`, `PeerPublicKey`

**Files:**
- Modify: `internal/security/curve/client.go` — flesh out READY branch + accessors.
- Modify: `internal/security/curve/client_test.go` — happy-path test that completes the handshake.

- [ ] **Step 1: Append the failing tests**

```go
func TestClientReceiveReadyCompletesHandshake(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	mdS := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
		{Name: []byte("Identity"), Value: []byte("server-1")},
	}

	c, err := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, _ := c.Start()
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	welcome, _ := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)
	if _, _, err := c.Receive(welcome); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}

	// Server seals a READY under afterReady = s' × C'.
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	ready, err := encodeReady(mdS, afterReadyServer, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeReady: %v", err)
	}

	out, done, err := c.Receive(ready)
	if err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}
	if !done || out != nil {
		t.Fatalf("Receive(READY): out=%+v done=%v, want nil/true", out, done)
	}
	if !c.Done() {
		t.Fatalf("Done() == false after READY")
	}
	pm := c.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "ROUTER" {
		t.Fatalf("PeerMetadata Socket-Type = %q, want ROUTER", v)
	}
	if c.PeerPublicKey() != serverLongPub {
		t.Fatalf("PeerPublicKey = %x, want %x", c.PeerPublicKey(), serverLongPub)
	}
}

func TestClientPeerMetadataIndependentOfInputBuffer(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	mdS := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
	}

	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])
	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	welcome, _ := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)
	c.Receive(welcome)

	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	ready, _ := encodeReady(mdS, afterReadyServer, 1, rand.Reader)

	// Wrap ready.Data in a fresh buffer we can later clobber.
	buf := make([]byte, len(ready.Data))
	copy(buf, ready.Data)
	ready = wire.Command{Name: ready.Name, Data: buf}

	if _, _, err := c.Receive(ready); err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}
	for i := range buf {
		buf[i] = 0xFF
	}
	pm := c.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "ROUTER" {
		t.Fatalf("PeerMetadata after clobber = %q, want ROUTER", v)
	}
}

func TestClientReceiveTamperedReady(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)

	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])
	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	welcome, _ := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)
	c.Receive(welcome)

	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	ready, _ := encodeReady(nil, afterReadyServer, 1, rand.Reader)
	ready.Data[len(ready.Data)-1] ^= 0x01

	if _, _, err := c.Receive(ready); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -count=1`
Expected: FAIL (`PeerPublicKey` undefined; READY branch falls through with `ErrUnexpectedCommand`).

- [ ] **Step 3: Replace the AWAIT_READY stub in `client.go`**

Replace the trailing block in `Receive`:

```go
	// AWAIT_READY — fleshed out in Task 16.
	c.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected READY)", ErrUnexpectedCommand, cmd.Name)
```

with:

```go
	// AWAIT_READY.
	switch cmd.Name {
	case readyCommandName:
		return c.handleReady(cmd)
	case wire.ErrorCommandName:
		return nil, false, c.failPeerError(cmd)
	}
	c.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected READY)", ErrUnexpectedCommand, cmd.Name)
```

Add the helper:

```go
func (c *ClientState) handleReady(cmd wire.Command) (*wire.Command, bool, error) {
	md, perr := parseReady(cmd, c.afterReady)
	if perr != nil {
		c.failed = true
		return nil, false, perr
	}
	c.peer = seccommon.CloneMetadata(md)
	c.done = true
	return nil, true, nil
}

// PeerMetadata returns the metadata the server advertised in READY.
// Valid only after Done(). Aliases an internal buffer; callers MUST
// NOT mutate it.
func (c *ClientState) PeerMetadata() wire.Metadata { return c.peer }

// PeerPublicKey returns the server's long-term public key (== ServerKey
// from ClientOptions). Provided for symmetry with ServerState.
func (c *ClientState) PeerPublicKey() PublicKey { return c.serverPub }
```

Add the import `"github.com/tomi77/zmq4/internal/security/seccommon"` at the top of the file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/curve/client.go internal/security/curve/client_test.go
git commit -m "$(cat <<'EOF'
security/curve: ClientState.Receive(READY) → done; PeerMetadata + PeerPublicKey

handleReady opens READY under afterReady, clones the metadata via
seccommon.CloneMetadata so PeerMetadata is independent of the input
buffer, and transitions to DONE. PeerPublicKey simply returns the
ServerKey supplied at construction — symmetric with ServerState.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 17: ClientState — `Wrap` / `Unwrap` / `Close` / lifecycle errors

**Files:**
- Modify: `internal/security/curve/client.go` — add `Wrap`, `Unwrap`, `Close`.
- Modify: `internal/security/curve/client_test.go` — Wrap/Unwrap/Close tests + lifecycle error coverage.

> **Test-helper design note:** Task 17 needs to exercise `Wrap` (client-side encode under `messageClientPrefix`) and `Unwrap` (client-side decode under `messageServerPrefix`) before `ServerState` exists. The helper `newClientDoneAndPeerKey` drives one `ClientState` to DONE via codec primitives, then exposes the shared `afterReady` key plus the two direction prefixes — so the test sends through the high-level `c.Wrap` and verifies via `parseMessage`, and conversely synthesises a peer-MESSAGE via `encodeMessage` and verifies via `c.Unwrap`. Real `(client, server)` round trips live in Chunk 7 once `ServerState` lands.

- [ ] **Step 1: Append the failing tests + helper**

```go
// newClientDoneAndPeerKey drives a fresh ClientState to DONE through
// the codec primitives and returns it together with the shared
// afterReady key the peer-server would have, plus the two direction
// prefixes. Used by Wrap/Unwrap tests in this task; Chunk 7's tests
// use the real ServerState pair.
func newClientDoneAndPeerKey(t *testing.T) (c *ClientState, peerKey *SharedKey, sendPrefix, recvPrefix [16]byte) {
	t.Helper()
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)

	c, err := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, _ := c.Start()
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	welcome, _ := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)
	if _, _, err := c.Receive(welcome); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	ready, _ := encodeReady(nil, afterReadyServer, 1, rand.Reader)
	if _, _, err := c.Receive(ready); err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}
	if !c.Done() {
		t.Fatalf("client not done")
	}
	return c, afterReadyServer, messageClientPrefix, messageServerPrefix
}

func TestClientWrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	_, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: []byte("x")})
	if !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("err = %v, want security.ErrNotDone", err)
	}
}

func TestClientUnwrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	_, err := c.Unwrap(wire.Frame{Kind: wire.FrameCommand, Body: make([]byte, 25)})
	if !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("err = %v, want security.ErrNotDone", err)
	}
}

func TestClientWrapUnwrapRoundTrip(t *testing.T) {
	c, peerKey, sendPrefix, recvPrefix := newClientDoneAndPeerKey(t)

	for _, tc := range []struct {
		name string
		more bool
		body []byte
	}{
		{"empty", false, []byte{}},
		{"more-true", true, []byte("hello")},
		{"large", false, bytes.Repeat([]byte{0x42}, 4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := wire.Frame{Kind: wire.FrameMessage, More: tc.more, Body: tc.body}
			wrapped, err := c.Wrap(in)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if wrapped.Kind != wire.FrameCommand || wrapped.More {
				t.Fatalf("wrapped = %+v, want FrameCommand non-MORE", wrapped)
			}
			cmd, perr := wire.ParseCommand(wrapped.Body)
			if perr != nil {
				t.Fatalf("ParseCommand: %v", perr)
			}
			gotFlags, gotPayload, _, derr := parseMessage(cmd, peerKey, sendPrefix)
			if derr != nil {
				t.Fatalf("parseMessage: %v", derr)
			}
			wantFlags := byte(0)
			if tc.more {
				wantFlags = 0x01
			}
			if gotFlags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", gotFlags, wantFlags)
			}
			if !bytes.Equal(gotPayload, tc.body) {
				t.Fatalf("payload differs")
			}

			// Reverse: synthesise a server→client MESSAGE under
			// recvPrefix and feed it to c.Unwrap.
			outer, err := encodeMessage(wantFlags, tc.body, peerKey, recvPrefix, uint64(1+ /*nonce slot per subtest*/ 0))
			if err != nil {
				t.Fatalf("encodeMessage: %v", err)
			}
			outerBody, err := wire.EncodeCommand(outer)
			if err != nil {
				t.Fatalf("EncodeCommand: %v", err)
			}
			gotFrame, err := c.Unwrap(wire.Frame{Kind: wire.FrameCommand, Body: outerBody})
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if gotFrame.Kind != wire.FrameMessage || gotFrame.More != tc.more || !bytes.Equal(gotFrame.Body, tc.body) {
				t.Fatalf("Unwrap = %+v, want %+v", gotFrame, in)
			}

			// New ClientState per subtest so recvNonce starts at 0
			// every iteration. (Re-running on the same c with nonce=1
			// each time would trigger ErrNonceReused on the second
			// subtest.) Replace c for the next iteration:
			c, peerKey, sendPrefix, recvPrefix = newClientDoneAndPeerKey(t)
			_ = sendPrefix
			_ = recvPrefix
		})
	}
}

func TestClientUnwrapReplayReturnsErrNonceReused(t *testing.T) {
	c, peerKey, _, recvPrefix := newClientDoneAndPeerKey(t)

	outer, _ := encodeMessage(0x00, []byte("once"), peerKey, recvPrefix, 1)
	outerBody, _ := wire.EncodeCommand(outer)
	frame := wire.Frame{Kind: wire.FrameCommand, Body: outerBody}

	if _, err := c.Unwrap(frame); err != nil {
		t.Fatalf("first Unwrap: %v", err)
	}
	if _, err := c.Unwrap(frame); !errors.Is(err, ErrNonceReused) {
		t.Fatalf("replay Unwrap = %v, want ErrNonceReused", err)
	}
}

func TestClientWrapNonceExhausted(t *testing.T) {
	c, _, _, _ := newClientDoneAndPeerKey(t)
	c.sendNonce = ^uint64(0) // all-ones
	if _, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage}); !errors.Is(err, ErrNonceExhausted) {
		t.Fatalf("err = %v, want ErrNonceExhausted", err)
	}
}

func TestClientCloseIdempotentAndPreservesLongTermSecret(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	c.Close()
	c.Close() // idempotent

	if _, err := c.Start(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close = %v, want ErrClosed", err)
	}
	if _, _, err := c.Receive(wire.Command{Name: welcomeCommandName}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Receive after Close = %v, want ErrClosed", err)
	}
	if _, err := c.Wrap(wire.Frame{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Wrap after Close = %v, want ErrClosed", err)
	}
	if _, err := c.Unwrap(wire.Frame{Kind: wire.FrameCommand, Body: make([]byte, 25)}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Unwrap after Close = %v, want ErrClosed", err)
	}
	if c.Done() {
		t.Fatalf("Done() == true after Close")
	}
	// Long-term secret must be intact (caller-owned). All-zeros would
	// be the post-Zero state; we assert it has at least one non-zero
	// byte — `makePair` returns non-zero with overwhelming probability.
	if clientLongSec == (SecretKey{}) {
		t.Fatalf("long-term secret was zeroed by Close")
	}
}

// --- Lifecycle / spec §6 coverage ---

func TestClientReceiveAfterDoneReturnsAlreadyDone(t *testing.T) {
	c, _, _, _ := newClientDoneAndPeerKey(t)
	if _, _, err := c.Receive(wire.Command{Name: readyCommandName}); !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("err = %v, want ErrAlreadyDone", err)
	}
}

func TestClientReceiveHelloAtAwaitWelcomeReturnsUnexpectedCommand(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	bogus := wire.Command{Name: helloCommandName, Data: make([]byte, helloBodyLen)}
	if _, _, err := c.Receive(bogus); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestClientPeerPublicKeyReturnsServerKeyFromOptions(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if got := c.PeerPublicKey(); got != serverLongPub {
		t.Fatalf("PeerPublicKey = %x, want %x", got, serverLongPub)
	}
}
```

Add the import `"github.com/tomi77/zmq4/internal/security"` to the test file (do not duplicate — merge into the existing import block).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -run TestClientWrap -run TestClientUnwrap -run TestClientClose -count=1`
Expected: FAIL (`(*ClientState).Wrap` undefined).

- [ ] **Step 3: Append `Wrap`, `Unwrap`, `Close` to `client.go`**

```go
import (
	// ... existing imports ...
	"github.com/tomi77/zmq4/internal/security"
)

// Wrap encapsulates an outgoing frame as MESSAGE. See
// security.Mechanism.Wrap. Each call advances the send-nonce counter.
// Returns ErrNonceExhausted if the counter would wrap past 2^64-1.
func (c *ClientState) Wrap(f wire.Frame) (wire.Frame, error) {
	switch {
	case c.closed:
		return wire.Frame{}, ErrClosed
	case !c.Done():
		return wire.Frame{}, security.ErrNotDone
	}
	if c.sendNonce == ^uint64(0) {
		return wire.Frame{}, ErrNonceExhausted
	}
	flags := byte(0)
	if f.More {
		flags = 0x01
	}
	cmd, err := encodeMessage(flags, f.Body, c.afterReady, messageClientPrefix, c.sendNonce)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("curve: encode MESSAGE: %w", err)
	}
	c.sendNonce++

	body, err := wire.EncodeCommand(cmd)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("curve: encode command: %w", err)
	}
	return wire.Frame{Kind: wire.FrameCommand, More: false, Body: body}, nil
}

// Unwrap decrypts an incoming MESSAGE. Each successful call advances
// recvNonce and rejects strictly-non-monotonic nonces with
// ErrNonceReused.
func (c *ClientState) Unwrap(f wire.Frame) (wire.Frame, error) {
	switch {
	case c.closed:
		return wire.Frame{}, ErrClosed
	case !c.Done():
		return wire.Frame{}, security.ErrNotDone
	}
	if f.Kind != wire.FrameCommand {
		return wire.Frame{}, fmt.Errorf("%w: kind %v", ErrMalformedMessage, f.Kind)
	}
	cmd, perr := wire.ParseCommand(f.Body)
	if perr != nil {
		return wire.Frame{}, fmt.Errorf("%w: %v", ErrMalformedMessage, perr)
	}
	flags, payload, nonce, perr := parseMessage(cmd, c.afterReady, messageServerPrefix)
	if perr != nil {
		return wire.Frame{}, perr
	}
	if nonce <= c.recvNonce {
		return wire.Frame{}, fmt.Errorf("%w: incoming=%d last=%d", ErrNonceReused, nonce, c.recvNonce)
	}
	c.recvNonce = nonce
	return wire.Frame{Kind: wire.FrameMessage, More: flags&0x01 == 0x01, Body: payload}, nil
}

// Close zeros the transient secret and any retained shared keys.
// Idempotent. After Close, every method returns ErrClosed. Long-term
// keys passed in via ClientOptions are NOT zeroed — the caller owns
// that lifetime.
func (c *ClientState) Close() {
	if c.closed {
		return
	}
	c.closed = true
	c.transSec.Zero()
	if c.handshakeShared != nil {
		c.handshakeShared.Zero()
	}
	if c.afterReady != nil {
		c.afterReady.Zero()
	}
	if c.vouchShared != nil {
		c.vouchShared.Zero()
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 5: vet / staticcheck**

Run: `go vet ./internal/security/curve/... && staticcheck ./internal/security/curve/...`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add internal/security/curve/client.go internal/security/curve/client_test.go
git commit -m "$(cat <<'EOF'
security/curve: ClientState — Wrap/Unwrap/Close + lifecycle gates

Wrap encrypts (flags||payload) under afterReady with messageClientPrefix
and emits a FrameCommand carrying the encoded MESSAGE. Unwrap inverts
with messageServerPrefix and rejects non-monotonic nonces. Close zeros
transient secret + all three precomputed shared keys; long-term
secrets are never zeroed (caller-owned). Every method gates on closed/
failed/Done() per the Mechanism contract.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 7: ServerState

### Task 18: `Authorizer`, `NewServer`, `Receive(HELLO)` → WELCOME

**Files:**
- Create: `internal/security/curve/server.go`
- Create: `internal/security/curve/server_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package curve

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func acceptAll(_ PublicKey, _ wire.Metadata) error { return nil }

func TestNewServerNilAuthorizerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("NewServer(nil Authorizer) did not panic")
		}
	}()
	_, sec := makePair(t)
	_, _ = NewServer(ServerOptions{
		OurPublicKey: PublicKey{1},
		OurSecretKey: &sec,
		Authorizer:   nil,
	})
}

func TestNewServerRejectsZeroOurPublicKey(t *testing.T) {
	_, sec := makePair(t)
	_, err := NewServer(ServerOptions{
		OurPublicKey: PublicKey{},
		OurSecretKey: &sec,
		Authorizer:   acceptAll,
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewServerRejectsNilOurSecretKey(t *testing.T) {
	_, err := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1},
		Authorizer:   acceptAll,
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewServerNotDone(t *testing.T) {
	_, sec := makePair(t)
	s, err := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.Done() {
		t.Fatalf("new server is Done()")
	}
}

func TestServerReceiveHelloEmitsValidWelcome(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	_ = clientLongPub

	s, err := NewServer(ServerOptions{
		OurPublicKey: serverLongPub,
		OurSecretKey: &serverLongSec,
		Authorizer:   acceptAll,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Build HELLO via a real ClientState so the test exercises the
	// production path on both sides.
	c, err := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	out, done, err := s.Receive(hello)
	if err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	if done {
		t.Fatalf("done=true after HELLO, want false")
	}
	if out == nil || out.Name != welcomeCommandName {
		t.Fatalf("out = %+v, want WELCOME", out)
	}
	if len(out.Data) != welcomeBodyLen {
		t.Fatalf("welcome len = %d, want %d", len(out.Data), welcomeBodyLen)
	}

	// Round-trip: client opens WELCOME successfully.
	if _, _, err := c.Receive(*out); err != nil {
		t.Fatalf("client.Receive(WELCOME): %v", err)
	}
}

// silence unused-import warnings for imports that fully grow in
// subsequent tasks. Drop these placeholders once the appended tests
// reference each import legitimately.
var (
	_ = bytes.Equal
	_ = strings.Contains
)
```

> **Compile-time interface assertion** lives in `server.go` (Step 3) — declared once globally; do not also add it to the test file.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -run TestNewServer -run TestServerReceiveHello -count=1`
Expected: FAIL (`undefined: NewServer`).

- [ ] **Step 3: Write `internal/security/curve/server.go`** (HELLO branch only — INITIATE in Task 19/20)

```go
package curve

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/seccommon"
	"github.com/tomi77/zmq4/internal/wire"
)

// Authorizer decides whether a client's long-term public key is allowed
// to connect. See docs/specs/02c-security-curve.md §4.4 for the full
// contract.
type Authorizer func(clientPublicKey PublicKey, peerMetadata wire.Metadata) error

// ServerOptions configures a CURVE ServerState.
type ServerOptions struct {
	OurPublicKey  PublicKey
	OurSecretKey  *SecretKey  // referenced; caller owns lifetime
	LocalMetadata wire.Metadata

	// Authorizer is required; NewServer panics if nil.
	Authorizer Authorizer

	// Rand supplies entropy for the transient keypair, cookie key,
	// cookie nonce, welcome nonce, ready nonce, and MESSAGE nonces.
	// Pass nil for crypto/rand.Reader.
	Rand io.Reader
}

// ServerState drives the server side of a CURVE handshake and traffic
// encapsulation. Single-shot; not safe for concurrent use.
type ServerState struct {
	ourLongPub PublicKey
	ourLongSec *SecretKey

	transPub PublicKey
	transSec SecretKey

	cookieKey SecretKey

	authorizer Authorizer

	handshakeShared *SharedKey // s × C'
	afterReady      *SharedKey // s' × C'

	peerLongPub  PublicKey
	peerTransPub PublicKey

	local wire.Metadata
	peer  wire.Metadata

	sendNonce uint64
	recvNonce uint64
	readyNonce uint64

	helloProcessed, done, failed, closed bool

	rand io.Reader
}

// NewServer constructs a CURVE ServerState. Panics if opts.Authorizer
// is nil. Returns ErrInvalidOptions for zero OurPublicKey / nil
// OurSecretKey, ErrCryptoRand for entropy failures (transient keypair
// + cookie key generation happen here).
func NewServer(opts ServerOptions) (*ServerState, error) {
	if opts.Authorizer == nil {
		panic("curve: NewServer requires a non-nil Authorizer")
	}
	if opts.OurPublicKey == (PublicKey{}) {
		return nil, fmt.Errorf("%w: zero OurPublicKey", ErrInvalidOptions)
	}
	if opts.OurSecretKey == nil {
		return nil, fmt.Errorf("%w: nil OurSecretKey", ErrInvalidOptions)
	}
	rng := opts.Rand
	if rng == nil {
		rng = rand.Reader
	}
	transPubArr, transSecArr, err := box.GenerateKey(rng)
	if err != nil {
		return nil, fmt.Errorf("%w: transient keypair: %v", ErrCryptoRand, err)
	}
	var transPub PublicKey
	var transSec SecretKey
	copy(transPub[:], transPubArr[:])
	copy(transSec[:], transSecArr[:])

	var cookieKey SecretKey
	if _, err := io.ReadFull(rng, cookieKey[:]); err != nil {
		return nil, fmt.Errorf("%w: cookie key: %v", ErrCryptoRand, err)
	}

	return &ServerState{
		ourLongPub: opts.OurPublicKey,
		ourLongSec: opts.OurSecretKey,
		transPub:   transPub,
		transSec:   transSec,
		cookieKey:  cookieKey,
		authorizer: opts.Authorizer,
		local:      opts.LocalMetadata,
		readyNonce: 1,
		sendNonce:  1,
		rand:       rng,
	}, nil
}

// Done reports whether the handshake completed successfully.
func (s *ServerState) Done() bool { return s.done && !s.failed && !s.closed }

// Receive consumes one peer command and advances the state machine.
// Server has no Start — it is purely reactive (HELLO arrives first).
func (s *ServerState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error) {
	switch {
	case s.closed:
		return nil, false, ErrClosed
	case s.failed:
		return nil, false, ErrAlreadyFailed
	case s.done:
		s.failed = true
		return nil, false, ErrAlreadyDone
	}

	if !s.helloProcessed {
		switch cmd.Name {
		case helloCommandName:
			return s.handleHello(cmd)
		case wire.ErrorCommandName:
			return nil, false, s.failPeerError(cmd)
		}
		s.failed = true
		return nil, false, fmt.Errorf("%w: %q (expected HELLO)", ErrUnexpectedCommand, cmd.Name)
	}

	// AWAIT_INITIATE — fleshed out in Task 19/20.
	s.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected INITIATE)", ErrUnexpectedCommand, cmd.Name)
}

func (s *ServerState) handleHello(cmd wire.Command) (*wire.Command, bool, error) {
	// HELLO is sealed under c'×S = box(serverLongSec, peerTransPub). The
	// server can only compute the shared key after it reads peerTransPub
	// from the cleartext part of HELLO — so we extract C' first, then
	// precompute s×C', then call parseHello to verify the box.
	if len(cmd.Data) != helloBodyLen {
		s.failed = true
		return nil, false, fmt.Errorf("%w: body size %d, want %d", ErrMalformedHello, len(cmd.Data), helloBodyLen)
	}
	var peerTransPub PublicKey
	copy(peerTransPub[:], cmd.Data[2+72:2+72+32])

	openShared := precompute(peerTransPub, s.ourLongSec) // s × C'
	if _, perr := parseHello(cmd, openShared); perr != nil {
		s.failed = true
		return nil, false, perr
	}
	s.peerTransPub = peerTransPub
	s.handshakeShared = openShared
	s.afterReady = precompute(peerTransPub, &s.transSec) // s' × C'

	// Seal cookie binding (C' || s') under cookieKey.
	ck, cErr := sealCookie(peerTransPub, s.transSec, &s.cookieKey, s.rand)
	if cErr != nil {
		s.failed = true
		return nil, false, fmt.Errorf("curve: seal cookie: %w", cErr)
	}
	welcome, wErr := encodeWelcome(s.transPub, ck, s.handshakeShared, s.rand)
	if wErr != nil {
		s.failed = true
		return nil, false, fmt.Errorf("curve: encode WELCOME: %w", wErr)
	}
	s.helloProcessed = true
	return &welcome, false, nil
}

// failPeerError mirrors ClientState.failPeerError.
func (s *ServerState) failPeerError(cmd wire.Command) error {
	s.failed = true
	ec, perr := wire.ParseError(cmd)
	if perr != nil {
		return fmt.Errorf("%w: malformed ERROR: %v", ErrPeerError, perr)
	}
	return fmt.Errorf("%w: %s", ErrPeerError, ec.Reason)
}

// PeerPublicKey returns the client's long-term public key (the value
// passed to the Authorizer). Valid only after Done().
func (s *ServerState) PeerPublicKey() PublicKey { return s.peerLongPub }

// PeerMetadata returns the metadata the client sent in INITIATE. Valid
// only after Done().
func (s *ServerState) PeerMetadata() wire.Metadata { return s.peer }

// Wrap encapsulates an outgoing frame as MESSAGE under
// messageServerPrefix. See ClientState.Wrap for the contract.
func (s *ServerState) Wrap(f wire.Frame) (wire.Frame, error) {
	switch {
	case s.closed:
		return wire.Frame{}, ErrClosed
	case !s.Done():
		return wire.Frame{}, security.ErrNotDone
	}
	if s.sendNonce == ^uint64(0) {
		return wire.Frame{}, ErrNonceExhausted
	}
	flags := byte(0)
	if f.More {
		flags = 0x01
	}
	cmd, err := encodeMessage(flags, f.Body, s.afterReady, messageServerPrefix, s.sendNonce)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("curve: encode MESSAGE: %w", err)
	}
	s.sendNonce++
	body, err := wire.EncodeCommand(cmd)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("curve: encode command: %w", err)
	}
	return wire.Frame{Kind: wire.FrameCommand, More: false, Body: body}, nil
}

// Unwrap inverts Wrap, opening peer MESSAGE under messageClientPrefix.
func (s *ServerState) Unwrap(f wire.Frame) (wire.Frame, error) {
	switch {
	case s.closed:
		return wire.Frame{}, ErrClosed
	case !s.Done():
		return wire.Frame{}, security.ErrNotDone
	}
	if f.Kind != wire.FrameCommand {
		return wire.Frame{}, fmt.Errorf("%w: kind %v", ErrMalformedMessage, f.Kind)
	}
	cmd, perr := wire.ParseCommand(f.Body)
	if perr != nil {
		return wire.Frame{}, fmt.Errorf("%w: %v", ErrMalformedMessage, perr)
	}
	flags, payload, nonce, perr := parseMessage(cmd, s.afterReady, messageClientPrefix)
	if perr != nil {
		return wire.Frame{}, perr
	}
	if nonce <= s.recvNonce {
		return wire.Frame{}, fmt.Errorf("%w: incoming=%d last=%d", ErrNonceReused, nonce, s.recvNonce)
	}
	s.recvNonce = nonce
	return wire.Frame{Kind: wire.FrameMessage, More: flags&0x01 == 0x01, Body: payload}, nil
}

// Close zeros transient secret + handshakeShared + afterReady +
// cookieKey. Idempotent; long-term secret is NOT zeroed.
func (s *ServerState) Close() {
	if s.closed {
		return
	}
	s.closed = true
	s.transSec.Zero()
	s.cookieKey.Zero()
	if s.handshakeShared != nil {
		s.handshakeShared.Zero()
	}
	if s.afterReady != nil {
		s.afterReady.Zero()
	}
}

// Compile-time assertion: ServerState implements security.Mechanism.
// (ClientState also implements security.ClientMechanism — that
// assertion lives in interfaces_conformance_test.go to avoid a cycle.)
var _ security.Mechanism = (*ServerState)(nil)

// Workaround for the unused-import warning if seccommon is not yet
// referenced in this file. Removed when handleInitiate (Task 19) lands.
var _ = seccommon.CloneMetadata
```

> **Why precompute happens inside `handleHello` and not in `NewServer`:** the handshakeShared key is `s × C'`, and the server only learns `C'` from HELLO. We therefore can't precompute at construction. The cookie key, in contrast, is independent of the peer and is generated up-front in `NewServer` so subsequent `Receive` calls have zero cryptographic randomness needs (besides the welcome long-nonce).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 5: vet / staticcheck**

Run: `go vet ./internal/security/curve/... && staticcheck ./internal/security/curve/...`
Expected: no output. (The `_ = seccommon.CloneMetadata` placeholder is removed in Task 19.)

- [ ] **Step 6: Commit**

```bash
git add internal/security/curve/server.go internal/security/curve/server_test.go
git commit -m "$(cat <<'EOF'
security/curve: ServerState — NewServer + Receive(HELLO) → WELCOME

NewServer generates s'/S' and a per-handshake cookieKey at
construction so handleHello has zero rand requirements beyond the
WELCOME long-nonce. handleHello extracts C' from cleartext, precomputes
handshakeShared = s×C' and afterReady = s'×C', seals the cookie under
cookieKey, and emits WELCOME.

Wrap/Unwrap/Close are wired up here too because the file otherwise
needs the same Mechanism shape as ClientState — keeping the layout
parallel.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 19: `Receive(INITIATE)` happy path → READY → done

**Files:**
- Modify: `internal/security/curve/server.go` — add `handleInitiate` (accept path), drop the `_ = seccommon.CloneMetadata` placeholder.
- Modify: `internal/security/curve/server_test.go` — happy-path tests.

- [ ] **Step 1: Append the failing tests**

```go
func TestServerReceiveInitiateAcceptCompletesHandshake(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	mdC := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
		{Name: []byte("Identity"), Value: []byte("client-1")},
	}
	mdS := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
	}

	s, err := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		LocalMetadata: mdS, Authorizer: acceptAll,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	c, err := NewClient(ClientOptions{
		ServerKey:    serverLongPub,
		OurPublicKey: clientLongPub,
		OurSecretKey: &clientLongSec,
		LocalMetadata: mdC,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	hello, _ := c.Start()
	welcome, _, err := s.Receive(hello)
	if err != nil {
		t.Fatalf("server.Receive(HELLO): %v", err)
	}
	initiate, _, err := c.Receive(*welcome)
	if err != nil {
		t.Fatalf("client.Receive(WELCOME): %v", err)
	}

	ready, done, err := s.Receive(*initiate)
	if err != nil {
		t.Fatalf("server.Receive(INITIATE): %v", err)
	}
	if !done || ready == nil {
		t.Fatalf("server.Receive(INITIATE): out=%+v done=%v, want READY/true", ready, done)
	}
	if !s.Done() {
		t.Fatalf("Done() == false after INITIATE accept")
	}
	if s.PeerPublicKey() != clientLongPub {
		t.Fatalf("PeerPublicKey = %x, want %x", s.PeerPublicKey(), clientLongPub)
	}
	pm := s.PeerMetadata()
	if v, ok := pm.Get("Identity"); !ok || string(v) != "client-1" {
		t.Fatalf("PeerMetadata Identity = %q, want client-1", v)
	}

	// Client Receive(READY) closes the handshake on the client side.
	if _, cdone, err := c.Receive(*ready); err != nil || !cdone {
		t.Fatalf("client.Receive(READY): err=%v done=%v", err, cdone)
	}
	if !c.Done() {
		t.Fatalf("client not done")
	}
	if v, ok := c.PeerMetadata().Get("Socket-Type"); !ok || string(v) != "ROUTER" {
		t.Fatalf("client PeerMetadata Socket-Type = %q, want ROUTER", v)
	}
}

func TestServerPeerMetadataIndependentOfInputBuffer(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	mdC := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
	}

	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: acceptAll,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
		LocalMetadata: mdC,
	})

	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	// Wrap initiate.Data in a fresh buffer we can clobber.
	buf := make([]byte, len(initiate.Data))
	copy(buf, initiate.Data)
	initiateClone := wire.Command{Name: initiate.Name, Data: buf}

	if _, _, err := s.Receive(initiateClone); err != nil {
		t.Fatalf("server.Receive(INITIATE): %v", err)
	}
	for i := range buf {
		buf[i] = 0xFF
	}
	if v, ok := s.PeerMetadata().Get("Socket-Type"); !ok || string(v) != "DEALER" {
		t.Fatalf("PeerMetadata after clobber = %q, want DEALER", v)
	}
}

func TestServerReceiveTamperedInitiate(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: acceptAll,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	initiate.Data[len(initiate.Data)-1] ^= 0x01
	if _, _, err := s.Receive(*initiate); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestServerReceiveInitiateWithTamperedCookie(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: acceptAll,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	// Flip a bit inside the 96-byte cookie at the start of INITIATE.
	initiate.Data[5] ^= 0x01
	_, _, err := s.Receive(*initiate)
	// The cookie's secretbox auth tag fails ⇒ ErrBoxOpen.
	if !errors.Is(err, ErrBoxOpen) && !errors.Is(err, ErrCookieMismatch) {
		t.Fatalf("err = %v, want ErrBoxOpen or ErrCookieMismatch", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -run TestServerReceiveInitiate -run TestServerPeerMetadata -count=1`
Expected: FAIL — server falls through to "(expected INITIATE)".

- [ ] **Step 3: Replace the AWAIT_INITIATE stub in `server.go`**

Replace:

```go
	// AWAIT_INITIATE — fleshed out in Task 19/20.
	s.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected INITIATE)", ErrUnexpectedCommand, cmd.Name)
```

with:

```go
	// AWAIT_INITIATE.
	switch cmd.Name {
	case initiateCommandName:
		return s.handleInitiate(cmd)
	case wire.ErrorCommandName:
		return nil, false, s.failPeerError(cmd)
	}
	s.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected INITIATE)", ErrUnexpectedCommand, cmd.Name)
```

Add the helper:

```go
func (s *ServerState) handleInitiate(cmd wire.Command) (*wire.Command, bool, error) {
	ck, v, peerLongPub, md, perr := parseInitiate(cmd, s.afterReady)
	if perr != nil {
		s.failed = true
		return nil, false, perr
	}
	// Open cookie under cookieKey. The inner (C', s') MUST match the
	// values we recorded in handleHello.
	ckC1, ckSPrimeSec, cErr := openCookie(ck, &s.cookieKey)
	if cErr != nil {
		s.failed = true
		return nil, false, cErr
	}
	if ckC1 != s.peerTransPub {
		s.failed = true
		return nil, false, fmt.Errorf("%w: cookie C' mismatch", ErrCookieMismatch)
	}
	if ckSPrimeSec != s.transSec {
		s.failed = true
		return nil, false, fmt.Errorf("%w: cookie s' mismatch", ErrCookieMismatch)
	}
	// Open vouch under (clientLongPub × ourLongSec) and verify the
	// inner (C' || S) matches our recorded values.
	vC1, vS, vErr := openVouch(v, peerLongPub, s.ourLongSec)
	if vErr != nil {
		s.failed = true
		return nil, false, vErr
	}
	if vC1 != s.peerTransPub {
		s.failed = true
		return nil, false, fmt.Errorf("%w: vouch C'", ErrBoxOpen)
	}
	if vS != s.ourLongPub {
		s.failed = true
		return nil, false, fmt.Errorf("%w: vouch S", ErrBoxOpen)
	}

	// Defensive copy of metadata before passing to Authorizer.
	clonedMd := seccommon.CloneMetadata(md)

	if authErr := s.authorizer(peerLongPub, clonedMd); authErr != nil {
		return s.failAuthRejected(authErr)
	}

	s.peerLongPub = peerLongPub
	s.peer = clonedMd

	ready, rErr := encodeReady(s.local, s.afterReady, s.readyNonce, s.rand)
	if rErr != nil {
		s.failed = true
		return nil, false, fmt.Errorf("curve: encode READY: %w", rErr)
	}
	s.readyNonce++
	s.done = true
	return &ready, true, nil
}

// failAuthRejected (Task 20) — placeholder to keep the helper name
// referenced; full implementation lands next.
func (s *ServerState) failAuthRejected(authErr error) (*wire.Command, bool, error) {
	s.failed = true
	return nil, false, fmt.Errorf("%w: %s", ErrAuthRejected, authErr)
}
```

Delete the line `var _ = seccommon.CloneMetadata` — `seccommon` is now used legitimately.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS — including the round-trip with both client and server transitioning to DONE.

- [ ] **Step 5: Commit**

```bash
git add internal/security/curve/server.go internal/security/curve/server_test.go
git commit -m "$(cat <<'EOF'
security/curve: ServerState.Receive(INITIATE accept) → READY → done

handleInitiate parses INITIATE under afterReady, re-opens the cookie
under cookieKey to recover (C', s') and matches them against the
recorded handshake state (ErrCookieMismatch on tampering), opens the
vouch under (peerLongPub × ourLongSec) and verifies its inner (C' || S),
clones the peer metadata defensively, calls the Authorizer, and on
acceptance seals READY under afterReady. failAuthRejected is currently
a stub that returns ErrAuthRejected without an out command — completed
in Task 20.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 20: `Receive(INITIATE reject)` → ERROR + `ErrAuthRejected`

**Files:**
- Modify: `internal/security/curve/server.go` — flesh out `failAuthRejected`.
- Modify: `internal/security/curve/server_test.go` — auth-reject + sanitization tests.

- [ ] **Step 1: Append the failing tests**

```go
func TestServerReceiveInitiateRejectEmitsErrorAndFails(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	rejecter := func(_ PublicKey, _ wire.Metadata) error { return errors.New("denied") }

	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: rejecter,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	out, done, err := s.Receive(*initiate)
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("err = %v, want ErrAuthRejected", err)
	}
	if done {
		t.Fatalf("done=true on auth reject")
	}
	if out == nil || out.Name != wire.ErrorCommandName {
		t.Fatalf("out = %+v, want ERROR command", out)
	}
	ec, perr := wire.ParseError(*out)
	if perr != nil {
		t.Fatalf("ParseError(out): %v", perr)
	}
	if ec.Reason != "denied" {
		t.Fatalf("reason = %q, want denied", ec.Reason)
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Fatalf("err %q does not include reason", err)
	}

	// Subsequent Receive returns ErrAlreadyFailed.
	if _, _, err := s.Receive(*initiate); !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Receive after reject = %v, want ErrAlreadyFailed", err)
	}

	// Client.Receive(ERROR) returns ErrPeerError with the reason.
	if _, _, err := c.Receive(*out); !errors.Is(err, ErrPeerError) {
		t.Fatalf("client.Receive(ERROR) = %v, want ErrPeerError", err)
	}
}

func TestServerAuthRejectReasonSanitized(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	dirty := "bad creds\n\x00user=alice"
	rejecter := func(_ PublicKey, _ wire.Metadata) error { return errors.New(dirty) }
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: rejecter,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	out, _, _ := s.Receive(*initiate)
	ec, _ := wire.ParseError(*out)
	if strings.ContainsAny(ec.Reason, "\n\x00") {
		t.Fatalf("reason %q has non-VCHAR bytes", ec.Reason)
	}
	if len(ec.Reason) != len(dirty) {
		t.Fatalf("len(reason) = %d, want %d", len(ec.Reason), len(dirty))
	}
}

func TestServerAuthRejectReasonTruncated(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	long := strings.Repeat("a", 300)
	rejecter := func(_ PublicKey, _ wire.Metadata) error { return errors.New(long) }
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec,
		Authorizer: rejecter,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)

	out, _, _ := s.Receive(*initiate)
	ec, _ := wire.ParseError(*out)
	if len(ec.Reason) != 255 {
		t.Fatalf("len(reason) = %d, want 255", len(ec.Reason))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/curve/... -run TestServerReceiveInitiateReject -run TestServerAuthReject -count=1`
Expected: FAIL — `out` is nil because `failAuthRejected` is still the stub.

- [ ] **Step 3: Replace `failAuthRejected` in `server.go`**

```go
func (s *ServerState) failAuthRejected(authErr error) (*wire.Command, bool, error) {
	s.failed = true
	reason := seccommon.SanitizeReason(authErr.Error())
	errCmd, encErr := wire.ErrorCommand{Reason: reason}.Encode()
	if encErr != nil {
		return nil, false, fmt.Errorf("curve: encode ERROR: %w", encErr)
	}
	return &errCmd, false, fmt.Errorf("%w: %s", ErrAuthRejected, reason)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/curve/server.go internal/security/curve/server_test.go
git commit -m "$(cat <<'EOF'
security/curve: ServerState — INITIATE auth-reject → ERROR + ErrAuthRejected

failAuthRejected mirrors the PLAIN auth-reject convention: the
authorizer's err.Error() is run through seccommon.SanitizeReason,
encoded as an ERROR command, and returned alongside ErrAuthRejected.
The caller writes *out and closes the connection.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 21: ServerState — error and lifecycle paths

**Files:**
- Modify: `internal/security/curve/server_test.go` — exhaustive lifecycle and error coverage.

No production-code changes are expected; Tasks 18–20 wired all branches. If a test fails, the corresponding branch in `Receive`/`Wrap`/`Unwrap`/`Close` is missing.

- [ ] **Step 1: Append the tests**

If not already imported in `server_test.go`, add `"github.com/tomi77/zmq4/internal/security"` to the import block (it is needed by the new `TestServerWrapBeforeDoneReturnsErrNotDone` test).

```go
func TestServerReceiveErrorAtHelloStep(t *testing.T) {
	_, sec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1, 2, 3}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	errCmd, _ := wire.ErrorCommand{Reason: "client gives up"}.Encode()
	_, _, err := s.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("err = %v, want ErrPeerError", err)
	}
	if !strings.Contains(err.Error(), "client gives up") {
		t.Fatalf("error %q does not include reason", err)
	}
}

func TestServerReceiveUnexpectedCommandAtHelloStep(t *testing.T) {
	_, sec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1, 2, 3}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	if _, _, err := s.Receive(wire.Command{Name: "PING"}); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestServerReceiveInitiateAtAwaitHelloReturnsUnexpectedCommand(t *testing.T) {
	_, sec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1, 2, 3}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	bogus := wire.Command{Name: initiateCommandName, Data: make([]byte, initiateMinBodyLen)}
	if _, _, err := s.Receive(bogus); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestServerReceiveMalformedHello(t *testing.T) {
	_, sec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	bad := wire.Command{Name: helloCommandName, Data: []byte{0x01}}
	if _, _, err := s.Receive(bad); !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestServerReceiveAfterDone(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec, Authorizer: acceptAll,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)
	if _, _, err := s.Receive(*initiate); err != nil {
		t.Fatalf("server.Receive(INITIATE): %v", err)
	}

	if _, _, err := s.Receive(*initiate); !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("Receive after done = %v, want ErrAlreadyDone", err)
	}
}

func TestServerCloseIdempotentAndRedacts(t *testing.T) {
	_, sec := makePair(t)
	s, err := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.Close()
	s.Close()

	if _, _, err := s.Receive(wire.Command{Name: helloCommandName}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Receive after Close = %v, want ErrClosed", err)
	}
	if _, err := s.Wrap(wire.Frame{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Wrap after Close = %v, want ErrClosed", err)
	}
	if _, err := s.Unwrap(wire.Frame{Kind: wire.FrameCommand, Body: make([]byte, 25)}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Unwrap after Close = %v, want ErrClosed", err)
	}
	// Caller-owned long-term secret untouched.
	if sec == (SecretKey{}) {
		t.Fatalf("long-term secret was zeroed by Close")
	}
}

func TestServerWrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	_, sec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: PublicKey{1}, OurSecretKey: &sec, Authorizer: acceptAll,
	})
	if _, err := s.Wrap(wire.Frame{Kind: wire.FrameMessage}); !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("err = %v, want security.ErrNotDone", err)
	}
}

func TestServerWrapUnwrapRoundTrip(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverLongPub, OurSecretKey: &serverLongSec, Authorizer: acceptAll,
	})
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)
	ready, _, _ := s.Receive(*initiate)
	c.Receive(*ready)

	in := wire.Frame{Kind: wire.FrameMessage, More: true, Body: []byte("ping")}
	wrapped, err := c.Wrap(in)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := s.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got.Kind != wire.FrameMessage || got.More != true || !bytes.Equal(got.Body, []byte("ping")) {
		t.Fatalf("round trip = %+v", got)
	}
	// Reverse direction.
	in2 := wire.Frame{Kind: wire.FrameMessage, More: false, Body: []byte("pong")}
	wrapped2, err := s.Wrap(in2)
	if err != nil {
		t.Fatalf("server Wrap: %v", err)
	}
	got2, err := c.Unwrap(wrapped2)
	if err != nil {
		t.Fatalf("client Unwrap: %v", err)
	}
	if !bytes.Equal(got2.Body, []byte("pong")) || got2.More {
		t.Fatalf("reverse round trip = %+v", got2)
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test -race ./internal/security/curve/... -count=1`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/security/curve/server_test.go
git commit -m "$(cat <<'EOF'
security/curve: ServerState — lifecycle and Wrap/Unwrap full round-trip

Exhaustive coverage of the server-side lifecycle gates (closed/
already-done/already-failed/unexpected-command/malformed-HELLO/
peer-ERROR) and a real client↔server Wrap/Unwrap round trip in both
directions. No production-code changes; Tasks 18–20 wired all
branches.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 8: Mechanism interface conformance

### Task 22: Cross-mechanism conformance test

**Files:**
- Create: `internal/security/interfaces_conformance_test.go` — compile-time assertions for all five concrete types + a parameterized handshake driver that exercises only the `Mechanism`/`ClientMechanism` surface.

> The test lives in `package security_test` (external test package) to avoid an import cycle: it imports `null`, `plain`, `curve`, all of which already import `security`. An external test package sees only the public API of `security` (which is what we want — a real consumer's view).

- [ ] **Step 1: Write `internal/security/interfaces_conformance_test.go`**

```go
package security_test

import (
	"bytes"
	"testing"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/curve"
	"github.com/tomi77/zmq4/internal/security/null"
	"github.com/tomi77/zmq4/internal/security/plain"
	"github.com/tomi77/zmq4/internal/wire"
)

// Compile-time assertions: every concrete type implements the
// interfaces it claims to.
var (
	_ security.Mechanism       = (*null.State)(nil)
	_ security.Mechanism       = (*plain.ClientState)(nil)
	_ security.Mechanism       = (*plain.ServerState)(nil)
	_ security.Mechanism       = (*curve.ClientState)(nil)
	_ security.Mechanism       = (*curve.ServerState)(nil)
	_ security.ClientMechanism = (*null.State)(nil)
	_ security.ClientMechanism = (*plain.ClientState)(nil)
	_ security.ClientMechanism = (*curve.ClientState)(nil)
)

// TestMechanismInterfaceCompilesForAllTypes runs the compile-time
// assertions above; if the file builds, this test trivially passes.
func TestMechanismInterfaceCompilesForAllTypes(t *testing.T) {
	t.Log("compile-time assertions in interfaces_conformance_test.go ensure all five concrete types satisfy security.Mechanism (and ClientMechanism for active sides)")
}

// TestNullConformance drives a NULL handshake through the Mechanism
// interface only.
func TestNullConformance(t *testing.T) {
	a, b := null.New(nil), null.New(nil)
	driveSymmetricHandshake(t, a, b)
	wrapUnwrapRoundTrip(t, a, b)
}

// TestPlainConformance drives a PLAIN handshake through the
// Mechanism/ClientMechanism interfaces only.
func TestPlainConformance(t *testing.T) {
	c, err := plain.NewClient([]byte("u"), []byte("p"), nil)
	if err != nil {
		t.Fatalf("plain.NewClient: %v", err)
	}
	s := plain.NewServer(func(_, _ []byte) error { return nil }, nil)
	driveAsymmetricHandshake(t, c, s)
	// PLAIN's Wrap/Unwrap is pass-through; round trip just checks identity.
	wrapUnwrapRoundTrip(t, c, s)
}

// TestCurveConformance drives a CURVE handshake through the
// Mechanism/ClientMechanism interfaces only.
func TestCurveConformance(t *testing.T) {
	clientPub, clientSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	serverPub, serverSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	c, err := curve.NewClient(curve.ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	if err != nil {
		t.Fatalf("curve.NewClient: %v", err)
	}
	s, err := curve.NewServer(curve.ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ curve.PublicKey, _ wire.Metadata) error { return nil },
	})
	if err != nil {
		t.Fatalf("curve.NewServer: %v", err)
	}
	driveAsymmetricHandshake(t, c, s)
	wrapUnwrapRoundTrip(t, c, s)
}

// driveSymmetricHandshake handles NULL: both peers Start, swap READY.
func driveSymmetricHandshake(t *testing.T, a, b security.ClientMechanism) {
	t.Helper()
	cmdA, err := a.Start()
	if err != nil {
		t.Fatalf("a.Start: %v", err)
	}
	cmdB, err := b.Start()
	if err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	if _, _, err := a.Receive(cmdB); err != nil {
		t.Fatalf("a.Receive: %v", err)
	}
	if _, _, err := b.Receive(cmdA); err != nil {
		t.Fatalf("b.Receive: %v", err)
	}
	if !a.Done() || !b.Done() {
		t.Fatalf("Done() = a:%v b:%v, want both true", a.Done(), b.Done())
	}
}

// driveAsymmetricHandshake handles PLAIN/CURVE: HELLO ↔ WELCOME ↔
// INITIATE ↔ READY.
func driveAsymmetricHandshake(t *testing.T, c security.ClientMechanism, s security.Mechanism) {
	t.Helper()
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	welcome, done, err := s.Receive(hello)
	if err != nil || done || welcome == nil {
		t.Fatalf("server.Receive(HELLO): out=%v done=%v err=%v", welcome, done, err)
	}
	initiate, done, err := c.Receive(*welcome)
	if err != nil || done || initiate == nil {
		t.Fatalf("client.Receive(WELCOME): out=%v done=%v err=%v", initiate, done, err)
	}
	ready, done, err := s.Receive(*initiate)
	if err != nil || !done || ready == nil {
		t.Fatalf("server.Receive(INITIATE): out=%v done=%v err=%v", ready, done, err)
	}
	out, done, err := c.Receive(*ready)
	if err != nil || !done || out != nil {
		t.Fatalf("client.Receive(READY): out=%v done=%v err=%v", out, done, err)
	}
	if !c.Done() || !s.Done() {
		t.Fatalf("Done() = c:%v s:%v, want both true", c.Done(), s.Done())
	}
}

// wrapUnwrapRoundTrip exercises the Wrap/Unwrap surface on both sides
// after a successful handshake.
func wrapUnwrapRoundTrip(t *testing.T, c, s security.Mechanism) {
	t.Helper()
	for _, payload := range [][]byte{{}, []byte("hello"), bytes.Repeat([]byte{0x42}, 1024)} {
		f := wire.Frame{Kind: wire.FrameMessage, More: true, Body: payload}
		wrapped, err := c.Wrap(f)
		if err != nil {
			t.Fatalf("c.Wrap: %v", err)
		}
		got, err := s.Unwrap(wrapped)
		if err != nil {
			t.Fatalf("s.Unwrap: %v", err)
		}
		if got.Kind != wire.FrameMessage || got.More != f.More || !bytes.Equal(got.Body, f.Body) {
			t.Fatalf("client→server: got=%+v want=%+v", got, f)
		}

		f2 := wire.Frame{Kind: wire.FrameMessage, More: false, Body: payload}
		wrapped2, err := s.Wrap(f2)
		if err != nil {
			t.Fatalf("s.Wrap: %v", err)
		}
		got2, err := c.Unwrap(wrapped2)
		if err != nil {
			t.Fatalf("c.Unwrap: %v", err)
		}
		if got2.Kind != wire.FrameMessage || got2.More != f2.More || !bytes.Equal(got2.Body, f2.Body) {
			t.Fatalf("server→client: got=%+v want=%+v", got2, f2)
		}
	}
}

```

> **Why per-mechanism tests instead of a table-driven `factories()` slice:** the CURVE case can't construct a working `(client, server)` pair from independent `mkClient`/`mkServer` factories — the two sides must share the same long-term server keypair. Rather than thread keypairs through the factory pattern, three small per-mechanism tests share the `driveSymmetricHandshake`, `driveAsymmetricHandshake`, and `wrapUnwrapRoundTrip` helpers directly.

- [ ] **Step 2: Run the tests**

Run: `go test -race ./internal/security/... -count=1`
Expected: PASS — including all three conformance tests across NULL, PLAIN, CURVE.

- [ ] **Step 3: vet / staticcheck**

Run: `go vet ./... && staticcheck ./...`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add internal/security/interfaces_conformance_test.go
git commit -m "$(cat <<'EOF'
security: cross-mechanism Mechanism/ClientMechanism conformance tests

Compile-time assertions guard that all five concrete types satisfy
the interfaces. Three runtime tests drive a real handshake plus
Wrap/Unwrap round trip through ONLY the security.Mechanism /
security.ClientMechanism surface — proving the abstractions are
honest.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 9: Property tests, vector tests, benchmarks, alloc budget

### Task 23: Property tests — happy path, auth-reject, tamper, replay

**Files:**
- Create: `internal/security/curve/handshake_property_test.go`

- [ ] **Step 1: Write the property tests**

```go
package curve

import (
	"bytes"
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"testing"
	"testing/quick"

	"github.com/tomi77/zmq4/internal/wire"
)

// randCurveMetadata returns a random Metadata. Names use a small fixed
// vocabulary so parser corner cases stay exercised; values are random
// bytes up to 32 B.
func randCurveMetadata(rng *mrand.Rand) wire.Metadata {
	names := []string{
		"Socket-Type", "Identity", "Resource",
		"X-Foo", "X-Bar", "X-Baz",
	}
	n := rng.Intn(len(names) + 1)
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

func TestCurveHappyPathProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 1000}
	prop := func(seed int64) bool {
		rng := mrand.New(mrand.NewSource(seed))
		clientPub, clientSec, err := GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Logf("client keypair: %v", err)
			return false
		}
		serverPub, serverSec, err := GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Logf("server keypair: %v", err)
			return false
		}
		mdC := randCurveMetadata(rng)
		mdS := randCurveMetadata(rng)

		c, err := NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
			LocalMetadata: mdC,
		})
		if err != nil {
			t.Logf("NewClient: %v", err)
			return false
		}
		s, err := NewServer(ServerOptions{
			OurPublicKey: serverPub, OurSecretKey: &serverSec,
			LocalMetadata: mdS,
			Authorizer:    func(_ PublicKey, _ wire.Metadata) error { return nil },
		})
		if err != nil {
			t.Logf("NewServer: %v", err)
			return false
		}

		hello, _ := c.Start()
		welcome, done, err := s.Receive(hello)
		if err != nil || done {
			t.Logf("server.Receive(HELLO): err=%v done=%v", err, done)
			return false
		}
		initiate, done, err := c.Receive(*welcome)
		if err != nil || done {
			t.Logf("client.Receive(WELCOME): err=%v done=%v", err, done)
			return false
		}
		ready, done, err := s.Receive(*initiate)
		if err != nil || !done {
			t.Logf("server.Receive(INITIATE): err=%v done=%v", err, done)
			return false
		}
		out, done, err := c.Receive(*ready)
		if err != nil || !done || out != nil {
			t.Logf("client.Receive(READY): err=%v done=%v out=%v", err, done, out)
			return false
		}
		if !metadataEqual(c.PeerMetadata(), mdS) {
			t.Logf("client.PeerMetadata mismatch")
			return false
		}
		if !metadataEqual(s.PeerMetadata(), mdC) {
			t.Logf("server.PeerMetadata mismatch")
			return false
		}
		if s.PeerPublicKey() != clientPub {
			t.Logf("server.PeerPublicKey mismatch")
			return false
		}

		// 32 round-trips of random frames in alternating directions.
		for i := 0; i < 32; i++ {
			body := make([]byte, rng.Intn(257))
			rng.Read(body)
			more := rng.Intn(2) == 1
			f := wire.Frame{Kind: wire.FrameMessage, More: more, Body: body}

			if i%2 == 0 {
				wrapped, err := c.Wrap(f)
				if err != nil {
					t.Logf("c.Wrap[%d]: %v", i, err)
					return false
				}
				got, err := s.Unwrap(wrapped)
				if err != nil {
					t.Logf("s.Unwrap[%d]: %v", i, err)
					return false
				}
				if got.More != f.More || !bytes.Equal(got.Body, f.Body) {
					t.Logf("c→s round trip[%d] mismatch", i)
					return false
				}
			} else {
				wrapped, err := s.Wrap(f)
				if err != nil {
					t.Logf("s.Wrap[%d]: %v", i, err)
					return false
				}
				got, err := c.Unwrap(wrapped)
				if err != nil {
					t.Logf("c.Unwrap[%d]: %v", i, err)
					return false
				}
				if got.More != f.More || !bytes.Equal(got.Body, f.Body) {
					t.Logf("s→c round trip[%d] mismatch", i)
					return false
				}
			}
		}
		return true
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCurveAuthRejectProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 1000}
	prop := func(seed int64) bool {
		clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
		serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)
		c, _ := NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		})
		s, _ := NewServer(ServerOptions{
			OurPublicKey: serverPub, OurSecretKey: &serverSec,
			Authorizer: func(_ PublicKey, _ wire.Metadata) error { return errors.New("denied") },
		})
		hello, _ := c.Start()
		welcome, _, _ := s.Receive(hello)
		initiate, _, _ := c.Receive(*welcome)
		out, done, err := s.Receive(*initiate)
		if !errors.Is(err, ErrAuthRejected) || done || out == nil {
			t.Logf("server.Receive(INITIATE): err=%v done=%v out=%v", err, done, out)
			return false
		}
		ec, perr := wire.ParseError(*out)
		if perr != nil || ec.Reason != "denied" {
			t.Logf("ERROR reason = %q (parse err=%v)", ec.Reason, perr)
			return false
		}
		_, _, err = c.Receive(*out)
		if !errors.Is(err, ErrPeerError) {
			t.Logf("client.Receive(ERROR): %v", err)
			return false
		}
		_ = seed
		return true
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCurveTamperRejectionProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 100}
	prop := func(seed int64) bool {
		rng := mrand.New(mrand.NewSource(seed))
		clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
		serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)
		c, _ := NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		})
		s, _ := NewServer(ServerOptions{
			OurPublicKey: serverPub, OurSecretKey: &serverSec,
			Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
		})

		hello, _ := c.Start()
		// Pick which command in the handshake to tamper.
		victim := rng.Intn(4) // 0=HELLO,1=WELCOME,2=INITIATE,3=READY
		flip := func(cmd *wire.Command) {
			if len(cmd.Data) == 0 {
				return
			}
			cmd.Data[rng.Intn(len(cmd.Data))] ^= 1 << uint(rng.Intn(8))
		}
		if victim == 0 {
			flip(&hello)
			_, _, err := s.Receive(hello)
			return err != nil // some flavor of failure
		}
		welcome, _, _ := s.Receive(hello)
		if victim == 1 {
			flip(welcome)
			_, _, err := c.Receive(*welcome)
			return err != nil
		}
		initiate, _, _ := c.Receive(*welcome)
		if victim == 2 {
			flip(initiate)
			_, _, err := s.Receive(*initiate)
			return err != nil
		}
		ready, _, _ := s.Receive(*initiate)
		if victim == 3 {
			flip(ready)
			_, _, err := c.Receive(*ready)
			return err != nil
		}
		return true
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCurveReplayRejection(t *testing.T) {
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)
	ready, _, _ := s.Receive(*initiate)
	c.Receive(*ready)

	wrapped, _ := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: []byte("ok")})
	if _, err := s.Unwrap(wrapped); err != nil {
		t.Fatalf("first Unwrap: %v", err)
	}
	if _, err := s.Unwrap(wrapped); !errors.Is(err, ErrNonceReused) {
		t.Fatalf("replay = %v, want ErrNonceReused", err)
	}
}
```

- [ ] **Step 2: Run the property tests**

Run: `go test ./internal/security/curve/... -run TestCurve.*Property -run TestCurveReplay -count=1`
Expected: PASS, 1000 iterations for happy/auth-reject and 100 for tamper.

- [ ] **Step 3: Commit**

```bash
git add internal/security/curve/handshake_property_test.go
git commit -m "$(cat <<'EOF'
security/curve: property-based handshake + traffic round-trip

Four properties: 1000-iteration happy path with random metadata and
32 message round-trips per iteration; 1000-iteration auth-reject;
100-iteration random-bit-flip tamper detection on each of the four
handshake commands; explicit replay rejection (one-shot test for
ErrNonceReused on duplicate MESSAGE).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 24: Vector tests — deterministic ChaCha8-driven byte vectors

**Files:**
- Create: `internal/security/curve/testdata/curve-hello-empty.bin`
- Create: `internal/security/curve/testdata/curve-welcome.bin`
- Create: `internal/security/curve/testdata/curve-initiate-empty-meta.bin`
- Create: `internal/security/curve/testdata/curve-initiate-with-socket-type.bin`
- Create: `internal/security/curve/testdata/curve-ready-empty-meta.bin`
- Create: `internal/security/curve/testdata/curve-ready-with-identity.bin`
- Create: `internal/security/curve/testdata/curve-message-empty.bin`
- Create: `internal/security/curve/testdata/curve-message-16b.bin`
- Create: `internal/security/curve/testdata/curve-message-more.bin`
- Create: `internal/security/curve/testdata/curve-error.bin`
- Create: `internal/security/curve/testdata/README.md`
- Create: `internal/security/curve/vector_test.go`

> Vectors use `math/rand/v2.NewChaCha8` seeded with a 32-byte sequence pinned in the test file. ChaCha8 is reproducible across Go versions (per the `math/rand/v2` stability guarantee) and has enough state for the multi-keypair workload. Cross-validation against libzmq is deferred to F4 interop.

- [ ] **Step 1: Write `internal/security/curve/testdata/README.md`**

```markdown
# F2c CURVE handshake + traffic vectors

Each .bin file holds the **command body** (command-name + command-data)
of one CURVE wire-format unit. Vectors are reproduced byte-for-byte
under a deterministic ChaCha8 RNG seeded with a fixed 32-byte sequence
declared in `vector_test.go` (variable `vectorSeed`).

| File | Contents |
|------|----------|
| `curve-hello-empty.bin` | HELLO with deterministic c'/C'. |
| `curve-welcome.bin` | WELCOME with deterministic s'/S' and cookie. |
| `curve-initiate-empty-meta.bin` | INITIATE with no metadata. |
| `curve-initiate-with-socket-type.bin` | INITIATE with `Socket-Type=DEALER`. |
| `curve-ready-empty-meta.bin` | READY with no metadata. |
| `curve-ready-with-identity.bin` | READY with `Socket-Type=ROUTER` + 8-byte `Identity`. |
| `curve-message-empty.bin` | MESSAGE wrapping an empty (0-byte) frame body, sendNonce=1, More=false. |
| `curve-message-16b.bin` | MESSAGE wrapping a 16-byte frame, sendNonce=2. |
| `curve-message-more.bin` | MESSAGE wrapping a 4-byte frame, More=true, sendNonce=3. |
| `curve-error.bin` | ERROR with reason `"Authentication failed"`. |

The seed is identical across all vectors so a single deterministic run
produces every fixture. To regenerate, run the vector test with
`-update` (the test file contains an opt-in regenerator gated on a flag).
```

- [ ] **Step 2: Write `internal/security/curve/vector_test.go`**

```go
package curve

import (
	"bytes"
	"flag"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

// vectorSeed is the 32-byte ChaCha8 seed for byte-deterministic
// vectors. NEVER change without regenerating every .bin file.
var vectorSeed = [32]byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

var updateVectors = flag.Bool("update-vectors", false,
	"regenerate testdata/curve-*.bin from the pinned ChaCha8 seed")

// newSeededRNG returns a *math/rand/v2.ChaCha8 — which implements
// io.Reader natively. Per the math/rand/v2 stability guarantee, the
// byte stream produced by ChaCha8.Read(p) is deterministic across Go
// versions for a fixed seed, so vectors stay stable.
func newSeededRNG() *mrand.ChaCha8 {
	return mrand.NewChaCha8(vectorSeed)
}

// buildAllVectors produces the canonical bytes for every vector. The
// returned map is in stable iteration order via the slice above.
func buildAllVectors(t *testing.T) []struct {
	name string
	body []byte
} {
	t.Helper()
	rng := newSeededRNG()

	clientPub, clientSec, err := GenerateKeyPair(rng)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	serverPub, serverSec, err := GenerateKeyPair(rng)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	c, err := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec, Rand: rng,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	s, err := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
		Rand:       rng,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	welcome, _, err := s.Receive(hello)
	if err != nil {
		t.Fatalf("server.Receive(HELLO): %v", err)
	}

	// Drive (c, s) — which has empty LocalMetadata on both sides — fully
	// to DONE. The client's INITIATE here is the empty-meta vector.
	initiateEmpty, _, err := c.Receive(*welcome)
	if err != nil {
		t.Fatalf("client.Receive(WELCOME): %v", err)
	}
	ready, _, err := s.Receive(*initiateEmpty)
	if err != nil {
		t.Fatalf("server.Receive(INITIATE): %v", err)
	}
	if _, _, err := c.Receive(*ready); err != nil {
		t.Fatalf("client.Receive(READY): %v", err)
	}

	// READY-with-identity: the server-side state's local meta is
	// ignored here; build via codec under the same afterReady.
	mdIdentity := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
		{Name: []byte("Identity"), Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
	}
	readyIdentity, err := encodeReady(mdIdentity, s.afterReady, 99, rng)
	if err != nil {
		t.Fatalf("encodeReady (identity): %v", err)
	}

	// INITIATE-with-socket-type: produced by an independent (cInit2,
	// sInit2) pair seeded from the same vectorSeed. The two INITIATE
	// fixtures are therefore independent fixtures (each reproducible
	// from `vectorSeed` alone), not consecutive frames of one stream.
	mdSocketType := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
	}
	cInit2, sInit2 := newSeededCURVEPair(t, mdSocketType, nil)
	hello2, _ := cInit2.Start()
	welcome2, _, _ := sInit2.Receive(hello2)
	initiateSocketType, _, _ := cInit2.Receive(*welcome2)

	// Build MESSAGE vectors from the (c, s) pair already in DONE.
	wrapEmpty, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: nil, More: false})
	if err != nil {
		t.Fatalf("Wrap empty: %v", err)
	}
	wrap16b, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: bytes.Repeat([]byte{0xAB}, 16), More: false})
	if err != nil {
		t.Fatalf("Wrap 16b: %v", err)
	}
	wrapMore, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: []byte{0xDE, 0xAD, 0xBE, 0xEF}, More: true})
	if err != nil {
		t.Fatalf("Wrap more: %v", err)
	}

	errCmd, err := wire.ErrorCommand{Reason: "Authentication failed"}.Encode()
	if err != nil {
		t.Fatalf("encode ERROR: %v", err)
	}

	mustEncCmd := func(cmd wire.Command) []byte {
		body, err := wire.EncodeCommand(cmd)
		if err != nil {
			t.Fatalf("EncodeCommand: %v", err)
		}
		return body
	}

	return []struct {
		name string
		body []byte
	}{
		{"curve-hello-empty.bin", mustEncCmd(hello)},
		{"curve-welcome.bin", mustEncCmd(*welcome)},
		{"curve-initiate-empty-meta.bin", mustEncCmd(*initiateEmpty)},
		{"curve-initiate-with-socket-type.bin", mustEncCmd(*initiateSocketType)},
		{"curve-ready-empty-meta.bin", mustEncCmd(*ready)},
		{"curve-ready-with-identity.bin", mustEncCmd(readyIdentity)},
		{"curve-message-empty.bin", wrapEmpty.Body},
		{"curve-message-16b.bin", wrap16b.Body},
		{"curve-message-more.bin", wrapMore.Body},
		{"curve-error.bin", mustEncCmd(errCmd)},
	}
}

// newSeededCURVEPair drives client+server through the same seeded RNG
// for fixture generation that does not depend on the live (c,s) pair.
func newSeededCURVEPair(t *testing.T, clientMd, serverMd wire.Metadata) (*ClientState, *ServerState) {
	t.Helper()
	rng := newSeededRNG()
	clientPub, clientSec, _ := GenerateKeyPair(rng)
	serverPub, serverSec, _ := GenerateKeyPair(rng)
	c, err := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		LocalMetadata: clientMd, Rand: rng,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	s, err := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		LocalMetadata: serverMd,
		Authorizer:    func(_ PublicKey, _ wire.Metadata) error { return nil },
		Rand:          rng,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return c, s
}

func TestCurveVectors(t *testing.T) {
	vectors := buildAllVectors(t)

	if *updateVectors {
		dir := "testdata"
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		for _, v := range vectors {
			if err := os.WriteFile(filepath.Join(dir, v.name), v.body, 0o644); err != nil {
				t.Fatalf("write %s: %v", v.name, err)
			}
		}
		t.Logf("regenerated %d vector files", len(vectors))
		return
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			path := filepath.Join("testdata", v.name)
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if !bytes.Equal(v.body, want) {
				t.Fatalf("byte mismatch for %s\ngot:  %x\nwant: %x", v.name, v.body, want)
			}
		})
	}
}
```

> **Note on determinism:** `*math/rand/v2.ChaCha8` implements `io.Reader` natively (`Read(p []byte) (int, error)`). The byte stream is part of the `math/rand/v2` stability guarantee, so a fixed `vectorSeed` produces identical bytes across Go versions and platforms — this is what pins the vector files. **Do not** wrap ChaCha8 in a per-byte `Uint32()` shim: that truncates 24 bits per call and changes the on-disk vectors.

- [ ] **Step 3: Generate the vectors**

Run: `go test ./internal/security/curve/ -run TestCurveVectors -update-vectors -count=1`
Expected: writes all ten files into `internal/security/curve/testdata/`. Inspect briefly with `ls -la internal/security/curve/testdata/` — all files should be non-empty, with sizes matching the spec (HELLO 200 B, WELCOME 167 B, INITIATE-empty 251 B, etc.; the encoded command-name overhead adds 7+name-len bytes via L1).

- [ ] **Step 4: Verify the vectors are stable**

Run: `go test ./internal/security/curve/ -run TestCurveVectors -count=1`
Expected: PASS. Re-running without `-update-vectors` confirms byte equality.

- [ ] **Step 5: Commit**

```bash
git add internal/security/curve/testdata internal/security/curve/vector_test.go
git commit -m "$(cat <<'EOF'
security/curve: deterministic CURVE vectors via ChaCha8-seeded RNG

Ten .bin fixtures pinned by a 32-byte ChaCha8 seed declared in
vector_test.go. Each fixture covers one wire format unit (HELLO,
WELCOME, INITIATE empty/with metadata, READY empty/with identity,
MESSAGE empty/16B/more, ERROR). The test re-encodes each vector
under the same seed and asserts byte-for-byte equality. Cross-
validation against libzmq is deferred to F4 interop per
00-meta-overview.md §6.

A -update-vectors flag regenerates the fixtures from the seed.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 25: Benchmarks

**Files:**
- Create: `internal/security/curve/bench_test.go`

- [ ] **Step 1: Write the benchmarks**

```go
package curve

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

// donePair is a small test helper: returns a (client, server) curve
// pair fully through DONE, ready for Wrap/Unwrap.
func donePair(b *testing.B) (*ClientState, *ServerState) {
	b.Helper()
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)
	ready, _, _ := s.Receive(*initiate)
	c.Receive(*ready)
	return c, s
}

func BenchmarkClientHandshake(b *testing.B) {
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)

	// Pre-build server-side outputs once; we re-use them for each
	// client iteration. This benchmark measures the CLIENT's
	// per-handshake cost.
	cBoot, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	sBoot, _ := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
	})
	helloBoot, _ := cBoot.Start()
	welcomeBoot, _, _ := sBoot.Receive(helloBoot)
	initiateBoot, _, _ := cBoot.Receive(*welcomeBoot)
	readyBoot, _, _ := sBoot.Receive(*initiateBoot)

	b.ReportAllocs()
	for b.Loop() {
		c, _ := NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		})
		_, _ = c.Start()
		_, _, _ = c.Receive(*welcomeBoot)
		_, _, _ = c.Receive(*readyBoot)
	}
	_ = initiateBoot // keep boot variables alive
}

func BenchmarkServerHandshake(b *testing.B) {
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)
	cBoot, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	helloBoot, _ := cBoot.Start()

	// Build a representative INITIATE for a fresh server to consume
	// each iteration. We need the server's transient pub for
	// afterReady; rebuild per iteration instead.
	b.ReportAllocs()
	for b.Loop() {
		s, _ := NewServer(ServerOptions{
			OurPublicKey: serverPub, OurSecretKey: &serverSec,
			Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
		})
		welcome, _, _ := s.Receive(helloBoot)
		// Build INITIATE matching this server's per-handshake cookie+s'.
		initiate, _, _ := cBoot.Receive(*welcome)
		_, _, _ = s.Receive(*initiate)
		// Reset cBoot: it has now advanced past WELCOME. Restart it.
		cBoot, _ = NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		})
		helloBoot, _ = cBoot.Start()
	}
}

func BenchmarkWrap(b *testing.B) {
	for _, sz := range []int{64, 1024, 65536, 1 << 20} {
		b.Run(humanSize(sz), func(b *testing.B) {
			c, _ := donePair(b)
			payload := bytes.Repeat([]byte{0x42}, sz)
			b.SetBytes(int64(sz))
			b.ReportAllocs()
			for b.Loop() {
				_, _ = c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: payload})
			}
		})
	}
}

func BenchmarkUnwrap(b *testing.B) {
	for _, sz := range []int{64, 1024, 65536, 1 << 20} {
		b.Run(humanSize(sz), func(b *testing.B) {
			c, s := donePair(b)
			payload := bytes.Repeat([]byte{0x42}, sz)
			// Pre-seed s with one wrapped frame per iteration; the
			// receiver must accept monotonically-increasing nonces, so
			// we batch produce N frames then iterate.
			frame := wire.Frame{Kind: wire.FrameMessage, Body: payload}
			wraps := make([]wire.Frame, 1024)
			for i := range wraps {
				w, err := c.Wrap(frame)
				if err != nil {
					b.Fatalf("Wrap[%d]: %v", i, err)
				}
				wraps[i] = w
			}
			b.SetBytes(int64(sz))
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if _, err := s.Unwrap(wraps[i%len(wraps)]); err != nil {
					b.Fatalf("Unwrap: %v", err)
				}
				i++
				// Once we exhaust wraps[], rebuild — Unwrap rejects
				// replays.
				if i%len(wraps) == 0 {
					c, s = donePair(b)
					for j := range wraps {
						w, _ := c.Wrap(frame)
						wraps[j] = w
					}
				}
			}
		})
	}
}

func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return "1MiB"
	case n >= 1<<16:
		return "64KiB"
	case n >= 1<<10:
		return "1KiB"
	default:
		return "64B"
	}
}
```

> **Why `b.Loop()`:** project convention per `MEMORY.md` (modernize sweep) — `b.Loop()` is the modern replacement for the `for i := 0; i < b.N; i++` idiom. Each `b.Run` subtest gets its own `b.Loop()`.

- [ ] **Step 2: Run the benchmarks once for sanity**

Run: `go test -bench BenchmarkClientHandshake -bench BenchmarkServerHandshake -bench BenchmarkWrap -bench BenchmarkUnwrap -benchmem -run='^$' ./internal/security/curve/...`
Expected: numbers print; alloc counts approximately match spec §5.6 (Wrap=2, Unwrap=1, handshakes ~3-5 each).

If alloc counts diverge significantly (more than 1.5×), inspect the implementation — Task 26 will pin them, and large divergences indicate a missed-optimization or accidental allocation in the codec.

- [ ] **Step 3: Commit**

```bash
git add internal/security/curve/bench_test.go
git commit -m "$(cat <<'EOF'
security/curve: handshake + Wrap/Unwrap benchmarks

ClientHandshake benches the client-only path with pre-canned server
outputs; ServerHandshake benches the server-only path. Wrap and
Unwrap have 64B/1KiB/64KiB/1MiB sub-benches via b.SetBytes for
throughput reporting. Allocations are pinned in alloc_budget_test.go
(Task 26).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 26: Allocation budget pin

**Files:**
- Create: `internal/security/curve/alloc_budget_test.go`

- [ ] **Step 1: Write the alloc-budget pins**

```go
package curve

import (
	"crypto/rand"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestClientHandshakeAllocBudget(t *testing.T) {
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)

	// Pre-canned server outputs (driven once, reused).
	cBoot, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	sBoot, _ := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
	})
	helloBoot, _ := cBoot.Start()
	welcomeBoot, _, _ := sBoot.Receive(helloBoot)
	initiateBoot, _, _ := cBoot.Receive(*welcomeBoot)
	readyBoot, _, _ := sBoot.Receive(*initiateBoot)

	allocs := testing.AllocsPerRun(50, func() {
		c, _ := NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		})
		_, _ = c.Start()
		_, _, _ = c.Receive(*welcomeBoot)
		_, _, _ = c.Receive(*readyBoot)
	})
	// Spec §5.6 expectations:
	//   Start:           ~3 (transient keypair + handshakeShared + vouchShared)
	//   Receive(WELCOME): ~3 (afterReady + INITIATE ciphertext + encoded body)
	//   Receive(READY):   ~1-2 (box.Open + metadata-clone for empty md = 0)
	//   ClientState struct: 1
	// Total expected: 8-9. Initial budget set to 10 (slack +1-2) so
	// regressions fail loudly. Step 3 below tunes downward to
	// `empirical+1` once the build is reproducible.
	const budget = 10
	if allocs > budget {
		t.Fatalf("client handshake allocs/op = %.0f, budget = %d", allocs, budget)
	}
}

func TestServerHandshakeAllocBudget(t *testing.T) {
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)

	cBoot, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	helloBoot, _ := cBoot.Start()

	allocs := testing.AllocsPerRun(50, func() {
		s, _ := NewServer(ServerOptions{
			OurPublicKey: serverPub, OurSecretKey: &serverSec,
			Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
		})
		welcome, _, _ := s.Receive(helloBoot)
		// Re-derive INITIATE for this fresh server (cBoot moved on).
		c2, _ := NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		})
		_, _ = c2.Start()
		initiate, _, _ := c2.Receive(*welcome)
		_, _, _ = s.Receive(*initiate)
	})
	// Server-side: NewServer (~3: transPub keypair + cookieKey + struct),
	//              handleHello (~3),
	//              handleInitiate (~3).
	// In-loop client work re-derives a fresh INITIATE per iteration
	// (~5-6 allocs). Budget therefore covers both sides — this is a
	// HARNESS-INCLUSIVE budget, not a pure server-side count. A future
	// refactor should pre-can the INITIATE outside AllocsPerRun and
	// inject it; until then, 14 is the realistic ceiling.
	const budget = 14
	if allocs > budget {
		t.Fatalf("server handshake allocs/op = %.0f, budget = %d (harness-inclusive)", allocs, budget)
	}
}

func TestWrapAllocBudget(t *testing.T) {
	c, _ := donePairForTest(t)
	allocs := testing.AllocsPerRun(100, func() {
		_, _ = c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: []byte("payload")})
	})
	// Spec §5.6: Wrap = 2 (one for Command.Data, one for Frame.Body).
	const budget = 3
	if allocs > budget {
		t.Fatalf("Wrap allocs/op = %.0f, budget = %d", allocs, budget)
	}
}

func TestUnwrapAllocBudget(t *testing.T) {
	c, s := donePairForTest(t)

	// Pre-build N wrapped frames so each Unwrap iteration gets a
	// fresh nonce (Unwrap rejects replays).
	const n = 200
	wraps := make([]wire.Frame, n)
	for i := range wraps {
		w, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: []byte("payload")})
		if err != nil {
			t.Fatalf("Wrap[%d]: %v", i, err)
		}
		wraps[i] = w
	}

	idx := 0
	allocs := testing.AllocsPerRun(50, func() {
		_, _ = s.Unwrap(wraps[idx])
		idx++
	})
	// Spec §5.6: Unwrap = 1 (one slice for the decrypted payload).
	const budget = 2
	if allocs > budget {
		t.Fatalf("Unwrap allocs/op = %.0f, budget = %d", allocs, budget)
	}
}

// donePairForTest mirrors donePair but takes *testing.T (alloc-budget
// tests, not benches).
func donePairForTest(t *testing.T) (*ClientState, *ServerState) {
	t.Helper()
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)
	ready, _, _ := s.Receive(*initiate)
	c.Receive(*ready)
	return c, s
}
```

- [ ] **Step 2: Run the alloc-budget tests**

Run: `go test ./internal/security/curve/... -run TestWrapAllocBudget -run TestUnwrapAllocBudget -run TestClientHandshakeAllocBudget -run TestServerHandshakeAllocBudget -count=10`
Expected: PASS reproducibly across 10 iterations.

If a test fails reproducibly, **investigate** (do not just bump the budget):
1. Run the corresponding benchmark with `-benchmem` and `-memprofile=mem.out`.
2. Inspect the profile with `go tool pprof -alloc_objects mem.out`.
3. Identify the unexpected allocation site and either fix it or, if it is structural (e.g. NaCl box.OpenAfterPrecomputation gained an internal allocation in a newer x/crypto release), bump the budget by **exactly** the new floor — do not pad.

- [ ] **Step 3: Tune budgets**

If the empirical alloc count is below the budget by >2, lower the budget to `empirical + 1` so a future regression is caught. Re-run `-count=10` to confirm reproducibility.

- [ ] **Step 4: Commit**

```bash
git add internal/security/curve/alloc_budget_test.go
git commit -m "$(cat <<'EOF'
security/curve: alloc-budget pins for Wrap/Unwrap and both handshakes

testing.AllocsPerRun pins per-operation allocation counts so future
optimizations (e.g. sync.Pool for ciphertext buffers) lower the
threshold in the same commit, and accidental regressions fail the
test suite.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Chunk 10: Done-criteria sweep + spec status flip + tag

### Task 27: Vet, staticcheck, modernize, race, status flips, doc updates

**Files:**
- Modify: `docs/specs/02c-security-curve.md` — flip status, tick Done criteria.
- Modify: `docs/specs/00-meta-overview.md` — update F2c row, add F2a/F2b amendment note, add `nacl/secretbox` to the §7 dependency list, list `phase-2c-curve-complete` once tagged.

- [ ] **Step 1: `go vet`**

Run: `go vet ./...`
Expected: no output.

- [ ] **Step 2: `staticcheck`**

Run: `staticcheck ./...`
Expected: no output.

If staticcheck flags any issue, fix it before continuing. Common flags after a phase like this: unused parameters in placeholder branches; redundant `_ = expr` lines that lasted past the chunk that introduced them.

- [ ] **Step 3: `modernize -fix ./...`**

Run: `modernize -fix ./...`
Expected: no diff.

If there is a diff, stage it and either fold into the closest related task's commit (only if it is local to one file) or create a follow-up commit:

```bash
git add -A
git commit -m "security/curve: modernize sweep"
```

(Project memory mandates this sweep before tagging the phase. See `MEMORY.md` and the analogous `security/plain: modernize sweep` commit.)

- [ ] **Step 4: race-mode tests**

Run: `go test -race -count=1 ./...`
Expected: PASS, no race reports.

- [ ] **Step 5: Update `docs/specs/02c-security-curve.md`**

Edit the spec header:
- Change `> **Status:** draft, awaiting implementation.` to `> **Status:** implemented, frozen for F4+.`.

Tick each `- [ ]` checkbox in §8.7 Done criteria after verifying the corresponding evidence:
- All unit tests pass — `go test ./internal/security/curve/...` green
- Mechanism / ClientMechanism conformance tests pass — `go test ./internal/security/...`
- Property tests — `TestCurve.*Property` pass at 1000 iterations
- Vector tests — `TestCurveVectors` byte-equal under pinned seed
- `go vet` / `staticcheck` / `modernize` clean
- `go test -race ./internal/security/curve/...` clean
- `go test -race ./internal/security/...` clean (root + curve)
- Allocs/op pinned for client+server handshakes, Wrap, Unwrap
- Phase tagged (after Step 8 below)
- `00-meta-overview.md` §4 + §7 updated (Step 6 below)
- F2a/F2b amendment note added (Step 6)

- [ ] **Step 6: Update `docs/specs/00-meta-overview.md`**

Edit:
- F2c row in §4: change "Spec drafted; implementation pending." (or whatever the current draft text is) to `Complete — tagged \`phase-2c-curve-complete\`.`
- §4: add a subsection (or extend the existing F1-amendments block) titled **"F2a/F2b amendments — Wrap/Unwrap added by F2c"** noting that `null.State`, `plain.ClientState`, and `plain.ServerState` each gained pass-through `Wrap` and `Unwrap` methods returning `security.ErrNotDone` before `Done()`. Both `phase-2a-null-complete` and `phase-2b-plain-complete` tags remain valid (the change is additive on a frozen surface).
- §7: confirm the dependency list mentions BOTH `golang.org/x/crypto/nacl/box` AND `golang.org/x/crypto/nacl/secretbox` as actually used by F2c.
- Top status line / tag list: add `phase-2c-curve-complete`.

- [ ] **Step 7: Final commits before tagging**

```bash
git add docs/specs/02c-security-curve.md docs/specs/00-meta-overview.md
git commit -m "$(cat <<'EOF'
security/curve: mark Phase 2c (CURVE handshake + traffic) complete

Spec status flipped to "implemented, frozen for F4+". Done criteria
ticked. Meta-overview updated: F2c row → Complete; F2a/F2b amendment
note added (Wrap/Unwrap pass-through added without re-tagging earlier
phases); §7 dependency list confirms both nacl/box and nacl/secretbox.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 28: Tag the phase

- [ ] **Step 1: Confirm clean tree**

Run: `git status`
Expected: `nothing to commit, working tree clean`.

- [ ] **Step 2: Tag**

Run: `git tag phase-2c-curve-complete`
Expected: tag created on `HEAD`.

(Do **not** push the tag automatically; the user/orchestrator decides when to publish.)

- [ ] **Step 3: Optional sanity — list tags**

Run: `git tag --list 'phase-*' --sort=v:refname`
Expected output includes `phase-2a-null-complete`, `phase-2b-plain-complete`, `phase-2c-curve-complete`.

---

## Done

If every checkbox above is ticked, F2c is complete. F4 (connection layer) can now consume `security.ClientMechanism` / `security.Mechanism` against any of NULL, PLAIN, or CURVE through a single uniform interface.



