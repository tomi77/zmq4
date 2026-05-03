# F2b PLAIN Security Implementation Plan

> **For Claude:** REQUIRED: Use superpowers:subagent-driven-development to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking. Each task is one commit.

**Goal:** Implement `internal/security/plain` per `docs/specs/02b-security-plain.md`: a pure, I/O-free pair of state machines (`ClientState`, `ServerState`) for the ZMTP 3.1 PLAIN handshake.

**Architecture:** L2 layer above `internal/wire` (F1). Two concrete types — asymmetric, no shared `Mechanism` interface yet. Server-side authentication is delegated to a caller-supplied `Authenticator` callback (F6 will replace with ZAP). HELLO/WELCOME/INITIATE bodies are encoded/decoded inside this package; INITIATE reuses L1's metadata codec via a small additive export.

**Tech Stack:** Pure Go 1.26, stdlib only, depends on `github.com/tomi77/zmq4/internal/wire`. No I/O, no goroutines, no time. Allocations: per-handshake limited to a defensive copy of peer metadata (one slice + one Name/Value buffer per property).

**Decisions baked into the plan:**
- Two types `ClientState` and `ServerState` instead of one `State` with a `Role` enum. Each in its own file.
- HELLO/WELCOME bodies are PLAIN-private — codecs live in `internal/security/plain/codec.go`. INITIATE body = metadata, encoded via the new `wire.EncodeMetadata` / `wire.ParseMetadata` exports.
- `Authenticator` is `func(username, password []byte) error`, not an interface (single callback shape, premature to abstract).
- Server has no `Start` — purely reactive.
- On auth-reject, server's `Receive(HELLO)` returns `(out=ERROR_cmd, err=ErrAuthRejected)`. Caller contract: send `out` then close.
- `NewServer(nil, ...)` panics — programming error, caught at construction.
- Username/password >255 bytes → `ErrCredentialsTooLong` from `NewClient`.
- Reasons inside ERROR commands are sanitized: non-VCHAR bytes replaced with `'?'`, then truncated to 255 bytes.
- `null.copyMetadata` is promoted to `internal/security/metaclone.Clone` — shared by `null` and `plain` (F2c will reuse).
- F1 receives ONE additive change: `parseMetadata` / `encodeMetadata` promoted to public `wire.ParseMetadata` / `wire.EncodeMetadata`. Existing `ReadyCommand` keeps working unchanged.

**Workflow note (project memory):** after each phase-end (here: end of Chunk 6), run `modernize -fix ./...` — see `MEMORY.md`.

---

## Chunk 1: L1 prerequisite — promote metadata helpers

### Task 1: Export `wire.ParseMetadata` / `wire.EncodeMetadata`

**Files:**
- Modify: `internal/wire/command_ready.go` — rename `parseMetadata` → `ParseMetadata`, `encodeMetadata` → `EncodeMetadata`. Update both call sites in `ParseReady` and `(ReadyCommand).Encode`.
- Create: `internal/wire/metadata_test.go` — exercise the new public API.

- [ ] **Step 1: Write the failing test in `internal/wire/metadata_test.go`**

```go
package wire

import (
	"bytes"
	"testing"
)

func TestEncodeMetadataRoundTrip(t *testing.T) {
	md := Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
		{Name: []byte("Identity"), Value: []byte{0x01, 0x02, 0x03}},
	}
	raw := EncodeMetadata(md)
	got, err := ParseMetadata(raw)
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if len(got) != len(md) {
		t.Fatalf("len = %d, want %d", len(got), len(md))
	}
	for i := range md {
		if !bytes.Equal(got[i].Name, md[i].Name) ||
			!bytes.Equal(got[i].Value, md[i].Value) {
			t.Fatalf("[%d] = %+v, want %+v", i, got[i], md[i])
		}
	}
}

func TestEncodeMetadataEmpty(t *testing.T) {
	raw := EncodeMetadata(nil)
	if len(raw) != 0 {
		t.Fatalf("EncodeMetadata(nil) = %x, want empty", raw)
	}
	got, err := ParseMetadata(raw)
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ParseMetadata(empty) = %+v, want empty", got)
	}
}

func TestParseMetadataRejectsZeroLengthName(t *testing.T) {
	// One-byte input: nameLen=0 → invalid per RFC 37 §2.4 (name must be 1..255).
	_, err := ParseMetadata([]byte{0x00})
	if err == nil {
		t.Fatalf("ParseMetadata(zero name): err=nil, want non-nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/wire/... -run TestEncodeMetadata -count=1`
Expected: FAIL (`undefined: EncodeMetadata`, `undefined: ParseMetadata`).

- [ ] **Step 3: Rename helpers in `internal/wire/command_ready.go`**

Rename the unexported helpers to their exported names:
- `func parseMetadata(data []byte) (Metadata, error)` → `func ParseMetadata(data []byte) (Metadata, error)`
- `func encodeMetadata(md Metadata) []byte` → `func EncodeMetadata(md Metadata) []byte`

Update the two call sites in the same file:
- `ParseReady` calls `parseMetadata(cmd.Data)` → `ParseMetadata(cmd.Data)`.
- `(ReadyCommand).Encode` calls `encodeMetadata(rc.Metadata)` → `EncodeMetadata(rc.Metadata)`.

Add brief godoc above each newly-exported function. Example:

```go
// ParseMetadata decodes a metadata blob (sequence of *property as defined
// in RFC 37 §2.4) into a Metadata value. The returned slice aliases the
// input buffer; copy if you need an independent lifetime.
//
// Used by ParseReady (READY) and by internal/security/plain (INITIATE).
func ParseMetadata(data []byte) (Metadata, error) { /* unchanged body */ }

// EncodeMetadata is the inverse of ParseMetadata.
//
// Used by (ReadyCommand).Encode and by internal/security/plain.
func EncodeMetadata(md Metadata) []byte { /* unchanged body */ }
```

- [ ] **Step 4: Run all wire tests to verify nothing regressed**

Run: `go test -race ./internal/wire/... -count=1`
Expected: PASS — `ReadyCommand` round-trips still work, the three new tests now pass.

- [ ] **Step 5: Run vet / staticcheck**

Run: `go vet ./internal/wire/... && staticcheck ./internal/wire/...`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add internal/wire/command_ready.go internal/wire/metadata_test.go
git commit -m "wire: export ParseMetadata/EncodeMetadata for F2b INITIATE"
```

Commit body should explain *why*: PLAIN's INITIATE body has the same metadata format as READY; we reuse the codec instead of duplicating.

---

## Chunk 2: Shared peer-metadata clone helper

### Task 2: Promote `copyMetadata` to `internal/security/metaclone`

**Rationale:** F2a's `internal/security/null/state.go:copyMetadata` is a pure helper. Both `plain` (F2b) and `curve` (F2c) need the same defensive-copy semantics. Extract once, before adding the second caller.

**Files:**
- Create: `internal/security/metaclone/doc.go`
- Create: `internal/security/metaclone/clone.go`
- Create: `internal/security/metaclone/clone_test.go`
- Modify: `internal/security/null/state.go` — replace `copyMetadata` call with `metaclone.Clone`; delete the local helper.

- [ ] **Step 1: Write failing test for `metaclone.Clone`**

Create `internal/security/metaclone/clone_test.go`:

```go
package metaclone

import (
	"bytes"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestCloneEmpty(t *testing.T) {
	if got := Clone(nil); got != nil {
		t.Fatalf("Clone(nil) = %+v, want nil", got)
	}
	if got := Clone(wire.Metadata{}); got != nil {
		t.Fatalf("Clone(empty) = %+v, want nil", got)
	}
}

func TestCloneIndependentBuffers(t *testing.T) {
	name := []byte("Socket-Type")
	value := []byte("REQ")
	src := wire.Metadata{
		{Name: name, Value: value},
	}
	dst := Clone(src)

	// Mutate the source buffers.
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

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/security/metaclone/... -count=1`
Expected: FAIL (package does not exist).

- [ ] **Step 3: Write `internal/security/metaclone/doc.go`**

```go
// Package metaclone provides a defensive deep-copy helper for
// wire.Metadata, shared by the L2 security mechanisms.
//
// The mechanisms (null, plain, curve) parse peer metadata out of frame
// buffers that the connection layer (F4) is free to reuse. PeerMetadata
// must therefore alias an independent buffer, decoupled from the input.
// Clone provides exactly that — a fresh slice, fresh Name/Value backing
// arrays, no shared bytes with the source.
package metaclone
```

- [ ] **Step 4: Write `internal/security/metaclone/clone.go`**

```go
package metaclone

import "github.com/tomi77/zmq4/internal/wire"

// Clone returns a deep copy of src: a fresh Metadata slice plus fresh
// Name/Value backing arrays for each property. The result aliases none
// of src's backing storage. Empty/nil input returns nil.
func Clone(src wire.Metadata) wire.Metadata {
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

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/security/metaclone/... -count=1`
Expected: PASS.

- [ ] **Step 6: Replace `null.copyMetadata` usage**

In `internal/security/null/state.go`:
- Add import: `"github.com/tomi77/zmq4/internal/security/metaclone"`.
- In `Receive`, change `s.peer = copyMetadata(rc.Metadata)` to `s.peer = metaclone.Clone(rc.Metadata)`.
- Delete the local `copyMetadata` function (and its leading comment) at the bottom of the file.

- [ ] **Step 7: Run null tests including race detector**

Run: `go test -race ./internal/security/null/... -count=1`
Expected: PASS — including `TestPeerMetadataIndependentOfInputBuffer`, which is the contract pin for this refactor.

- [ ] **Step 8: vet / staticcheck**

Run: `go vet ./... && staticcheck ./...`
Expected: no output.

- [ ] **Step 9: Commit**

```bash
git add internal/security/metaclone internal/security/null/state.go
git commit -m "security: extract metaclone.Clone shared by null, plain, curve"
```

---

## Chunk 3: PLAIN package skeleton + body codec

### Task 3: Package skeleton — `doc.go` and `errors.go`

**Files:**
- Create: `internal/security/plain/doc.go`
- Create: `internal/security/plain/errors.go`

- [ ] **Step 1: Write `internal/security/plain/doc.go`**

```go
// Package plain implements the ZMTP 3.1 PLAIN security handshake.
//
// PLAIN authenticates a peer with a clear-text username/password pair.
// It provides no confidentiality and is appropriate only over already-
// secured transports (TLS-tunnelled TCP, trusted IPC, authenticated VPN)
// or in development.
//
// The handshake is asymmetric. ClientState drives the client side
// (HELLO → WELCOME → INITIATE → READY); ServerState drives the server
// side (the same exchange, in reverse). The two state machines are
// independent — neither is an alias for the other and there is (yet)
// no shared Mechanism interface (deferred to F2c).
//
// Server-side authentication is delegated to a caller-supplied
// Authenticator callback. F6 will provide a ZAP-backed authenticator
// that satisfies the same callback shape.
//
// This package is pure: it does no I/O, allocates no goroutines, and
// reads no clocks. It consumes and produces wire.Command values on
// behalf of the caller.
//
// See docs/specs/02b-security-plain.md for the full specification.
package plain
```

- [ ] **Step 2: Write `internal/security/plain/errors.go`**

```go
package plain

import "errors"

var (
	// ErrCredentialsTooLong is returned by NewClient when username or
	// password exceeds 255 bytes (RFC 37 §3.2 ABNF limit).
	ErrCredentialsTooLong = errors.New("plain: credentials too long")

	// ErrAlreadyStarted is returned by ClientState.Start on second call.
	ErrAlreadyStarted = errors.New("plain: handshake already started")

	// ErrNotStarted is returned by ClientState.Receive before Start.
	ErrNotStarted = errors.New("plain: handshake not started")

	// ErrAlreadyDone is returned when any method is called after the
	// handshake completed successfully.
	ErrAlreadyDone = errors.New("plain: handshake already complete")

	// ErrAlreadyFailed is returned when any method is called after a
	// previous error has put the state into the failed state.
	ErrAlreadyFailed = errors.New("plain: handshake already failed")

	// ErrUnexpectedCommand is returned when the peer sends a command
	// whose name is not the one expected in the current state (and is
	// not ERROR).
	ErrUnexpectedCommand = errors.New("plain: unexpected command")

	// ErrPeerError is returned when the peer sends an ERROR command.
	// The wrapped error includes the peer's reason string.
	ErrPeerError = errors.New("plain: peer sent ERROR")

	// ErrAuthRejected is returned by ServerState.Receive when the
	// Authenticator callback returned a non-nil error for HELLO.
	// Returned alongside a non-nil out *wire.Command containing the
	// ERROR command the caller MUST send before closing the connection.
	ErrAuthRejected = errors.New("plain: authenticator rejected credentials")

	// ErrMalformedHello is returned when HELLO body fails to parse as
	// "username password" per RFC 37 §3.2.
	ErrMalformedHello = errors.New("plain: malformed HELLO")

	// ErrMalformedWelcome is returned when WELCOME has a non-empty body.
	ErrMalformedWelcome = errors.New("plain: malformed WELCOME")

	// ErrMalformedInitiate is returned when INITIATE body fails
	// wire.ParseMetadata.
	ErrMalformedInitiate = errors.New("plain: malformed INITIATE")

	// ErrMalformedReady is returned when READY body fails
	// wire.ParseMetadata.
	ErrMalformedReady = errors.New("plain: malformed READY")
)
```

- [ ] **Step 3: Verify package compiles**

Run: `go build ./internal/security/plain/...`
Expected: success, no output.

- [ ] **Step 4: Commit**

```bash
git add internal/security/plain/doc.go internal/security/plain/errors.go
git commit -m "security/plain: package skeleton and sentinel errors"
```

---

### Task 4: HELLO / WELCOME body codec + sanitizeReason

**Files:**
- Create: `internal/security/plain/codec.go`
- Create: `internal/security/plain/codec_test.go`

- [ ] **Step 1: Write the failing tests in `codec_test.go`**

```go
package plain

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestEncodeHelloRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name     string
		username []byte
		password []byte
	}{
		{"empty", []byte{}, []byte{}},
		{"creds", []byte("admin"), []byte("secret")},
		{"max-len", bytes.Repeat([]byte("u"), 255), bytes.Repeat([]byte("p"), 255)},
		{"binary-password", []byte("user"), []byte{0x00, 0x01, 0xFF, 0x7F}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := encodeHello(helloBody{Username: tc.username, Password: tc.password})
			if err != nil {
				t.Fatalf("encodeHello: %v", err)
			}
			if cmd.Name != helloCommandName {
				t.Fatalf("cmd.Name = %q, want %q", cmd.Name, helloCommandName)
			}
			got, err := parseHello(cmd)
			if err != nil {
				t.Fatalf("parseHello: %v", err)
			}
			if !bytes.Equal(got.Username, tc.username) {
				t.Fatalf("Username = %x, want %x", got.Username, tc.username)
			}
			if !bytes.Equal(got.Password, tc.password) {
				t.Fatalf("Password = %x, want %x", got.Password, tc.password)
			}
		})
	}
}

func TestParseHelloRejectsTruncatedUsername(t *testing.T) {
	// usernameLen=5 but only 2 bytes follow.
	bad := wire.Command{Name: helloCommandName, Data: []byte{0x05, 'a', 'b'}}
	if _, err := parseHello(bad); err == nil {
		t.Fatalf("parseHello(truncated username): err=nil, want non-nil")
	}
}

func TestParseHelloRejectsTruncatedPassword(t *testing.T) {
	// usernameLen=2, "ab", passwordLen=5, but only 1 byte follows.
	bad := wire.Command{Name: helloCommandName, Data: []byte{0x02, 'a', 'b', 0x05, 'x'}}
	if _, err := parseHello(bad); err == nil {
		t.Fatalf("parseHello(truncated password): err=nil, want non-nil")
	}
}

func TestParseHelloRejectsTrailingBytes(t *testing.T) {
	// Two zero-length fields (legal) followed by an extra byte.
	bad := wire.Command{Name: helloCommandName, Data: []byte{0x00, 0x00, 0xAA}}
	if _, err := parseHello(bad); err == nil {
		t.Fatalf("parseHello(trailing): err=nil, want non-nil")
	}
}

func TestParseHelloRejectsWrongName(t *testing.T) {
	cmd := wire.Command{Name: "READY", Data: []byte{0x00, 0x00}}
	if _, err := parseHello(cmd); err == nil {
		t.Fatalf("parseHello(name=READY): err=nil, want non-nil")
	}
}

func TestEncodeWelcomeIsEmpty(t *testing.T) {
	cmd := encodeWelcome()
	if cmd.Name != welcomeCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, welcomeCommandName)
	}
	if len(cmd.Data) != 0 {
		t.Fatalf("cmd.Data = %x, want empty", cmd.Data)
	}
	if err := parseWelcome(cmd); err != nil {
		t.Fatalf("parseWelcome(empty): %v", err)
	}
}

func TestParseWelcomeRejectsNonEmptyBody(t *testing.T) {
	cmd := wire.Command{Name: welcomeCommandName, Data: []byte{0xAA}}
	if err := parseWelcome(cmd); err == nil {
		t.Fatalf("parseWelcome(non-empty): err=nil, want non-nil")
	}
}

func TestParseWelcomeRejectsWrongName(t *testing.T) {
	cmd := wire.Command{Name: "READY"}
	if err := parseWelcome(cmd); err == nil {
		t.Fatalf("parseWelcome(name=READY): err=nil, want non-nil")
	}
}

func TestSanitizeReasonReplacesNonVCHAR(t *testing.T) {
	// VCHAR = 0x21..0x7E. Inputs include space (0x20), tab, newline,
	// nul, DEL, and a high-bit byte — all non-VCHAR.
	in := "ok\nhuh\x00\tend\x7F\xFF "
	out := sanitizeReason(in)
	if strings.ContainsAny(out, "\n\t\x00\x7F\xFF ") {
		t.Fatalf("sanitizeReason left non-VCHAR bytes in %q", out)
	}
	if len(out) != len(in) {
		t.Fatalf("sanitizeReason length = %d, want %d", len(out), len(in))
	}
}

func TestSanitizeReasonTruncatesTo255(t *testing.T) {
	in := strings.Repeat("a", 300)
	out := sanitizeReason(in)
	if len(out) != 255 {
		t.Fatalf("len = %d, want 255", len(out))
	}
}

func TestSanitizeReasonEmpty(t *testing.T) {
	if out := sanitizeReason(""); out != "" {
		t.Fatalf("sanitizeReason(\"\") = %q, want \"\"", out)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/plain/... -count=1`
Expected: FAIL (`undefined: encodeHello`, `undefined: parseHello`, etc.).

- [ ] **Step 3: Write `internal/security/plain/codec.go`**

```go
package plain

import (
	"fmt"

	"github.com/tomi77/zmq4/internal/wire"
)

const (
	helloCommandName    = "HELLO"
	welcomeCommandName  = "WELCOME"
	initiateCommandName = "INITIATE"
)

// helloBody is the parsed body of a HELLO command:
//   hello = "HELLO" username password
//   username = OCTET 0*255OCTET    ; 1-byte length prefix
//   password = OCTET 0*255OCTET    ; 1-byte length prefix
type helloBody struct {
	Username []byte
	Password []byte
}

func encodeHello(b helloBody) (wire.Command, error) {
	if len(b.Username) > 255 {
		return wire.Command{}, fmt.Errorf("%w: username", ErrCredentialsTooLong)
	}
	if len(b.Password) > 255 {
		return wire.Command{}, fmt.Errorf("%w: password", ErrCredentialsTooLong)
	}
	data := make([]byte, 0, 2+len(b.Username)+len(b.Password))
	data = append(data, byte(len(b.Username)))
	data = append(data, b.Username...)
	data = append(data, byte(len(b.Password)))
	data = append(data, b.Password...)
	return wire.Command{Name: helloCommandName, Data: data}, nil
}

func parseHello(cmd wire.Command) (helloBody, error) {
	if cmd.Name != helloCommandName {
		return helloBody{}, fmt.Errorf("%w: command name %q", ErrMalformedHello, cmd.Name)
	}
	d := cmd.Data
	if len(d) < 1 {
		return helloBody{}, fmt.Errorf("%w: missing username length", ErrMalformedHello)
	}
	uLen := int(d[0])
	d = d[1:]
	if len(d) < uLen {
		return helloBody{}, fmt.Errorf("%w: username truncated", ErrMalformedHello)
	}
	user := d[:uLen]
	d = d[uLen:]
	if len(d) < 1 {
		return helloBody{}, fmt.Errorf("%w: missing password length", ErrMalformedHello)
	}
	pLen := int(d[0])
	d = d[1:]
	if len(d) < pLen {
		return helloBody{}, fmt.Errorf("%w: password truncated", ErrMalformedHello)
	}
	pass := d[:pLen]
	d = d[pLen:]
	if len(d) != 0 {
		return helloBody{}, fmt.Errorf("%w: %d trailing bytes", ErrMalformedHello, len(d))
	}
	return helloBody{Username: user, Password: pass}, nil
}

func encodeWelcome() wire.Command {
	return wire.Command{Name: welcomeCommandName, Data: nil}
}

func parseWelcome(cmd wire.Command) error {
	if cmd.Name != welcomeCommandName {
		return fmt.Errorf("%w: command name %q", ErrMalformedWelcome, cmd.Name)
	}
	if len(cmd.Data) != 0 {
		return fmt.Errorf("%w: %d unexpected body bytes", ErrMalformedWelcome, len(cmd.Data))
	}
	return nil
}

// sanitizeReason makes s safe to put inside an ERROR command body
// (RFC 37 §3 ABNF: error-reason = OCTET 0*255VCHAR). Replaces any
// non-VCHAR byte with '?', then truncates to 255 bytes.
//
// VCHAR is %x21..%x7E (printable ASCII excluding space).
func sanitizeReason(s string) string {
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/plain/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/plain/codec.go internal/security/plain/codec_test.go
git commit -m "security/plain: HELLO/WELCOME codec and reason sanitizer"
```

---

## Chunk 4: ClientState

### Task 5: ClientState — `NewClient` + `Start` (HELLO emission)

**Files:**
- Create: `internal/security/plain/client.go`
- Create: `internal/security/plain/client_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package plain

import (
	"bytes"
	"errors"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestNewClientRejectsLongUsername(t *testing.T) {
	long := bytes.Repeat([]byte("u"), 256)
	_, err := NewClient(long, []byte("p"), nil)
	if !errors.Is(err, ErrCredentialsTooLong) {
		t.Fatalf("err = %v, want ErrCredentialsTooLong", err)
	}
}

func TestNewClientRejectsLongPassword(t *testing.T) {
	long := bytes.Repeat([]byte("p"), 256)
	_, err := NewClient([]byte("u"), long, nil)
	if !errors.Is(err, ErrCredentialsTooLong) {
		t.Fatalf("err = %v, want ErrCredentialsTooLong", err)
	}
}

func TestNewClientNotDone(t *testing.T) {
	c, err := NewClient([]byte("u"), []byte("p"), nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Done() {
		t.Fatalf("new client is Done()")
	}
}

func TestClientStartEmitsHello(t *testing.T) {
	c, err := NewClient([]byte("admin"), []byte("secret"), nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	cmd, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if cmd.Name != helloCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, helloCommandName)
	}
	body, err := parseHello(cmd)
	if err != nil {
		t.Fatalf("parseHello: %v", err)
	}
	if !bytes.Equal(body.Username, []byte("admin")) {
		t.Fatalf("Username = %x, want admin", body.Username)
	}
	if !bytes.Equal(body.Password, []byte("secret")) {
		t.Fatalf("Password = %x, want secret", body.Password)
	}
}

func TestClientStartTwiceReturnsAlreadyStarted(t *testing.T) {
	c, err := NewClient(nil, nil, nil)
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

// silence unused-import warning until later tasks use wire.
var _ = wire.ReadyCommandName
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/plain/... -run TestNewClient -count=1`
Expected: FAIL (`undefined: NewClient`).

- [ ] **Step 3: Write `internal/security/plain/client.go`** (initial cut — `Receive` is a stub for now, fleshed out in Task 6)

```go
package plain

import (
	"github.com/tomi77/zmq4/internal/wire"
)

// ClientState drives the client side of a ZMTP 3.1 PLAIN handshake.
// Single-shot; not safe for concurrent use.
type ClientState struct {
	username []byte
	password []byte
	local    wire.Metadata // metadata for INITIATE
	peer     wire.Metadata // metadata from peer READY (defensively copied)

	started         bool
	welcomeReceived bool
	done            bool
	failed          bool
}

// NewClient constructs a client. username and password are referenced,
// not copied; callers must not mutate them after passing them in. Each
// must be ≤255 bytes per RFC 37 §3.2.
//
// localMetadata is sent in INITIATE (step 3); referenced, not copied.
func NewClient(username, password []byte, localMetadata wire.Metadata) (*ClientState, error) {
	if len(username) > 255 {
		return nil, fmt.Errorf("%w: username %d bytes", ErrCredentialsTooLong, len(username))
	}
	if len(password) > 255 {
		return nil, fmt.Errorf("%w: password %d bytes", ErrCredentialsTooLong, len(password))
	}
	return &ClientState{
		username: username,
		password: password,
		local:    localMetadata,
	}, nil
}

// Done reports whether the handshake has completed successfully.
func (c *ClientState) Done() bool { return c.done && !c.failed }

// Start emits HELLO. Must be called exactly once before Receive.
func (c *ClientState) Start() (wire.Command, error) {
	if c.failed {
		return wire.Command{}, ErrAlreadyFailed
	}
	if c.started {
		return wire.Command{}, ErrAlreadyStarted
	}
	cmd, err := encodeHello(helloBody{Username: c.username, Password: c.password})
	if err != nil {
		c.failed = true
		return wire.Command{}, fmt.Errorf("plain: encode HELLO: %w", err)
	}
	c.started = true
	return cmd, nil
}
```

Add `import "fmt"` at the top of the file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/plain/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/plain/client.go internal/security/plain/client_test.go
git commit -m "security/plain: ClientState construction and HELLO emission"
```

---

### Task 6: ClientState — `Receive(WELCOME)` → INITIATE; `Receive(READY)` → done

**Files:**
- Modify: `internal/security/plain/client.go` — add `Receive`, `PeerMetadata`.
- Modify: `internal/security/plain/client_test.go` — happy-path tests.

- [ ] **Step 1: Write the failing tests**

Append to `client_test.go`:

```go
func TestClientReceiveWelcomeEmitsInitiate(t *testing.T) {
	c, err := NewClient([]byte("u"), []byte("p"), wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REQ")},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	out, done, err := c.Receive(encodeWelcome())
	if err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	if done {
		t.Fatalf("done=true after WELCOME, want false")
	}
	if out == nil {
		t.Fatalf("out=nil after WELCOME, want INITIATE")
	}
	if out.Name != initiateCommandName {
		t.Fatalf("out.Name = %q, want %q", out.Name, initiateCommandName)
	}
	md, err := wire.ParseMetadata(out.Data)
	if err != nil {
		t.Fatalf("ParseMetadata(INITIATE): %v", err)
	}
	if v, ok := md.Get("Socket-Type"); !ok || string(v) != "REQ" {
		t.Fatalf("INITIATE Socket-Type = %q, want REQ", v)
	}
}

func TestClientReceiveReadyCompletesHandshake(t *testing.T) {
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

	peerReady, err := wire.ReadyCommand{
		Metadata: wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("REP")},
			{Name: []byte("Identity"), Value: []byte("server-1")},
		},
	}.Encode()
	if err != nil {
		t.Fatalf("encode peer READY: %v", err)
	}

	out, done, err := c.Receive(peerReady)
	if err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}
	if !done {
		t.Fatalf("done=false after READY, want true")
	}
	if out != nil {
		t.Fatalf("out=%+v after READY, want nil", out)
	}
	if !c.Done() {
		t.Fatalf("Done()=false after successful Receive")
	}
	pm := c.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "REP" {
		t.Fatalf("PeerMetadata Socket-Type = %q, want REP", v)
	}
	if v, ok := pm.Get("Identity"); !ok || string(v) != "server-1" {
		t.Fatalf("PeerMetadata Identity = %q, want server-1", v)
	}
}

func TestClientPeerMetadataIndependentOfInputBuffer(t *testing.T) {
	original, err := wire.ReadyCommand{
		Metadata: wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
		},
	}.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	buf := make([]byte, len(original.Data))
	copy(buf, original.Data)
	peerReady := wire.Command{Name: original.Name, Data: buf}

	c, err := NewClient(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	if _, _, err := c.Receive(peerReady); err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}

	for i := range buf {
		buf[i] = 0xFF
	}
	pm := c.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "DEALER" {
		t.Fatalf("PeerMetadata after clobber = %q, want DEALER", v)
	}
}
```

Remove the placeholder `var _ = wire.ReadyCommandName` from Task 5 — `wire` is now used legitimately.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/plain/... -count=1`
Expected: FAIL (`undefined: (*ClientState).Receive`).

- [ ] **Step 3: Add `Receive` and `PeerMetadata` to `client.go`**

```go
// Receive consumes one peer command and advances the state machine.
//   step 2: cmd=WELCOME ⇒ out=INITIATE, done=false
//   step 4: cmd=READY   ⇒ out=nil,      done=true
//   any:    cmd=ERROR   ⇒ err=ErrPeerError(reason)
func (c *ClientState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error) {
	if c.failed {
		return nil, false, ErrAlreadyFailed
	}
	if !c.started {
		c.failed = true
		return nil, false, ErrNotStarted
	}
	if c.done {
		c.failed = true
		return nil, false, ErrAlreadyDone
	}

	if !c.welcomeReceived {
		// Expecting WELCOME.
		switch cmd.Name {
		case welcomeCommandName:
			if perr := parseWelcome(cmd); perr != nil {
				c.failed = true
				return nil, false, perr
			}
			initiate := &wire.Command{
				Name: initiateCommandName,
				Data: wire.EncodeMetadata(c.local),
			}
			c.welcomeReceived = true
			return initiate, false, nil
		case wire.ErrorCommandName:
			return nil, false, c.failPeerError(cmd)
		}
		c.failed = true
		return nil, false, fmt.Errorf("%w: %q (expected WELCOME)", ErrUnexpectedCommand, cmd.Name)
	}

	// Expecting READY.
	switch cmd.Name {
	case wire.ReadyCommandName:
		rc, perr := wire.ParseReady(cmd)
		if perr != nil {
			c.failed = true
			return nil, false, fmt.Errorf("%w: %v", ErrMalformedReady, perr)
		}
		c.peer = metaclone.Clone(rc.Metadata)
		c.done = true
		return nil, true, nil
	case wire.ErrorCommandName:
		return nil, false, c.failPeerError(cmd)
	}
	c.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected READY)", ErrUnexpectedCommand, cmd.Name)
}

// failPeerError marks the state failed and returns an ErrPeerError-wrapped
// reason extracted from the peer's ERROR command.
func (c *ClientState) failPeerError(cmd wire.Command) error {
	c.failed = true
	ec, perr := wire.ParseError(cmd)
	if perr != nil {
		return fmt.Errorf("%w: malformed ERROR: %v", ErrPeerError, perr)
	}
	return fmt.Errorf("%w: %s", ErrPeerError, ec.Reason)
}

// PeerMetadata returns the metadata the server advertised in its READY
// command. Valid only after Receive returned done=true. The slice
// aliases an internal buffer; callers must NOT mutate it.
func (c *ClientState) PeerMetadata() wire.Metadata { return c.peer }
```

Add the import `"github.com/tomi77/zmq4/internal/security/metaclone"` at the top.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/plain/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/plain/client.go internal/security/plain/client_test.go
git commit -m "security/plain: ClientState happy-path Receive (WELCOME→INITIATE, READY→done)"
```

---

### Task 7: ClientState — error and lifecycle paths

**Files:**
- Modify: `internal/security/plain/client_test.go` — exhaustive error-path tests.

No production code changes are expected; Task 6 already wired all branches. If a test fails, the corresponding branch in `Receive` is missing and must be added.

- [ ] **Step 1: Write the failing (or passing-the-pin) tests**

Append to `client_test.go`:

```go
func TestClientReceiveBeforeStart(t *testing.T) {
	c, _ := NewClient(nil, nil, nil)
	_, _, err := c.Receive(encodeWelcome())
	if !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Receive before Start = %v, want ErrNotStarted", err)
	}
}

func TestClientReceiveErrorAtWelcomeStep(t *testing.T) {
	errCmd, _ := wire.ErrorCommand{Reason: "go away"}.Encode()
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := c.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("err = %v, want ErrPeerError", err)
	}
	if !strings.Contains(err.Error(), "go away") {
		t.Fatalf("error %q does not include reason", err)
	}
}

func TestClientReceiveErrorAtReadyStep(t *testing.T) {
	errCmd, _ := wire.ErrorCommand{Reason: "denied"}.Encode()
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	_, _, err := c.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("err = %v, want ErrPeerError", err)
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Fatalf("error %q does not include reason", err)
	}
}

func TestClientReceiveUnexpectedCommandAtWelcomeStep(t *testing.T) {
	cmd := wire.Command{Name: "PING"}
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := c.Receive(cmd)
	if !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestClientReceiveUnexpectedCommandAtReadyStep(t *testing.T) {
	cmd := wire.Command{Name: "PING"}
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	_, _, err := c.Receive(cmd)
	if !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestClientReceiveMalformedWelcome(t *testing.T) {
	bad := wire.Command{Name: welcomeCommandName, Data: []byte{0xAA}}
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err := c.Receive(bad)
	if !errors.Is(err, ErrMalformedWelcome) {
		t.Fatalf("err = %v, want ErrMalformedWelcome", err)
	}
}

func TestClientReceiveMalformedReady(t *testing.T) {
	bad := wire.Command{
		Name: wire.ReadyCommandName,
		// nameLen=5 but only 2 bytes follow
		Data: []byte{0x05, 'A', 'B'},
	}
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	_, _, err := c.Receive(bad)
	if !errors.Is(err, ErrMalformedReady) {
		t.Fatalf("err = %v, want ErrMalformedReady", err)
	}
}

func TestClientReceiveAfterDone(t *testing.T) {
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(encodeWelcome()); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	peerReady, _ := wire.ReadyCommand{}.Encode()
	if _, _, err := c.Receive(peerReady); err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}
	_, _, err := c.Receive(peerReady)
	if !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("Receive after done = %v, want ErrAlreadyDone", err)
	}
}

func TestClientReceiveAfterFailed(t *testing.T) {
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(wire.Command{Name: "PING"}); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("first Receive: %v", err)
	}
	_, _, err := c.Receive(wire.Command{Name: "PING"})
	if !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Receive after failure = %v, want ErrAlreadyFailed", err)
	}
}

func TestClientStartAfterFailedReturnsAlreadyFailed(t *testing.T) {
	c, _ := NewClient(nil, nil, nil)
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := c.Receive(wire.Command{Name: "PING"}); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("Receive: %v", err)
	}
	_, err := c.Start()
	if !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Start after failure = %v, want ErrAlreadyFailed", err)
	}
}
```

Add `"strings"` to the test file's imports if not already present.

- [ ] **Step 2: Run tests**

Run: `go test ./internal/security/plain/... -count=1`
Expected: PASS — Task 6 already covers all these branches.

If anything fails, fix the corresponding branch in `Receive` / `Start` and re-run.

- [ ] **Step 3: Commit**

```bash
git add internal/security/plain/client_test.go
git commit -m "security/plain: ClientState lifecycle and error-path tests"
```

---

## Chunk 5: ServerState

### Task 8: ServerState — `NewServer` + `Receive(HELLO accept)` → WELCOME

**Files:**
- Create: `internal/security/plain/server.go`
- Create: `internal/security/plain/server_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package plain

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func acceptAll(_, _ []byte) error { return nil }

func TestNewServerNilAuthPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("NewServer(nil, ...) did not panic")
		}
	}()
	_ = NewServer(nil, nil)
}

func TestNewServerNotDone(t *testing.T) {
	s := NewServer(acceptAll, nil)
	if s.Done() {
		t.Fatalf("new server is Done()")
	}
}

func TestServerReceiveHelloAcceptEmitsWelcome(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, err := encodeHello(helloBody{Username: []byte("u"), Password: []byte("p")})
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
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
	if len(out.Data) != 0 {
		t.Fatalf("WELCOME body = %x, want empty", out.Data)
	}
}

// silence unused imports if the rest of the file doesn't use them yet.
var (
	_ = bytes.Equal
	_ = errors.Is
	_ = strings.Contains
)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/plain/... -run TestNewServer -count=1`
Expected: FAIL (`undefined: NewServer`).

- [ ] **Step 3: Write `internal/security/plain/server.go`** (initial cut — `Receive` only handles the HELLO step; INITIATE step in Task 9)

```go
package plain

import (
	"fmt"

	"github.com/tomi77/zmq4/internal/wire"
)

// ServerState drives the server side of a ZMTP 3.1 PLAIN handshake.
// Single-shot; not safe for concurrent use.
type ServerState struct {
	auth  Authenticator
	local wire.Metadata // metadata for READY
	peer  wire.Metadata // metadata from peer INITIATE (defensively copied)

	helloProcessed bool
	done           bool
	failed         bool
}

// Authenticator decides whether to accept a (username, password) pair.
// Returning nil ⇒ WELCOME. Returning non-nil ⇒ ERROR (reason = err.Error()
// after sanitization). Runs synchronously; must not do I/O or take
// locks held elsewhere.
type Authenticator func(username, password []byte) error

// NewServer constructs a server. auth must not be nil; passing nil is
// a programming error and panics. localMetadata is sent in READY at the
// end of the handshake; referenced, not copied.
func NewServer(auth Authenticator, localMetadata wire.Metadata) *ServerState {
	if auth == nil {
		panic("plain: NewServer requires a non-nil Authenticator")
	}
	return &ServerState{auth: auth, local: localMetadata}
}

// Done reports whether the handshake has completed successfully.
func (s *ServerState) Done() bool { return s.done && !s.failed }

// PeerMetadata returns the metadata the client sent in INITIATE. Valid
// only after Receive returned done=true.
func (s *ServerState) PeerMetadata() wire.Metadata { return s.peer }

// Receive consumes one peer command and advances the state machine.
// See spec §4.2 for the contract.
func (s *ServerState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error) {
	if s.failed {
		return nil, false, ErrAlreadyFailed
	}
	if s.done {
		s.failed = true
		return nil, false, ErrAlreadyDone
	}

	if !s.helloProcessed {
		// Expecting HELLO.
		switch cmd.Name {
		case helloCommandName:
			body, perr := parseHello(cmd)
			if perr != nil {
				s.failed = true
				return nil, false, perr
			}
			if authErr := s.auth(body.Username, body.Password); authErr != nil {
				return s.failAuthRejected(authErr)
			}
			welcome := encodeWelcome()
			s.helloProcessed = true
			return &welcome, false, nil
		case wire.ErrorCommandName:
			return nil, false, s.failPeerError(cmd)
		}
		s.failed = true
		return nil, false, fmt.Errorf("%w: %q (expected HELLO)", ErrUnexpectedCommand, cmd.Name)
	}

	// Expecting INITIATE — fleshed out in Task 9.
	s.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected INITIATE)", ErrUnexpectedCommand, cmd.Name)
}

// failAuthRejected encodes an ERROR command carrying the authenticator's
// reason and marks the state as failed. The caller MUST send the
// returned out command before closing the connection.
func (s *ServerState) failAuthRejected(authErr error) (*wire.Command, bool, error) {
	s.failed = true
	reason := sanitizeReason(authErr.Error())
	errCmd, encErr := wire.ErrorCommand{Reason: reason}.Encode()
	if encErr != nil {
		return nil, false, fmt.Errorf("plain: encode ERROR: %w", encErr)
	}
	return &errCmd, false, fmt.Errorf("%w: %s", ErrAuthRejected, reason)
}

func (s *ServerState) failPeerError(cmd wire.Command) error {
	s.failed = true
	ec, perr := wire.ParseError(cmd)
	if perr != nil {
		return fmt.Errorf("%w: malformed ERROR: %v", ErrPeerError, perr)
	}
	return fmt.Errorf("%w: %s", ErrPeerError, ec.Reason)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/plain/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/plain/server.go internal/security/plain/server_test.go
git commit -m "security/plain: ServerState construction and HELLO accept path"
```

---

### Task 9: ServerState — `Receive(HELLO reject)` and `Receive(INITIATE)` → READY → done

**Files:**
- Modify: `internal/security/plain/server.go` — flesh out the AWAIT_INITIATE branch.
- Modify: `internal/security/plain/server_test.go` — reject + INITIATE tests.

- [ ] **Step 1: Write the failing tests**

Append to `server_test.go`:

```go
func TestServerReceiveHelloRejectEmitsErrorAndFails(t *testing.T) {
	rejecter := func(_, _ []byte) error { return errors.New("denied") }
	s := NewServer(rejecter, nil)
	hello, _ := encodeHello(helloBody{Username: []byte("u"), Password: []byte("p")})

	out, done, err := s.Receive(hello)
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("err = %v, want ErrAuthRejected", err)
	}
	if done {
		t.Fatalf("done=true on auth reject, want false")
	}
	if out == nil || out.Name != wire.ErrorCommandName {
		t.Fatalf("out = %+v, want ERROR command", out)
	}
	ec, perr := wire.ParseError(*out)
	if perr != nil {
		t.Fatalf("ParseError(out): %v", perr)
	}
	if ec.Reason != "denied" {
		t.Fatalf("reason = %q, want \"denied\"", ec.Reason)
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Fatalf("err %q does not include reason", err)
	}
}

func TestServerAuthRejectReasonSanitized(t *testing.T) {
	dirty := "bad creds\n\x00user=alice"
	rejecter := func(_, _ []byte) error { return errors.New(dirty) }
	s := NewServer(rejecter, nil)
	hello, _ := encodeHello(helloBody{})

	out, _, _ := s.Receive(hello)
	ec, _ := wire.ParseError(*out)
	if strings.ContainsAny(ec.Reason, "\n\x00") {
		t.Fatalf("reason %q has non-VCHAR bytes", ec.Reason)
	}
	if len(ec.Reason) != len(dirty) {
		t.Fatalf("len(reason) = %d, want %d", len(ec.Reason), len(dirty))
	}
}

func TestServerAuthRejectReasonTruncated(t *testing.T) {
	long := strings.Repeat("a", 300)
	rejecter := func(_, _ []byte) error { return errors.New(long) }
	s := NewServer(rejecter, nil)
	hello, _ := encodeHello(helloBody{})

	out, _, _ := s.Receive(hello)
	ec, _ := wire.ParseError(*out)
	if len(ec.Reason) != 255 {
		t.Fatalf("len(reason) = %d, want 255", len(ec.Reason))
	}
}

func TestServerReceiveAfterAuthReject(t *testing.T) {
	rejecter := func(_, _ []byte) error { return errors.New("nope") }
	s := NewServer(rejecter, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("first Receive: %v", err)
	}
	_, _, err := s.Receive(hello)
	if !errors.Is(err, ErrAlreadyFailed) {
		t.Fatalf("Receive after reject = %v, want ErrAlreadyFailed", err)
	}
}

func TestServerReceiveInitiateCompletesHandshake(t *testing.T) {
	s := NewServer(acceptAll, wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REP")},
	})
	hello, _ := encodeHello(helloBody{Username: []byte("u"), Password: []byte("p")})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}

	clientMeta := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REQ")},
		{Name: []byte("Identity"), Value: []byte("client-1")},
	}
	initiate := wire.Command{
		Name: initiateCommandName,
		Data: wire.EncodeMetadata(clientMeta),
	}

	out, done, err := s.Receive(initiate)
	if err != nil {
		t.Fatalf("Receive(INITIATE): %v", err)
	}
	if !done {
		t.Fatalf("done=false after INITIATE, want true")
	}
	if out == nil || out.Name != wire.ReadyCommandName {
		t.Fatalf("out = %+v, want READY", out)
	}
	rc, perr := wire.ParseReady(*out)
	if perr != nil {
		t.Fatalf("ParseReady(out): %v", perr)
	}
	if v, ok := rc.Metadata.Get("Socket-Type"); !ok || string(v) != "REP" {
		t.Fatalf("READY Socket-Type = %q, want REP", v)
	}
	if !s.Done() {
		t.Fatalf("Done()=false after success")
	}
	pm := s.PeerMetadata()
	if v, ok := pm.Get("Identity"); !ok || string(v) != "client-1" {
		t.Fatalf("PeerMetadata Identity = %q, want client-1", v)
	}
}

func TestServerPeerMetadataIndependentOfInputBuffer(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}

	originalData := wire.EncodeMetadata(wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
	})
	buf := make([]byte, len(originalData))
	copy(buf, originalData)
	initiate := wire.Command{Name: initiateCommandName, Data: buf}

	if _, _, err := s.Receive(initiate); err != nil {
		t.Fatalf("Receive(INITIATE): %v", err)
	}

	for i := range buf {
		buf[i] = 0xFF
	}
	pm := s.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "DEALER" {
		t.Fatalf("PeerMetadata after clobber = %q, want DEALER", v)
	}
}
```

You can now delete the placeholder `var (_ = bytes.Equal …)` block from Task 8 — those imports are used legitimately.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/security/plain/... -count=1`
Expected: most server tests FAIL with `ErrUnexpectedCommand` (the AWAIT_INITIATE stub from Task 8).

- [ ] **Step 3: Replace the AWAIT_INITIATE stub in `server.go`**

Replace the trailing block in `Receive`:

```go
	// Expecting INITIATE — fleshed out in Task 9.
	s.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected INITIATE)", ErrUnexpectedCommand, cmd.Name)
```

with:

```go
	// Expecting INITIATE.
	switch cmd.Name {
	case initiateCommandName:
		md, perr := wire.ParseMetadata(cmd.Data)
		if perr != nil {
			s.failed = true
			return nil, false, fmt.Errorf("%w: %v", ErrMalformedInitiate, perr)
		}
		s.peer = metaclone.Clone(md)
		ready, encErr := wire.ReadyCommand{Metadata: s.local}.Encode()
		if encErr != nil {
			s.failed = true
			return nil, false, fmt.Errorf("plain: encode READY: %w", encErr)
		}
		s.done = true
		return &ready, true, nil
	case wire.ErrorCommandName:
		return nil, false, s.failPeerError(cmd)
	}
	s.failed = true
	return nil, false, fmt.Errorf("%w: %q (expected INITIATE)", ErrUnexpectedCommand, cmd.Name)
```

Add the `metaclone` import to `server.go`:
`"github.com/tomi77/zmq4/internal/security/metaclone"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/security/plain/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/plain/server.go internal/security/plain/server_test.go
git commit -m "security/plain: ServerState auth-reject and INITIATE→READY"
```

---

### Task 10: ServerState — error and lifecycle paths

**Files:**
- Modify: `internal/security/plain/server_test.go` — exhaustive error-path tests.

- [ ] **Step 1: Write the failing (or passing-the-pin) tests**

Append:

```go
func TestServerReceiveMalformedHello(t *testing.T) {
	s := NewServer(acceptAll, nil)
	bad := wire.Command{Name: helloCommandName, Data: []byte{0xFF}} // claims 255-byte username, no body
	_, _, err := s.Receive(bad)
	if !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestServerReceiveUnexpectedCommandAtHelloStep(t *testing.T) {
	s := NewServer(acceptAll, nil)
	cmd := wire.Command{Name: "PING"}
	_, _, err := s.Receive(cmd)
	if !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestServerReceiveUnexpectedCommandAtInitiateStep(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	_, _, err := s.Receive(wire.Command{Name: "PING"})
	if !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestServerReceiveMalformedInitiate(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	bad := wire.Command{Name: initiateCommandName, Data: []byte{0x05, 'A'}}
	_, _, err := s.Receive(bad)
	if !errors.Is(err, ErrMalformedInitiate) {
		t.Fatalf("err = %v, want ErrMalformedInitiate", err)
	}
}

func TestServerReceiveErrorAtHelloStep(t *testing.T) {
	s := NewServer(acceptAll, nil)
	errCmd, _ := wire.ErrorCommand{Reason: "client gives up"}.Encode()
	_, _, err := s.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("err = %v, want ErrPeerError", err)
	}
	if !strings.Contains(err.Error(), "client gives up") {
		t.Fatalf("error %q does not include reason", err)
	}
}

func TestServerReceiveErrorAtInitiateStep(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	errCmd, _ := wire.ErrorCommand{Reason: "client aborts"}.Encode()
	_, _, err := s.Receive(errCmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("err = %v, want ErrPeerError", err)
	}
}

func TestServerReceiveAfterDone(t *testing.T) {
	s := NewServer(acceptAll, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	initiate := wire.Command{Name: initiateCommandName, Data: wire.EncodeMetadata(nil)}
	if _, _, err := s.Receive(initiate); err != nil {
		t.Fatalf("Receive(INITIATE): %v", err)
	}
	_, _, err := s.Receive(initiate)
	if !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("err = %v, want ErrAlreadyDone", err)
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/security/plain/... -count=1`
Expected: PASS — Task 9 covers all branches.

If anything fails, fix the corresponding branch in `Receive` and re-run.

- [ ] **Step 3: Commit**

```bash
git add internal/security/plain/server_test.go
git commit -m "security/plain: ServerState lifecycle and error-path tests"
```

---

## Chunk 6: Property tests, vectors, benchmarks, done sweep

### Task 11: Property tests — happy path and auth reject

**Files:**
- Create: `internal/security/plain/handshake_property_test.go`

- [ ] **Step 1: Write the property tests**

```go
package plain

import (
	"bytes"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"testing/quick"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestPlainHappyPathProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 1000}
	prop := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		user, pass := randCreds(rng)
		mdC := randMetadata(rng)
		mdS := randMetadata(rng)

		client, err := NewClient(user, pass, mdC)
		if err != nil {
			t.Logf("NewClient: %v", err)
			return false
		}
		server := NewServer(func(_, _ []byte) error { return nil }, mdS)

		hello, err := client.Start()
		if err != nil {
			t.Logf("Start: %v", err)
			return false
		}
		welcome, done, err := server.Receive(hello)
		if err != nil || done || welcome == nil {
			t.Logf("server.Receive(HELLO): out=%v done=%v err=%v", welcome, done, err)
			return false
		}
		initiate, done, err := client.Receive(*welcome)
		if err != nil || done || initiate == nil {
			t.Logf("client.Receive(WELCOME): out=%v done=%v err=%v", initiate, done, err)
			return false
		}
		ready, done, err := server.Receive(*initiate)
		if err != nil || !done || ready == nil {
			t.Logf("server.Receive(INITIATE): out=%v done=%v err=%v", ready, done, err)
			return false
		}
		out, done, err := client.Receive(*ready)
		if err != nil || !done || out != nil {
			t.Logf("client.Receive(READY): out=%v done=%v err=%v", out, done, err)
			return false
		}
		return metadataEqual(client.PeerMetadata(), mdS) &&
			metadataEqual(server.PeerMetadata(), mdC)
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestPlainAuthRejectProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 1000}
	prop := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		user, pass := randCreds(rng)

		client, err := NewClient(user, pass, nil)
		if err != nil {
			return false
		}
		rejecter := func(_, _ []byte) error { return errors.New("denied") }
		server := NewServer(rejecter, nil)

		hello, err := client.Start()
		if err != nil {
			return false
		}
		out, done, err := server.Receive(hello)
		if !errors.Is(err, ErrAuthRejected) || done || out == nil {
			t.Logf("server.Receive(HELLO): out=%v done=%v err=%v", out, done, err)
			return false
		}
		ec, perr := wire.ParseError(*out)
		if perr != nil || ec.Reason != "denied" {
			t.Logf("ERROR reason = %q (parse err=%v)", ec.Reason, perr)
			return false
		}
		// Client receives the ERROR.
		_, _, err = client.Receive(*out)
		if !errors.Is(err, ErrPeerError) || !strings.Contains(err.Error(), "denied") {
			t.Logf("client.Receive(ERROR) = %v", err)
			return false
		}
		// Both states are now FAILED.
		if _, _, err := client.Receive(*out); !errors.Is(err, ErrAlreadyFailed) {
			t.Logf("client.Receive after ERROR = %v, want ErrAlreadyFailed", err)
			return false
		}
		if _, _, err := server.Receive(hello); !errors.Is(err, ErrAlreadyFailed) {
			t.Logf("server.Receive after reject = %v, want ErrAlreadyFailed", err)
			return false
		}
		return true
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func randCreds(rng *rand.Rand) ([]byte, []byte) {
	user := make([]byte, rng.Intn(32))
	pass := make([]byte, rng.Intn(32))
	rng.Read(user)
	rng.Read(pass)
	return user, pass
}

func randMetadata(rng *rand.Rand) wire.Metadata {
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
```

- [ ] **Step 2: Run the property tests**

Run: `go test ./internal/security/plain/... -run TestPlain.*Property -count=1`
Expected: PASS, 1000 iterations each.

- [ ] **Step 3: Commit**

```bash
git add internal/security/plain/handshake_property_test.go
git commit -m "security/plain: property-based handshake round-trip"
```

---

### Task 12: Vector tests (7 hand-crafted .bin files)

**Files:**
- Create: `internal/security/plain/testdata/plain-hello-empty.bin`
- Create: `internal/security/plain/testdata/plain-hello-creds.bin`
- Create: `internal/security/plain/testdata/plain-welcome.bin`
- Create: `internal/security/plain/testdata/plain-initiate-empty.bin`
- Create: `internal/security/plain/testdata/plain-initiate-with-socket-type.bin`
- Create: `internal/security/plain/testdata/plain-ready-with-identity.bin`
- Create: `internal/security/plain/testdata/plain-error-auth-failed.bin`
- Create: `internal/security/plain/testdata/README.md`
- Create: `internal/security/plain/vector_test.go`

> Vectors are hand-crafted from RFC 37 §3.2 using F1's encoder + F2b's HELLO codec. Each .bin file holds the **command body** (command-name + command-data) — same format as F2a's vectors. Cross-validation against libzmq is deferred to F4 interop.

- [ ] **Step 1: Write a one-off generator at `internal/security/plain/gen_vectors.go.tmp`**

```go
//go:build ignore

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tomi77/zmq4/internal/wire"
)

const (
	helloCmd    = "HELLO"
	welcomeCmd  = "WELCOME"
	initiateCmd = "INITIATE"
)

// helloBody is duplicated here because the real one is unexported in
// internal/security/plain. The generator never imports the package it
// generates fixtures for.
type helloBody struct {
	Username []byte
	Password []byte
}

func encodeHello(b helloBody) wire.Command {
	data := []byte{byte(len(b.Username))}
	data = append(data, b.Username...)
	data = append(data, byte(len(b.Password)))
	data = append(data, b.Password...)
	return wire.Command{Name: helloCmd, Data: data}
}

func main() {
	dir := "internal/security/plain/testdata"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}

	type vector struct {
		name string
		cmd  wire.Command
	}

	mustEncReady := func(rc wire.ReadyCommand) wire.Command {
		c, err := rc.Encode()
		if err != nil {
			panic(err)
		}
		return c
	}
	mustEncError := func(reason string) wire.Command {
		c, err := wire.ErrorCommand{Reason: reason}.Encode()
		if err != nil {
			panic(err)
		}
		return c
	}
	encInitiate := func(md wire.Metadata) wire.Command {
		return wire.Command{Name: initiateCmd, Data: wire.EncodeMetadata(md)}
	}

	vectors := []vector{
		{"plain-hello-empty.bin", encodeHello(helloBody{})},
		{"plain-hello-creds.bin", encodeHello(helloBody{Username: []byte("admin"), Password: []byte("secret")})},
		{"plain-welcome.bin", wire.Command{Name: welcomeCmd}},
		{"plain-initiate-empty.bin", encInitiate(nil)},
		{"plain-initiate-with-socket-type.bin", encInitiate(wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
		})},
		{"plain-ready-with-identity.bin", mustEncReady(wire.ReadyCommand{
			Metadata: wire.Metadata{
				{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
				{Name: []byte("Identity"), Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
			},
		})},
		{"plain-error-auth-failed.bin", mustEncError("Authentication failed")},
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

Run: `go run internal/security/plain/gen_vectors.go.tmp && rm internal/security/plain/gen_vectors.go.tmp`
Expected: prints seven "wrote ..." lines, all seven .bin files exist.

- [ ] **Step 3: Write `internal/security/plain/testdata/README.md`**

```markdown
# F2b PLAIN handshake vectors

Hand-crafted from RFC 37 §3.2 using F1's encoder + F2b's HELLO codec.
Cross-validation against libzmq is deferred to F4 interop, per
`docs/specs/02b-security-plain.md` §8.

| File | Contents |
|------|----------|
| `plain-hello-empty.bin` | `HELLO` with empty username and password. |
| `plain-hello-creds.bin` | `HELLO` with `username="admin"`, `password="secret"`. |
| `plain-welcome.bin` | `WELCOME` with empty body. |
| `plain-initiate-empty.bin` | `INITIATE` with no metadata. |
| `plain-initiate-with-socket-type.bin` | `INITIATE` with `Socket-Type=DEALER`. |
| `plain-ready-with-identity.bin` | `READY` with `Socket-Type=ROUTER` and 8-byte `Identity`. |
| `plain-error-auth-failed.bin` | `ERROR` with reason `"Authentication failed"`. |

Each file holds the **command body** (command-name + command-data); the
outer FrameCommand framing is L1's concern.
```

- [ ] **Step 4: Write `internal/security/plain/vector_test.go`**

```go
package plain

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

func TestVectorHelloEmpty(t *testing.T) {
	raw := readVector(t, "plain-hello-empty.bin")
	cmd := parseAsCommand(t, raw)
	body, err := parseHello(cmd)
	if err != nil {
		t.Fatalf("parseHello: %v", err)
	}
	if len(body.Username) != 0 || len(body.Password) != 0 {
		t.Fatalf("hello = %+v, want empty", body)
	}
	// Re-encode and compare bytes.
	cmd2, err := encodeHello(body)
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	raw2, err := wire.EncodeCommand(cmd2)
	if err != nil {
		t.Fatalf("EncodeCommand: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("re-encoded bytes differ: got %x want %x", raw2, raw)
	}
}

func TestVectorHelloCreds(t *testing.T) {
	raw := readVector(t, "plain-hello-creds.bin")
	cmd := parseAsCommand(t, raw)
	body, err := parseHello(cmd)
	if err != nil {
		t.Fatalf("parseHello: %v", err)
	}
	if string(body.Username) != "admin" || string(body.Password) != "secret" {
		t.Fatalf("hello = %+v, want admin/secret", body)
	}
}

func TestVectorWelcome(t *testing.T) {
	raw := readVector(t, "plain-welcome.bin")
	cmd := parseAsCommand(t, raw)
	if err := parseWelcome(cmd); err != nil {
		t.Fatalf("parseWelcome: %v", err)
	}
}

func TestVectorInitiateEmpty(t *testing.T) {
	raw := readVector(t, "plain-initiate-empty.bin")
	cmd := parseAsCommand(t, raw)
	if cmd.Name != initiateCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, initiateCommandName)
	}
	md, err := wire.ParseMetadata(cmd.Data)
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if len(md) != 0 {
		t.Fatalf("metadata = %+v, want empty", md)
	}
}

func TestVectorInitiateWithSocketType(t *testing.T) {
	raw := readVector(t, "plain-initiate-with-socket-type.bin")
	cmd := parseAsCommand(t, raw)

	// Drive Receive end-to-end: server consumes INITIATE → emits READY.
	s := NewServer(func(_, _ []byte) error { return nil }, nil)
	hello, _ := encodeHello(helloBody{})
	if _, _, err := s.Receive(hello); err != nil {
		t.Fatalf("Receive(HELLO): %v", err)
	}
	out, done, err := s.Receive(cmd)
	if err != nil || !done || out == nil {
		t.Fatalf("Receive(INITIATE): out=%v done=%v err=%v", out, done, err)
	}
	if v, ok := s.PeerMetadata().Get("Socket-Type"); !ok || string(v) != "DEALER" {
		t.Fatalf("Socket-Type = %q, want DEALER", v)
	}
}

func TestVectorReadyWithIdentity(t *testing.T) {
	raw := readVector(t, "plain-ready-with-identity.bin")
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

func TestVectorErrorAuthFailed(t *testing.T) {
	raw := readVector(t, "plain-error-auth-failed.bin")
	cmd := parseAsCommand(t, raw)

	// Drive client.Receive(ERROR) at the AWAIT_WELCOME step.
	c, err := NewClient(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, _, err = c.Receive(cmd)
	if !errors.Is(err, ErrPeerError) {
		t.Fatalf("Receive(ERROR) = %v, want ErrPeerError", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("Authentication failed")) {
		t.Fatalf("error %q does not contain peer reason", err)
	}
}
```

- [ ] **Step 5: Run all plain tests + race**

Run: `go test -race ./internal/security/plain/... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/security/plain/testdata internal/security/plain/vector_test.go
git commit -m "security/plain: hand-crafted handshake vectors"
```

---

### Task 13: Benchmarks

**Files:**
- Create: `internal/security/plain/bench_test.go`

- [ ] **Step 1: Write the benchmarks**

```go
package plain

import (
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func BenchmarkClientHandshake(b *testing.B) {
	user := []byte("admin")
	pass := []byte("secret")
	mdC := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REQ")},
	}
	welcome := encodeWelcome()
	peerReady, err := wire.ReadyCommand{
		Metadata: wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("REP")},
		},
	}.Encode()
	if err != nil {
		b.Fatalf("encode peer READY: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		c, err := NewClient(user, pass, mdC)
		if err != nil {
			b.Fatalf("NewClient: %v", err)
		}
		if _, err := c.Start(); err != nil {
			b.Fatalf("Start: %v", err)
		}
		if _, _, err := c.Receive(welcome); err != nil {
			b.Fatalf("Receive(WELCOME): %v", err)
		}
		if _, _, err := c.Receive(peerReady); err != nil {
			b.Fatalf("Receive(READY): %v", err)
		}
	}
}

func BenchmarkServerHandshake(b *testing.B) {
	auth := func(_, _ []byte) error { return nil }
	mdS := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("REP")},
	}
	hello, err := encodeHello(helloBody{Username: []byte("admin"), Password: []byte("secret")})
	if err != nil {
		b.Fatalf("encodeHello: %v", err)
	}
	initiate := wire.Command{
		Name: initiateCommandName,
		Data: wire.EncodeMetadata(wire.Metadata{
			{Name: []byte("Socket-Type"), Value: []byte("REQ")},
		}),
	}

	b.ReportAllocs()
	for b.Loop() {
		s := NewServer(auth, mdS)
		if _, _, err := s.Receive(hello); err != nil {
			b.Fatalf("Receive(HELLO): %v", err)
		}
		if _, _, err := s.Receive(initiate); err != nil {
			b.Fatalf("Receive(INITIATE): %v", err)
		}
	}
}
```

- [ ] **Step 2: Run the benchmarks**

Run: `go test -bench BenchmarkClientHandshake -bench BenchmarkServerHandshake -benchmem -run='^$' ./internal/security/plain/...`
Expected: PASS, allocs/op reported. Numbers are informational; they bound F2c regression checks.

- [ ] **Step 3: Commit**

```bash
git add internal/security/plain/bench_test.go
git commit -m "security/plain: handshake benchmarks"
```

---

### Task 14: Done-criteria sweep + spec status flip + tag

**Files:**
- Modify: `docs/specs/02b-security-plain.md` — flip status, tick done-criteria.
- Modify: `docs/specs/00-meta-overview.md` — update F2b row to "Complete".

- [ ] **Step 1: `go vet`**

Run: `go vet ./...`
Expected: no output.

- [ ] **Step 2: `staticcheck`**

Run: `staticcheck ./...` (install with `go install honnef.co/go/tools/cmd/staticcheck@latest` if missing).
Expected: no output.

- [ ] **Step 3: `modernize -fix ./...`**

Run: `modernize -fix ./...`
Expected: no diff. If there is a diff, stage it and amend it into the closest related task's commit (or create a small follow-up commit `security/plain: modernize sweep`).

- [ ] **Step 4: race-mode tests**

Run: `go test -race -count=1 ./...`
Expected: PASS, no race reports.

- [ ] **Step 5: Pin alloc budget for happy paths**

Append to `internal/security/plain/bench_test.go`:

```go
import "testing"

// (existing imports)

func TestClientHandshakeAllocBudget(t *testing.T) {
	user := []byte("admin")
	pass := []byte("secret")
	mdC := wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("REQ")}}
	welcome := encodeWelcome()
	peerReady, _ := wire.ReadyCommand{
		Metadata: wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("REP")}},
	}.Encode()

	allocs := testing.AllocsPerRun(100, func() {
		c, _ := NewClient(user, pass, mdC)
		_, _ = c.Start()
		_, _, _ = c.Receive(welcome)
		_, _, _ = c.Receive(peerReady)
	})
	// Budget: HELLO encode (1), INITIATE encode (1+metadata-encode), peer READY parse aliases input,
	// metaclone Clone of peer metadata = 1 slice + 1 Name + 1 Value per peer prop.
	// One peer property → 1+1+1 = 3 metaclone allocs. Plus state struct (1).
	// Empirical budget: pin at the observed value — record it here and assert with a small slack.
	const budget = 12 // tightened after observation; adjust if benchmarks change
	if allocs > budget {
		t.Fatalf("client allocs/op = %.0f, budget = %d", allocs, budget)
	}
}

func TestServerHandshakeAllocBudget(t *testing.T) {
	mdS := wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("REP")}}
	hello, _ := encodeHello(helloBody{Username: []byte("u"), Password: []byte("p")})
	initiate := wire.Command{
		Name: initiateCommandName,
		Data: wire.EncodeMetadata(wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("REQ")}}),
	}

	allocs := testing.AllocsPerRun(100, func() {
		s := NewServer(func(_, _ []byte) error { return nil }, mdS)
		_, _, _ = s.Receive(hello)
		_, _, _ = s.Receive(initiate)
	})
	const budget = 12 // tightened after observation
	if allocs > budget {
		t.Fatalf("server allocs/op = %.0f, budget = %d", allocs, budget)
	}
}
```

Run: `go test ./internal/security/plain/... -run TestClientHandshakeAllocBudget -run TestServerHandshakeAllocBudget -count=1`

Tune the `budget` constant down to the empirical observation + slack of 1–2 (whichever value lets the test pass reliably under `-count=10`). Commit only after the chosen budget is reproducible.

- [ ] **Step 6: Update spec done-criteria**

Edit `docs/specs/02b-security-plain.md`:
- Change status from `draft, awaiting approval before implementation.` to `implemented, frozen for F2c+.`.
- Tick each `- [ ]` checkbox in §8.6 Done criteria, but only after the corresponding evidence (vet output, staticcheck output, race output, vector tests passing, property tests passing, modernize clean, alloc-budget pin passing) has actually been verified.

- [ ] **Step 7: Update meta-overview**

Edit `docs/specs/00-meta-overview.md`:
- F2b row: change "Spec drafted; implementation pending." to "Complete — tagged `phase-2b-plain-complete`."
- Top status line: add `phase-2b-plain-complete` to the tagged-list and remove "F2b spec drafted ... implementation pending".

- [ ] **Step 8: Final commits**

```bash
git add internal/security/plain/bench_test.go
git commit -m "security/plain: alloc-budget pins"

git add docs/specs/02b-security-plain.md docs/specs/00-meta-overview.md
git commit -m "security/plain: mark Phase 2b (PLAIN handshake) complete"
```

- [ ] **Step 9: Tag (after orchestrator confirms)**

```bash
git tag phase-2b-plain-complete
```

(Push left to user.)
