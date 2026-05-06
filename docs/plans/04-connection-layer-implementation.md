# F4 Connection Layer Implementation Plan

> **For Claude:** REQUIRED: Use `superpowers:subagent-driven-development` to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking. Each task is one commit.

**Goal:** Implement `internal/conn` per `docs/specs/04-connection-layer.md`: a pure-Go, ZMTP-3.1-speaking connection layer that wires F1 wire codec + F2 security + F3 transport into a full-duplex `*Conn` exposing blocking `ReadFrame` / `WriteFrame`. F4 is the first phase to do live interop with `libzmq`.

**Architecture:** L4 sits between F2/F3 (which it consumes) and F5 (its sole consumer). F4 takes a raw `net.Conn` from F5 plus a configured `security.Mechanism` and produces a `*Conn` after a successful greeting + handshake. The package contains no long-lived goroutines after handshake; reads and writes are synchronous on the calling goroutine. The plan also lands two F1 amendments (`wire.MessageCommandName`, `wire.ReadGreetingPhaseA`) and one F2 amendment (`Mechanism.Name()`) that F4 needs.

**Tech Stack:** Pure Go 1.26, stdlib only — `net`, `context`, `sync`, `time`, `errors`, `fmt`, `io`. Reuses `internal/wire` (codec), `internal/security` (mechanism state machines), `internal/security/seccommon` (`CloneMetadata`). Interop tests under build tag `interop` use Docker + libzmq 4.3.5 pinned via Dockerfile. No external Go deps beyond `golang.org/x/crypto/nacl/{box,secretbox}` already present in F2c.

**Decisions baked into the plan:**
- **F4 owns no transport plumbing.** F5 calls `transport.Dial`/`transport.Listen` and hands F4 a ready `net.Conn`.
- **Two FrameReaders per Conn lifetime.** A transient handshake reader capped at `cfg.maxHandshakeCommandSize` (default 64 KiB), then a fresh post-handshake reader at `cfg.maxFrameBodySize` (default `wire.MaxFrameBodySize`).
- **Greeting send order is asymmetric** (client-first) to avoid `net.Pipe` deadlock on inproc. Server reads peer greeting, then sends.
- **`ctx` MUST carry a deadline.** No-deadline → `ErrNoDeadline` returned before touching raw. Watcher goroutine joins via `wg.Wait()` before main clears the deadline (race fix per spec §6.6).
- **PING/PONG pass-through only.** Operational heartbeat is F6.
- **`PeerMetadata` is defensively cloned** at handshake done via `seccommon.CloneMetadata`.
- **F4 does NOT emit ERROR** for malformed peer commands post-handshake (spec §6.4); F5 owns close on protocol violation.
- **No `modernize -fix` per task.** Run only at the final done-criteria sweep (Task 28) before tagging. Per-task verification stops at `go vet` + `go test -race`.
- **Phase tag:** `phase-4-conn-complete` after Task 28, gated on the 38 interop tests in §7.5 of the spec.
- Test fixtures use `net.Pipe()` for raw conns where possible (zero external deps, deterministic). Greeting / handshake tests build directly on `net.Pipe`.
- Interop tests under `internal/conn/interop/` are gated by `//go:build interop`; the package is excluded from default test runs.

---

## File Structure

### Files created

| Path | Responsibility |
|------|----------------|
| `internal/conn/doc.go` | Package overview pointing at the spec. |
| `internal/conn/errors.go` | Sentinels (`ErrNoDeadline`, `ErrInvalidGreeting`, …) + `*ErrPeerError`. |
| `internal/conn/options.go` | `config`, `Option`, `WithMaxMetadataSize`, `WithMaxHandshakeCommandSize`, `WithMaxFrameBodySize`, defaults. |
| `internal/conn/conn.go` | `Conn` struct, `ReadFrame`, `WriteFrame`, `PeerMetadata`, `Close`, `RemoteAddr`, `LocalAddr`. |
| `internal/conn/handshake.go` | `ClientHandshake`, `ServerHandshake`, `emitERROR` helper, ctx-watcher, greeting + handshake driver loop. |
| `internal/conn/options_test.go` | Unit tests for option panics + defaults. |
| `internal/conn/handshake_test.go` | Greeting + handshake-driver unit tests (every sentinel exercised). |
| `internal/conn/conn_test.go` | Post-handshake traffic tests, Close semantics, race tests. |
| `internal/conn/mech_test.go` | Cross-mechanism conformance table (NULL/PLAIN/CURVE × client/server). |
| `internal/conn/interop/Dockerfile` | Pinned libzmq 4.3.5 image used by interop fixtures. |
| `internal/conn/interop/fixture/fixture.go` | Helpers to spin libzmq peer container, build endpoints, attach `Socket-Type=PAIR` metadata. |
| `internal/conn/interop/interop_test.go` | Build-tagged matrix runner: 3 mech × 2 transport × 2 directions × 3 scenarios + 2 negative. |

### Files modified

| Path | Change |
|------|--------|
| `internal/wire/command.go` | Add `MessageCommandName = "MESSAGE"` constant (additive). |
| `internal/wire/greeting_io.go` | Add `ReadGreetingPhaseA(io.Reader) error`; refactor `ReadGreeting` to call it (additive). |
| `internal/wire/greeting_io_test.go` | Tests for the new phase-A helper. |
| `internal/security/interfaces.go` | Add `Name() string` to `Mechanism` interface (additive). |
| `internal/security/null/state.go` | `(*State).Name()` returns `"NULL"`. |
| `internal/security/plain/client.go`, `server.go` | `Name()` returns `"PLAIN"` on both. |
| `internal/security/curve/client.go`, `server.go` | `Name()` returns `"CURVE"` on both. |
| `internal/security/curve/codec.go` | Drop private `messageCommandName`; reference `wire.MessageCommandName`. |
| `docs/specs/01-zmtp-wire-protocol.md` | Add F4 amendment subsection (`MessageCommandName`, `ReadGreetingPhaseA`). |
| `docs/specs/02a-security-null.md` | Add F4 amendment (`Name()` on `null.State`). |
| `docs/specs/02b-security-plain.md` | Add F4 amendment (`Name()` on PLAIN states). |
| `docs/specs/02c-security-curve.md` | Add F4 amendment (`Name()` on CURVE states). |
| `docs/specs/00-meta-overview.md` | Update phase status when F4 work begins / completes; add F1/F2 amendments references in §4 amendment notes. |

All `internal/security/*` files keep existing call signatures; `Name()` is purely additive on a frozen surface.

---

## Chunk 1: F1 + F2 amendments

This chunk makes F4 buildable: the wire and security layers grow the additive surface area F4 needs (one constant, one helper, one method on five types). Frozen tags `phase-1-wire-complete`, `phase-2a/2b/2c-…-complete` remain valid because every change is additive on the existing interface.

### Task 1: Add `wire.MessageCommandName` constant

**Files:**
- Modify: `internal/wire/command.go`
- Modify: `internal/wire/command_test.go` (or create new test if not present)

- [ ] **Step 1: Read existing wire command name constants for pattern**

Run: `grep -n 'CommandName' internal/wire/*.go`
Expected: see `ReadyCommandName`, `ErrorCommandName`, `PingCommandName`, `PongCommandName`, `SubscribeCommandName`, `CancelCommandName`. Confirms the pattern: `<Name>CommandName = "<NAME>"` at top of the corresponding file.

- [ ] **Step 2: Write a failing test for `MessageCommandName`**

Add to `internal/wire/command_test.go` (create the test if file doesn't have one, or append to an existing block):

```go
func TestMessageCommandName(t *testing.T) {
	if MessageCommandName != "MESSAGE" {
		t.Fatalf("MessageCommandName = %q, want %q", MessageCommandName, "MESSAGE")
	}
}
```

- [ ] **Step 3: Run the test to verify it fails to compile**

Run: `go test ./internal/wire/ -run TestMessageCommandName`
Expected: build failure — `undefined: MessageCommandName`.

- [ ] **Step 4: Add the constant**

Append to `internal/wire/command.go` (placed near the bottom of the file or as a sibling to existing command names — look for an existing `Name = "READY"` style block and add nearby):

```go
// MessageCommandName is the wire name for the MESSAGE command — the
// envelope CURVE wraps user data into post-handshake. NULL and PLAIN
// do not use it. See RFC 25/CURVEZMQ §"only MESSAGE commands are
// encrypted".
const MessageCommandName = "MESSAGE"
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/wire/ -run TestMessageCommandName -v`
Expected: PASS.

- [ ] **Step 6: Verify nothing else broke**

Run: `go test ./internal/wire/...`
Expected: all wire tests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/wire/command.go internal/wire/command_test.go
git commit -m "wire: add MessageCommandName constant (F4 amendment)

Additive: F4 needs to identify CURVE-wrapped MESSAGE commands in the
post-handshake stream. Symmetric with ReadyCommandName/ErrorCommandName/
PingCommandName/etc. F2c will switch to wire.MessageCommandName in a
later F4 task."
```

---

### Task 2: Add `wire.ReadGreetingPhaseA` helper and refactor `ReadGreeting`

**Files:**
- Modify: `internal/wire/greeting_io.go`
- Modify: `internal/wire/greeting_io_test.go`

- [ ] **Step 1: Read current `ReadGreeting`**

Run: `cat internal/wire/greeting_io.go`
Expected: single function reading 64 bytes via `io.ReadFull`, calling `DecodeGreeting`. The amendment splits this into phase-A (11 bytes: signature + version major) and phase-B (53 bytes: rest).

- [ ] **Step 2: Write failing tests for `ReadGreetingPhaseA`**

Append to `internal/wire/greeting_io_test.go`:

```go
func TestReadGreetingPhaseAHappyPath(t *testing.T) {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"}); err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(buf[:11])
	if err := ReadGreetingPhaseA(r); err != nil {
		t.Fatalf("ReadGreetingPhaseA: %v", err)
	}
}

func TestReadGreetingPhaseATruncated(t *testing.T) {
	var buf [GreetingSize]byte
	_ = EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"})
	if err := ReadGreetingPhaseA(bytes.NewReader(buf[:5])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadGreetingPhaseABadSignature(t *testing.T) {
	bad := make([]byte, 11)
	bad[0] = 0xAA
	bad[9] = 0x7F
	bad[10] = 0x03
	if err := ReadGreetingPhaseA(bytes.NewReader(bad)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

func TestReadGreetingPhaseABadVersionMajor(t *testing.T) {
	bad := make([]byte, 11)
	bad[0] = 0xFF
	bad[9] = 0x7F
	bad[10] = 0x02 // major = 2 → ZMTP 2.x
	if err := ReadGreetingPhaseA(bytes.NewReader(bad)); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
}

func TestReadGreetingPhaseAStopsAfter11Bytes(t *testing.T) {
	// Reader yields one byte at a time; assert ReadGreetingPhaseA reads
	// exactly 11 and no more.
	var buf [GreetingSize]byte
	_ = EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"})
	cr := &countingReader{src: bytes.NewReader(buf[:])}
	if err := ReadGreetingPhaseA(cr); err != nil {
		t.Fatal(err)
	}
	if cr.n != 11 {
		t.Fatalf("read %d bytes, want exactly 11", cr.n)
	}
}

type countingReader struct {
	src io.Reader
	n   int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.n += n
	return n, err
}
```

- [ ] **Step 3: Run tests to verify they fail to compile**

Run: `go test ./internal/wire/ -run 'TestReadGreetingPhaseA' -v`
Expected: build failure — `undefined: ReadGreetingPhaseA`.

- [ ] **Step 4: Implement `ReadGreetingPhaseA` and refactor `ReadGreeting`**

Replace the body of `internal/wire/greeting_io.go` with:

```go
package wire

import (
	"fmt"
	"io"
)

// ReadGreetingPhaseA reads the first 11 bytes of a ZMTP 3.1 greeting
// (signature 10 B + version major 1 B) from r and validates them.
//
// On any byte mismatch, returns the appropriate sentinel without
// consuming additional bytes:
//   - signature bytes wrong → ErrInvalidSignature.
//   - version major != 0x03 → ErrUnsupportedVersion.
//
// Truncated input returns io.ErrUnexpectedEOF.
//
// This is the lockstep gate at the top of a ZMTP greeting per RFC 23
// §3.2: it lets a peer reject a connection cleanly before the
// remaining 53 bytes are read.
func ReadGreetingPhaseA(r io.Reader) error {
	var hdr [11]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if hdr[0] != 0xFF || hdr[9] != 0x7F {
		return fmt.Errorf("%w: got 0x%02X..0x%02X, want 0xFF..0x7F", ErrInvalidSignature, hdr[0], hdr[9])
	}
	for i := 1; i < 9; i++ {
		if hdr[i] != 0 {
			return fmt.Errorf("%w: byte %d = 0x%02X, want 0x00", ErrInvalidSignature, i, hdr[i])
		}
	}
	if hdr[10] != 0x03 {
		return fmt.Errorf("%w: got major %d, want 3", ErrUnsupportedVersion, hdr[10])
	}
	return nil
}

// ReadGreeting reads exactly GreetingSize bytes from r and decodes them.
// Returns io.ErrUnexpectedEOF on truncated input.
//
// Internally calls ReadGreetingPhaseA on the first 11 bytes (signature
// + version major), then reads the remaining 53 bytes (version minor +
// mechanism + as-server + filler) and decodes the full buffer.
func ReadGreeting(r io.Reader) (Greeting, error) {
	var buf [GreetingSize]byte
	// Phase-A: signature + version major. Validates inline; on failure we
	// abort before reading the remaining 53 bytes (RFC 23 §3.2 lockstep).
	if err := ReadGreetingPhaseA(r); err != nil {
		return Greeting{}, err
	}
	// Reconstruct the validated phase-A bytes; ReadGreetingPhaseA does not
	// return them, but we know exactly what they are post-validation.
	buf[0] = 0xFF
	// buf[1..8] = 0 (already zero)
	buf[9] = 0x7F
	buf[10] = 0x03
	if _, err := io.ReadFull(r, buf[11:]); err != nil {
		if err == io.EOF {
			return Greeting{}, io.ErrUnexpectedEOF
		}
		return Greeting{}, err
	}
	return DecodeGreeting(buf[:])
}

// WriteGreeting encodes g and writes the resulting GreetingSize bytes to w.
func WriteGreeting(w io.Writer, g Greeting) error {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], g); err != nil {
		return err
	}
	_, err := w.Write(buf[:])
	return err
}
```

- [ ] **Step 5: Run new tests to verify they pass**

Run: `go test ./internal/wire/ -run 'TestReadGreetingPhaseA' -v`
Expected: all 5 PhaseA tests PASS.

- [ ] **Step 6: Run full wire suite to verify no regression**

Run: `go test ./internal/wire/...`
Expected: all PASS (existing `TestReadGreetingHappyPath`, `TestReadGreetingPartialReads`, `TestReadGreetingTruncated`, `TestWriteGreetingHappyPath` still pass after the refactor).

- [ ] **Step 7: Run race detector**

Run: `go test -race ./internal/wire/...`
Expected: PASS, no data races.

- [ ] **Step 8: Commit**

```bash
git add internal/wire/greeting_io.go internal/wire/greeting_io_test.go
git commit -m "wire: add ReadGreetingPhaseA helper, refactor ReadGreeting (F4 amendment)

Additive: F4 needs lockstep greeting validation — read+validate the
11-byte signature + version major before deciding whether to read the
remaining 53 bytes. ReadGreeting now delegates phase-A to the helper
and reconstructs the full 64-byte buffer from the validated values.

Existing ReadGreeting/WriteGreeting tests unchanged; new tests cover
phase-A happy path, truncation, bad signature, bad version major,
and exact-11-byte read bound."
```

---

### Task 3: Add `Name() string` to `security.Mechanism` interface

**Files:**
- Modify: `internal/security/interfaces.go`
- Modify: `internal/security/interfaces_conformance_test.go` (extend compile-time assertions; the existing tests already type-assert each concrete type as `Mechanism` — once the interface grows the method, those assertions only compile if every type implements it).

- [ ] **Step 1: Add `Name()` to the `Mechanism` interface**

Edit `internal/security/interfaces.go`. Find the `Mechanism` interface block and append a new method. The method goes after `PeerMetadata()` for tidiness:

```go
	// Name returns the wire mechanism name advertised in the ZMTP
	// greeting — one of "NULL", "PLAIN", "CURVE". Stable for the
	// lifetime of the Mechanism. Used by F4 (connection layer) to
	// populate the greeting's mechanism field and to validate the
	// peer-advertised mechanism matches.
	Name() string
```

The complete `Mechanism` interface should now end with the existing `PeerMetadata` doc comment + signature, then this `Name` doc comment + signature.

- [ ] **Step 2: Run security tests to verify compile failures**

Run: `go test ./internal/security/...`
Expected: build failures across `null`, `plain`, `curve` packages because none of the concrete types implement `Name()`. Specifically, `internal/security/interfaces_conformance_test.go` should fail with `*null.State does not implement security.Mechanism (missing Name method)` and similar for plain/curve.

- [ ] **Step 3: Commit interface-only change (intentionally broken-build commit on this branch)**

This task creates a build break that is fixed in the next four tasks. We commit the interface change in isolation so the diff is reviewable. (Subsequent tasks fix one mechanism each.)

```bash
git add internal/security/interfaces.go
git commit -m "security: add Name() to Mechanism interface (F4 amendment)

Interface-only commit; concrete implementations follow in subsequent
commits (null, plain client/server, curve client/server). Build is
intentionally broken until Tasks 4–6 land.

Frozen tags phase-2a/2b/2c-…-complete remain valid: this is additive on
a frozen surface (precedent: Wrap/Unwrap added retroactively in F2c)."
```

---

### Task 4: Implement `(*null.State).Name()`

**Files:**
- Modify: `internal/security/null/state.go`
- Modify: `internal/security/null/state_test.go`

- [ ] **Step 1: Write failing test**

Append to `internal/security/null/state_test.go`:

```go
func TestStateName(t *testing.T) {
	s := New(nil)
	if got := s.Name(); got != "NULL" {
		t.Fatalf("Name() = %q, want %q", got, "NULL")
	}
}
```

- [ ] **Step 2: Run test to verify it fails to compile**

Run: `go test ./internal/security/null/ -run TestStateName`
Expected: build failure — `s.Name undefined`.

- [ ] **Step 3: Add `Name` method**

Append to `internal/security/null/state.go` (place near other `*State` methods):

```go
// Name returns "NULL". See security.Mechanism.Name.
func (s *State) Name() string { return "NULL" }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/security/null/ -run TestStateName -v`
Expected: PASS.

- [ ] **Step 5: Run full null package test suite**

Run: `go test -race ./internal/security/null/...`
Expected: all PASS, no races.

- [ ] **Step 6: Commit**

```bash
git add internal/security/null/state.go internal/security/null/state_test.go
git commit -m "security/null: implement Mechanism.Name() (F4 amendment)

Returns the constant string \"NULL\". Restores build for the null
package after the Mechanism interface gained Name() in the previous
commit."
```

---

### Task 5: Implement `Name()` on `plain.ClientState` and `plain.ServerState`

**Files:**
- Modify: `internal/security/plain/client.go`
- Modify: `internal/security/plain/server.go`
- Modify: `internal/security/plain/client_test.go`
- Modify: `internal/security/plain/server_test.go`

- [ ] **Step 1: Write failing tests**

Append to `internal/security/plain/client_test.go`:

```go
func TestClientStateName(t *testing.T) {
	c, err := NewClient([]byte("u"), []byte("p"), nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got := c.Name(); got != "PLAIN" {
		t.Fatalf("Name() = %q, want %q", got, "PLAIN")
	}
}
```

Append to `internal/security/plain/server_test.go`:

```go
func TestServerStateName(t *testing.T) {
	s := NewServer(func(_, _ []byte) error { return nil }, nil)
	if got := s.Name(); got != "PLAIN" {
		t.Fatalf("Name() = %q, want %q", got, "PLAIN")
	}
}
```

- [ ] **Step 2: Run tests to verify build failure**

Run: `go test ./internal/security/plain/ -run 'StateName'`
Expected: build failure — both methods undefined.

- [ ] **Step 3: Add `Name` to `ClientState`**

Append to `internal/security/plain/client.go` (near other `*ClientState` methods):

```go
// Name returns "PLAIN". See security.Mechanism.Name.
func (c *ClientState) Name() string { return "PLAIN" }
```

- [ ] **Step 4: Add `Name` to `ServerState`**

Append to `internal/security/plain/server.go` (near other `*ServerState` methods):

```go
// Name returns "PLAIN". See security.Mechanism.Name.
func (s *ServerState) Name() string { return "PLAIN" }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/security/plain/ -run 'StateName' -v`
Expected: both PASS.

- [ ] **Step 6: Run full plain package test suite**

Run: `go test -race ./internal/security/plain/...`
Expected: all PASS, no races.

- [ ] **Step 7: Commit**

```bash
git add internal/security/plain/client.go internal/security/plain/server.go internal/security/plain/client_test.go internal/security/plain/server_test.go
git commit -m "security/plain: implement Mechanism.Name() (F4 amendment)

Both ClientState and ServerState return \"PLAIN\". Restores build for
the plain package."
```

---

### Task 6: Implement `Name()` on `curve.ClientState` and `curve.ServerState`

**Files:**
- Modify: `internal/security/curve/client.go`
- Modify: `internal/security/curve/server.go`
- Modify: `internal/security/curve/client_test.go`
- Modify: `internal/security/curve/server_test.go`

- [ ] **Step 1: Write failing tests**

Append to `internal/security/curve/client_test.go`:

```go
func TestClientStateName(t *testing.T) {
	clientPub, clientSec, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	serverPub, _, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	c, err := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got := c.Name(); got != "CURVE" {
		t.Fatalf("Name() = %q, want %q", got, "CURVE")
	}
}
```

Append to `internal/security/curve/server_test.go`:

```go
func TestServerStateName(t *testing.T) {
	serverPub, serverSec, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	s, err := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if got := s.Name(); got != "CURVE" {
		t.Fatalf("Name() = %q, want %q", got, "CURVE")
	}
}
```

If `wire` is not yet imported in `server_test.go`, add the import.

- [ ] **Step 2: Run tests to verify build failure**

Run: `go test ./internal/security/curve/ -run 'StateName'`
Expected: build failure — both methods undefined.

- [ ] **Step 3: Add `Name` to `ClientState`**

Append to `internal/security/curve/client.go` (near other `*ClientState` methods):

```go
// Name returns "CURVE". See security.Mechanism.Name.
func (c *ClientState) Name() string { return "CURVE" }
```

- [ ] **Step 4: Add `Name` to `ServerState`**

Append to `internal/security/curve/server.go` (near other `*ServerState` methods):

```go
// Name returns "CURVE". See security.Mechanism.Name.
func (s *ServerState) Name() string { return "CURVE" }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/security/curve/ -run 'StateName' -v`
Expected: both PASS.

- [ ] **Step 6: Run full security suite (build is now whole)**

Run: `go test -race ./internal/security/...`
Expected: all PASS — including the cross-package conformance tests in `interface_conformance_test.go`. The compile-time assertions there now require all five concrete types to satisfy the extended `Mechanism` interface.

- [ ] **Step 7: Commit**

```bash
git add internal/security/curve/client.go internal/security/curve/server.go internal/security/curve/client_test.go internal/security/curve/server_test.go
git commit -m "security/curve: implement Mechanism.Name() (F4 amendment)

Both ClientState and ServerState return \"CURVE\". Restores build for
the curve package; the security tree (including conformance tests in
internal/security/interfaces_conformance_test.go) now compiles and
passes."
```

---

### Task 7: Switch `internal/security/curve/codec.go` and `codec_test.go` to `wire.MessageCommandName`

**Files:**
- Modify: `internal/security/curve/codec.go`
- Modify: `internal/security/curve/codec_test.go` (test file is in the same package and references the private `messageCommandName`; must be updated together to keep the build green)

- [ ] **Step 1: Locate every reference to the private constant**

Run: `grep -rn 'messageCommandName' internal/security/curve/`
Expected: 4 matches —
  - `codec.go`: 1 hit (the `const messageCommandName  = "MESSAGE"` declaration in the `const (...)` block).
  - `codec_test.go`: 3 hits (lines ≈521, 522, 553 — equality check, error message, `wire.Command{Name: messageCommandName, …}` literal).

- [ ] **Step 2: Drop the private constant in `codec.go`; reference `wire.MessageCommandName`**

In `internal/security/curve/codec.go`:
- Remove the `messageCommandName  = "MESSAGE"` line from the `const (...)` block.
- Replace every other reference to `messageCommandName` in this file with `wire.MessageCommandName`.

- [ ] **Step 3: Update `codec_test.go` references**

In `internal/security/curve/codec_test.go`:
- Replace each `messageCommandName` reference (3 sites) with `wire.MessageCommandName`.
- The `wire` package is already imported in this file (it uses `wire.Command{...}` literals already), so no import change is needed; verify by re-reading the import block.

Run after both edits: `grep -rn 'messageCommandName' internal/security/curve/`
Expected: no matches anywhere in the directory.

- [ ] **Step 4: Verify imports of `codec.go`**

`codec.go` already imports `internal/wire` (it operates on `wire.Command` types). Confirm via: `head -15 internal/security/curve/codec.go`
Expected: `wire` import present in the imports block.

- [ ] **Step 5: Run curve tests**

Run: `go test -race ./internal/security/curve/...`
Expected: all PASS — encoding/decoding behaviour is byte-identical because the constant value is the same string.

- [ ] **Step 6: Run full security tests once more**

Run: `go test -race ./internal/security/...`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/security/curve/codec.go internal/security/curve/codec_test.go
git commit -m "security/curve: use wire.MessageCommandName (F4 amendment)

Drops the private messageCommandName constant in favour of the public
wire.MessageCommandName added in an earlier F4 commit. codec_test.go
referenced the private name from the same package and is updated in
the same commit to keep the build green. No behavioural change — same
string, same encoded bytes — but consolidates ZMTP command names in
the wire layer where the rest live."
```

---

### Task 8: Update spec amendment notes (F1 + F2)

**Files:**
- Modify: `docs/specs/01-zmtp-wire-protocol.md`
- Modify: `docs/specs/02a-security-null.md`
- Modify: `docs/specs/02b-security-plain.md`
- Modify: `docs/specs/02c-security-curve.md`

These edits add a small "F4 amendment" subsection to each frozen spec, documenting the additive changes that landed during F4 work. The frozen tags remain valid because the changes are additive on the frozen surface. Use the precedent established by `00-meta-overview.md` §F1 amendments and §F2a/F2b amendments — Wrap/Unwrap added by F2c.

- [ ] **Step 1: Add F4 amendment to `docs/specs/01-zmtp-wire-protocol.md`**

Find the section heading where similar amendments would naturally live (look for an existing "F2 amendment" or "additive change" subsection if present, or place near the bottom of the spec body before References). Add:

```markdown
## F4 amendments

Additive changes landed after `phase-1-wire-complete` was tagged. None
break the tagged API; they extend it. Tracked here (rather than
re-tagged) so the original phase boundary stays intact.

- `MessageCommandName = "MESSAGE"` constant added to `internal/wire`.
  Symmetric with `ReadyCommandName`, `ErrorCommandName`,
  `PingCommandName`, etc. F4 (`internal/conn`) and F2c
  (`internal/security/curve`) now reference the wire constant instead
  of using string literals or shadow constants.

- `ReadGreetingPhaseA(io.Reader) error` helper added to
  `internal/wire`. Reads and validates the first 11 bytes of a ZMTP
  3.1 greeting (signature 10 B + version major 1 B). On signature
  failure → `ErrInvalidSignature`; on `version major != 0x03` →
  `ErrUnsupportedVersion`; truncated input → `io.ErrUnexpectedEOF`.
  `ReadGreeting` was refactored to call this helper for the first 11
  bytes, then read the remaining 53 bytes inline. F4 uses the helper
  directly to short-circuit lockstep handshake on phase-A failure.
```

- [ ] **Step 2: Add F4 amendment to `docs/specs/02a-security-null.md`**

Append before the References section (or wherever amendment-style notes live):

```markdown
## F4 amendments

Additive change landed after `phase-2a-null-complete` was tagged.
Frozen tag remains valid (additive on frozen surface).

- `(*State).Name() string` returns `"NULL"`. Required by the extended
  `security.Mechanism` interface — F4 (connection layer) needs the
  wire mechanism name to populate the ZMTP greeting and to validate
  the peer-advertised mechanism matches.
```

- [ ] **Step 3: Add F4 amendment to `docs/specs/02b-security-plain.md`**

Append:

```markdown
## F4 amendments

Additive change landed after `phase-2b-plain-complete` was tagged.
Frozen tag remains valid (additive on frozen surface).

- `(*ClientState).Name() string` and `(*ServerState).Name() string`
  both return `"PLAIN"`. Required by the extended `security.Mechanism`
  interface — F4 needs the wire mechanism name for greeting
  population and peer validation.
```

- [ ] **Step 4: Add F4 amendment to `docs/specs/02c-security-curve.md`**

Append:

```markdown
## F4 amendments

Additive changes landed after `phase-2c-curve-complete` was tagged.
Frozen tag remains valid (additive on frozen surface).

- `(*ClientState).Name() string` and `(*ServerState).Name() string`
  both return `"CURVE"`. Required by the extended `security.Mechanism`
  interface (F4 connection layer).

- `internal/security/curve/codec.go` no longer defines a private
  `messageCommandName` constant; it now references the public
  `wire.MessageCommandName`. No behavioural change — same string, same
  encoded bytes. The wire layer is the canonical home for ZMTP
  command-name constants.
```

- [ ] **Step 5: Verify spec files render**

Run: `grep -c '## F4 amendments' docs/specs/01-zmtp-wire-protocol.md docs/specs/02a-security-null.md docs/specs/02b-security-plain.md docs/specs/02c-security-curve.md`
Expected: each file outputs `1`.

- [ ] **Step 6: Commit**

```bash
git add docs/specs/01-zmtp-wire-protocol.md docs/specs/02a-security-null.md docs/specs/02b-security-plain.md docs/specs/02c-security-curve.md
git commit -m "specs: document F4 amendments to F1/F2 (additive on frozen surface)

Adds F4-amendment subsections to the four frozen specs (01 wire, 02a
null, 02b plain, 02c curve) documenting the additive changes landed
during F4 work:

- F1: wire.MessageCommandName, wire.ReadGreetingPhaseA.
- F2: Mechanism.Name() implemented by null/plain/curve states.
- F2c codec switches from private messageCommandName to
  wire.MessageCommandName.

Frozen tags remain valid (additive only); precedent is the
Wrap/Unwrap amendment landed retroactively in F2c."
```

---

**End of Chunk 1.** F1 and F2 now have everything F4 needs. The next chunk starts the F4 package itself.

---

## Chunk 2: F4 skeleton + Conn struct + handshake helpers

This chunk lands the `internal/conn` package skeleton: doc, errors.go, options.go, the `Conn` struct (with non-handshake methods stubbed), and the two private handshake helpers (`emitERROR`, `runWithCtxDeadline`). Greeting, handshake driver, and the public constructors are deferred to Chunk 3.

### Task 9: F4 package skeleton — doc.go + errors.go + options.go

**Files:**
- Create: `internal/conn/doc.go`
- Create: `internal/conn/errors.go`
- Create: `internal/conn/options.go`
- Create: `internal/conn/options_test.go`

- [ ] **Step 1: Create `internal/conn/doc.go`**

```go
// Package conn implements the F4 connection layer for ZMTP 3.1.
//
// It takes a raw net.Conn (typically from internal/transport via F5)
// plus a configured security.Mechanism (from internal/security) and
// produces a *Conn after a successful greeting + handshake. The *Conn
// exposes blocking ReadFrame / WriteFrame on the post-handshake byte
// stream.
//
// F4 owns no transport plumbing (F5 calls transport.Dial / Listen),
// no socket-type semantics (F5), no reconnect (F5), no operational
// heartbeat (F6), and no long-lived goroutines after handshake.
//
// See docs/specs/04-connection-layer.md for the full specification.
package conn
```

- [ ] **Step 2: Create `internal/conn/errors.go`**

```go
package conn

import (
	"errors"
	"fmt"
)

// Sentinels returned by ClientHandshake / ServerHandshake. Every sentinel
// is wrapped via fmt.Errorf("%w: …", sentinel, …) with context (mechanism
// name, side, raw conn RemoteAddr) before being returned. F5 uses
// errors.Is to discriminate.
var (
	// ErrNoDeadline is returned before the constructor touches raw when
	// the supplied ctx carries no deadline. Spec §6.6.
	ErrNoDeadline = errors.New("conn: ctx must carry a deadline")

	// ErrInvalidGreeting is returned when the peer's ZMTP greeting fails
	// signature validation. Spec §6.1 step 2.
	ErrInvalidGreeting = errors.New("conn: invalid ZMTP greeting")

	// ErrMechanismMismatch is returned when the peer-advertised mechanism
	// in the greeting does not match our local Mechanism.Name(). Spec §6.1
	// step 5. RFC 23 §3.3: "If the mechanisms don't match, the connection
	// MUST be closed."
	ErrMechanismMismatch = errors.New("conn: mechanism mismatch with peer")

	// ErrRoleConflict is returned for asymmetric mechanisms (PLAIN, CURVE)
	// when both peers advertise the same as-server bit. NULL is symmetric
	// and ignores the bit. Spec §6.1 step 6.
	ErrRoleConflict = errors.New("conn: as-server role conflict with peer")

	// ErrHandshakeFail wraps any non-sentinel reason a handshake aborted —
	// peer-emitted ERROR, local mech.Receive / mech.Start error, malformed
	// command body, mid-handshake EOF. Spec §6.2 / §6.3.
	ErrHandshakeFail = errors.New("conn: handshake aborted")

	// ErrMetadataTooLarge is returned when a metadata-bearing handshake
	// command body (READY for NULL/PLAIN/CURVE; INITIATE for PLAIN/CURVE)
	// exceeds the configured cap. Spec §6.2.
	ErrMetadataTooLarge = errors.New("conn: handshake metadata exceeds cap")

	// ErrCommandTooLarge is returned when any single handshake command
	// frame exceeds the configured per-command cap. Spec §6.2.
	ErrCommandTooLarge = errors.New("conn: handshake command exceeds cap")

	// ErrUnexpectedFrame is returned during the handshake when the peer
	// sends a FrameMessage instead of a FrameCommand. Spec §6.2.
	ErrUnexpectedFrame = errors.New("conn: unexpected frame kind during handshake")
)

// ErrPeerError carries the reason from a peer-emitted ERROR command on
// the post-handshake stream. Surfaced as a pointer so errors.As can
// recover the Reason. The in-handshake equivalent (peer ERROR during
// handshake) does not use *ErrPeerError; it returns ErrHandshakeFail
// wrapping a string with the reason embedded — F5 reacts differently.
type ErrPeerError struct {
	Reason string
}

func (e *ErrPeerError) Error() string {
	return fmt.Sprintf("conn: peer ERROR: %q", e.Reason)
}
```

- [ ] **Step 3: Create `internal/conn/options.go`**

```go
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
```

- [ ] **Step 4: Create `internal/conn/options_test.go`**

```go
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
```

- [ ] **Step 5: Run tests**

Run: `go test -race ./internal/conn/...`
Expected: 5 tests PASS (TestNewConfigDefaults, TestWithMaxMetadataSize, TestWithMaxHandshakeCommandSize, TestWithMaxFrameBodySize, TestOptionsPanicOnNonPositive with 6 subtests).

- [ ] **Step 6: Run vet**

Run: `go vet ./internal/conn/...`
Expected: no issues.

- [ ] **Step 7: Commit**

```bash
git add internal/conn/doc.go internal/conn/errors.go internal/conn/options.go internal/conn/options_test.go
git commit -m "conn: package skeleton — doc, errors, options

Lays down the F4 (internal/conn) package boundary: doc.go pointing at
the spec; errors.go with all sentinels and *ErrPeerError; options.go
with config, Option, and the three With* knobs (max-metadata,
max-handshake-command, max-frame-body) plus their defaults. No
constructors yet — those land alongside the handshake driver.

Spec: docs/specs/04-connection-layer.md §3.2, §5.1."
```

---

### Task 10: `Conn` struct + Close + RemoteAddr/LocalAddr

**Files:**
- Create: `internal/conn/conn.go`
- Create: `internal/conn/conn_test.go`

This task lands the `*Conn` type with its non-handshake methods. `ReadFrame` and `WriteFrame` are stubbed to return `errors.New("not implemented")`; they get real bodies in Chunk 3. The struct shape, Close idempotency, and addr delegation are testable now.

- [ ] **Step 1: Write failing tests**

Create `internal/conn/conn_test.go`:

```go
package conn

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/tomi77/zmq4/internal/security/null"
	"github.com/tomi77/zmq4/internal/wire"
)

// newPipeConn builds an unhandshaken *Conn around one end of a net.Pipe
// for testing the non-handshake surface. The mech is a fresh null state
// (it is never driven; the conn is post-construction synthetic).
func newPipeConn(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	ours, peer := net.Pipe()
	cfg := newConfig(nil)
	c := &Conn{
		raw:      ours,
		fr:       wire.NewFrameReader(ours, wire.WithMaxBodySize(cfg.maxFrameBodySize)),
		fw:       wire.NewFrameWriter(ours),
		mech:     null.New(nil),
		peerMeta: nil,
	}
	t.Cleanup(func() {
		_ = c.Close()
		_ = peer.Close()
	})
	return c, peer
}

func TestConnCloseIdempotent(t *testing.T) {
	c, _ := newPipeConn(t)
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestConnCloseClosesRaw(t *testing.T) {
	c, peer := newPipeConn(t)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Reading the peer side should now see EOF (or ErrClosedPipe — net.Pipe
	// closes both directions on one Close).
	buf := make([]byte, 1)
	_, err := peer.Read(buf)
	if err == nil {
		t.Fatalf("peer.Read after Close: nil error, want EOF/ErrClosedPipe")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("peer.Read after Close: %v, want io.EOF or io.ErrClosedPipe", err)
	}
}

func TestConnRemoteLocalAddrDelegate(t *testing.T) {
	c, peer := newPipeConn(t)
	if c.RemoteAddr() == nil {
		t.Errorf("RemoteAddr() = nil")
	}
	if c.LocalAddr() == nil {
		t.Errorf("LocalAddr() = nil")
	}
	// Both should equal the underlying conn's addrs.
	if c.RemoteAddr().String() != c.raw.RemoteAddr().String() {
		t.Errorf("RemoteAddr delegation mismatch")
	}
	if c.LocalAddr().String() != c.raw.LocalAddr().String() {
		t.Errorf("LocalAddr delegation mismatch")
	}
	_ = peer
}

func TestConnPeerMetadataReturnsStoredSlice(t *testing.T) {
	c, _ := newPipeConn(t)
	c.peerMeta = wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("PAIR")}}
	got := c.PeerMetadata()
	if len(got) != 1 || string(got[0].Name) != "Socket-Type" || string(got[0].Value) != "PAIR" {
		t.Fatalf("PeerMetadata() = %+v, want one Socket-Type=PAIR property", got)
	}
}
```

- [ ] **Step 2: Run tests to verify build failure**

Run: `go test ./internal/conn/...`
Expected: build failure — `Conn` undefined, `ReadFrame`/`WriteFrame`/`Close`/`RemoteAddr`/`LocalAddr`/`PeerMetadata` undefined.

- [ ] **Step 3: Create `internal/conn/conn.go`**

```go
package conn

import (
	"errors"
	"net"
	"sync"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/wire"
)

// Conn is one ZMTP 3.1 connection: a single, full-duplex peering over a
// raw net.Conn that has completed greeting and security handshake.
// Returned by ClientHandshake / ServerHandshake; never constructed by F5
// directly.
//
// ReadFrame is not goroutine-safe (one reader at a time). WriteFrame is
// goroutine-safe (internal mutex serialises bytes on raw). Close is
// idempotent; concurrent reads/writes after Close observe net.ErrClosed
// (or io.ErrClosedPipe for inproc per F3 §4.4).
type Conn struct {
	raw      net.Conn
	fr       *wire.FrameReader
	fw       *wire.FrameWriter
	mech     security.Mechanism
	peerMeta wire.Metadata

	writeMu sync.Mutex

	closeMu sync.Mutex
	closed  bool
}

// ReadFrame is implemented in Chunk 3.
func (c *Conn) ReadFrame() (wire.Frame, error) {
	return wire.Frame{}, errors.New("conn: ReadFrame not implemented")
}

// WriteFrame is implemented in Chunk 3.
func (c *Conn) WriteFrame(f wire.Frame) error {
	return errors.New("conn: WriteFrame not implemented")
}

// PeerMetadata returns the metadata advertised by the peer in handshake.
// The returned Metadata is a defensive clone made at handshake done
// (spec §4.2): owned by *Conn, decoupled from the mechanism, stable for
// the lifetime of the *Conn. Callers MUST NOT mutate it.
func (c *Conn) PeerMetadata() wire.Metadata { return c.peerMeta }

// Close releases the underlying raw net.Conn and unblocks any in-flight
// reader or writer. Idempotent. After Close, ReadFrame and WriteFrame
// return net.ErrClosed (or io.ErrClosedPipe for inproc).
//
// ZMTP 3.1 has no graceful disconnect handshake; F4 just releases the
// FD. F5 owns linger semantics for in-flight messages.
func (c *Conn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return nil
	}
	c.closed = true
	c.closeMu.Unlock()
	return c.raw.Close()
}

// RemoteAddr returns the underlying raw net.Conn's remote address.
// Stable for the lifetime of the *Conn including post-Close.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// LocalAddr returns the underlying raw net.Conn's local address.
// Stable for the lifetime of the *Conn including post-Close.
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -race ./internal/conn/...`
Expected: 4 tests PASS (TestConnCloseIdempotent, TestConnCloseClosesRaw, TestConnRemoteLocalAddrDelegate, TestConnPeerMetadataReturnsStoredSlice) + 5 from Task 9.

- [ ] **Step 5: Run vet**

Run: `go vet ./internal/conn/...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add internal/conn/conn.go internal/conn/conn_test.go
git commit -m "conn: Conn struct + Close + RemoteAddr/LocalAddr + PeerMetadata

Lands the *Conn type with its non-handshake surface. ReadFrame and
WriteFrame are stubbed (return 'not implemented' errors) until Chunk 4.
Close is idempotent, releases raw, unblocks in-flight I/O.
PeerMetadata returns the stored defensive clone from c.peerMeta.

Tests use synthetic *Conn over net.Pipe to exercise Close and addr
delegation without driving a handshake.

Spec: docs/specs/04-connection-layer.md §3.3, §4.2."
```

---

### Task 11: Handshake helpers — `emitERROR` + `runWithCtxDeadline`

**Files:**
- Create: `internal/conn/handshake.go`
- Create: `internal/conn/handshake_test.go`

This task lands the two private helpers used by both constructors: `emitERROR` (best-effort ERROR command emission) and `runWithCtxDeadline` (the ctx-watcher harness from spec §6.6 with the load-bearing `wg.Wait()` race fix).

- [ ] **Step 1: Write failing tests**

Create `internal/conn/handshake_test.go`:

```go
package conn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestEmitERRORHappyPath(t *testing.T) {
	var sink bytes.Buffer
	fw := wire.NewFrameWriter(&sink)
	emitERROR(fw, "no thanks")
	// The peer should see one FrameCommand containing an ERROR command
	// with reason "no thanks".
	fr := wire.NewFrameReader(&sink)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Kind != wire.FrameCommand {
		t.Fatalf("frame.Kind = %v, want FrameCommand", f.Kind)
	}
	cmd, err := wire.ParseCommand(f.Body)
	if err != nil {
		t.Fatalf("ParseCommand: %v", err)
	}
	ec, err := wire.ParseError(cmd)
	if err != nil {
		t.Fatalf("ParseError: %v", err)
	}
	if ec.Reason != "no thanks" {
		t.Fatalf("Reason = %q, want %q", ec.Reason, "no thanks")
	}
}

func TestEmitERRORTruncatesLongReason(t *testing.T) {
	long := strings.Repeat("x", 500)
	var sink bytes.Buffer
	fw := wire.NewFrameWriter(&sink)
	emitERROR(fw, long)
	fr := wire.NewFrameReader(&sink)
	f, _ := fr.ReadFrame()
	cmd, _ := wire.ParseCommand(f.Body)
	ec, err := wire.ParseError(cmd)
	if err != nil {
		t.Fatalf("ParseError: %v", err)
	}
	if len(ec.Reason) != 255 {
		t.Fatalf("Reason length = %d, want 255 (truncated)", len(ec.Reason))
	}
	if !strings.HasPrefix(ec.Reason, "xxxx") {
		t.Fatalf("Reason prefix unexpected: %q", ec.Reason[:10])
	}
}

func TestEmitERRORSwallowsWriteFailure(t *testing.T) {
	// Closed pipe → fw.WriteFrame returns io.ErrClosedPipe. emitERROR
	// must not panic and must return cleanly (it has no return value).
	a, b := net.Pipe()
	_ = a.Close()
	_ = b.Close()
	fw := wire.NewFrameWriter(a)
	emitERROR(fw, "doomed") // must not panic.
}

func TestRunWithCtxDeadlineSuccess(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	called := false
	err := runWithCtxDeadline(ctx, a, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("runWithCtxDeadline: %v", err)
	}
	if !called {
		t.Fatalf("inner fn was not invoked")
	}
	// After success, the deadline should be cleared so a fresh read on a
	// is not stuck with a past deadline.
	go func() { _, _ = b.Write([]byte{0xAA}) }()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(a, buf); err != nil {
		t.Fatalf("post-success read: %v (deadline not cleared?)", err)
	}
}

func TestRunWithCtxDeadlineCtxNoDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	err := runWithCtxDeadline(context.Background(), a, func() error {
		t.Fatalf("inner fn should NOT be called when ctx has no deadline")
		return nil
	})
	if !errors.Is(err, ErrNoDeadline) {
		t.Fatalf("err = %v, want ErrNoDeadline", err)
	}
}

func TestRunWithCtxDeadlineCtxCancelMidFn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := runWithCtxDeadline(ctx, a, func() error {
		// Block on a read; the ctx watcher will SetDeadline(past) and
		// unblock us with os.ErrDeadlineExceeded.
		buf := make([]byte, 1)
		_, err := io.ReadFull(a, buf)
		return err
	})
	if err == nil {
		t.Fatalf("expected error from cancelled handshake, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify build failure**

Run: `go test ./internal/conn/...`
Expected: build failure — `emitERROR`, `runWithCtxDeadline` undefined.

- [ ] **Step 3: Implement `emitERROR` in `internal/conn/handshake.go`**

Create `internal/conn/handshake.go`:

```go
package conn

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/tomi77/zmq4/internal/wire"
)

// emitERROR is a best-effort ERROR-command emitter used by the handshake
// driver to inform the peer of a local abort before tearing down the
// conn. RFC 23 §6 caps the reason at one octet length prefix (255 B);
// emitERROR truncates silently. All write/encode errors are swallowed —
// the conn is being torn down regardless.
func emitERROR(fw *wire.FrameWriter, reason string) {
	if len(reason) > 255 {
		reason = reason[:255]
	}
	cmd, err := wire.ErrorCommand{Reason: reason}.Encode()
	if err != nil {
		return // truncation guarantees this branch is unreachable.
	}
	body, err := wire.EncodeCommand(cmd)
	if err != nil {
		return
	}
	_ = fw.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body})
}

// runWithCtxDeadline executes fn while a watcher goroutine bridges
// ctx cancellation to raw.SetDeadline. ctx MUST carry a deadline; if
// not, ErrNoDeadline is returned before raw is touched.
//
// On entry: raw.SetDeadline(ctx-deadline-time).
// During fn: a watcher goroutine selects on ctx.Done() and on a private
// done channel; if ctx.Done() fires first, the watcher pokes
// raw.SetDeadline(time.Unix(1,0)) to unblock any in-flight Read/Write.
// On fn return: close(done); wg.Wait() (load-bearing — see spec §6.6
// for the race rationale); raw.SetDeadline(time.Time{}) to clear.
//
// fn's return value is propagated unchanged. If both ctx fired and fn
// returned an error, fn's error is returned (the deadline-induced
// os.ErrDeadlineExceeded is the natural surface).
func runWithCtxDeadline(ctx context.Context, raw net.Conn, fn func() error) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ErrNoDeadline
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return err
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			_ = raw.SetDeadline(time.Unix(1, 0))
		case <-done:
		}
	}()

	err := fn()
	close(done)
	wg.Wait()                                  // race fix: see spec §6.6.
	_ = raw.SetDeadline(time.Time{})           // clear deadline post-handshake.
	return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -race ./internal/conn/ -run 'EmitERROR|RunWithCtxDeadline' -v`
Expected: all 6 tests PASS.

- [ ] **Step 5: Run full conn suite**

Run: `go test -race ./internal/conn/...`
Expected: all PASS (Tasks 9–11 tests combined).

- [ ] **Step 6: Commit**

```bash
git add internal/conn/handshake.go internal/conn/handshake_test.go
git commit -m "conn: emitERROR + runWithCtxDeadline handshake helpers

emitERROR best-effort emits a wire-level ERROR command before abort,
truncating reason at 255 B per RFC 23 §6. All write/encode errors
swallowed — conn is being torn down.

runWithCtxDeadline bridges ctx cancellation to raw.SetDeadline using
a watcher goroutine. The wg.Wait() after closing done is load-bearing
(spec §6.6): without it the watcher could fire SetDeadline(past)
*after* the success path cleared the deadline, leaving the post-
handshake *Conn with a stuck deadline. Tests cover happy path
(deadline cleared after success), no-deadline (ErrNoDeadline before
raw is touched), and cancel-mid-fn (deadline-driven unblock).

Spec: docs/specs/04-connection-layer.md §6.2 (emitERROR), §6.6 (ctx-watcher)."
```

---

**End of Chunk 2.** Skeleton + helpers ready. Chunk 3 wires greeting, handshake driver, and the public constructors.

---

## Chunk 3: Greeting + handshake driver + public constructors

This chunk implements §6.1 (lockstep greeting with asymmetric send order), §6.2/§6.3 (handshake driver loop), and §6.6 integration. After this chunk, `ClientHandshake` and `ServerHandshake` work end-to-end on `net.Pipe`. Post-handshake `ReadFrame`/`WriteFrame` stubs from Chunk 2 remain in place; they get real bodies in Chunk 4.

### Task 12: Greeting flow — send + lockstep read

**Files:**
- Modify: `internal/conn/handshake.go` (add `greetingExchange` + helpers)
- Modify: `internal/conn/handshake_test.go` (add greeting tests)

This task implements §6.1: client sends greeting first then reads peer; server reads peer first then sends. Mechanism mismatch / role conflict / signature error / version downgrade all surface as the right sentinel. Greeting filler is ignored.

- [ ] **Step 1: Write failing tests**

Add `null` and `plain` to the existing import block at the top of `internal/conn/handshake_test.go` (the block already imports `bytes`, `context`, `errors`, `io`, `net`, `strings`, `testing`, `time`, `wire` from Task 11). Then append the test bodies below to the same file.

```go
// imports needed in this task (add to the existing import block at the top of the file):
//   "github.com/tomi77/zmq4/internal/security/null"
//   "github.com/tomi77/zmq4/internal/security/plain"

// driveGreetingPair runs greetingExchange on both sides in goroutines
// and returns the two errors. Uses TCP loopback (not net.Pipe) so that
// the asymmetric send-ordering can complete without deadlocking when
// both peers happen to share the same role bit (the spec explicitly
// supports symmetric NULL conns and ErrRoleConflict for PLAIN/CURVE
// — both require a buffered transport, not net.Pipe's synchronous one).
func driveGreetingPair(t *testing.T, ourSide, peerSide greetingTestSide) (ourErr, peerErr error) {
	t.Helper()
	a, b := tcpPipePair(t)
	defer a.Close()
	defer b.Close()
	type res struct{ err error }
	ours := make(chan res, 1)
	peer := make(chan res, 1)
	go func() {
		err := greetingExchange(a, ourSide.role, ourSide.mech)
		ours <- res{err}
	}()
	go func() {
		err := greetingExchange(b, peerSide.role, peerSide.mech)
		peer <- res{err}
	}()
	return (<-ours).err, (<-peer).err
}

// tcpPipePair returns two connected TCP loopback net.Conns. Used by
// greeting tests that exercise role-symmetric scenarios: net.Pipe is
// synchronous (zero-buffer) so two simultaneous Writes deadlock; the
// TCP socket buffer accepts the 64-byte greeting without blocking and
// lets the test progress to the validation logic that is actually
// being exercised. The listener is closed inline once the pair is
// established (the pair's lifetime is independent of it).
func tcpPipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := lis.Accept()
		ch <- accepted{c, err}
	}()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	a, err := dialer.Dial("tcp", lis.Addr().String())
	if err != nil {
		_ = lis.Close()
		t.Fatalf("dial: %v", err)
	}
	res := <-ch
	if res.err != nil {
		_ = a.Close()
		_ = lis.Close()
		t.Fatalf("accept: %v", res.err)
	}
	_ = lis.Close() // listener is no longer needed; pair is established.
	return a, res.c
}

type greetingTestSide struct {
	role greetingRole // greetingRoleClient or greetingRoleServer
	mech mockMech
}

type mockMech struct {
	name string
}

func (m mockMech) Name() string { return m.name }

func TestGreetingExchangeNullBothSides(t *testing.T) {
	our, peer := driveGreetingPair(t,
		greetingTestSide{greetingRoleClient, mockMech{"NULL"}},
		greetingTestSide{greetingRoleServer, mockMech{"NULL"}})
	if our != nil || peer != nil {
		t.Fatalf("our=%v peer=%v, want both nil", our, peer)
	}
}

func TestGreetingExchangeMechanismMismatch(t *testing.T) {
	our, peer := driveGreetingPair(t,
		greetingTestSide{greetingRoleClient, mockMech{"NULL"}},
		greetingTestSide{greetingRoleServer, mockMech{"PLAIN"}})
	if !errors.Is(our, ErrMechanismMismatch) {
		t.Errorf("our: want ErrMechanismMismatch, got %v", our)
	}
	if !errors.Is(peer, ErrMechanismMismatch) {
		t.Errorf("peer: want ErrMechanismMismatch, got %v", peer)
	}
}

func TestGreetingExchangeRoleConflictPLAIN(t *testing.T) {
	our, peer := driveGreetingPair(t,
		greetingTestSide{greetingRoleServer, mockMech{"PLAIN"}},
		greetingTestSide{greetingRoleServer, mockMech{"PLAIN"}})
	// Both peers claim as-server=true → role conflict.
	if !errors.Is(our, ErrRoleConflict) && !errors.Is(peer, ErrRoleConflict) {
		t.Fatalf("expected ErrRoleConflict on at least one side, got our=%v peer=%v", our, peer)
	}
}

func TestGreetingExchangeRoleConflictNULLIgnored(t *testing.T) {
	// Two NULL "clients" (both as-server=0 since NULL is symmetric — the
	// greetingRoleClient enum maps to as-server=0). Should succeed.
	our, peer := driveGreetingPair(t,
		greetingTestSide{greetingRoleClient, mockMech{"NULL"}},
		greetingTestSide{greetingRoleClient, mockMech{"NULL"}})
	if our != nil || peer != nil {
		t.Fatalf("our=%v peer=%v, want both nil for symmetric NULL", our, peer)
	}
}

func TestGreetingFillerIgnored(t *testing.T) {
	// Hand-craft a greeting with non-zero filler. Validate it is accepted.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		var buf [wire.GreetingSize]byte
		_ = wire.EncodeGreeting(buf[:], wire.Greeting{Mechanism: "NULL"})
		// Stomp filler bytes 33..63 with garbage.
		for i := 33; i < 64; i++ {
			buf[i] = byte(0xAA + i&0x0F)
		}
		_, _ = b.Write(buf[:])
	}()
	if err := greetingExchange(a, greetingRoleServer, mockMech{"NULL"}); err != nil {
		t.Fatalf("greeting with garbage filler should be accepted, got %v", err)
	}
}

func TestGreetingPhaseAFailureAbortsBeforeRest(t *testing.T) {
	// Peer sends a corrupt signature (byte 0). Our side must abort with
	// ErrInvalidGreeting after reading phase A only — the remaining 53
	// bytes must NOT be read.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		// Send only the broken phase-A 11 bytes; do NOT send phase-B.
		bad := make([]byte, 11)
		bad[0] = 0xAA
		bad[9] = 0x7F
		bad[10] = 0x03
		_, _ = b.Write(bad)
	}()
	err := greetingExchange(a, greetingRoleServer, mockMech{"NULL"})
	if !errors.Is(err, ErrInvalidGreeting) && !errors.Is(err, wire.ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidGreeting or wire.ErrInvalidSignature", err)
	}
}

func TestGreetingVersionDowngradeAbortsBeforeRest(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		// Phase-A only with version major = 0x02 (ZMTP 2.x).
		bad := make([]byte, 11)
		bad[0] = 0xFF
		bad[9] = 0x7F
		bad[10] = 0x02
		_, _ = b.Write(bad)
	}()
	err := greetingExchange(a, greetingRoleServer, mockMech{"NULL"})
	if !errors.Is(err, wire.ErrUnsupportedVersion) {
		t.Fatalf("err = %v, want wire.ErrUnsupportedVersion", err)
	}
}

// Compile-time check: real mechanisms also satisfy mockMech's Name shape.
var _ = []interface{ Name() string }{
	(*null.State)(nil),
	(*plain.ClientState)(nil),
}
```

- [ ] **Step 2: Run tests to verify build failure**

Run: `go test ./internal/conn/...`
Expected: build failure — `greetingRole`, `greetingRoleClient`, `greetingRoleServer`, `greetingExchange` undefined.

- [ ] **Step 3: Implement greeting flow**

Append to `internal/conn/handshake.go`:

```go
// greetingRole tags the local side of a greeting exchange. Clients send
// first; servers read first. The role also determines as-server for
// asymmetric mechanisms (PLAIN, CURVE).
type greetingRole int

const (
	greetingRoleClient greetingRole = 0 // as-server=false
	greetingRoleServer greetingRole = 1 // as-server=true
)

func (r greetingRole) asServer() bool { return r == greetingRoleServer }

// nameAware is the subset of security.Mechanism that greetingExchange
// uses. Lets tests substitute a tiny mock without constructing a real
// state machine.
type nameAware interface {
	Name() string
}

// greetingExchange runs the §6.1 lockstep greeting against raw. On
// success the mechanism name and role match the peer. On failure
// returns one of: ErrInvalidGreeting, wire.ErrUnsupportedVersion,
// ErrMechanismMismatch, ErrRoleConflict, or any I/O error wrapped.
func greetingExchange(raw net.Conn, role greetingRole, mech nameAware) error {
	ourGreeting := wire.Greeting{
		Mechanism: mech.Name(),
		AsServer:  role.asServer(),
	}

	// Asymmetric ordering avoids deadlock on inproc (net.Pipe is
	// synchronous): client writes first, server reads first.
	if role == greetingRoleClient {
		if err := wire.WriteGreeting(raw, ourGreeting); err != nil {
			return err
		}
	}

	if err := wire.ReadGreetingPhaseA(raw); err != nil {
		// Wrap signature failure as ErrInvalidGreeting; pass through
		// version-major failure (wire.ErrUnsupportedVersion).
		return wrapPhaseA(err)
	}
	// Reconstruct the validated phase-A bytes for DecodeGreeting.
	var buf [wire.GreetingSize]byte
	buf[0] = 0xFF
	buf[9] = 0x7F
	buf[10] = 0x03
	if _, err := io.ReadFull(raw, buf[11:]); err != nil {
		return err
	}
	peerG, err := wire.DecodeGreeting(buf[:])
	if err != nil {
		return err
	}
	if peerG.Mechanism != mech.Name() {
		return errMechMismatch(mech.Name(), peerG.Mechanism)
	}
	if mech.Name() != "NULL" {
		// Asymmetric mechanism: peer.AsServer must differ from ourSide.
		if peerG.AsServer == role.asServer() {
			return errRoleConflict(role.asServer(), peerG.AsServer)
		}
	}

	if role == greetingRoleServer {
		if err := wire.WriteGreeting(raw, ourGreeting); err != nil {
			return err
		}
	}

	return nil
}

// wrapPhaseA classifies an error returned by ReadGreetingPhaseA. Bad
// signature → ErrInvalidGreeting wrapping the wire sentinel; version
// mismatch → forwarded as wire.ErrUnsupportedVersion. Truncation /
// other I/O errors pass through.
func wrapPhaseA(err error) error {
	switch {
	case errors.Is(err, wire.ErrInvalidSignature):
		return fmt.Errorf("%w: %v", ErrInvalidGreeting, err)
	case errors.Is(err, wire.ErrUnsupportedVersion):
		return err
	default:
		return err
	}
}

func errMechMismatch(ours, theirs string) error {
	return fmt.Errorf("%w: ours=%q peer=%q", ErrMechanismMismatch, ours, theirs)
}

func errRoleConflict(ours, theirs bool) error {
	return fmt.Errorf("%w: both peers as-server=%t (ours=%t peer=%t)",
		ErrRoleConflict, ours, ours, theirs)
}
```

Add the missing imports — at the top of `handshake.go` add `"errors"`, `"fmt"`, `"io"` to the import block.

- [ ] **Step 4: Run tests**

Run: `go test -race ./internal/conn/ -run 'Greeting' -v`
Expected: 7 tests PASS (TestGreetingExchangeNullBothSides, TestGreetingExchangeMechanismMismatch, TestGreetingExchangeRoleConflictPLAIN, TestGreetingExchangeRoleConflictNULLIgnored, TestGreetingFillerIgnored, TestGreetingPhaseAFailureAbortsBeforeRest, TestGreetingVersionDowngradeAbortsBeforeRest).

- [ ] **Step 5: Run full conn suite**

Run: `go test -race ./internal/conn/...`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/conn/handshake.go internal/conn/handshake_test.go
git commit -m "conn: implement greetingExchange (lockstep send + read)

§6.1 greeting flow: client sends 64-byte greeting first, server reads
first (asymmetric to avoid net.Pipe deadlock on inproc). Both sides
read using ReadGreetingPhaseA for early version/signature rejection,
then read the remaining 53 bytes and call DecodeGreeting on the
reconstructed buffer. Validates mechanism match and as-server bit
(asymmetric mech only — NULL ignores).

Tests cover NULL happy path, mech mismatch, role conflict
(PLAIN), NULL-symmetric (no role conflict), filler ignored,
phase-A signature failure, version downgrade. Each negative case
asserts no further bytes are read after the abort."
```

---

### Task 13: Handshake driver loop — `runHandshakeLoop`

**Files:**
- Modify: `internal/conn/handshake.go` (add `runHandshakeLoop`)
- Modify: `internal/conn/handshake_test.go` (add driver-loop tests)

This task implements the loop body of §6.2 / §6.3: read frame → enforce caps → parse command → handle ERROR → mech.Receive → emit out → check done. Used by both client and server (the only difference is the active side's first `mech.Start()` step, which lives in the constructor).

- [ ] **Step 1: Write failing tests**

Append to `internal/conn/handshake_test.go`:

```go
// stubMech is a Mechanism+ClientMechanism mock that records calls and
// returns scripted responses. Used to drive runHandshakeLoop without
// pulling in real null/plain/curve states.
type stubMech struct {
	name             string
	startCmd         wire.Command
	startErr         error
	receiveResponses []receiveResponse
	receiveCallCount int
	doneAfter        int
	wrapPassthrough  bool
}

type receiveResponse struct {
	out  *wire.Command
	done bool
	err  error
}

func (s *stubMech) Name() string { return s.name }

func (s *stubMech) Start() (wire.Command, error) {
	return s.startCmd, s.startErr
}

func (s *stubMech) Receive(_ wire.Command) (*wire.Command, bool, error) {
	idx := s.receiveCallCount
	s.receiveCallCount++
	if idx >= len(s.receiveResponses) {
		return nil, true, nil // default: done.
	}
	r := s.receiveResponses[idx]
	return r.out, r.done, r.err
}

func (s *stubMech) Wrap(f wire.Frame) (wire.Frame, error)   { return f, nil }
func (s *stubMech) Unwrap(f wire.Frame) (wire.Frame, error) { return f, nil }

// Done always returns false. runHandshakeLoop never inspects mech.Done()
// (it only acts on the `done` boolean returned from Receive), so this
// is fine for unit tests. Returning a constant false avoids any subtle
// interaction if a future test wires stubMech into a higher-level
// driver that does poll Done().
func (s *stubMech) Done() bool                  { return false }
func (s *stubMech) PeerMetadata() wire.Metadata { return nil }

// driveLoopPair runs runHandshakeLoop on both sides of a net.Pipe with
// scripted stubMechs. The "active" side does Start() first; the
// "passive" side just runs the loop.
func runLoopPair(t *testing.T, active, passive *stubMech, cfg *config) (activeErr, passiveErr error) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	type res struct{ err error }
	ac := make(chan res, 1)
	pc := make(chan res, 1)
	go func() {
		fw := wire.NewFrameWriter(a)
		// Active side: emit Start() first.
		startCmd, err := active.Start()
		if err != nil {
			ac <- res{err}
			return
		}
		body, err := wire.EncodeCommand(startCmd)
		if err != nil {
			ac <- res{err}
			return
		}
		_ = fw.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body})
		ac <- res{runHandshakeLoop(a, fw, active, cfg)}
	}()
	go func() {
		fw := wire.NewFrameWriter(b)
		pc <- res{runHandshakeLoop(b, fw, passive, cfg)}
	}()
	return (<-ac).err, (<-pc).err
}

func TestRunHandshakeLoopUnexpectedFrame(t *testing.T) {
	// Peer sends a FrameMessage during handshake → ErrUnexpectedFrame.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		fw := wire.NewFrameWriter(b)
		_ = fw.WriteFrame(wire.Frame{Kind: wire.FrameMessage, Body: []byte("oops")})
	}()
	stub := &stubMech{name: "NULL"}
	cfg := newConfig(nil)
	fw := wire.NewFrameWriter(a)
	err := runHandshakeLoop(a, fw, stub, cfg)
	if !errors.Is(err, ErrUnexpectedFrame) {
		t.Fatalf("err = %v, want ErrUnexpectedFrame", err)
	}
}

func TestRunHandshakeLoopPeerERROR(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		fw := wire.NewFrameWriter(b)
		ec, _ := wire.ErrorCommand{Reason: "no thanks"}.Encode()
		body, _ := wire.EncodeCommand(ec)
		_ = fw.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body})
	}()
	stub := &stubMech{name: "NULL"}
	cfg := newConfig(nil)
	fw := wire.NewFrameWriter(a)
	err := runHandshakeLoop(a, fw, stub, cfg)
	if !errors.Is(err, ErrHandshakeFail) {
		t.Fatalf("err = %v, want wrap of ErrHandshakeFail", err)
	}
	if !strings.Contains(err.Error(), "no thanks") {
		t.Fatalf("err message %q does not contain peer reason", err.Error())
	}
}

func TestRunHandshakeLoopMechReceiveError(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// Peer sends a valid READY command.
	go func() {
		fw := wire.NewFrameWriter(b)
		ready, _ := wire.EncodeCommand(wire.Command{Name: wire.ReadyCommandName, Data: nil})
		_ = fw.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: ready})
		// Then read whatever ERROR we emit back.
		fr := wire.NewFrameReader(b)
		_, _ = fr.ReadFrame()
	}()
	stub := &stubMech{
		name: "NULL",
		receiveResponses: []receiveResponse{
			{out: nil, done: false, err: errors.New("synthetic mech failure")},
		},
	}
	cfg := newConfig(nil)
	fw := wire.NewFrameWriter(a)
	err := runHandshakeLoop(a, fw, stub, cfg)
	if !errors.Is(err, ErrHandshakeFail) {
		t.Fatalf("err = %v, want wrap of ErrHandshakeFail", err)
	}
	if !strings.Contains(err.Error(), "synthetic mech failure") {
		t.Fatalf("err = %q, want to contain mech reason", err.Error())
	}
}

func TestRunHandshakeLoopMetadataCap(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		fw := wire.NewFrameWriter(b)
		// READY with 9 KiB of metadata-shaped bytes (cap is 8 KiB).
		bigData := bytes.Repeat([]byte{0x00}, 9*1024)
		body, _ := wire.EncodeCommand(wire.Command{Name: wire.ReadyCommandName, Data: bigData})
		_ = fw.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body})
		// Drain ERROR.
		fr := wire.NewFrameReader(b)
		_, _ = fr.ReadFrame()
	}()
	stub := &stubMech{name: "NULL"}
	cfg := newConfig(nil) // 8 KiB metadata cap.
	fw := wire.NewFrameWriter(a)
	err := runHandshakeLoop(a, fw, stub, cfg)
	if !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("err = %v, want ErrMetadataTooLarge", err)
	}
}

func TestRunHandshakeLoopCommandCap(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		// 65 KiB > default 64 KiB cap. We need only the header for the
		// cap check to fire (FrameReader rejects before reading body),
		// but writing the body too keeps the wire well-formed if the
		// implementation ever changes to drain.
		oversize := bytes.Repeat([]byte{0x42}, 65*1024)
		// Flags byte: long-form command frame = (cmd|long) = 0x04|0x02 = 0x06.
		_, _ = b.Write([]byte{0x06})
		// 8-byte big-endian size for 65*1024 = 66560 = 0x10400 →
		// {0x00,0x00,0x00,0x00,0x00,0x01,0x04,0x00}.
		sz := [8]byte{0, 0, 0, 0, 0, 0x01, 0x04, 0x00}
		_, _ = b.Write(sz[:])
		_, _ = b.Write(oversize)
	}()
	stub := &stubMech{name: "NULL"}
	cfg := newConfig(nil)
	fw := wire.NewFrameWriter(a)
	err := runHandshakeLoop(a, fw, stub, cfg)
	if !errors.Is(err, ErrCommandTooLarge) {
		t.Fatalf("err = %v, want ErrCommandTooLarge", err)
	}
}
```

- [ ] **Step 2: Run tests to verify build failure**

Run: `go test ./internal/conn/...`
Expected: build failure — `runHandshakeLoop` undefined.

- [ ] **Step 3: Implement `runHandshakeLoop`**

Append to `internal/conn/handshake.go`:

```go
// runHandshakeLoop drives mech.Receive against frames read from raw
// until mech.Done() — or an error. Used by both ClientHandshake (after
// emitting Start()'s command) and ServerHandshake.
//
// Per spec §6.2:
//   - reads via a transient FrameReader capped at cfg.maxHandshakeCommandSize;
//   - rejects FrameMessage as ErrUnexpectedFrame;
//   - parses the command body; on parse error, returns wrapped
//     ErrHandshakeFail (and does NOT emit ERROR back — peer is already
//     malformed);
//   - on peer ERROR, returns wrapped ErrHandshakeFail with the reason;
//   - enforces metadata cap on READY/INITIATE commands; on overflow,
//     emits ERROR and returns ErrMetadataTooLarge;
//   - on mech.Receive error, emits ERROR and returns wrapped
//     ErrHandshakeFail.
//
// fw is the shared FrameWriter on raw (also used by emitERROR for
// abort signalling). mech is the local Mechanism (already constructed
// and, for the active side, already had Start() called by the caller).
func runHandshakeLoop(raw net.Conn, fw *wire.FrameWriter, mech security.Mechanism, cfg *config) error {
	hsfr := wire.NewFrameReader(raw, wire.WithMaxBodySize(int64(cfg.maxHandshakeCommandSize)))
	for {
		f, err := hsfr.ReadFrame()
		if err != nil {
			switch {
			case errors.Is(err, wire.ErrFrameTooLarge):
				return fmt.Errorf("%w: %v", ErrCommandTooLarge, err)
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
				return fmt.Errorf("%w: peer closed mid-handshake: %v", ErrHandshakeFail, err)
			default:
				return err
			}
		}
		if f.Kind != wire.FrameCommand {
			return fmt.Errorf("%w: got Kind=%v", ErrUnexpectedFrame, f.Kind)
		}
		cmd, err := wire.ParseCommand(f.Body)
		if err != nil {
			return fmt.Errorf("%w: parse: %v", ErrHandshakeFail, err)
		}
		if cmd.Name == wire.ErrorCommandName {
			ec, perr := wire.ParseError(cmd)
			if perr != nil {
				return fmt.Errorf("%w: malformed peer ERROR: %v", ErrHandshakeFail, perr)
			}
			return fmt.Errorf("%w: peer ERROR: %s", ErrHandshakeFail, ec.Reason)
		}
		if isMetadataBearing(cmd.Name) && len(cmd.Data) > cfg.maxMetadataSize {
			emitERROR(fw, "metadata exceeds cap")
			return fmt.Errorf("%w: %s body=%dB cap=%dB",
				ErrMetadataTooLarge, cmd.Name, len(cmd.Data), cfg.maxMetadataSize)
		}
		out, done, err := mech.Receive(cmd)
		if err != nil {
			emitERROR(fw, err.Error())
			return fmt.Errorf("%w: mech.Receive: %v", ErrHandshakeFail, err)
		}
		if out != nil {
			body, err := wire.EncodeCommand(*out)
			if err != nil {
				return fmt.Errorf("%w: encode mech out: %v", ErrHandshakeFail, err)
			}
			if err := fw.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body}); err != nil {
				return err
			}
		}
		if done {
			return nil
		}
	}
}

// isMetadataBearing reports whether a handshake command body parses as
// metadata properties. The metadata cap applies only to these.
//
// READY (NULL/PLAIN/CURVE) and INITIATE (PLAIN/CURVE) carry metadata;
// HELLO and WELCOME do not (they have mechanism-specific bodies). For
// CURVE, INITIATE's body is encrypted (cookie + vouch box + sealed
// metadata), so the cap acts as a wire-level allocation bound rather
// than a plaintext-size limit. See spec §6.2.
func isMetadataBearing(name string) bool {
	switch name {
	case wire.ReadyCommandName, "INITIATE":
		return true
	default:
		return false
	}
}
```

Add `"github.com/tomi77/zmq4/internal/security"` to the import block at the top of `handshake.go` if not already present.

- [ ] **Step 4: Run new tests**

Run: `go test -race ./internal/conn/ -run 'RunHandshakeLoop' -v`
Expected: 5 tests PASS (UnexpectedFrame, PeerERROR, MechReceiveError, MetadataCap, CommandCap).

- [ ] **Step 5: Run full conn suite**

Run: `go test -race ./internal/conn/...`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/conn/handshake.go internal/conn/handshake_test.go
git commit -m "conn: implement runHandshakeLoop driver

§6.2 / §6.3 loop body: transient handshake FrameReader capped at
cfg.maxHandshakeCommandSize, rejects FrameMessage as
ErrUnexpectedFrame, parses command body, detects peer ERROR,
enforces metadata cap on READY/INITIATE bodies, calls mech.Receive,
emits ERROR on mech failure or cap overflow, terminates on done.

Used by both ClientHandshake (after emitting Start()'s command) and
ServerHandshake. Tests use a stubMech to script Receive responses
and exercise every error sentinel in the loop body."
```

---

### Task 14: ClientHandshake + ServerHandshake constructors

**Files:**
- Modify: `internal/conn/handshake.go` (add public constructors)
- Modify: `internal/conn/handshake_test.go` (integration tests with real null mechanisms)

This task wires §6.6 (ctx-watcher), greeting (§6.1), and the driver loop (§6.2/§6.3) together into the public API. After this task, F4 has end-to-end NULL/PLAIN/CURVE handshake on `net.Pipe`.

- [ ] **Step 1: Write failing integration tests**

Add `curve` to the existing import block at the top of `internal/conn/handshake_test.go` (the block already imports `bytes`, `context`, `errors`, `io`, `net`, `strings`, `testing`, `time`, `wire`, `null`, `plain` from previous tasks). Then append the test bodies below to the same file.

```go
// imports needed in this task (add to the existing import block at the top of the file):
//   "github.com/tomi77/zmq4/internal/security/curve"

func runHandshakePair(t *testing.T,
	mkClient func() security.ClientMechanism,
	mkServer func() security.Mechanism,
) (cConn, sConn *Conn, cErr, sErr error) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	type cres struct {
		c   *Conn
		err error
	}
	cChan := make(chan cres, 1)
	sChan := make(chan cres, 1)
	go func() {
		c, err := ClientHandshake(ctx, a, mkClient())
		cChan <- cres{c, err}
	}()
	go func() {
		c, err := ServerHandshake(ctx, b, mkServer())
		sChan <- cres{c, err}
	}()
	cR := <-cChan
	sR := <-sChan
	t.Cleanup(func() {
		if cR.c != nil {
			_ = cR.c.Close()
		}
		if sR.c != nil {
			_ = sR.c.Close()
		}
	})
	return cR.c, sR.c, cR.err, sR.err
}

func TestClientServerHandshakeNULL(t *testing.T) {
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil {
		t.Errorf("client: %v", cErr)
	}
	if sErr != nil {
		t.Errorf("server: %v", sErr)
	}
	if c == nil || s == nil {
		t.Fatalf("nil Conn returned: c=%v s=%v", c, s)
	}
	if c.PeerMetadata() == nil {
		t.Errorf("client peerMeta is nil; want defensive clone (may be empty Metadata{})")
	}
}

func TestClientServerHandshakePLAIN(t *testing.T) {
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism {
			cli, err := plain.NewClient([]byte("user"), []byte("pass"), nil)
			if err != nil {
				t.Fatalf("plain.NewClient: %v", err)
			}
			return cli
		},
		func() security.Mechanism {
			return plain.NewServer(func(_, _ []byte) error { return nil }, nil)
		})
	if cErr != nil {
		t.Errorf("client: %v", cErr)
	}
	if sErr != nil {
		t.Errorf("server: %v", sErr)
	}
	if c == nil || s == nil {
		t.Fatalf("nil Conn returned: c=%v s=%v", c, s)
	}
}

func TestClientServerHandshakeCURVE(t *testing.T) {
	clientPub, clientSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	serverPub, serverSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism {
			cli, err := curve.NewClient(curve.ClientOptions{
				ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
			})
			if err != nil {
				t.Fatalf("curve.NewClient: %v", err)
			}
			return cli
		},
		func() security.Mechanism {
			s, err := curve.NewServer(curve.ServerOptions{
				OurPublicKey: serverPub, OurSecretKey: &serverSec,
				Authorizer: func(_ curve.PublicKey, _ wire.Metadata) error { return nil },
			})
			if err != nil {
				t.Fatalf("curve.NewServer: %v", err)
			}
			return s
		})
	if cErr != nil {
		t.Errorf("client: %v", cErr)
	}
	if sErr != nil {
		t.Errorf("server: %v", sErr)
	}
	if c == nil || s == nil {
		t.Fatalf("nil Conn returned: c=%v s=%v", c, s)
	}
}

func TestClientHandshakeNoDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, err := ClientHandshake(context.Background(), a, null.New(nil))
	if !errors.Is(err, ErrNoDeadline) {
		t.Fatalf("err = %v, want ErrNoDeadline", err)
	}
	// raw must NOT be closed.
	go func() { _, _ = b.Write([]byte{0}) }()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(a, buf); err != nil {
		t.Fatalf("raw was unexpectedly closed: %v", err)
	}
}

func TestClientHandshakeCtxCancelClosesRaw(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // ensures cancel func is called on every test exit path (go vet appeasement).
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, 2*time.Second)
	defer timeoutCancel()
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	// Server side does not respond → handshake stalls until cancel.
	_, err := ClientHandshake(timeoutCtx, a, null.New(nil))
	if err == nil {
		t.Fatalf("expected error from cancelled handshake")
	}
	// raw should be closed: a.Read should return ErrClosedPipe.
	buf := make([]byte, 1)
	if _, err := a.Read(buf); err == nil {
		t.Errorf("raw not closed after cancel")
	}
}
```

- [ ] **Step 2: Run tests to verify build failure**

Run: `go test ./internal/conn/...`
Expected: build failure — `ClientHandshake`, `ServerHandshake` undefined.

- [ ] **Step 3: Implement `ClientHandshake` and `ServerHandshake`**

Append to `internal/conn/handshake.go`:

```go
// ClientHandshake performs the ZMTP greeting and security handshake on
// the active side. raw is a connected net.Conn (typically the result of
// transport.Dial). mech is a configured ClientMechanism; F5 owns its
// construction and metadata setup.
//
// ctx MUST carry a deadline. Without one, ClientHandshake returns
// ErrNoDeadline before touching raw.
//
// On success, returns a *Conn ready for ReadFrame/WriteFrame; raw is
// owned by *Conn (Close releases it). On failure, raw is closed by F4
// and the error is returned (wrapped with %w).
func ClientHandshake(ctx context.Context, raw net.Conn,
	mech security.ClientMechanism, opts ...Option) (*Conn, error) {
	return doHandshake(ctx, raw, mech, mech, greetingRoleClient, opts)
}

// ServerHandshake performs the ZMTP greeting and security handshake on
// the passive side. Symmetric to ClientHandshake, taking the base
// Mechanism interface (no Start required).
func ServerHandshake(ctx context.Context, raw net.Conn,
	mech security.Mechanism, opts ...Option) (*Conn, error) {
	return doHandshake(ctx, raw, mech, nil, greetingRoleServer, opts)
}

// doHandshake is the shared implementation. activeMech is non-nil only
// for clients; when set, doHandshake calls activeMech.Start() between
// greeting and the loop.
func doHandshake(ctx context.Context, raw net.Conn,
	mech security.Mechanism, activeMech security.ClientMechanism,
	role greetingRole, opts []Option) (*Conn, error) {

	cfg := newConfig(opts)

	// Pre-deadline check: ErrNoDeadline must fire before raw is touched.
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrNoDeadline
	}

	var c *Conn
	err := runWithCtxDeadline(ctx, raw, func() error {
		// 1. Greeting (lockstep, asymmetric send order).
		if err := greetingExchange(raw, role, mech); err != nil {
			return err
		}
		// 2. Active side emits Start() first.
		fw := wire.NewFrameWriter(raw)
		if activeMech != nil {
			startCmd, err := activeMech.Start()
			if err != nil {
				emitERROR(fw, err.Error())
				return fmt.Errorf("%w: mech.Start: %v", ErrHandshakeFail, err)
			}
			body, err := wire.EncodeCommand(startCmd)
			if err != nil {
				return fmt.Errorf("%w: encode Start: %v", ErrHandshakeFail, err)
			}
			if err := fw.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body}); err != nil {
				return err
			}
		}
		// 3. Drive the loop.
		if err := runHandshakeLoop(raw, fw, mech, cfg); err != nil {
			return err
		}
		// 4. Build the post-handshake *Conn.
		c = &Conn{
			raw:      raw,
			fr:       wire.NewFrameReader(raw, wire.WithMaxBodySize(cfg.maxFrameBodySize)),
			fw:       fw,
			mech:     mech,
			peerMeta: seccommon.CloneMetadata(mech.PeerMetadata()),
		}
		return nil
	})

	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}
```

Add `"github.com/tomi77/zmq4/internal/security/seccommon"` to the imports at the top of `handshake.go` (the `context` import was already added in Task 11; no change needed there).

- [ ] **Step 4: Run new tests**

Run: `go test -race ./internal/conn/ -run 'ClientServerHandshake|ClientHandshakeNoDeadline|ClientHandshakeCtxCancel' -v`
Expected: 5 tests PASS.

- [ ] **Step 5: Run full conn suite**

Run: `go test -race ./internal/conn/...`
Expected: all PASS — full F4 handshake matrix is now exercised on `net.Pipe`. ReadFrame/WriteFrame stubs are still in place; Chunk 3 lands their bodies.

- [ ] **Step 6: Run vet**

Run: `go vet ./internal/conn/...`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add internal/conn/handshake.go internal/conn/handshake_test.go
git commit -m "conn: ClientHandshake + ServerHandshake constructors

Wires together the Chunk 2 building blocks: ErrNoDeadline pre-check,
runWithCtxDeadline harness, greetingExchange (asymmetric), optional
mech.Start emission for the active side, runHandshakeLoop body, and
post-handshake *Conn construction (persistent FrameReader at
maxFrameBodySize + defensive seccommon.CloneMetadata of peer metadata).

On failure the constructor closes raw and returns the wrapped error;
on success raw ownership transfers to *Conn (Close releases it).

Integration tests cover NULL, PLAIN, and CURVE end-to-end on net.Pipe,
plus ErrNoDeadline (raw untouched) and ctx-cancel mid-handshake (raw
closed)."
```

---

**End of Chunk 3.** F4 has a working handshake end-to-end on `net.Pipe`. Post-handshake `ReadFrame`/`WriteFrame` are still stubbed; Chunk 4 lands them plus the cross-mechanism conformance suite.
