# ZMTP 3.1 Wire Protocol Implementation Plan (Phase 1)

> **For Claude:** REQUIRED: Use `superpowers:subagent-driven-development` (if subagents available) or `superpowers:executing-plans` to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the `internal/wire` package per [`docs/specs/01-zmtp-wire-protocol.md`](../specs/01-zmtp-wire-protocol.md): a pure, I/O-free codec for the ZMTP 3.1 wire format, plus a thin streaming wrapper over `io.Reader` / `io.Writer`.

**Architecture:** Strict TDD, single Go package (`github.com/tomi77/zmq4/internal/wire`). One responsibility per file, tests live next to production code. Zero external dependencies (stdlib only). All sentinel errors wrappable via `errors.Is`. Decoders are zero-copy by aliasing input buffers; streaming readers allocate per frame.

**Tech Stack:** Go 1.26, stdlib only. `testing/quick` for property-based tests. `go test -fuzz` for fuzzing. `testing.AllocsPerRun` for allocation contracts. `libzmq` (in Docker) for capturing wire vectors.

**Working directory for all commands:** `~/Projects/github.com/tomi77/zmq4` — every `git`, `go`, and shell command in this plan assumes you're inside it. Use `git -C` / `cd` as appropriate; the plan uses `cd` once at the top of each task block.

---

## File structure (target end-state of Phase 1)

```
internal/wire/
├── doc.go                        # package documentation
├── errors.go                     # sentinel errors
├── greeting.go                   # Greeting struct, EncodeGreeting, DecodeGreeting
├── greeting_io.go                # ReadGreeting, WriteGreeting (io.Reader/io.Writer)
├── greeting_test.go
├── greeting_io_test.go
├── frame.go                      # FrameKind, Frame, MaxShortBodySize, EncodeFrame, DecodeFrame, WireSize
├── frame_test.go
├── frame_reader.go               # FrameReader (io.Reader → Frame)
├── frame_reader_test.go
├── frame_writer.go               # FrameWriter (Frame → io.Writer)
├── frame_writer_test.go
├── command.go                    # Command, ParseCommand, EncodeCommand
├── command_test.go
├── command_ready.go              # ReadyCommand, Metadata, MetadataProperty
├── command_ready_test.go
├── command_error.go              # ErrorCommand
├── command_error_test.go
├── command_ping.go               # PingCommand, PongCommand
├── command_ping_test.go
├── command_subscribe.go          # SubscribeCommand, CancelCommand
├── command_subscribe_test.go
├── fuzz_test.go                  # FuzzDecodeFrame, FuzzDecodeGreeting
├── bench_test.go                 # encode/decode benchmarks
└── testdata/
    ├── README.md                 # how to regenerate vectors
    └── interop/
        ├── greeting-null.bin
        ├── greeting-plain.bin
        ├── greeting-curve.bin
        ├── frame-empty.bin
        ├── frame-short.bin
        ├── frame-long.bin
        ├── frame-multipart.bin
        ├── cmd-ready-empty.bin
        ├── cmd-ready-typical.bin
        ├── cmd-error.bin
        ├── cmd-ping.bin
        ├── cmd-pong.bin
        ├── cmd-subscribe.bin
        └── cmd-cancel.bin
testdata/interop/wire/             # capture script lives here (out of internal/)
└── capture.sh
```

**One file = one responsibility.** Tests live next to production. Long tables of sub-cases collapse into a single test function with subtests (`t.Run`).

---

## Conventions used by every task

- **TDD step skeleton (used in every implementation task):**
  1. Write the failing test.
  2. Run it; confirm it fails for the *expected* reason.
  3. Implement the minimum code to pass.
  4. Run tests; confirm green.
  5. Commit.
- **Test layout:** Each test file has table-driven tests using `t.Run` for subtests. Keep tables in `var <name>Cases = []struct{...}{...}` blocks at the top of the file.
- **Subtest names:** lowercase, hyphenated, descriptive — e.g. `t.Run("short-message-empty", ...)`.
- **Commit messages:** `wire: <short imperative>`. Body explains *why*. Example: `wire: add greeting codec`.
- **Run command for tests:** `go test ./internal/wire/...` (always from repo root).
- **Run command for vet:** `go vet ./internal/wire/...`.
- **Run command for staticcheck (optional but encouraged):** `staticcheck ./internal/wire/...`.
- **Where the spec is referenced** (e.g. "RFC 37 §X"), check [`docs/specs/01-zmtp-wire-protocol.md`](../specs/01-zmtp-wire-protocol.md) §3 for the embedded ABNF — that is the local authority.

---

## Chunk 1: Foundation (package skeleton, errors, greeting)

### Task 1: Package skeleton and sentinel errors

**Files:**
- Create: `internal/wire/doc.go`
- Create: `internal/wire/errors.go`

- [ ] **Step 1: Create `doc.go`**

```go
// Package wire implements the ZMTP 3.1 wire protocol codec.
//
// This package performs no I/O of its own beyond what the caller's
// io.Reader / io.Writer does. It defines no state machine, no
// goroutines, no timers. It is the lowest layer of the zmq4
// implementation and is consumed by internal/conn (Phase 4) and above.
//
// See docs/specs/01-zmtp-wire-protocol.md for the full design and
// docs/specs/00-meta-overview.md for the project layering.
package wire
```

- [ ] **Step 2: Create `errors.go`**

```go
package wire

import "errors"

var (
	// ErrShortBuffer indicates the supplied buffer is shorter than the
	// minimum required to encode or decode the value.
	ErrShortBuffer = errors.New("zmq4/wire: buffer too short")

	// ErrInvalidSignature indicates the greeting signature bytes do not
	// match the required 0xFF...0x7F marker.
	ErrInvalidSignature = errors.New("zmq4/wire: invalid greeting signature")

	// ErrUnsupportedVersion indicates the greeting version is not 3.1.
	ErrUnsupportedVersion = errors.New("zmq4/wire: unsupported ZMTP version (only 3.1 is supported)")

	// ErrInvalidMechanism indicates the mechanism field is malformed
	// (oversized, contains disallowed characters, or not NUL-padded).
	ErrInvalidMechanism = errors.New("zmq4/wire: invalid mechanism field")

	// ErrReservedFlags indicates a frame's flags byte sets reserved bits 3..7.
	ErrReservedFlags = errors.New("zmq4/wire: frame uses reserved flag bits")

	// ErrCommandHasMore indicates a command frame has the MORE flag set,
	// which is forbidden by RFC 37.
	ErrCommandHasMore = errors.New("zmq4/wire: command frame has MORE flag set")

	// ErrInvalidCommand indicates a command body is malformed (bad name
	// length, non-letter chars in name, etc.).
	ErrInvalidCommand = errors.New("zmq4/wire: malformed command")

	// ErrFrameTooLarge indicates a frame size exceeds 2^63-1 octets.
	ErrFrameTooLarge = errors.New("zmq4/wire: frame size exceeds 2^63-1")
)
```

- [ ] **Step 3: Run `go vet ./internal/wire/...`. Expected: no output (success).**

- [ ] **Step 4: Run `go build ./internal/wire/...`. Expected: no output.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/doc.go internal/wire/errors.go
git commit -m "wire: package skeleton with sentinel errors"
```

---

### Task 2: Greeting — pure codec (`EncodeGreeting`, `DecodeGreeting`)

**Files:**
- Create: `internal/wire/greeting.go`
- Create: `internal/wire/greeting_test.go`

The greeting is 64 bytes, layout per spec §3 (RFC 37):

| Offset | Size | Field |
|--------|------|-------|
| 0      | 1    | `0xFF` |
| 1..8   | 8    | padding (any value on read; we emit zeros) |
| 9      | 1    | `0x7F` |
| 10     | 1    | major = `0x03` |
| 11     | 1    | minor = `0x01` |
| 12..31 | 20   | mechanism (ASCII per RFC, NUL-padded) |
| 32     | 1    | as-server (0 or 1) |
| 33..63 | 31   | filler (zeros) |

Allowed mechanism characters per RFC ABNF: `A-Z`, digit, `-`, `_`, `.`, `+`, plus the `\x00` padding for unused trailing slots. We accept this set and reject anything else.

- [ ] **Step 1: Write the failing test (round-trip happy path)**

`internal/wire/greeting_test.go`:

```go
package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeGreetingDecodeGreetingRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		greeting Greeting
	}{
		{"null-client", Greeting{Mechanism: "NULL", AsServer: false}},
		{"null-server", Greeting{Mechanism: "NULL", AsServer: true}},
		{"plain-client", Greeting{Mechanism: "PLAIN", AsServer: false}},
		{"curve-server", Greeting{Mechanism: "CURVE", AsServer: true}},
		{"max-len-mechanism", Greeting{Mechanism: "ABCDEFGHIJKLMNOPQRST", AsServer: false}}, // 20 chars
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf [GreetingSize]byte
			if err := EncodeGreeting(buf[:], c.greeting); err != nil {
				t.Fatalf("EncodeGreeting: %v", err)
			}
			got, err := DecodeGreeting(buf[:])
			if err != nil {
				t.Fatalf("DecodeGreeting: %v", err)
			}
			if got != c.greeting {
				t.Fatalf("round trip mismatch: got %+v, want %+v", got, c.greeting)
			}
		})
	}
}

func TestEncodeGreetingShortBuffer(t *testing.T) {
	short := make([]byte, GreetingSize-1)
	if err := EncodeGreeting(short, Greeting{Mechanism: "NULL"}); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}

func TestEncodeGreetingOversizedMechanism(t *testing.T) {
	var buf [GreetingSize]byte
	err := EncodeGreeting(buf[:], Greeting{Mechanism: "ABCDEFGHIJKLMNOPQRSTU"}) // 21 chars
	if !errors.Is(err, ErrInvalidMechanism) {
		t.Fatalf("want ErrInvalidMechanism, got %v", err)
	}
}

func TestDecodeGreetingShortBuffer(t *testing.T) {
	if _, err := DecodeGreeting(make([]byte, GreetingSize-1)); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}

func TestDecodeGreetingBadSignature(t *testing.T) {
	var buf [GreetingSize]byte
	// Encode a valid greeting first, then corrupt byte 0.
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"}); err != nil {
		t.Fatalf("setup encode: %v", err)
	}
	corrupt := buf
	corrupt[0] = 0x00
	if _, err := DecodeGreeting(corrupt[:]); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("byte 0 corrupted: want ErrInvalidSignature, got %v", err)
	}
	corrupt = buf
	corrupt[9] = 0x00
	if _, err := DecodeGreeting(corrupt[:]); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("byte 9 corrupted: want ErrInvalidSignature, got %v", err)
	}
}

func TestDecodeGreetingUnsupportedVersion(t *testing.T) {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"}); err != nil {
		t.Fatalf("setup encode: %v", err)
	}
	cases := []struct {
		name        string
		major, minor byte
	}{
		{"3.0", 0x03, 0x00},
		{"4.0", 0x04, 0x00},
		{"2.0", 0x02, 0x00},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tweaked := buf
			tweaked[10] = c.major
			tweaked[11] = c.minor
			if _, err := DecodeGreeting(tweaked[:]); !errors.Is(err, ErrUnsupportedVersion) {
				t.Fatalf("want ErrUnsupportedVersion, got %v", err)
			}
		})
	}
}

func TestDecodeGreetingMechanismValidation(t *testing.T) {
	mkBuf := func(mechBytes []byte) [GreetingSize]byte {
		var buf [GreetingSize]byte
		buf[0] = 0xFF
		buf[9] = 0x7F
		buf[10] = 0x03
		buf[11] = 0x01
		copy(buf[12:32], mechBytes)
		return buf
	}
	t.Run("non-ascii", func(t *testing.T) {
		buf := mkBuf([]byte{0xC3, 0xA9}) // "é" — disallowed
		if _, err := DecodeGreeting(buf[:]); !errors.Is(err, ErrInvalidMechanism) {
			t.Fatalf("want ErrInvalidMechanism, got %v", err)
		}
	})
	t.Run("disallowed-char", func(t *testing.T) {
		buf := mkBuf([]byte("FOO BAR")) // space — disallowed
		if _, err := DecodeGreeting(buf[:]); !errors.Is(err, ErrInvalidMechanism) {
			t.Fatalf("want ErrInvalidMechanism, got %v", err)
		}
	})
	t.Run("non-zero-after-name", func(t *testing.T) {
		buf := mkBuf([]byte("NULL"))
		buf[12+5] = 'X' // garbage after NUL terminator
		if _, err := DecodeGreeting(buf[:]); !errors.Is(err, ErrInvalidMechanism) {
			t.Fatalf("want ErrInvalidMechanism, got %v", err)
		}
	})
}

func TestEncodeGreetingFillerIsZero(t *testing.T) {
	var buf [GreetingSize]byte
	for i := range buf {
		buf[i] = 0xAA // pre-fill to detect leftover data
	}
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"}); err != nil {
		t.Fatal(err)
	}
	expectedFiller := make([]byte, 31)
	if !bytes.Equal(buf[33:64], expectedFiller) {
		t.Fatalf("filler not zeroed: %x", buf[33:64])
	}
}

func TestEncodeGreetingZeroAllocations(t *testing.T) {
	var buf [GreetingSize]byte
	g := Greeting{Mechanism: "NULL"}
	got := testing.AllocsPerRun(1000, func() {
		_ = EncodeGreeting(buf[:], g)
	})
	if got != 0 {
		t.Fatalf("EncodeGreeting allocates %v allocs/op, want 0", got)
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: compile errors / FAIL — `Greeting`, `EncodeGreeting`, `DecodeGreeting`, `GreetingSize` undefined.**

- [ ] **Step 3: Implement `internal/wire/greeting.go`**

```go
package wire

import "fmt"

// GreetingSize is the on-wire size of a complete ZMTP 3.1 greeting.
const GreetingSize = 64

// Greeting is the parsed form of the ZMTP 3.1 connection greeting.
type Greeting struct {
	// Mechanism is the security mechanism name (e.g. "NULL", "PLAIN", "CURVE").
	// Must be ≤20 ASCII characters from the set [A-Z 0-9 - _ . +].
	Mechanism string
	// AsServer signals the peer's role for mechanism negotiation.
	AsServer bool
}

// EncodeGreeting writes a 64-byte greeting into dst.
//
// Returns ErrShortBuffer if len(dst) < GreetingSize.
// Returns ErrInvalidMechanism if g.Mechanism is too long or contains
// disallowed characters.
func EncodeGreeting(dst []byte, g Greeting) error {
	if len(dst) < GreetingSize {
		return ErrShortBuffer
	}
	if err := validateMechanism(g.Mechanism); err != nil {
		return err
	}
	// Signature
	dst[0] = 0xFF
	for i := 1; i < 9; i++ {
		dst[i] = 0
	}
	dst[9] = 0x7F
	// Version
	dst[10] = 0x03
	dst[11] = 0x01
	// Mechanism (NUL-padded)
	for i := 0; i < 20; i++ {
		dst[12+i] = 0
	}
	copy(dst[12:32], g.Mechanism)
	// As-server
	dst[32] = 0
	if g.AsServer {
		dst[32] = 1
	}
	// Filler
	for i := 33; i < 64; i++ {
		dst[i] = 0
	}
	return nil
}

// DecodeGreeting parses a 64-byte greeting from src.
func DecodeGreeting(src []byte) (Greeting, error) {
	if len(src) < GreetingSize {
		return Greeting{}, ErrShortBuffer
	}
	if src[0] != 0xFF || src[9] != 0x7F {
		return Greeting{}, fmt.Errorf("%w: got 0x%02X..0x%02X, want 0xFF..0x7F", ErrInvalidSignature, src[0], src[9])
	}
	if src[10] != 0x03 || src[11] != 0x01 {
		return Greeting{}, fmt.Errorf("%w: got %d.%d, want 3.1", ErrUnsupportedVersion, src[10], src[11])
	}
	mech, err := parseMechanism(src[12:32])
	if err != nil {
		return Greeting{}, err
	}
	return Greeting{
		Mechanism: mech,
		AsServer:  src[32] == 1,
	}, nil
}

// validateMechanism returns ErrInvalidMechanism if name is too long or
// contains disallowed characters.
func validateMechanism(name string) error {
	if len(name) > 20 {
		return fmt.Errorf("%w: mechanism name too long (%d > 20)", ErrInvalidMechanism, len(name))
	}
	for i := 0; i < len(name); i++ {
		if !isMechanismChar(name[i]) {
			return fmt.Errorf("%w: invalid char 0x%02X at offset %d", ErrInvalidMechanism, name[i], i)
		}
	}
	return nil
}

// parseMechanism reads the 20-byte mechanism field. It returns the
// non-NUL prefix and verifies the trailing bytes are NUL-padded.
func parseMechanism(field []byte) (string, error) {
	end := -1
	for i := 0; i < len(field); i++ {
		c := field[i]
		if c == 0x00 {
			end = i
			break
		}
		if !isMechanismChar(c) {
			return "", fmt.Errorf("%w: invalid char 0x%02X at offset %d", ErrInvalidMechanism, c, i)
		}
	}
	var name string
	if end == -1 {
		name = string(field)
	} else {
		name = string(field[:end])
		// Verify the rest is NUL.
		for i := end + 1; i < len(field); i++ {
			if field[i] != 0x00 {
				return "", fmt.Errorf("%w: non-NUL byte 0x%02X after terminator at offset %d", ErrInvalidMechanism, field[i], i)
			}
		}
	}
	return name, nil
}

func isMechanismChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_' || c == '.' || c == '+':
		return true
	}
	return false
}
```

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS for all `TestEncodeGreeting*` / `TestDecodeGreeting*`.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/greeting.go internal/wire/greeting_test.go
git commit -m "wire: greeting codec with full validation"
```

---

### Task 3: Greeting — streaming (`ReadGreeting`, `WriteGreeting`)

**Files:**
- Create: `internal/wire/greeting_io.go`
- Create: `internal/wire/greeting_io_test.go`

- [ ] **Step 1: Write the failing test**

`internal/wire/greeting_io_test.go`:

```go
package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestReadGreetingHappyPath(t *testing.T) {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL", AsServer: true}); err != nil {
		t.Fatal(err)
	}
	g, err := ReadGreeting(bytes.NewReader(buf[:]))
	if err != nil {
		t.Fatal(err)
	}
	want := Greeting{Mechanism: "NULL", AsServer: true}
	if g != want {
		t.Fatalf("got %+v, want %+v", g, want)
	}
}

func TestReadGreetingPartialReads(t *testing.T) {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "PLAIN"}); err != nil {
		t.Fatal(err)
	}
	r := iotest.OneByteReader(bytes.NewReader(buf[:]))
	g, err := ReadGreeting(r)
	if err != nil {
		t.Fatal(err)
	}
	if g.Mechanism != "PLAIN" {
		t.Fatalf("got mechanism %q, want PLAIN", g.Mechanism)
	}
}

func TestReadGreetingTruncated(t *testing.T) {
	var buf [GreetingSize]byte
	if err := EncodeGreeting(buf[:], Greeting{Mechanism: "NULL"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadGreeting(bytes.NewReader(buf[:GreetingSize-1])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestWriteGreetingHappyPath(t *testing.T) {
	var sink bytes.Buffer
	if err := WriteGreeting(&sink, Greeting{Mechanism: "CURVE", AsServer: true}); err != nil {
		t.Fatal(err)
	}
	if sink.Len() != GreetingSize {
		t.Fatalf("wrote %d bytes, want %d", sink.Len(), GreetingSize)
	}
	g, err := DecodeGreeting(sink.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	want := Greeting{Mechanism: "CURVE", AsServer: true}
	if g != want {
		t.Fatalf("got %+v, want %+v", g, want)
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: FAIL — `ReadGreeting` / `WriteGreeting` undefined.**

- [ ] **Step 3: Implement `internal/wire/greeting_io.go`**

```go
package wire

import "io"

// ReadGreeting reads exactly GreetingSize bytes from r and decodes them.
// Returns io.ErrUnexpectedEOF on truncated input.
func ReadGreeting(r io.Reader) (Greeting, error) {
	var buf [GreetingSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
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

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS for all `Test*Greeting*`.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/greeting_io.go internal/wire/greeting_io_test.go
git commit -m "wire: streaming greeting reader/writer"
```

---

## Chunk 2: Frame codec

### Task 4: Frame type and `WireSize`

**Files:**
- Create: `internal/wire/frame.go` (initial version with types only)
- Create: `internal/wire/frame_test.go` (skeleton)

- [ ] **Step 1: Write the failing test**

`internal/wire/frame_test.go` (initial):

```go
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
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: FAIL — undefined types.**

- [ ] **Step 3: Implement types and `WireSize`** in `internal/wire/frame.go`:

```go
package wire

// FrameKind distinguishes message frames from command frames.
type FrameKind uint8

const (
	// FrameMessage carries application payload.
	FrameMessage FrameKind = iota
	// FrameCommand carries protocol metadata (READY, ERROR, PING, ...).
	FrameCommand
)

// MaxShortBodySize is the largest body that can use the short-size encoding.
const MaxShortBodySize = 255

// Frame is a single ZMTP 3.1 frame.
//
// For decoded frames, Body aliases the source buffer (zero-copy). The
// caller owns the buffer's lifetime — copy if you retain Body past the
// next decode call. Streaming readers (FrameReader) always allocate a
// fresh Body slice.
type Frame struct {
	Kind FrameKind
	More bool   // continuation flag; must be false when Kind == FrameCommand
	Body []byte // raw payload; for commands, see ParseCommand
}

// WireSize returns the total on-wire size of f, including the flags byte
// and the size field.
func (f Frame) WireSize() int {
	if len(f.Body) <= MaxShortBodySize {
		return 1 + 1 + len(f.Body)
	}
	return 1 + 8 + len(f.Body)
}
```

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS for `TestFrameWireSize`.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/frame.go internal/wire/frame_test.go
git commit -m "wire: Frame type and WireSize"
```

---

### Task 5: `EncodeFrame`

**Files:**
- Modify: `internal/wire/frame.go`
- Modify: `internal/wire/frame_test.go`

- [ ] **Step 1: Add failing tests** to `internal/wire/frame_test.go`.

  Merge these imports into the existing top-of-file import block (do not add a second `import (...)`):

  ```go
  "bytes"
  "encoding/binary"
  "errors"
  ```

  Then append the following test functions:

```go
func TestEncodeFrameShortMessage(t *testing.T) {
	body := []byte("hello")
	f := Frame{Kind: FrameMessage, Body: body}
	var buf [16]byte
	n, err := EncodeFrame(buf[:], f)
	if err != nil {
		t.Fatal(err)
	}
	if n != f.WireSize() {
		t.Fatalf("n=%d, want %d", n, f.WireSize())
	}
	want := []byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("got %x, want %x", buf[:n], want)
	}
}

func TestEncodeFrameShortMessageMore(t *testing.T) {
	f := Frame{Kind: FrameMessage, More: true, Body: []byte("X")}
	var buf [4]byte
	n, err := EncodeFrame(buf[:], f)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x01, 0x01, 'X'}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("got %x, want %x", buf[:n], want)
	}
}

func TestEncodeFrameLongMessage(t *testing.T) {
	body := bytes.Repeat([]byte{0xAB}, 300)
	f := Frame{Kind: FrameMessage, Body: body}
	buf := make([]byte, f.WireSize())
	if _, err := EncodeFrame(buf, f); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x02 {
		t.Fatalf("flags=0x%02X, want 0x02 (long message, no MORE)", buf[0])
	}
	if got := binary.BigEndian.Uint64(buf[1:9]); got != 300 {
		t.Fatalf("size=%d, want 300", got)
	}
	if !bytes.Equal(buf[9:], body) {
		t.Fatal("body mismatch")
	}
}

func TestEncodeFrameShortCommand(t *testing.T) {
	f := Frame{Kind: FrameCommand, Body: []byte("READY")}
	buf := make([]byte, f.WireSize())
	if _, err := EncodeFrame(buf, f); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x04 {
		t.Fatalf("flags=0x%02X, want 0x04", buf[0])
	}
	if buf[1] != 5 {
		t.Fatalf("size=%d, want 5", buf[1])
	}
}

func TestEncodeFrameLongCommand(t *testing.T) {
	body := bytes.Repeat([]byte{0xCD}, 500)
	f := Frame{Kind: FrameCommand, Body: body}
	buf := make([]byte, f.WireSize())
	if _, err := EncodeFrame(buf, f); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x06 {
		t.Fatalf("flags=0x%02X, want 0x06", buf[0])
	}
	if got := binary.BigEndian.Uint64(buf[1:9]); got != 500 {
		t.Fatalf("size=%d, want 500", got)
	}
}

func TestEncodeFrameShortBuffer(t *testing.T) {
	f := Frame{Kind: FrameMessage, Body: []byte("hello")}
	if _, err := EncodeFrame(make([]byte, 3), f); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}

func TestEncodeFrameCommandWithMore(t *testing.T) {
	f := Frame{Kind: FrameCommand, More: true, Body: []byte("READY")}
	buf := make([]byte, f.WireSize())
	if _, err := EncodeFrame(buf, f); !errors.Is(err, ErrCommandHasMore) {
		t.Fatalf("want ErrCommandHasMore, got %v", err)
	}
}

func TestEncodeFrameZeroAllocations(t *testing.T) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	buf := make([]byte, f.WireSize())
	got := testing.AllocsPerRun(1000, func() {
		_, _ = EncodeFrame(buf, f)
	})
	if got != 0 {
		t.Fatalf("EncodeFrame allocates %v allocs/op, want 0", got)
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: FAIL — `EncodeFrame` undefined.**

- [ ] **Step 3: Implement `EncodeFrame`** in `internal/wire/frame.go`.

  Add `"encoding/binary"` to the existing top-of-file import block (or create one immediately after `package wire` if none exists yet — do not place imports between functions).

  Then append:

```go
// EncodeFrame writes f's wire representation into dst. Returns the number
// of bytes written. dst must be at least f.WireSize() bytes long.
func EncodeFrame(dst []byte, f Frame) (int, error) {
	need := f.WireSize()
	if len(dst) < need {
		return 0, ErrShortBuffer
	}
	if f.Kind == FrameCommand && f.More {
		return 0, ErrCommandHasMore
	}

	var flags byte
	if f.More {
		flags |= 0x01
	}
	long := len(f.Body) > MaxShortBodySize
	if long {
		flags |= 0x02
	}
	if f.Kind == FrameCommand {
		flags |= 0x04
	}
	dst[0] = flags

	off := 1
	if long {
		binary.BigEndian.PutUint64(dst[off:off+8], uint64(len(f.Body)))
		off += 8
	} else {
		dst[off] = byte(len(f.Body))
		off++
	}
	copy(dst[off:], f.Body)
	return need, nil
}
```

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS for all encode tests.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/frame.go internal/wire/frame_test.go
git commit -m "wire: EncodeFrame for short/long, message/command frames"
```

---

### Task 6: `DecodeFrame`

**Files:**
- Modify: `internal/wire/frame.go`
- Modify: `internal/wire/frame_test.go`

- [ ] **Step 1: Add failing tests** to `internal/wire/frame_test.go`:

```go
func TestDecodeFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		f    Frame
	}{
		{"empty-msg-last", Frame{Kind: FrameMessage}},
		{"empty-msg-more", Frame{Kind: FrameMessage, More: true}},
		{"short-msg-last", Frame{Kind: FrameMessage, Body: []byte("hi")}},
		{"short-msg-more", Frame{Kind: FrameMessage, More: true, Body: []byte("hi")}},
		{"boundary-255", Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{1}, 255)}},
		{"long-256", Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{2}, 256)}},
		{"long-1mib", Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{3}, 1<<20)}},
		{"short-cmd", Frame{Kind: FrameCommand, Body: []byte("READY")}},
		{"long-cmd", Frame{Kind: FrameCommand, Body: bytes.Repeat([]byte{4}, 500)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, c.f.WireSize())
			if _, err := EncodeFrame(buf, c.f); err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, n, err := DecodeFrame(buf)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if n != len(buf) {
				t.Fatalf("consumed %d, want %d", n, len(buf))
			}
			if got.Kind != c.f.Kind || got.More != c.f.More {
				t.Fatalf("got %+v, want %+v", got, c.f)
			}
			if !bytes.Equal(got.Body, c.f.Body) {
				t.Fatal("body mismatch")
			}
		})
	}
}

func TestDecodeFrameTruncated(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
	}{
		{"empty", []byte{}},
		{"flag-only", []byte{0x00}},
		{"short-trunc-body", []byte{0x00, 0x05, 'h', 'i'}},
		{"long-trunc-size", []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}}, // missing 1 size byte
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := DecodeFrame(c.buf); !errors.Is(err, ErrShortBuffer) {
				t.Fatalf("want ErrShortBuffer, got %v", err)
			}
		})
	}
}

func TestDecodeFrameReservedFlags(t *testing.T) {
	for _, flag := range []byte{0x08, 0x10, 0x20, 0x40, 0x80} {
		t.Run(fmt.Sprintf("flag-%02X", flag), func(t *testing.T) {
			buf := []byte{flag, 0x00}
			if _, _, err := DecodeFrame(buf); !errors.Is(err, ErrReservedFlags) {
				t.Fatalf("want ErrReservedFlags, got %v", err)
			}
		})
	}
}

func TestDecodeFrameCommandWithMoreInvalid(t *testing.T) {
	buf := []byte{0x05, 0x00} // 0x04 (command) | 0x01 (more)
	if _, _, err := DecodeFrame(buf); !errors.Is(err, ErrCommandHasMore) {
		t.Fatalf("want ErrCommandHasMore, got %v", err)
	}
	buf = []byte{0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // 0x06 | 0x01
	if _, _, err := DecodeFrame(buf); !errors.Is(err, ErrCommandHasMore) {
		t.Fatalf("want ErrCommandHasMore, got %v", err)
	}
}

func TestDecodeFrameZeroAllocations(t *testing.T) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	buf := make([]byte, f.WireSize())
	if _, err := EncodeFrame(buf, f); err != nil {
		t.Fatal(err)
	}
	got := testing.AllocsPerRun(1000, func() {
		_, _, _ = DecodeFrame(buf)
	})
	if got != 0 {
		t.Fatalf("DecodeFrame allocates %v allocs/op, want 0", got)
	}
}

func TestDecodeFrameBodyAliasesInput(t *testing.T) {
	src := []byte{0x00, 0x03, 'a', 'b', 'c'}
	got, _, err := DecodeFrame(src)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the input buffer; the Body should reflect it (zero-copy).
	src[2] = 'X'
	if got.Body[0] != 'X' {
		t.Fatal("Body does not alias src — zero-copy contract violated")
	}
}
```

**Imports to add to `frame_test.go`** (merge into the existing import block, do not duplicate): `"fmt"` (for `fmt.Sprintf` in `TestDecodeFrameReservedFlags`).

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: FAIL — `DecodeFrame` undefined.**

- [ ] **Step 3: Implement `DecodeFrame`** in `internal/wire/frame.go`:

```go
// DecodeFrame parses one frame starting at src[0]. Returns the parsed
// frame, the number of input bytes consumed, and any error. Body
// aliases src (zero-copy); copy if you retain it past the next decode.
func DecodeFrame(src []byte) (Frame, int, error) {
	if len(src) < 1 {
		return Frame{}, 0, ErrShortBuffer
	}
	flags := src[0]
	if flags&0xF8 != 0 {
		return Frame{}, 0, ErrReservedFlags
	}
	more := flags&0x01 != 0
	long := flags&0x02 != 0
	cmd := flags&0x04 != 0
	if cmd && more {
		return Frame{}, 0, ErrCommandHasMore
	}

	off := 1
	var size uint64
	if long {
		if len(src) < off+8 {
			return Frame{}, 0, ErrShortBuffer
		}
		size = binary.BigEndian.Uint64(src[off : off+8])
		off += 8
	} else {
		if len(src) < off+1 {
			return Frame{}, 0, ErrShortBuffer
		}
		size = uint64(src[off])
		off++
	}

	if uint64(len(src)-off) < size {
		return Frame{}, 0, ErrShortBuffer
	}
	end := off + int(size)
	kind := FrameMessage
	if cmd {
		kind = FrameCommand
	}
	return Frame{
		Kind: kind,
		More: more,
		Body: src[off:end],
	}, end, nil
}
```

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS for all decode tests.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/frame.go internal/wire/frame_test.go
git commit -m "wire: DecodeFrame with zero-copy Body aliasing"
```

---

### Task 7: Multipart sequence test

**Files:**
- Modify: `internal/wire/frame_test.go`

- [ ] **Step 1: Add a multipart test**

```go
func TestEncodeDecodeMultipartSequence(t *testing.T) {
	frames := []Frame{
		{Kind: FrameMessage, More: true, Body: []byte("part-1")},
		{Kind: FrameMessage, More: true, Body: []byte("part-2")},
		{Kind: FrameMessage, More: false, Body: []byte("part-3-last")},
	}
	var buf bytes.Buffer
	scratch := make([]byte, 64)
	for _, f := range frames {
		n, err := EncodeFrame(scratch[:f.WireSize()], f)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		buf.Write(scratch[:n])
	}

	in := buf.Bytes()
	var got []Frame
	for len(in) > 0 {
		f, n, err := DecodeFrame(in)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		got = append(got, Frame{Kind: f.Kind, More: f.More, Body: append([]byte(nil), f.Body...)})
		in = in[n:]
	}
	if len(got) != len(frames) {
		t.Fatalf("got %d frames, want %d", len(got), len(frames))
	}
	for i, f := range frames {
		if got[i].Kind != f.Kind || got[i].More != f.More || !bytes.Equal(got[i].Body, f.Body) {
			t.Fatalf("frame %d: got %+v, want %+v", i, got[i], f)
		}
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: PASS (no new code needed).**

- [ ] **Step 3: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/frame_test.go
git commit -m "wire: multipart sequence test"
```

---

### Task 8: Property-based round-trip test

**Files:**
- Modify: `internal/wire/frame_test.go`

- [ ] **Step 1: Add property test**

  Add `"testing/quick"` to the existing import block at the top of `frame_test.go`. Then append:

```go
func TestFrameRoundTripProperty(t *testing.T) {
	prop := func(kind uint8, more bool, body []byte) bool {
		k := FrameMessage
		if kind%2 == 1 {
			k = FrameCommand
		}
		// Commands cannot have MORE.
		if k == FrameCommand {
			more = false
		}
		f := Frame{Kind: k, More: more, Body: body}
		buf := make([]byte, f.WireSize())
		if _, err := EncodeFrame(buf, f); err != nil {
			return false
		}
		got, n, err := DecodeFrame(buf)
		if err != nil || n != len(buf) {
			return false
		}
		return got.Kind == f.Kind && got.More == f.More && bytes.Equal(got.Body, f.Body)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: PASS.**

- [ ] **Step 3: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/frame_test.go
git commit -m "wire: property-based frame round-trip test"
```

---

## Chunk 3: Streaming readers and writers

### Task 9: `FrameReader`

**Files:**
- Create: `internal/wire/frame_reader.go`
- Create: `internal/wire/frame_reader_test.go`

- [ ] **Step 1: Write failing tests**

```go
package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestFrameReaderHappyPath(t *testing.T) {
	want := []Frame{
		{Kind: FrameMessage, More: true, Body: []byte("hello")},
		{Kind: FrameMessage, Body: []byte("world")},
		{Kind: FrameCommand, Body: []byte("READY")},
		{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 300)},
	}
	var buf bytes.Buffer
	scratch := make([]byte, 1024)
	for _, f := range want {
		n, err := EncodeFrame(scratch[:f.WireSize()], f)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(scratch[:n])
	}
	fr := NewFrameReader(&buf)
	for i, w := range want {
		g, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if g.Kind != w.Kind || g.More != w.More || !bytes.Equal(g.Body, w.Body) {
			t.Fatalf("frame %d: got %+v, want %+v", i, g, w)
		}
	}
	if _, err := fr.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF after last frame, got %v", err)
	}
}

func TestFrameReaderPartialReads(t *testing.T) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0x42}, 100)}
	var buf bytes.Buffer
	scratch := make([]byte, f.WireSize())
	if _, err := EncodeFrame(scratch, f); err != nil {
		t.Fatal(err)
	}
	buf.Write(scratch)

	fr := NewFrameReader(iotest.OneByteReader(&buf))
	got, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Body, f.Body) {
		t.Fatal("body mismatch under partial reads")
	}
}

func TestFrameReaderTruncatedMidFrame(t *testing.T) {
	full := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0x10}, 50)}
	scratch := make([]byte, full.WireSize())
	if _, err := EncodeFrame(scratch, full); err != nil {
		t.Fatal(err)
	}
	// Truncate halfway.
	r := bytes.NewReader(scratch[:len(scratch)-10])
	fr := NewFrameReader(r)
	if _, err := fr.ReadFrame(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestFrameReaderReservedFlags(t *testing.T) {
	bad := []byte{0x08, 0x00}
	fr := NewFrameReader(bytes.NewReader(bad))
	if _, err := fr.ReadFrame(); !errors.Is(err, ErrReservedFlags) {
		t.Fatalf("want ErrReservedFlags, got %v", err)
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: FAIL — `FrameReader` undefined.**

- [ ] **Step 3: Implement `internal/wire/frame_reader.go`**

```go
package wire

import (
	"encoding/binary"
	"io"
)

// FrameReader reads ZMTP 3.1 frames from an io.Reader. Each ReadFrame
// allocates a fresh Body slice. Not safe for concurrent use.
type FrameReader struct {
	r      io.Reader
	header [9]byte
}

// NewFrameReader returns a FrameReader that reads from r.
func NewFrameReader(r io.Reader) *FrameReader { return &FrameReader{r: r} }

// ReadFrame reads the next frame from the underlying reader. Returns
// io.EOF only when the stream cleanly ends between frames; a truncated
// frame surfaces io.ErrUnexpectedEOF.
func (fr *FrameReader) ReadFrame() (Frame, error) {
	// Flags byte.
	if _, err := io.ReadFull(fr.r, fr.header[:1]); err != nil {
		return Frame{}, err // io.EOF passes through cleanly here.
	}
	flags := fr.header[0]
	if flags&0xF8 != 0 {
		return Frame{}, ErrReservedFlags
	}
	more := flags&0x01 != 0
	long := flags&0x02 != 0
	cmd := flags&0x04 != 0
	if cmd && more {
		return Frame{}, ErrCommandHasMore
	}

	var size uint64
	if long {
		if _, err := io.ReadFull(fr.r, fr.header[:8]); err != nil {
			return Frame{}, mapEOF(err)
		}
		size = binary.BigEndian.Uint64(fr.header[:8])
	} else {
		if _, err := io.ReadFull(fr.r, fr.header[:1]); err != nil {
			return Frame{}, mapEOF(err)
		}
		size = uint64(fr.header[0])
	}

	body := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(fr.r, body); err != nil {
			return Frame{}, mapEOF(err)
		}
	}
	kind := FrameMessage
	if cmd {
		kind = FrameCommand
	}
	return Frame{Kind: kind, More: more, Body: body}, nil
}

// mapEOF converts a clean io.EOF mid-frame into io.ErrUnexpectedEOF.
func mapEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
```

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/frame_reader.go internal/wire/frame_reader_test.go
git commit -m "wire: FrameReader streaming decoder"
```

---

### Task 10: `FrameWriter`

**Files:**
- Create: `internal/wire/frame_writer.go`
- Create: `internal/wire/frame_writer_test.go`

- [ ] **Step 1: Write failing tests**

```go
package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestFrameWriterRoundTrip(t *testing.T) {
	frames := []Frame{
		{Kind: FrameMessage, More: true, Body: []byte("a")},
		{Kind: FrameMessage, Body: []byte("b")},
		{Kind: FrameCommand, Body: []byte("READY")},
		{Kind: FrameMessage, Body: bytes.Repeat([]byte{0x77}, 1000)},
	}
	var sink bytes.Buffer
	fw := NewFrameWriter(&sink)
	for _, f := range frames {
		if err := fw.WriteFrame(f); err != nil {
			t.Fatal(err)
		}
	}
	fr := NewFrameReader(&sink)
	for i, w := range frames {
		g, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if g.Kind != w.Kind || g.More != w.More || !bytes.Equal(g.Body, w.Body) {
			t.Fatalf("frame %d: got %+v, want %+v", i, g, w)
		}
	}
}

func TestFrameWriterCommandWithMoreRejected(t *testing.T) {
	fw := NewFrameWriter(&bytes.Buffer{})
	err := fw.WriteFrame(Frame{Kind: FrameCommand, More: true, Body: []byte("X")})
	if !errors.Is(err, ErrCommandHasMore) {
		t.Fatalf("want ErrCommandHasMore, got %v", err)
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: FAIL.**

- [ ] **Step 3: Implement `internal/wire/frame_writer.go`**

```go
package wire

import (
	"encoding/binary"
	"io"
)

// FrameWriter writes ZMTP 3.1 frames to an io.Writer. Not safe for
// concurrent use.
type FrameWriter struct {
	w      io.Writer
	header [9]byte
}

// NewFrameWriter returns a FrameWriter wrapping w.
func NewFrameWriter(w io.Writer) *FrameWriter { return &FrameWriter{w: w} }

// WriteFrame encodes f and writes it to the underlying writer. Returns
// ErrCommandHasMore if f is a command with the MORE flag set.
func (fw *FrameWriter) WriteFrame(f Frame) error {
	if f.Kind == FrameCommand && f.More {
		return ErrCommandHasMore
	}
	var flags byte
	if f.More {
		flags |= 0x01
	}
	long := len(f.Body) > MaxShortBodySize
	if long {
		flags |= 0x02
	}
	if f.Kind == FrameCommand {
		flags |= 0x04
	}
	fw.header[0] = flags
	hdrLen := 2
	if long {
		binary.BigEndian.PutUint64(fw.header[1:9], uint64(len(f.Body)))
		hdrLen = 9
	} else {
		fw.header[1] = byte(len(f.Body))
	}
	if _, err := fw.w.Write(fw.header[:hdrLen]); err != nil {
		return err
	}
	if len(f.Body) > 0 {
		if _, err := fw.w.Write(f.Body); err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/frame_writer.go internal/wire/frame_writer_test.go
git commit -m "wire: FrameWriter streaming encoder"
```

---

## Chunk 4: Commands

### Task 11: Generic `ParseCommand` / `EncodeCommand`

**Files:**
- Create: `internal/wire/command.go`
- Create: `internal/wire/command_test.go`

Per RFC 37: a command body is `command-name = short-size 1*255command-name-char`, where `command-name-char` is `ALPHA` (A–Z, a–z). Body is the raw remainder.

- [ ] **Step 1: Write failing tests**

```go
package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeParseCommandRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		cmd  Command
	}{
		{"ready", Command{Name: "READY", Data: []byte("metadata")}},
		{"empty-data", Command{Name: "PING", Data: nil}},
		{"max-name-len", Command{Name: string(bytes.Repeat([]byte{'A'}, 255)), Data: []byte{0x00}}},
		{"binary-data", Command{Name: "ERROR", Data: []byte{0x00, 0xFF, 0x80, 0x7F}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, err := EncodeCommand(c.cmd)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseCommand(body)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != c.cmd.Name || !bytes.Equal(got.Data, c.cmd.Data) {
				t.Fatalf("got %+v, want %+v", got, c.cmd)
			}
		})
	}
}

func TestEncodeCommandRejectInvalidName(t *testing.T) {
	cases := []struct {
		name string
		nm   string
	}{
		{"empty", ""},
		{"too-long", string(bytes.Repeat([]byte{'A'}, 256))},
		{"non-letter", "FOO_BAR"},
		{"digit", "F00"},
		{"non-ascii", "FOOÉ"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := EncodeCommand(Command{Name: c.nm}); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("want ErrInvalidCommand, got %v", err)
			}
		})
	}
}

func TestParseCommandTruncated(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"empty", []byte{}},
		{"name-len-zero", []byte{0x00}},
		{"name-truncated", []byte{0x05, 'R', 'E', 'A'}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseCommand(c.body); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("want ErrInvalidCommand, got %v", err)
			}
		})
	}
}

func TestParseCommandNonLetterName(t *testing.T) {
	body := []byte{0x03, 'F', '0', '0'} // digit in name
	if _, err := ParseCommand(body); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: FAIL.**

- [ ] **Step 3: Implement `internal/wire/command.go`**

```go
package wire

import "fmt"

// Command is a parsed command-frame body.
//
// Data aliases the input buffer when produced by ParseCommand; copy if
// you retain it past the next parse call.
type Command struct {
	Name string // ASCII letters only, 1..255 chars
	Data []byte // command-specific payload
}

// ParseCommand parses a command body (the bytes inside a command Frame.Body).
// On success, Data aliases body.
func ParseCommand(body []byte) (Command, error) {
	if len(body) < 1 {
		return Command{}, fmt.Errorf("%w: empty body", ErrInvalidCommand)
	}
	nameLen := int(body[0])
	if nameLen == 0 {
		return Command{}, fmt.Errorf("%w: name length is zero", ErrInvalidCommand)
	}
	if 1+nameLen > len(body) {
		return Command{}, fmt.Errorf("%w: name truncated (length %d, body %d)", ErrInvalidCommand, nameLen, len(body)-1)
	}
	for i := 0; i < nameLen; i++ {
		if !isCommandNameChar(body[1+i]) {
			return Command{}, fmt.Errorf("%w: non-letter byte 0x%02X in name at offset %d", ErrInvalidCommand, body[1+i], i)
		}
	}
	return Command{
		Name: string(body[1 : 1+nameLen]),
		Data: body[1+nameLen:],
	}, nil
}

// EncodeCommand returns the wire body for c, suitable as Frame.Body.
func EncodeCommand(c Command) ([]byte, error) {
	if err := validateCommandName(c.Name); err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(c.Name)+len(c.Data))
	out[0] = byte(len(c.Name))
	copy(out[1:], c.Name)
	copy(out[1+len(c.Name):], c.Data)
	return out, nil
}

func validateCommandName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("%w: empty command name", ErrInvalidCommand)
	}
	if len(name) > 255 {
		return fmt.Errorf("%w: command name too long (%d > 255)", ErrInvalidCommand, len(name))
	}
	for i := 0; i < len(name); i++ {
		if !isCommandNameChar(name[i]) {
			return fmt.Errorf("%w: non-letter byte 0x%02X in name at offset %d", ErrInvalidCommand, name[i], i)
		}
	}
	return nil
}

// isCommandNameChar implements the ABNF "ALPHA" rule (A-Z / a-z).
func isCommandNameChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}
```

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/command.go internal/wire/command_test.go
git commit -m "wire: generic Command parse/encode"
```

---

### Task 12: `ReadyCommand` + metadata

**Files:**
- Create: `internal/wire/command_ready.go`
- Create: `internal/wire/command_ready_test.go`

ABNF (RFC 37):
- `ready = command-size %d5 "READY" metadata`
- `metadata = *property`
- `property = name value`
- `name = short-size 1*255name-char`, `name-char = ALPHA / DIGIT / "-" / "_" / "." / "+"`
- `value = value-size value-data`, `value-size = 4OCTET` (big-endian)

Note: per RFC 27/ZMTP, property names are case-insensitive; we preserve the case as transmitted but `Metadata.Get` is case-insensitive.

- [ ] **Step 1: Write failing tests**

```go
package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadyEncodeDecodeRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		rc   ReadyCommand
	}{
		{"empty", ReadyCommand{}},
		{"single-prop", ReadyCommand{Metadata: Metadata{
			{Name: "Socket-Type", Value: []byte("REQ")},
		}}},
		{"multi-prop-ordered", ReadyCommand{Metadata: Metadata{
			{Name: "Socket-Type", Value: []byte("DEALER")},
			{Name: "Identity", Value: []byte("client-1")},
			{Name: "Resource", Value: []byte("/tmp/foo")},
		}}},
		{"binary-value", ReadyCommand{Metadata: Metadata{
			{Name: "X-Bin", Value: []byte{0x00, 0xFF, 0x80}},
		}}},
		{"empty-value", ReadyCommand{Metadata: Metadata{
			{Name: "X-Empty", Value: []byte{}},
		}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := c.rc.Encode()
			if cmd.Name != "READY" {
				t.Fatalf("encoded command name=%q, want READY", cmd.Name)
			}
			got, err := ParseReady(cmd)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Metadata) != len(c.rc.Metadata) {
				t.Fatalf("metadata length: got %d, want %d", len(got.Metadata), len(c.rc.Metadata))
			}
			for i, p := range c.rc.Metadata {
				if got.Metadata[i].Name != p.Name || !bytes.Equal(got.Metadata[i].Value, p.Value) {
					t.Fatalf("property %d: got %+v, want %+v", i, got.Metadata[i], p)
				}
			}
		})
	}
}

func TestParseReadyWrongCommandName(t *testing.T) {
	if _, err := ParseReady(Command{Name: "ERROR"}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}

func TestParseReadyMalformedMetadata(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"name-len-zero", []byte{0x00}},
		{"name-truncated", []byte{0x05, 'A', 'B'}},
		{"value-size-truncated", []byte{0x01, 'X', 0x00, 0x00}},
		{"value-truncated", []byte{0x01, 'X', 0x00, 0x00, 0x00, 0x05, 'a', 'b'}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := Command{Name: "READY", Data: c.data}
			if _, err := ParseReady(cmd); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("want ErrInvalidCommand, got %v", err)
			}
		})
	}
}

func TestMetadataGetCaseInsensitive(t *testing.T) {
	m := Metadata{
		{Name: "Socket-Type", Value: []byte("REQ")},
	}
	v, ok := m.Get("socket-type")
	if !ok || string(v) != "REQ" {
		t.Fatalf("Get returned (%q, %v), want (REQ, true)", v, ok)
	}
	if _, ok := m.Get("Identity"); ok {
		t.Fatal("Get returned ok=true for missing key")
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: FAIL.**

- [ ] **Step 3: Implement `internal/wire/command_ready.go`**

```go
package wire

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ReadyCommandName is the wire name for the READY command.
const ReadyCommandName = "READY"

// ReadyCommand is the parsed body of a READY command (RFC 37).
type ReadyCommand struct {
	Metadata Metadata
}

// Metadata is an ordered list of properties carried by READY (and
// potentially other commands). Order is preserved on round-trip.
type Metadata []MetadataProperty

// MetadataProperty is one name/value pair.
type MetadataProperty struct {
	// Name: 1..255 chars from [A-Z a-z 0-9 - _ . +]. Case-insensitive on lookup.
	Name string
	// Value: 0..2^32-1 bytes, opaque.
	Value []byte
}

// Get returns the value of the first property whose name matches name
// (case-insensitive ASCII) and a boolean indicating presence.
func (m Metadata) Get(name string) ([]byte, bool) {
	for _, p := range m {
		if strings.EqualFold(p.Name, name) {
			return p.Value, true
		}
	}
	return nil, false
}

// ParseReady parses cmd as a READY command body.
func ParseReady(cmd Command) (ReadyCommand, error) {
	if cmd.Name != ReadyCommandName {
		return ReadyCommand{}, fmt.Errorf("%w: expected READY, got %q", ErrInvalidCommand, cmd.Name)
	}
	md, err := parseMetadata(cmd.Data)
	if err != nil {
		return ReadyCommand{}, err
	}
	return ReadyCommand{Metadata: md}, nil
}

// Encode returns the Command form of rc, suitable for embedding in a
// FrameCommand body via EncodeCommand.
func (rc ReadyCommand) Encode() Command {
	data := encodeMetadata(rc.Metadata)
	return Command{Name: ReadyCommandName, Data: data}
}

func parseMetadata(data []byte) (Metadata, error) {
	var out Metadata
	for off := 0; off < len(data); {
		if off+1 > len(data) {
			return nil, fmt.Errorf("%w: metadata truncated at name-size", ErrInvalidCommand)
		}
		nameLen := int(data[off])
		off++
		if nameLen == 0 {
			return nil, fmt.Errorf("%w: metadata property has zero-length name", ErrInvalidCommand)
		}
		if off+nameLen > len(data) {
			return nil, fmt.Errorf("%w: metadata name truncated", ErrInvalidCommand)
		}
		name := string(data[off : off+nameLen])
		off += nameLen
		if !isMetadataName(name) {
			return nil, fmt.Errorf("%w: invalid metadata name %q", ErrInvalidCommand, name)
		}
		if off+4 > len(data) {
			return nil, fmt.Errorf("%w: metadata value-size truncated", ErrInvalidCommand)
		}
		valSize := binary.BigEndian.Uint32(data[off : off+4])
		off += 4
		if off+int(valSize) > len(data) {
			return nil, fmt.Errorf("%w: metadata value truncated", ErrInvalidCommand)
		}
		out = append(out, MetadataProperty{Name: name, Value: data[off : off+int(valSize)]})
		off += int(valSize)
	}
	return out, nil
}

func encodeMetadata(md Metadata) []byte {
	size := 0
	for _, p := range md {
		size += 1 + len(p.Name) + 4 + len(p.Value)
	}
	out := make([]byte, size)
	off := 0
	for _, p := range md {
		out[off] = byte(len(p.Name))
		off++
		copy(out[off:], p.Name)
		off += len(p.Name)
		binary.BigEndian.PutUint32(out[off:off+4], uint32(len(p.Value)))
		off += 4
		copy(out[off:], p.Value)
		off += len(p.Value)
	}
	return out
}

func isMetadataName(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == '+':
		default:
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/command_ready.go internal/wire/command_ready_test.go
git commit -m "wire: ReadyCommand with metadata properties"
```

---

### Task 13: `ErrorCommand`

**Files:**
- Create: `internal/wire/command_error.go`
- Create: `internal/wire/command_error_test.go`

ABNF: `error = command-size %d5 "ERROR" error-reason`, `error-reason = short-size 0*255VCHAR`.

- [ ] **Step 1: Write failing tests**

```go
package wire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestErrorEncodeDecodeRoundTrip(t *testing.T) {
	cases := []ErrorCommand{
		{Reason: ""},
		{Reason: "Authentication failure"},
		{Reason: strings.Repeat("X", 255)},
	}
	for _, ec := range cases {
		cmd := ec.Encode()
		got, err := ParseError(cmd)
		if err != nil {
			t.Fatalf("%q: %v", ec.Reason, err)
		}
		if got.Reason != ec.Reason {
			t.Fatalf("got %q, want %q", got.Reason, ec.Reason)
		}
	}
}

func TestErrorEncodeOversized(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on oversized reason")
		}
	}()
	_ = ErrorCommand{Reason: strings.Repeat("X", 256)}.Encode()
}

func TestParseErrorMalformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"reason-truncated", []byte{0x05, 'a', 'b'}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := Command{Name: "ERROR", Data: c.data}
			if _, err := ParseError(cmd); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("want ErrInvalidCommand, got %v", err)
			}
		})
	}
}

func TestParseErrorTrailingData(t *testing.T) {
	cmd := Command{Name: "ERROR", Data: append([]byte{0x02, 'a', 'b'}, 0xFF)}
	if _, err := ParseError(cmd); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}

func TestParseErrorWrongName(t *testing.T) {
	if _, err := ParseError(Command{Name: "READY"}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}

func TestErrorEncodeWireBytes(t *testing.T) {
	ec := ErrorCommand{Reason: "X"}
	cmd := ec.Encode()
	if !bytes.Equal(cmd.Data, []byte{0x01, 'X'}) {
		t.Fatalf("got %x, want %x", cmd.Data, []byte{0x01, 'X'})
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: FAIL.**

- [ ] **Step 3: Implement `internal/wire/command_error.go`**

```go
package wire

import "fmt"

// ErrorCommandName is the wire name for the ERROR command.
const ErrorCommandName = "ERROR"

// ErrorCommand is the parsed body of an ERROR command (RFC 37).
type ErrorCommand struct {
	// Reason: 0..255 visible-ASCII characters describing the failure.
	Reason string
}

// ParseError parses cmd as an ERROR command body.
func ParseError(cmd Command) (ErrorCommand, error) {
	if cmd.Name != ErrorCommandName {
		return ErrorCommand{}, fmt.Errorf("%w: expected ERROR, got %q", ErrInvalidCommand, cmd.Name)
	}
	if len(cmd.Data) < 1 {
		return ErrorCommand{}, fmt.Errorf("%w: ERROR body missing reason-size", ErrInvalidCommand)
	}
	reasonLen := int(cmd.Data[0])
	if 1+reasonLen != len(cmd.Data) {
		return ErrorCommand{}, fmt.Errorf("%w: ERROR reason length %d does not match body %d", ErrInvalidCommand, reasonLen, len(cmd.Data)-1)
	}
	return ErrorCommand{Reason: string(cmd.Data[1 : 1+reasonLen])}, nil
}

// Encode produces the wire form. Panics if Reason is longer than 255
// characters — callers must validate before calling.
func (ec ErrorCommand) Encode() Command {
	if len(ec.Reason) > 255 {
		panic("wire: ErrorCommand.Reason exceeds 255 chars")
	}
	data := make([]byte, 1+len(ec.Reason))
	data[0] = byte(len(ec.Reason))
	copy(data[1:], ec.Reason)
	return Command{Name: ErrorCommandName, Data: data}
}
```

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/command_error.go internal/wire/command_error_test.go
git commit -m "wire: ErrorCommand"
```

---

### Task 14: `PingCommand` / `PongCommand`

**Files:**
- Create: `internal/wire/command_ping.go`
- Create: `internal/wire/command_ping_test.go`

ABNF:
- `ping = command-size %d4 "PING" ping-ttl ping-context`
- `ping-ttl = 2OCTET` (big-endian, tenths of a second)
- `ping-context = 0*16OCTET`
- `pong = command-size %d4 "PONG" ping-context`

- [ ] **Step 1: Write failing tests**

```go
package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestPingPongRoundTrip(t *testing.T) {
	pings := []PingCommand{
		{TTL: 0, Context: nil},
		{TTL: 100, Context: []byte("ctx")},
		{TTL: 0xFFFF, Context: bytes.Repeat([]byte{0xAA}, 16)},
	}
	for _, p := range pings {
		got, err := ParsePing(p.Encode())
		if err != nil {
			t.Fatalf("ping: %v", err)
		}
		if got.TTL != p.TTL || !bytes.Equal(got.Context, p.Context) {
			t.Fatalf("got %+v, want %+v", got, p)
		}
	}

	pongs := []PongCommand{
		{Context: nil},
		{Context: []byte("ctx")},
		{Context: bytes.Repeat([]byte{0xBB}, 16)},
	}
	for _, p := range pongs {
		got, err := ParsePong(p.Encode())
		if err != nil {
			t.Fatalf("pong: %v", err)
		}
		if !bytes.Equal(got.Context, p.Context) {
			t.Fatalf("got %x, want %x", got.Context, p.Context)
		}
	}
}

func TestPingEncodeOversizedContext(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("want panic on oversized context")
		}
	}()
	_ = PingCommand{Context: make([]byte, 17)}.Encode()
}

func TestParsePingMalformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"ttl-truncated", []byte{0x00}},
		{"context-too-long", append([]byte{0x00, 0x10}, bytes.Repeat([]byte{0xCC}, 17)...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := Command{Name: "PING", Data: c.data}
			if _, err := ParsePing(cmd); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("want ErrInvalidCommand, got %v", err)
			}
		})
	}
}

func TestParsePingWrongName(t *testing.T) {
	if _, err := ParsePing(Command{Name: "PONG"}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}

func TestParsePongTooLong(t *testing.T) {
	cmd := Command{Name: "PONG", Data: bytes.Repeat([]byte{0xDD}, 17)}
	if _, err := ParsePong(cmd); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: FAIL.**

- [ ] **Step 3: Implement `internal/wire/command_ping.go`**

```go
package wire

import (
	"encoding/binary"
	"fmt"
)

// PingCommandName / PongCommandName are the wire names.
const (
	PingCommandName = "PING"
	PongCommandName = "PONG"
)

// PingContextMaxSize is the largest allowed PING / PONG context.
const PingContextMaxSize = 16

// PingCommand is the parsed body of a PING heartbeat (RFC 37).
type PingCommand struct {
	TTL     uint16 // tenths of a second
	Context []byte // 0..16 bytes; echoed by PONG
}

// PongCommand is the response to PING.
type PongCommand struct {
	Context []byte // 0..16 bytes; should equal the PING's context
}

// ParsePing parses cmd as a PING body.
func ParsePing(cmd Command) (PingCommand, error) {
	if cmd.Name != PingCommandName {
		return PingCommand{}, fmt.Errorf("%w: expected PING, got %q", ErrInvalidCommand, cmd.Name)
	}
	if len(cmd.Data) < 2 {
		return PingCommand{}, fmt.Errorf("%w: PING TTL truncated", ErrInvalidCommand)
	}
	ctx := cmd.Data[2:]
	if len(ctx) > PingContextMaxSize {
		return PingCommand{}, fmt.Errorf("%w: PING context %d > 16", ErrInvalidCommand, len(ctx))
	}
	return PingCommand{
		TTL:     binary.BigEndian.Uint16(cmd.Data[:2]),
		Context: ctx,
	}, nil
}

// Encode produces the Command form. Panics if Context > 16 bytes.
func (pc PingCommand) Encode() Command {
	if len(pc.Context) > PingContextMaxSize {
		panic("wire: PingCommand.Context exceeds 16 bytes")
	}
	data := make([]byte, 2+len(pc.Context))
	binary.BigEndian.PutUint16(data[:2], pc.TTL)
	copy(data[2:], pc.Context)
	return Command{Name: PingCommandName, Data: data}
}

// ParsePong parses cmd as a PONG body.
func ParsePong(cmd Command) (PongCommand, error) {
	if cmd.Name != PongCommandName {
		return PongCommand{}, fmt.Errorf("%w: expected PONG, got %q", ErrInvalidCommand, cmd.Name)
	}
	if len(cmd.Data) > PingContextMaxSize {
		return PongCommand{}, fmt.Errorf("%w: PONG context %d > 16", ErrInvalidCommand, len(cmd.Data))
	}
	return PongCommand{Context: cmd.Data}, nil
}

// Encode produces the Command form. Panics if Context > 16 bytes.
func (pc PongCommand) Encode() Command {
	if len(pc.Context) > PingContextMaxSize {
		panic("wire: PongCommand.Context exceeds 16 bytes")
	}
	return Command{Name: PongCommandName, Data: append([]byte(nil), pc.Context...)}
}
```

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/command_ping.go internal/wire/command_ping_test.go
git commit -m "wire: PingCommand / PongCommand"
```

---

### Task 15: `SubscribeCommand` / `CancelCommand`

**Files:**
- Create: `internal/wire/command_subscribe.go`
- Create: `internal/wire/command_subscribe_test.go`

- [ ] **Step 1: Write failing tests**

```go
package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestSubscribeCancelRoundTrip(t *testing.T) {
	subs := []SubscribeCommand{
		{Topic: nil},
		{Topic: []byte("news")},
		{Topic: bytes.Repeat([]byte{0xFF}, 4096)},
	}
	for _, s := range subs {
		got, err := ParseSubscribe(s.Encode())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Topic, s.Topic) {
			t.Fatalf("got %x, want %x", got.Topic, s.Topic)
		}
	}
	cancels := []CancelCommand{
		{Topic: nil},
		{Topic: []byte("news")},
	}
	for _, c := range cancels {
		got, err := ParseCancel(c.Encode())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Topic, c.Topic) {
			t.Fatalf("got %x, want %x", got.Topic, c.Topic)
		}
	}
}

func TestParseSubscribeWrongName(t *testing.T) {
	if _, err := ParseSubscribe(Command{Name: "CANCEL"}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("want ErrInvalidCommand, got %v", err)
	}
}
```

- [ ] **Step 2: Run `go test ./internal/wire/...`. Expected: FAIL.**

- [ ] **Step 3: Implement `internal/wire/command_subscribe.go`**

```go
package wire

import "fmt"

const (
	SubscribeCommandName = "SUBSCRIBE"
	CancelCommandName    = "CANCEL"
)

// SubscribeCommand asks the peer to deliver messages matching Topic.
type SubscribeCommand struct{ Topic []byte }

// CancelCommand undoes a prior SUBSCRIBE for Topic.
type CancelCommand struct{ Topic []byte }

func ParseSubscribe(cmd Command) (SubscribeCommand, error) {
	if cmd.Name != SubscribeCommandName {
		return SubscribeCommand{}, fmt.Errorf("%w: expected SUBSCRIBE, got %q", ErrInvalidCommand, cmd.Name)
	}
	return SubscribeCommand{Topic: cmd.Data}, nil
}

func (sc SubscribeCommand) Encode() Command {
	return Command{Name: SubscribeCommandName, Data: append([]byte(nil), sc.Topic...)}
}

func ParseCancel(cmd Command) (CancelCommand, error) {
	if cmd.Name != CancelCommandName {
		return CancelCommand{}, fmt.Errorf("%w: expected CANCEL, got %q", ErrInvalidCommand, cmd.Name)
	}
	return CancelCommand{Topic: cmd.Data}, nil
}

func (cc CancelCommand) Encode() Command {
	return Command{Name: CancelCommandName, Data: append([]byte(nil), cc.Topic...)}
}
```

- [ ] **Step 4: Run `go test ./internal/wire/...`. Expected: PASS.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/command_subscribe.go internal/wire/command_subscribe_test.go
git commit -m "wire: SubscribeCommand / CancelCommand"
```

---

## Chunk 5: Quality (vectors, fuzz, benchmarks, done)

### Task 16: Captured-wire vectors infrastructure

**Files:**
- Create: `internal/wire/testdata/README.md`
- Create: `testdata/interop/wire/capture.sh`

- [ ] **Step 1: Write `testdata/interop/wire/capture.sh`** — a script that runs `libzmq` peers in Docker, captures TCP traffic, and writes `.bin` files to `internal/wire/testdata/interop/`. Document required tools (`docker`, `tcpdump`) in the README.

```bash
#!/usr/bin/env bash
# Regenerates the wire-format vector files in
# internal/wire/testdata/interop/<name>.bin from a real libzmq instance.
#
# Usage: ./capture.sh [vector-name]
#
# Requires: docker (with the libzmq Docker image), tcpdump (for capture
# script alternative — currently we use `socat` to splice and Wireshark
# to extract bytes manually for new vectors). For each vector, see the
# corresponding section below.
set -euo pipefail
# ... vector capture procedures ...
echo "TODO: implement per-vector capture for the listed scenarios."
exit 1
```

This task only commits the *infrastructure* and a placeholder script.
The vectors themselves come from running the script (Task 17).

- [ ] **Step 2: Write `internal/wire/testdata/README.md`** explaining each vector file's purpose and how to regenerate it.

- [ ] **Step 3: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add testdata/interop/wire/capture.sh internal/wire/testdata/README.md
chmod +x testdata/interop/wire/capture.sh
git commit -m "wire: testdata layout and capture script skeleton"
```

---

### Task 17: Capture initial vectors and add vector tests

**Files:**
- Create: `internal/wire/testdata/interop/*.bin` (14 files)
- Create: `internal/wire/vector_test.go`

**Constraint:** the entire project forbids `cgo` (see `docs/specs/00-meta-overview.md` §7). The capture procedure therefore must not link any cgo wrappers (e.g. `pebbe/zmq4`) — even in a `cmd/` tool. Use only external `libzmq` binaries.

**Capture procedure** (run outside our Go module; nothing here lands in our `go.mod`):

1. Pull a known `libzmq` image: `docker pull confluentinc/cp-zookeeper:latest` *or* build from source. A workable image is whatever ships `zmq_*` example tools (e.g. `zmqpub`, `zmqsub`); alternatively use the `zmqcat` tool from the `python-zmq` package (CPython, no cgo on **our** side).
2. Inside the container (or a venv), launch a paired sender/receiver per scenario (NULL, PLAIN, CURVE handshakes; short/long/multipart messages; commands `READY`, `ERROR`, `PING`, `PONG`, `SUBSCRIBE`, `CANCEL`).
3. Capture loopback traffic with `tcpdump -i lo -w cap.pcap`.
4. Use `tshark -r cap.pcap -Tfields -e tcp.payload -Y 'tcp.port==<port>'` to extract the hex payload, decode to bytes, and write the relevant slice to `internal/wire/testdata/interop/<name>.bin`. (For multi-frame scenarios extract per-frame slices into separate files.)
5. Verify each `.bin` byte-for-byte against the ABNF in spec §3 before committing — tests in step 2 below will catch any drift.

Hand-crafting from the ABNF is acceptable for the simplest vectors (e.g. `greeting-null.bin`, an empty message frame, a short message frame), provided each is later confirmed against a `libzmq` capture during F4 interop work. Do not hand-craft `greeting-curve.bin` or any CURVE-handshake bytes — those depend on real `libzmq` cryptographic state.

- [ ] **Step 1: Capture (or hand-craft, where allowed) the vectors**, place them at `internal/wire/testdata/interop/<name>.bin`. Required filenames per spec §9.3.

- [ ] **Step 2: Write `internal/wire/vector_test.go`**

```go
package wire

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGreetingVectors(t *testing.T) {
	cases := []struct {
		file      string
		wantMech  string
		wantAsSrv bool
	}{
		{"greeting-null.bin", "NULL", false},
		{"greeting-plain.bin", "PLAIN", false},
		{"greeting-curve.bin", "CURVE", true},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			path := filepath.Join("testdata", "interop", c.file)
			raw, err := os.ReadFile(path)
			if err != nil {
				if os.Getenv("ZMQ4_VECTORS_PENDING") == "1" {
					t.Skipf("vector not yet captured: %v", err)
				}
				t.Fatalf("required vector missing (set ZMQ4_VECTORS_PENDING=1 during dev only): %v", err)
			}
			g, err := DecodeGreeting(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if g.Mechanism != c.wantMech || g.AsServer != c.wantAsSrv {
				t.Fatalf("got %+v, want mech=%s asServer=%v", g, c.wantMech, c.wantAsSrv)
			}
			// Re-encode and compare. Padding/filler must round-trip identically
			// (we always emit zeros).
			var enc [GreetingSize]byte
			if err := EncodeGreeting(enc[:], g); err != nil {
				t.Fatalf("encode: %v", err)
			}
			// Padding bytes 1..8 are "any" per spec; mask them out before compare.
			rawNorm := append([]byte{}, raw...)
			for i := 1; i < 9; i++ {
				rawNorm[i] = 0
			}
			if !bytes.Equal(enc[:], rawNorm) {
				t.Fatalf("round-trip mismatch:\ngot:  %x\nwant: %x", enc[:], rawNorm)
			}
		})
	}
}

// TODO: similar tests for frame-* and cmd-* vectors.
```

- [ ] **Step 3: Add similar functions for frame-* and cmd-* vectors.**

- [ ] **Step 4: Run `ZMQ4_VECTORS_PENDING=1 go test ./internal/wire/...`. Expected: PASS for all captured vectors. Vectors not yet captured produce SKIP. Task 20 will fail-close if any required vector is still missing at done-criteria time.**

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/testdata/interop/ internal/wire/vector_test.go
git commit -m "wire: captured-wire vector tests"
```

---

### Task 18: Fuzz tests

**Files:**
- Create: `internal/wire/fuzz_test.go`

- [ ] **Step 1: Write fuzz harness**

```go
package wire

import "testing"

func FuzzDecodeFrame(f *testing.F) {
	// Seed with a few hand-picked good and bad inputs.
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'})
	f.Add([]byte{0x04, 0x05, 'R', 'E', 'A', 'D', 'Y'})
	f.Add([]byte{0xFF}) // reserved bits
	f.Fuzz(func(t *testing.T, data []byte) {
		fr, n, err := DecodeFrame(data)
		if err != nil {
			return
		}
		if n < 0 || n > len(data) {
			t.Fatalf("invariant: n=%d out of range for input %d", n, len(data))
		}
		// Re-encode and verify it parses back identically.
		buf := make([]byte, fr.WireSize())
		if _, err := EncodeFrame(buf, fr); err != nil {
			t.Fatalf("re-encode failed for valid decode: %v", err)
		}
	})
}

func FuzzDecodeGreeting(f *testing.F) {
	var seed [GreetingSize]byte
	_ = EncodeGreeting(seed[:], Greeting{Mechanism: "NULL"})
	f.Add(seed[:])
	f.Add(make([]byte, GreetingSize))
	f.Add(make([]byte, GreetingSize-1))
	f.Fuzz(func(t *testing.T, data []byte) {
		g, err := DecodeGreeting(data)
		if err != nil {
			return
		}
		var enc [GreetingSize]byte
		if err := EncodeGreeting(enc[:], g); err != nil {
			t.Fatalf("re-encode failed for valid decode: %v", err)
		}
	})
}
```

- [ ] **Step 2: Smoke run** — `go test -run=^$ -fuzz=FuzzDecodeFrame -fuzztime=10s ./internal/wire/...` should not panic. Same for `FuzzDecodeGreeting`.

- [ ] **Step 3: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/fuzz_test.go
git commit -m "wire: fuzz harnesses for decoder no-panic invariants"
```

---

### Task 19: Benchmarks

**Files:**
- Create: `internal/wire/bench_test.go`

- [ ] **Step 1: Write benchmarks**

```go
package wire

import (
	"bytes"
	"testing"
)

func BenchmarkEncodeFrame1KiB(b *testing.B) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	buf := make([]byte, f.WireSize())
	b.SetBytes(int64(f.WireSize()))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeFrame(buf, f)
	}
}

func BenchmarkDecodeFrame1KiB(b *testing.B) {
	f := Frame{Kind: FrameMessage, Body: bytes.Repeat([]byte{0xAA}, 1024)}
	buf := make([]byte, f.WireSize())
	_, _ = EncodeFrame(buf, f)
	b.SetBytes(int64(f.WireSize()))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = DecodeFrame(buf)
	}
}

func BenchmarkEncodeGreeting(b *testing.B) {
	var buf [GreetingSize]byte
	g := Greeting{Mechanism: "NULL"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeGreeting(buf[:], g)
	}
}
```

- [ ] **Step 2: Run** `go test -bench=. -benchmem ./internal/wire/...`. Confirm `B/op == 0` for `BenchmarkEncodeFrame1KiB` and `BenchmarkDecodeFrame1KiB`. Throughput should be ≥ 1 GB/s on the dev machine; flag if not.

- [ ] **Step 3: Commit**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add internal/wire/bench_test.go
git commit -m "wire: encode/decode benchmarks"
```

---

### Task 20: Cleanup, vet, staticcheck, and Done-criteria sweep

**Files:**
- Possibly minor edits across `internal/wire/`.

- [ ] **Step 1: Run `go vet ./internal/wire/...`.** Fix any warnings.

- [ ] **Step 2: Run `staticcheck ./internal/wire/...` (install if needed: `go install honnef.co/go/tools/cmd/staticcheck@latest`).** Fix any findings; commit per fix.

- [ ] **Step 3: Run full test suite once more, including allocation contracts:**

```bash
go test -count=1 -race ./internal/wire/...
go test -run=TestEncodeFrameZeroAllocations ./internal/wire/...
go test -run=TestDecodeFrameZeroAllocations ./internal/wire/...
go test -run=TestEncodeGreetingZeroAllocations ./internal/wire/...
```

- [ ] **Step 4: Verify all required wire vectors are present** (no `ZMQ4_VECTORS_PENDING` shortcut allowed at this point):

```bash
cd ~/Projects/github.com/tomi77/zmq4
required=(
  greeting-null.bin greeting-plain.bin greeting-curve.bin
  frame-empty.bin frame-short.bin frame-long.bin frame-multipart.bin
  cmd-ready-empty.bin cmd-ready-typical.bin
  cmd-error.bin cmd-ping.bin cmd-pong.bin
  cmd-subscribe.bin cmd-cancel.bin
)
missing=0
for f in "${required[@]}"; do
  if [ ! -s "internal/wire/testdata/interop/$f" ]; then
    echo "MISSING: $f"
    missing=1
  fi
done
[ "$missing" -eq 0 ] || { echo "Done criteria not met: missing wire vectors above"; exit 1; }
unset ZMQ4_VECTORS_PENDING
go test -count=1 ./internal/wire/...
```

Expected: no `MISSING:` output and all tests PASS.

- [ ] **Step 5: Cross-reference Done-criteria checklist** in [`docs/specs/01-zmtp-wire-protocol.md`](../specs/01-zmtp-wire-protocol.md) §12. Every box must be checkable.

- [ ] **Step 6: Commit any cleanup**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add -p   # stage changes by hunk; verify
git commit -m "wire: cleanup and final-sweep adjustments"
```

---

### Task 21: Mark Phase 1 complete

**Files:**
- Modify: `docs/specs/01-zmtp-wire-protocol.md` (status line)
- Modify: `docs/specs/00-meta-overview.md` (phase table progress, optional)

- [ ] **Step 1: Update F1 spec status** from `draft, awaiting approval before implementation` to `implemented, frozen for F2+`.

- [ ] **Step 2: Tick the Done-criteria checklist boxes** in §12 of the F1 spec.

- [ ] **Step 3: Commit and tag**

```bash
cd ~/Projects/github.com/tomi77/zmq4
git add docs/specs/01-zmtp-wire-protocol.md
git commit -m "wire: mark Phase 1 (ZMTP wire protocol) complete"
git tag phase-1-wire-complete
```

(Tag is local-only until a remote is added; the user can decide later whether to push it.)

---

## Out of scope for Phase 1 (do **not** add here)

- Connection state machine (F4).
- Security mechanism state machines (F2).
- Socket-type semantics (F5).
- Network code (F3 is `tcp`/`ipc`/`inproc`; this layer never touches `net`).
- ZAP authentication (F6).
- `JOIN` / `LEAVE` commands (out-of-scope per spec §2).

If during implementation you find yourself wanting to add any of the above to satisfy a test, the test belongs in a later phase. Stop and re-check the spec.

---

## Reference cheatsheet (during implementation)

- **Greeting layout:** spec §3, ABNF block, or table at top of Task 2.
- **Flag byte values:** Task 2 / spec §3 — `0x00..0x06`, others reserved.
- **ABNF rules for command names / metadata names:** spec §3.
- **Done criteria:** spec §12.
- **Buffer ownership table:** spec §7.
