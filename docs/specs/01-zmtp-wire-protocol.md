# 01 — ZMTP 3.1 wire protocol (Phase 1)

> **Status:** implemented, frozen for F2+.
> **Author:** Tomasz Rup
> **Date:** 2026-05-02
> **Layer:** L1 — `internal/wire`
> **Depends on:** nothing.
> **Consumed by:** F2 (security), F4 (connection), F5 (sockets).

## 1. Summary

This phase delivers `internal/wire`: a pure, I/O-free codec for the ZMTP 3.1
wire format. It defines and implements:

- The 64-byte connection greeting.
- The frame format (short/long, message/command, with the `MORE` flag).
- The command frame body structure and the standard command names defined
  by ZMTP 3.1.

It does **not** implement any state machine, connection lifecycle, security
handshake, or socket-type semantics. Those are later phases. This phase is
"give me bytes, get a Go struct" and "give me a Go struct, get bytes".

A thin streaming layer over `io.Reader` / `io.Writer` is included so that
later phases (and tests) don't have to reinvent length-prefixed frame reads.
It still does no networking I/O of its own — no `Dial`, `Listen`, or socket
ownership — and no blocking or concurrency: it strictly uses the caller-
provided `io` interfaces. The one exception is `net.Buffers`, used by
`FrameWriter` to emit header+body in a single writev syscall when the
caller's writer supports it (e.g. `*net.TCPConn`); it is a passive batching
helper, not a networking primitive.

## 2. Mapping to RFC 37/ZMTP 3.1

| RFC section | F1 covers |
|-------------|-----------|
| Connection — greeting | **Yes** (encode + decode + version & signature validation). |
| Framing | **Yes** (short/long, command/message, `MORE`). |
| Commands — generic format | **Yes** (encode + decode of `command-name` + `command-data`). |
| `READY` body / metadata | **Yes** (parse + encode metadata properties). |
| `ERROR` body | **Yes** (parse + encode error reason). |
| `SUBSCRIBE` / `CANCEL` body | **Format only** (semantics in F5b: pub/sub sockets). |
| `PING` / `PONG` body | **Yes** (parse + encode; semantics — heartbeat — in F4). |
| `JOIN` / `LEAVE` | **Out of scope** (draft socket types). |
| Security handshake | **F2** (this phase parses commands but does not drive a handshake). |
| Connection lifecycle | **F4**. |

## 3. ABNF (verbatim from RFC 37, for implementation reference)

```abnf
zmtp = greeting traffic
traffic = *(message | command)

;; Greeting -- 64 octets total
greeting        = signature version mechanism as-server filler
signature       = %xFF padding %x7F
padding         = 8OCTET                      ; not significant
version         = %x03 %x01                   ; ZMTP 3.1
mechanism       = 20mechanism-char
mechanism-char  = "A"-"Z" | DIGIT | "-" | "_" | "." | "+" | %x0
as-server       = %x00 | %x01
filler          = 31%x00

;; Frames
message         = message-more | message-last
message-more    = ( %x01 short-size | %x03 long-size ) message-body
message-last    = ( %x00 short-size | %x02 long-size ) message-body
message-body    = *OCTET
short-size      = OCTET                       ; 0..255
long-size       = 8OCTET                      ; big-endian, 0..2^63-1

command         = command-size command-body
command-size    = %x04 short-size | %x06 long-size
command-body    = command-name command-data
command-name    = short-size 1*255command-name-char
command-name-char = ALPHA
command-data    = *OCTET

;; Standard command bodies (after the command-name)
ready           = command-size %d5 "READY" metadata
metadata        = *property
property        = name value
name            = short-size 1*255name-char
name-char       = ALPHA | DIGIT | "-" | "_" | "." | "+"
value           = value-size value-data
value-size      = 4OCTET                      ; big-endian
value-data      = *OCTET

error           = command-size %d5 "ERROR" error-reason
error-reason    = short-size 0*255VCHAR

subscribe       = command-size %d9 "SUBSCRIBE" subscription
cancel          = command-size %d6 "CANCEL"    subscription
subscription    = *OCTET

ping            = command-size %d4 "PING" ping-ttl ping-context
ping-ttl        = 2OCTET                      ; tenths of a second
ping-context    = 0*16OCTET

pong            = command-size %d4 "PONG" ping-context
```

The flags byte concrete values (derived from the ABNF):

| Hex | Meaning |
|-----|---------|
| `0x00` | message, short size, last (no `MORE`) |
| `0x01` | message, short size, more |
| `0x02` | message, long size, last |
| `0x03` | message, long size, more |
| `0x04` | command, short size |
| `0x06` | command, long size |
| any other | reserved — must reject |

Bit layout: `0 0 0 0 0 [COMMAND] [LONG] [MORE]`. Reserved bits 3..7 must be
zero. Combinations `0x05` and `0x07` (command with `MORE`) are invalid and
must be rejected.

## 4. Public interface (within `internal/wire`)

```go
// Package wire implements the ZMTP 3.1 wire protocol codec.
// It performs no I/O of its own beyond what the caller's io.Reader /
// io.Writer does. It defines no state machine and is safe to use
// concurrently as long as different callers use different buffers.
package wire

// ---------- Greeting ----------

const GreetingSize = 64

// Greeting is the parsed form of the 64-byte ZMTP 3.1 connection greeting.
type Greeting struct {
    Mechanism string // "NULL", "PLAIN", "CURVE" or future ASCII name (≤20 chars)
    AsServer  bool   // peer's role for mechanism negotiation
}

// EncodeGreeting writes a 64-byte greeting into dst.
// Returns ErrShortBuffer if len(dst) < 64.
// Mechanism is right-padded with NULs; an oversized name returns ErrInvalidMechanism.
func EncodeGreeting(dst []byte, g Greeting) error

// DecodeGreeting parses a 64-byte greeting from src.
// Returns ErrShortBuffer if len(src) < 64.
// Returns ErrInvalidSignature, ErrUnsupportedVersion, or ErrInvalidMechanism
// if validation fails.
func DecodeGreeting(src []byte) (Greeting, error)

// ReadGreeting reads exactly 64 bytes from r and decodes them.
func ReadGreeting(r io.Reader) (Greeting, error)

// WriteGreeting encodes and writes a 64-byte greeting to w.
func WriteGreeting(w io.Writer, g Greeting) error

// ---------- Frames ----------

// FrameKind distinguishes message frames from command frames.
type FrameKind uint8
const (
    FrameMessage FrameKind = iota
    FrameCommand
)

// Frame is a single ZMTP frame.
//
// For decoded frames, Body aliases the source buffer for zero-copy. The
// caller owns the buffer's lifetime. Streaming readers (FrameReader) always
// allocate a fresh Body.
type Frame struct {
    Kind FrameKind
    More bool   // continuation flag; must be false when Kind == FrameCommand
    Body []byte // raw payload; for commands, see ParseCommand / EncodeCommand
}

// MaxShortBodySize is the largest body that can use the short-size encoding.
const MaxShortBodySize = 255

// WireSize returns the total on-wire size of f, including flags and size fields.
func (f Frame) WireSize() int

// EncodeFrame writes f's wire representation into dst.
// Returns ErrShortBuffer if len(dst) < f.WireSize().
// Returns ErrCommandHasMore if f.Kind == FrameCommand && f.More.
func EncodeFrame(dst []byte, f Frame) (int, error)

// DecodeFrame parses one frame starting at src[0].
// Returns the frame, the number of bytes consumed, and any error.
// Returns ErrShortBuffer if src is truncated.
// On error other than ErrShortBuffer, the second return value is 0.
func DecodeFrame(src []byte) (Frame, int, error)

// FrameReader reads framed messages from an io.Reader.
type FrameReader struct { /* ... */ }

func NewFrameReader(r io.Reader) *FrameReader

// ReadFrame reads the next frame, allocating a fresh Body slice.
// Returns io.EOF only when the stream cleanly ends between frames.
// Returns io.ErrUnexpectedEOF if a frame is truncated mid-read.
func (fr *FrameReader) ReadFrame() (Frame, error)

// FrameWriter writes framed messages to an io.Writer.
type FrameWriter struct { /* ... */ }

func NewFrameWriter(w io.Writer) *FrameWriter

// WriteFrame encodes and writes f. Returns the underlying writer's error,
// or ErrCommandHasMore if f is a command with MORE set.
func (fw *FrameWriter) WriteFrame(f Frame) error

// ---------- Commands ----------

// Command is a parsed command frame body.
type Command struct {
    Name string // ASCII letters only, 1..255 chars
    Data []byte // command-specific payload; aliases caller buffer for zero-copy
}

// ParseCommand parses a command body (the bytes inside a command Frame.Body).
// Returns ErrInvalidCommand if the name length is invalid or contains
// non-ASCII-letter characters.
func ParseCommand(body []byte) (Command, error)

// EncodeCommand returns the wire body for a Command (suitable for Frame.Body).
// Returns ErrInvalidCommand if c.Name is empty or contains non-letter chars.
func EncodeCommand(c Command) ([]byte, error)

// ---------- Standard commands ----------

// Metadata is the keyed, ordered property map used by READY.
// Order is preserved on round-trip.
type Metadata []MetadataProperty
type MetadataProperty struct {
    Name  string // ASCII, 1..255 chars, allowed: letters, digits, "-_.+ "
    Value []byte // 0..2^32-1 bytes
}

// Get returns the value of the first property with the given name (case-insensitive
// per RFC) and whether it was present.
func (m Metadata) Get(name string) ([]byte, bool)

// ReadyCommand is the parsed body of the READY command (post-name).
type ReadyCommand struct{ Metadata Metadata }

func ParseReady(cmd Command) (ReadyCommand, error)
func (rc ReadyCommand) Encode() Command

// ErrorCommand is the parsed body of the ERROR command (post-name).
type ErrorCommand struct{ Reason string }

func ParseError(cmd Command) (ErrorCommand, error)
func (ec ErrorCommand) Encode() Command

// PingCommand / PongCommand: heartbeat (consumed by F4).
type PingCommand struct {
    TTL     uint16 // tenths of a second
    Context []byte // 0..16 bytes
}
type PongCommand struct {
    Context []byte // 0..16 bytes
}

func ParsePing(cmd Command) (PingCommand, error)
func (pc PingCommand) Encode() Command
func ParsePong(cmd Command) (PongCommand, error)
func (pc PongCommand) Encode() Command

// SubscribeCommand / CancelCommand: pub/sub topic management
// (semantics consumed by F5b).
type SubscribeCommand struct{ Topic []byte }
type CancelCommand struct{ Topic []byte }

func ParseSubscribe(cmd Command) (SubscribeCommand, error)
func (sc SubscribeCommand) Encode() Command
func ParseCancel(cmd Command) (CancelCommand, error)
func (cc CancelCommand) Encode() Command
```

## 5. Internal data structures

The package is stateless. The two types that hold state are `FrameReader`
and `FrameWriter`, and that state is just an internal scratch buffer to
avoid allocating on every read/write of size headers.

```go
type FrameReader struct {
    r      io.Reader
    header [9]byte // 1 flag + up to 8 size bytes
}

type FrameWriter struct {
    w      io.Writer
    header [9]byte
}
```

No goroutines, no mutexes, no timers. Concurrency safety: a single
`FrameReader` / `FrameWriter` is used by at most one goroutine at a time
(documented contract). Different readers/writers are independent.

## 6. Error model

Sentinel errors, all wrappable via `errors.Is`:

```go
var (
    ErrShortBuffer        = errors.New("zmq4/wire: buffer too short")
    ErrInvalidSignature   = errors.New("zmq4/wire: invalid greeting signature")
    ErrUnsupportedVersion = errors.New("zmq4/wire: unsupported ZMTP version (only 3.1 is supported)")
    ErrInvalidMechanism   = errors.New("zmq4/wire: invalid mechanism field")
    ErrReservedFlags      = errors.New("zmq4/wire: frame uses reserved flag bits")
    ErrCommandHasMore     = errors.New("zmq4/wire: command frame has MORE flag set")
    ErrInvalidCommand     = errors.New("zmq4/wire: malformed command")
    ErrFrameTooLarge      = errors.New("zmq4/wire: frame size exceeds 2^63-1")
)
```

`ReadGreeting`, `FrameReader.ReadFrame`, `WriteGreeting`, `FrameWriter.WriteFrame`
return underlying I/O errors unwrapped (so `errors.Is(err, io.EOF)` works).
A truncated read mid-frame returns `io.ErrUnexpectedEOF` (per Go convention).

Decoder errors include enough context to debug interop issues — they wrap
the sentinel and append the offending bytes when it helps:

```go
fmt.Errorf("%w: got 0x%02X 0x%02X, want 0xFF...0x7F", ErrInvalidSignature, src[0], src[9])
```

## 7. Buffer ownership

| Function | Returned slice | Caller must... |
|----------|----------------|----------------|
| `DecodeGreeting` | n/a (returns struct of strings/bools) | — |
| `DecodeFrame` | `Frame.Body` aliases `src` | copy if retained beyond next decode |
| `FrameReader.ReadFrame` | `Frame.Body` is freshly allocated | — |
| `ParseCommand` | `Command.Data` aliases input | copy if retained beyond next parse |
| `ParseReady` etc. | `Metadata` value slices alias input | copy if retained |

This is the same convention as `bufio.Scanner` and is documented per
function. F4 (connection layer) is where the trade-off is decided per call
site (it knows whether the underlying buffer outlives the frame).

## 8. State machines

None. F1 is a stateless codec.

## 9. Test plan

### 9.1 Unit tests

Per-component round-trip and edge-case tests, in
`internal/wire/*_test.go`:

- **Greeting**: round-trip; encode then decode equals input. Reject:
  bad signature byte 0, bad signature byte 9, version 3.0 (reject),
  version 4.0 (reject), mechanism with non-allowed char, mechanism without
  NUL termination at correct offset, oversized mechanism.
- **Frame**: round-trip for every flag combination (`0x00..0x06`).
  Boundary sizes: 0, 1, 254, 255 (boundary short/long), 256, 65535,
  16 MiB. Reject: reserved bits 3..7 set, flags `0x05`, flags `0x07`,
  truncated short frame, truncated long frame.
- **Multipart**: encode `[Frame{More:true}, Frame{More:true}, Frame{More:false}]`,
  decode same.
- **Commands**: round-trip for every standard command; invalid name
  characters; zero-length name; oversized name.
- **READY metadata**: empty metadata; one property; multiple properties;
  property with binary value containing `0x00` and `0xFF`; property name
  with allowed punctuation (`-_.+`).

### 9.2 Property-based tests

Using `testing/quick` (or `gopter` if `quick` proves limited):

- For random `Frame` (random kind, random body length, random MORE flag
  modulo command constraint): `Decode(Encode(f)) == f`.
- For random `Greeting`: round-trip.
- For random `ReadyCommand` (random metadata): round-trip including order.

### 9.3 Captured-wire vector tests

`testdata/interop/wire/` will hold byte dumps captured from `libzmq`. The
tests assert that we decode them correctly and that re-encoding the parsed
value produces byte-identical output (modulo greeting padding, which is
"any value" per spec — for our re-encoder we always emit zeros and accept
anything on read).

Capture script (committed under `internal/wire/testdata/`) runs two
`libzmq` peers, captures their TCP traffic with the standard
`SO_REUSEADDR` localhost trick, and dumps the bytes. Re-runnable
deterministically.

Initial vectors:
- `greeting-null.bin` — NULL handshake.
- `greeting-plain.bin` — PLAIN.
- `greeting-curve.bin` — CURVE.
- `frame-empty.bin`, `frame-short.bin`, `frame-long.bin`, `frame-multipart.bin`.
- `cmd-ready-empty.bin`, `cmd-ready-typical.bin`, `cmd-error.bin`,
  `cmd-ping.bin`, `cmd-pong.bin`, `cmd-subscribe.bin`, `cmd-cancel.bin`.

### 9.4 Streaming tests

`FrameReader` is exercised against:
- A `bytes.Reader` (happy path).
- A custom `iotest.OneByteReader`-style wrapper (forces partial reads).
- A reader that returns `io.ErrUnexpectedEOF` mid-frame.
- A reader that returns a transient error then resumes (must surface error
  cleanly without losing sync).

### 9.5 Fuzzing

A `go test -fuzz` target on `DecodeFrame` and `DecodeGreeting`:

- Must never panic.
- Must never read past `len(src)` when the function returns `(_, n, nil)`
  with `n > 0`. (Verified by oversizing the input and checking n.)

## 10. Non-functional requirements

- **Allocation**: `EncodeFrame` and `DecodeFrame` must allocate **zero**
  on the hot path (no Go heap allocation per frame). Verified by
  `testing.AllocsPerRun`. Streaming `FrameReader.ReadFrame` allocates
  exactly one `[]byte` per frame for the body.
- **Throughput target**: pure encode/decode of a 1 KiB short frame runs
  at ≥ 1 GB/s on the dev machine. Benchmarked in `bench_test.go`. This is
  a sanity floor, not a hard contract.

## 11. Open questions

1. **`Greeting.Mechanism` representation**: string vs. `[20]byte`. Going
   with `string` for ergonomics; downside is a small allocation in
   `DecodeGreeting`. **Resolved: string.**
2. **Should `Frame.Body` for a command be the raw command bytes (including
   the leading name-length and name) or only the post-name `command-data`?**
   **Decision:** raw bytes. `ParseCommand` peels off the name. This keeps
   `Frame` agnostic of command vs. message body interpretation.
3. **`PING` TTL in tenths of a second** — surface as `uint16` raw, or
   convert to `time.Duration`? **Decision:** raw `uint16` here. F4
   converts when consuming, since the heartbeat policy lives there.
4. **Should we expose `EncodeFrameTo(w io.Writer, f Frame)` in addition to
   `EncodeFrame(dst []byte, ...)`?** **Decision:** yes — `FrameWriter` is
   the streaming form. Single-call `EncodeFrame` stays for tests and
   places the caller wants to control buffering.
5. **Should standard-command parsers live here or in their consumers
   (F2/F4/F5b)?** **Decision:** here. The wire format is generic; keeping
   parsers next to the codec keeps `internal/wire` the single source of
   truth for the wire spec, and makes captured-wire vector tests easy to
   write without depending on later phases.

## 12. Done criteria

Phase 1 is "done" when:

- [x] All public functions in §4 are implemented and documented.
- [x] All tests in §9 pass: unit, property-based, captured-wire,
      streaming, fuzz.
- [x] `go vet ./internal/wire/...` clean. `staticcheck` clean.
- [x] `testing.AllocsPerRun` shows zero allocations for `EncodeFrame` and
      `DecodeFrame` in the documented hot paths.
- [x] At least one captured-wire vector exists for: greeting (NULL),
      message frame (short and long), multipart message, READY,
      ERROR, PING, PONG, SUBSCRIBE, CANCEL.
- [x] Code review against this spec confirms no requirement is missed.

The package is then frozen until F4 needs to consume it; bug fixes only.

## 13. References

- [RFC 37/ZMTP 3.1](https://rfc.zeromq.org/spec/37/) — primary reference.
- [RFC 23/ZMTP 3.0](https://rfc.zeromq.org/spec/23/) — predecessor;
  cross-reference for fields unchanged in 3.1.
- [`docs/specs/00-meta-overview.md`](./00-meta-overview.md) — parent spec.
