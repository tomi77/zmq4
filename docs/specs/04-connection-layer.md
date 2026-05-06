# 04 — Connection layer (Phase 4)

> **Status:** design approved, implementation pending.
> **Author:** Tomasz Rup
> **Date:** 2026-05-06
> **Layer:** L4 — `internal/conn`
> **Depends on:** F1 (`internal/wire`), F2a/F2b/F2c (`internal/security`),
> F3 (`internal/transport`).
> **Consumed by:** F5 (socket layer).

## 1. Summary

This phase delivers `internal/conn`: the layer that takes a raw `net.Conn`
(produced by F5 via `internal/transport`) plus a configured security
mechanism (from `internal/security`) and turns the pair into a single,
full-duplex, ZMTP-3.1-speaking connection. F4 owns the greeting (RFC 23
§3.2), the security handshake driver (RFC 23 §3.3, §4), and the
post-handshake frame stream (RFC 23 §5).

The public surface is two constructors plus a small `*Conn` API:

```go
func ClientHandshake(ctx context.Context, raw net.Conn,
    mech security.ClientMechanism, opts ...Option) (*Conn, error)
func ServerHandshake(ctx context.Context, raw net.Conn,
    mech security.Mechanism, opts ...Option) (*Conn, error)

type Conn struct{ /* opaque */ }

func (c *Conn) ReadFrame() (wire.Frame, error)
func (c *Conn) WriteFrame(f wire.Frame) error
func (c *Conn) PeerMetadata() wire.Metadata
func (c *Conn) Close() error
func (c *Conn) RemoteAddr() net.Addr
func (c *Conn) LocalAddr() net.Addr
```

What F4 explicitly does **not** do:

- **No reconnect.** A `*Conn` is single-shot. Reconnection (endpoint list,
  retry timing) is F5's job.
- **No socket-type semantics.** SUBSCRIBE/CANCEL filtering, REQ/REP request
  ID handling, ROUTER identity routing, PUSH/PULL fair-queueing — all F5.
- **No heartbeat.** PING/PONG (RFC 23 §5.1) are pass-through commands at L4.
  Operational heartbeat (sender, pong-watcher, idle-detection) is F6.
- **No HWM.** Per-pipe queue size is a socket-layer concern (F5/F6).
- **No goroutines after handshake.** Handshake spawns one short-lived
  context-watcher; it exits before `*Conn` is returned. Post-handshake
  reads and writes are synchronous on the calling goroutine.
- **No transport plumbing.** F4 does not parse endpoints, dial, listen, or
  accept. F5 calls `internal/transport` and hands F4 a ready `net.Conn`.

This phase is the **first live interop with `libzmq`** per
`00-meta-overview.md` §4: a containerised libzmq peer cross-validates the
greeting, handshake, and traffic frame stream for each
(mechanism × transport × direction) combination.

Forbidden dependencies (per `00-meta-overview.md` §3): `socket`. Allowed:
F1, F2, F3, standard library, `golang.org/x/crypto` (transitively via
F2c). No `cgo`.

## 2. Mapping to RFC 23/ZMTP 3.1

| RFC 23 § | F4 covers |
|----------|-----------|
| §3.2 Greeting (signature, version, mechanism, as-server, filler) | **Yes** — lockstep send-full / read-11 / validate / read-rest. |
| §3.3 Mechanism negotiation (exact name match) | **Yes** — mismatch returns `ErrMechanismMismatch` and aborts. No fallback. |
| §3.3.2 As-server bit, asymmetric vs symmetric mechanisms | **Yes** — PLAIN/CURVE require role flip, NULL ignores. |
| §4 Security handshake (HELLO/WELCOME/INITIATE/READY/...) | **Yes** — F4 drives `Mechanism.{Start,Receive,Done,PeerMetadata}` end-to-end. |
| §5 Traffic frames — messages | **Yes** — `wire.FrameReader`/`FrameWriter`, with `Mechanism.Wrap`/`Unwrap` for MESSAGE encapsulation in CURVE. |
| §5 Traffic commands — SUBSCRIBE/CANCEL/PING/PONG and unknown | **Pass-through.** F4 does not interpret traffic commands beyond ERROR. F5 owns SUBSCRIBE/CANCEL semantics; F6 owns PING/PONG. |
| §5.1 PING/PONG heartbeat | **No.** Pass-through only; operational heartbeat in F6. |
| §6 ERROR command (handshake or mid-traffic abort) | **Yes** — handshake: returns `ErrHandshakeFail` wrapping the reason. Mid-traffic: `ReadFrame` returns `*ErrPeerError` carrying the reason. |
| Multipart messages (MORE bit chains) | **Yes** — preserved verbatim through `ReadFrame`/`WriteFrame`. |
| ZMTP 3.0 / 2.0 / 1.0 fallback | **No.** Per `00-meta-overview.md` §7, only 3.1. Peer with version major ≠ 3 → `ErrUnsupportedVersion`. |
| Socket-type compatibility check (RFC 23 §2.4 metadata semantics) | **No.** F4 ferries `Socket-Type` and other metadata properties; semantic compatibility (e.g. `REQ` may only talk to `REP`/`ROUTER`) lives in F5. |
| ZAP (RFC 27) authentication for PLAIN/CURVE | **No.** Mechanism-level. F2b/F2c expose an `Authenticator` callback; F6 will provide a ZAP-backed implementation. |

### 2.1 Additive changes to F2 (amendments)

F4 needs the local mechanism's wire name to populate the greeting and the
peer's mechanism name to validate the match. The `security.Mechanism`
interface is extended with one method:

```go
// Name returns the wire name of this mechanism: "NULL", "PLAIN", or "CURVE".
// Stable for the lifetime of the Mechanism.
Name() string
```

This is **additive** on a frozen surface, following the precedent from F2c
(which retroactively added `Wrap`/`Unwrap` to `null.State`,
`plain.ClientState`, `plain.ServerState` per `02c-security-curve.md`
§2.1). The five existing implementations grow trivial accessors:

- `null.State.Name()` → `"NULL"`
- `plain.ClientState.Name()`, `plain.ServerState.Name()` → `"PLAIN"`
- `curve.ClientState.Name()`, `curve.ServerState.Name()` → `"CURVE"`

The frozen tags `phase-2a-null-complete`, `phase-2b-plain-complete`,
`phase-2c-curve-complete` remain valid (additive on a frozen surface). The
F2a/F2b/F2c spec docs gain a "F4 amendment" subsection mirroring this
section. No existing call site changes.

## 3. Public interface

All public API lives in `internal/conn`. The package is internal — the
only consumer is F5.

### 3.1 Constructors

```go
package conn

// ClientHandshake performs the ZMTP greeting and security handshake on the
// active side. raw is a connected net.Conn (typically the result of
// transport.Dial). mech is a configured ClientMechanism; F5 owns its
// construction and metadata setup.
//
// ctx MUST carry a deadline. Without one, ClientHandshake returns
// ErrNoDeadline before touching raw. With one, F4 sets raw.SetDeadline at
// entry and clears it before returning the *Conn.
//
// On success, returns a *Conn ready for ReadFrame/WriteFrame; raw is
// owned by *Conn (Close releases it). On failure, raw is closed by F4
// and the error is returned (wrapped with %w).
func ClientHandshake(ctx context.Context, raw net.Conn,
    mech security.ClientMechanism, opts ...Option) (*Conn, error)

// ServerHandshake — symmetric, takes a server-side (passive) Mechanism.
// Behaviour identical to ClientHandshake apart from greeting ordering
// (server reads peer greeting before sending its own; see §6.1) and the
// absence of mech.Start (server-side mechanisms react to client's first
// command).
func ServerHandshake(ctx context.Context, raw net.Conn,
    mech security.Mechanism, opts ...Option) (*Conn, error)
```

### 3.2 Options

```go
// Option configures handshake limits.
type Option func(*config)

// WithMaxMetadataSize caps the total TLV-encoded metadata bytes accepted
// from the peer in handshake (READY/INITIATE bodies). Default 8192.
// Panics if n <= 0.
func WithMaxMetadataSize(n int) Option

// WithMaxHandshakeCommandSize caps the body of any single handshake
// command frame received from the peer. Default 65536. Panics if n <= 0.
func WithMaxHandshakeCommandSize(n int) Option

// WithMaxFrameBodySize caps the body of post-handshake frames. Default
// wire.MaxFrameBodySize. Plumbed into wire.FrameReader. Panics if n <= 0.
func WithMaxFrameBodySize(n int64) Option
```

The defaults (8 KiB metadata, 64 KiB handshake command, F1's
`MaxFrameBodySize` for post-handshake) are set at the F4 level so F5 can
override per-socket as policy dictates.

### 3.3 *Conn methods

```go
// ReadFrame reads one post-handshake application frame from the peer.
// Not goroutine-safe. Frame body is freshly allocated (per F1 §7).
//
// Returns:
//   io.EOF                              on clean peer close between frames.
//   io.ErrUnexpectedEOF                 mid-frame truncation.
//   *ErrPeerError                       peer sent an ERROR command.
//   net.ErrClosed / io.ErrClosedPipe    after Close().
//   any error from mech.Unwrap          wrapped via fmt.Errorf with %w.
//
// FrameMessage frames are passed through mech.Unwrap (NULL/PLAIN: alias;
// CURVE: not expected on this path — see §6.4). FrameCommand frames are
// inspected by name:
//   "MESSAGE"                  → mech.Unwrap (CURVE post-handshake data).
//   "ERROR"                    → return *ErrPeerError with parsed reason.
//   anything else (SUBSCRIBE,
//   CANCEL, PING, PONG, …)     → return verbatim to F5.
func (c *Conn) ReadFrame() (wire.Frame, error)

// WriteFrame sends one application frame to the peer. Goroutine-safe via
// an internal mutex (one writer at a time on raw; bytes per frame are
// atomic on the wire). Body ownership rules per F2c: F4 reads f.Body
// synchronously and never retains a reference after WriteFrame returns.
//
// FrameMessage frames are run through mech.Wrap (NULL/PLAIN: alias;
// CURVE: encrypted into a MESSAGE command frame). FrameCommand frames
// are sent verbatim — F5 owns command-name correctness.
//
// Returns:
//   net.ErrClosed / io.ErrClosedPipe    after Close().
//   any error from mech.Wrap or         wrapped via fmt.Errorf with %w.
//   the underlying writer.
func (c *Conn) WriteFrame(f wire.Frame) error

// PeerMetadata returns the metadata advertised by the peer in handshake
// (READY for NULL, INITIATE+READY merge for PLAIN/CURVE — exact set
// determined by the mechanism). Read-only; valid for the lifetime of
// the Conn. Per F2c §2.1 the slice is owned by the mechanism; callers
// MUST NOT mutate it.
func (c *Conn) PeerMetadata() wire.Metadata

// Close closes the underlying raw conn and releases any in-flight reader
// or writer. Idempotent. After Close, ReadFrame and WriteFrame return
// net.ErrClosed (or io.ErrClosedPipe for inproc — see F3 §4.4).
//
// Close does NOT emit an ERROR command or a goodbye frame; ZMTP 3.1
// has no graceful-disconnect handshake. F5 owns linger semantics for
// in-flight messages.
func (c *Conn) Close() error

// RemoteAddr / LocalAddr delegate to the underlying raw net.Conn. For
// inproc, the addr.Network() is "inproc" per F3 §5.4.
func (c *Conn) RemoteAddr() net.Addr
func (c *Conn) LocalAddr() net.Addr
```

### 3.4 Why this shape

- **Two constructors instead of one with a side flag.** Type-level
  asymmetry between active and passive: `ClientHandshake` requires a
  `ClientMechanism` (which has `Start()`), `ServerHandshake` accepts the
  base `Mechanism`. Misusing the wrong constructor is a compile error,
  not a runtime panic.
- **Blocking `Read/Write` mirroring `net.Conn`.** Idiomatic Go; F5 already
  has goroutine-per-conn × per-direction for muxing, so channels would be
  redundant abstraction. Errors propagate via return value (no
  out-of-band channel for "peer closed").
- **`*Conn` not exporting the underlying `net.Conn`.** Once F4 owns it,
  arbitrary external use (custom `Read`/`Write`) would break the security
  layer's framing invariants. F5 must use `ReadFrame`/`WriteFrame`.
- **Functional options.** Spans a small, growing knob list. Mirrors
  `wire.NewFrameReader` (F1's pattern); `transport.Listen`/`Dial` have
  none, but F4 has a different cap surface.
- **Constructors close raw on failure.** Otherwise F5 would have to track
  ownership transfer carefully; explicit "raw closed iff err != nil"
  contract is simpler.

### 3.5 Blocking and goroutine semantics

After `*Conn` is returned from a constructor:

- `ReadFrame` blocks until one full frame arrives, EOF, peer ERROR, or
  Close. No internal deadline; F5 sets read deadlines via
  `c.RemoteAddr()`-tied bookkeeping if needed (F4 deliberately omits a
  `SetDeadline` method — the underlying `net.Conn` is not exposed; F5 can
  use `c.Close()` for cancellation).
- `WriteFrame` blocks until the frame's bytes are committed (queued in
  kernel buffer for tcp/ipc; consumed by peer Read for inproc per F3
  §4.4). Multiple goroutines may call concurrently; F4 serialises.
- F4 spawns no long-lived goroutines. The context-watcher used during
  handshake (§6.5) terminates before the constructor returns.

## 4. Internal data structures

### 4.1 Configuration (`internal/conn/options.go`)

```go
type config struct {
    maxMetadataSize         int
    maxHandshakeCommandSize int
    maxFrameBodySize        int64
}

const (
    defaultMaxMetadataSize         = 8 * 1024
    defaultMaxHandshakeCommandSize = 64 * 1024
)

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
```

Each `WithX(n)` panics on `n <= 0` (mirrors `wire.WithMaxBodySize`).

### 4.2 Conn (`internal/conn/conn.go`)

```go
type Conn struct {
    raw      net.Conn
    fr       *wire.FrameReader   // wraps raw with maxFrameBodySize
    fw       *wire.FrameWriter   // wraps raw
    mech     security.Mechanism
    peerMeta wire.Metadata       // snapshot at handshake done

    writeMu  sync.Mutex          // serialises WriteFrame; never held across Wrap

    closeMu  sync.Mutex
    closed   bool                // set under closeMu by Close
}
```

The closeMu/closed pair (instead of `sync.Once` plus a channel) keeps the
closed-check inline with the read/write path's existing critical section
choices. Close itself is idempotent.

`fr` owns no buffer beyond F1's standard 9-byte header; each `ReadFrame`
allocates a fresh body slice (F1 §7). `fw` is stateless apart from the
underlying writer reference.

### 4.3 Greeting helpers

F4 sends the full 64-byte greeting via `wire.WriteGreeting`, but reads in
two phases (lockstep, §6.1). The 11-byte phase-A buffer and the 53-byte
phase-B buffer are stack-allocated arrays in the handshake function; no
new exported helpers in `internal/wire`. (Promotion of an
`io.Reader`-based phase-A helper is filed as Open Q §9.2.)

### 4.4 Allocation profile

F4 makes no per-handshake or per-frame allocation guarantees beyond what
F1 (codec) and the mechanism (`Wrap`/`Unwrap`) impose. The handshake
allocates a small constant per command parsed/emitted; post-handshake
allocations are dominated by F1's body slices. **No
`testing.AllocsPerRun` pin** is required (mirrors F3 §5.5).

## 5. Error model

### 5.1 Sentinels (`internal/conn/errors.go`)

```go
var (
    ErrNoDeadline           = errors.New("conn: ctx must carry a deadline")
    ErrInvalidGreeting      = errors.New("conn: invalid ZMTP greeting")
    ErrUnsupportedVersion   = errors.New("conn: peer ZMTP version unsupported")
    ErrMechanismMismatch    = errors.New("conn: mechanism mismatch with peer")
    ErrRoleConflict         = errors.New("conn: as-server role conflict with peer")
    ErrHandshakeFail        = errors.New("conn: handshake aborted")
    ErrMetadataTooLarge     = errors.New("conn: handshake metadata exceeds cap")
    ErrCommandTooLarge      = errors.New("conn: handshake command exceeds cap")
    ErrUnexpectedFrame      = errors.New("conn: unexpected frame kind during handshake")
)
```

Wrapping: every error returned by a constructor is `fmt.Errorf("%w: ...",
sentinel, ...)` with context (mechanism name, side, raw conn `RemoteAddr`).
F5 uses `errors.Is` to discriminate.

### 5.2 ErrPeerError

```go
// ErrPeerError carries the reason from a peer-emitted ERROR command in
// the post-handshake stream. Returned by ReadFrame.
type ErrPeerError struct {
    Reason string
}

func (e *ErrPeerError) Error() string {
    return fmt.Sprintf("conn: peer ERROR: %q", e.Reason)
}
```

Surfaced as a pointer so `errors.As(err, &peerErr)` recovers `Reason`. The
in-handshake equivalent (peer ERROR during handshake) does NOT use
`*ErrPeerError`; it returns `ErrHandshakeFail` wrapping a string with the
reason embedded. The split keeps the handshake-vs-traffic distinction
clear: F5 reacts differently.

### 5.3 Errors flowing through unchanged

- `io.EOF`, `io.ErrUnexpectedEOF` from `wire.FrameReader`.
- `net.ErrClosed`, `io.ErrClosedPipe` from the raw conn after Close.
- `os.ErrDeadlineExceeded` from raw deadline expiry (handshake timeout).
- `context.Canceled`, `context.DeadlineExceeded` from ctx-watcher.
- Errors from `security.Mechanism.{Start,Receive,Wrap,Unwrap}` —
  forwarded via `%w` wrapping. F2's documented sentinels
  (`security.ErrNotDone`, mechanism-specific aborts) remain
  identifiable via `errors.Is`.
- Errors from `wire.ParseCommand`, `wire.DecodeGreeting` — forwarded via
  `%w`.

`errors.Is(err, net.ErrClosed)` and `errors.As(err, &op *net.OpError)`
work as expected. F4 does not introduce new error types beyond the
sentinels and `*ErrPeerError`.

## 6. State machines

### 6.1 Greeting (lockstep, both sides)

The full 64-byte greeting is sent via `wire.WriteGreeting` in a single
`Write`. Reading is two-phase per RFC 23 §3.2:

```
1. io.ReadFull(raw, hdr[:11])
2. validate hdr[0] == 0xFF
   validate hdr[1..9] == 0x00 each
   validate hdr[9] == 0x7F
   validate hdr[10] == 0x03                  (version major)
   on any failure → ErrInvalidGreeting or ErrUnsupportedVersion;
   abort BEFORE reading the remaining 53 bytes.
3. io.ReadFull(raw, hdr[11:64])
4. peerG, err := wire.DecodeGreeting(hdr[:])
   (validates minor == 0x01, mechanism format, as-server in {0,1})
5. if peerG.Mechanism != mech.Name() → ErrMechanismMismatch.
6. if mech.Name() ∈ {"PLAIN", "CURVE"}:
        if peerG.AsServer == ourSide {
            ErrRoleConflict
        }
   if mech.Name() == "NULL":
        // ignore as-server (RFC 23 §3.3.2: no semantic meaning).
```

**Send/receive ordering.** The two sides are not symmetric:

- **Client (active):** send full greeting → read peer greeting (lockstep).
- **Server (passive):** read peer greeting (lockstep) → send full greeting.

Asymmetry exists to avoid deadlock on inproc (`net.Pipe` is synchronous
per F3 §4.4 — concurrent `Write` from both sides would block both Reads
indefinitely). For tcp/ipc the kernel buffer accepts 64 B without
blocking, so functionally equivalent. Open Q §9.1 notes that a
short-lived send goroutine could symmetrise this and shave 1 RTT off the
TCP connect path.

### 6.2 Handshake driver — active (client)

After greeting succeeds:

```
1. cmd, err := mech.Start()
   if err: emit ERROR(reason=err.Error()); abort with err.
2. body, _ := wire.EncodeCommand(cmd)
   fw.WriteFrame(wire.Frame{Kind: FrameCommand, Body: body})
3. loop:
     f, err := fr.ReadFrame()
       fr is configured with WithMaxBodySize(cfg.maxHandshakeCommandSize).
       err handling: io.EOF / io.ErrUnexpectedEOF → ErrHandshakeFail("peer closed mid-handshake").
                     wire.ErrFrameTooLarge → ErrCommandTooLarge.
                     other → forward via %w.
     if f.Kind != wire.FrameCommand: ErrUnexpectedFrame.
     cmd, err := wire.ParseCommand(f.Body)
       err → ErrHandshakeFail wrapping the parse error.
     if cmd.Name == wire.ErrorCommandName:
        ec, _ := wire.ParseError(cmd)
        return ErrHandshakeFail wrapping "peer ERROR: " + ec.Reason.
     enforceMetadataCap(cmd, cfg.maxMetadataSize)
       For metadata-bearing commands (READY, and INITIATE in PLAIN/CURVE
       per F2b §2/F2c §3), len(cmd.Data) > cap → emit ERROR; abort with
       ErrMetadataTooLarge. Other commands have non-metadata bodies and
       skip this check; the per-command body cap (cfg.maxHandshakeCommandSize)
       still applies via the FrameReader cap above.
     out, done, err := mech.Receive(cmd)
     if err:
        emit ERROR(reason=err.Error())
        return ErrHandshakeFail wrapping err.
     if out != nil:
        body, _ := wire.EncodeCommand(*out)
        fw.WriteFrame(wire.Frame{Kind: FrameCommand, Body: body})
     if done: break.
4. c.peerMeta = mech.PeerMetadata()
5. return *Conn
```

### 6.3 Handshake driver — passive (server)

Same as §6.2 minus step 1–2 (no `Start`); the loop runs from the very
beginning, the first `fr.ReadFrame` reads the client's first handshake
command. All other steps (metadata cap, command cap, ERROR detection,
mech-emitted ERROR on failure) are identical.

`mech.Receive` may return `done=true` while also returning a non-nil
`out`. F4 emits `out` first, then breaks the loop. Mirrors F2b §4
"server's READY is the last frame the server sends" behaviour.

### 6.4 Post-handshake `ReadFrame` (§3.3 expanded)

```go
f, err := c.fr.ReadFrame()
if err != nil:
    return wire.Frame{}, err   // includes io.EOF, ErrFrameTooLarge, etc.

if f.Kind == wire.FrameMessage:
    return c.mech.Unwrap(f)
    // NULL/PLAIN: pass-through (alias). CURVE: not expected on this path
    // — CURVE wraps user data into MESSAGE commands, so a FrameMessage
    // arriving for a CURVE conn is a peer protocol error. CURVE.Unwrap
    // returns a mech-specific error which F4 forwards via %w.

// f.Kind == FrameCommand
cmd, err := wire.ParseCommand(f.Body)
if err != nil:
    return wire.Frame{}, fmt.Errorf("conn: bad post-handshake command: %w", err)

switch cmd.Name {
case "MESSAGE":
    return c.mech.Unwrap(f)            // CURVE-only data path.
case wire.ErrorCommandName:
    ec, perr := wire.ParseError(cmd)
    if perr != nil:
        return wire.Frame{}, fmt.Errorf("conn: malformed ERROR: %w", perr)
    return wire.Frame{}, &ErrPeerError{Reason: ec.Reason}
default:
    return f, nil                       // SUBSCRIBE/CANCEL/PING/PONG/etc.
}
```

The literal string `"MESSAGE"` matches `internal/security/curve`'s
private `messageCommandName`. Promotion to a public `wire.MessageCommandName`
constant is filed as Open Q §9.4 — for the initial F4 implementation a
local `const messageCommandName = "MESSAGE"` in `internal/conn` suffices
and is documented as a "shadow constant" comment.

### 6.5 Post-handshake `WriteFrame`

```go
c.writeMu.Lock()
defer c.writeMu.Unlock()

if c.closed: return net.ErrClosed   // checked under writeMu via closeMu

if f.Kind == wire.FrameMessage:
    out, err := c.mech.Wrap(f)
    if err != nil:
        return fmt.Errorf("conn: mech.Wrap: %w", err)
    return c.fw.WriteFrame(out)

// FrameCommand: F5 owns name correctness; F4 sends verbatim.
return c.fw.WriteFrame(f)
```

Per RFC 25 ("only MESSAGE commands are encrypted"), CURVE traffic
commands (PING/PONG/SUBSCRIBE/CANCEL) must NOT be wrapped. F4 enforces
this by skipping `mech.Wrap` for any FrameCommand. NULL/PLAIN are
unaffected — their `Wrap` is a no-op alias either way.

### 6.6 Context cancellation watcher

Both constructors run for the duration of the handshake. To honour
`ctx`:

```
1. require ctx.Deadline non-zero; else ErrNoDeadline (raw untouched).
2. raw.SetDeadline(ctx-deadline-time)
3. done := make(chan struct{})
4. go func() {
       select {
       case <-ctx.Done():
           raw.SetDeadline(time.Unix(1, 0))   // unblock any in-flight I/O
       case <-done:
           // handshake finished; let watcher exit.
       }
   }()
5. run handshake; on completion or error, close(done).
6. on success: raw.SetDeadline(time.Time{}); return *Conn.
7. on error: raw.Close(); return wrapped error.
```

`ErrNoDeadline` is enforced because F2b §3 wants F4 to bound the
handshake. Requiring an explicit deadline forces F5 to make a choice
rather than inheriting indefinite blocking. The watcher's `time.Unix(1,
0)` (1970-01-01 00:00:01 UTC) is the canonical "deadline already past"
sentinel — `net.Conn` deadline contract treats any past time as
immediate cancellation.

### 6.7 Close semantics

```go
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
```

Close releases the raw conn. Concurrent readers/writers observe
`net.ErrClosed` (or `io.ErrClosedPipe` for inproc). The `closed`
boolean is checked under `writeMu` in `WriteFrame` to short-circuit
writes after Close (avoids racing the raw `Close` with a queued
`fw.WriteFrame`). `ReadFrame` does not check `closed`; the underlying
raw `Read` returns the right error directly.

### 6.8 Goroutine safety summary

| Operation | Safe under concurrent... |
|-----------|--------------------------|
| `ClientHandshake` / `ServerHandshake` | N/A — single call producing one Conn. |
| `(c *Conn) ReadFrame` | One reader. Concurrent readers on the same Conn: undefined (mirrors `wire.FrameReader`). |
| `(c *Conn) WriteFrame` | Multiple writers. Internal `writeMu` serialises. |
| `(c *Conn) ReadFrame` + `(c *Conn) WriteFrame` | Yes — independent paths. |
| `(c *Conn) Close` + any of Read/Write | Yes. Close is idempotent; in-flight Read/Write returns ErrClosed. |
| `(c *Conn) PeerMetadata` | Multiple callers. Snapshotted at handshake done; never mutated. |
| `(c *Conn) RemoteAddr` / `LocalAddr` | Multiple callers. Stable. |

`go test -race` is mandatory and gating per §7.7.

## 7. Test plan

### 7.1 Unit — handshake (`handshake_test.go`)

Each test uses `net.Pipe()` for raw to keep tests pure and deterministic.

- **TestClientHandshakeNULL** — both sides drive in parallel; assert peer
  metadata exchanged.
- **TestServerHandshakeNULL** — symmetric.
- **TestHandshakePLAIN** — Client + Server with an in-test `Authenticator`
  callback (mirrors F2b test fixture).
- **TestHandshakeCURVE** — fresh keypairs both sides; assert
  `PeerMetadata` round-trip and that the resulting `Conn` can wrap a
  test FrameMessage.
- **TestGreetingMismatchSignature** — peer corrupts byte 0; assert
  `errors.Is(err, ErrInvalidGreeting)` and that read aborts before
  consuming the remaining 53 bytes (assert via byte counter on a
  spy reader).
- **TestGreetingVersionDowngrade** — peer sends `0x02` for major version;
  assert `ErrUnsupportedVersion` and early abort.
- **TestMechanismMismatch** — client says NULL, server says PLAIN; assert
  `ErrMechanismMismatch` on both sides.
- **TestRoleConflict** — two PLAIN servers meet; assert `ErrRoleConflict`.
- **TestRoleConflictNULLIgnored** — two NULL "clients" with `as-server=0`
  on both sides handshake successfully (NULL is symmetric).
- **TestHandshakeMetadataCap** — peer sends READY with 9 KiB of metadata
  while cap is 8 KiB; assert `ErrMetadataTooLarge` and that the local
  side emits an ERROR command before closing.
- **TestHandshakeCommandCap** — peer sends a 65 KiB command frame while
  cap is 64 KiB; assert `ErrCommandTooLarge`. (Exercised via direct
  byte-write of an oversized frame header on the spy raw, since no
  mechanism produces frames that large naturally.)
- **TestHandshakeNoDeadline** — `context.Background()` without deadline;
  assert `ErrNoDeadline` and that raw is NOT closed (assert via raw spy).
- **TestHandshakeCtxCancel** — cancel ctx mid-handshake (between
  greeting send and first command read); assert `errors.Is(err,
  context.Canceled)` and raw is closed.
- **TestHandshakeCtxDeadlineExpires** — set ctx deadline 10 ms past;
  peer never replies; assert `os.ErrDeadlineExceeded` and raw closed.
- **TestHandshakePeerERROR** — peer sends ERROR command mid-handshake
  with reason "no thanks"; assert `errors.Is(err, ErrHandshakeFail)`
  and that the wrapped message contains the reason.
- **TestHandshakeMechReceiveError** — inject a mock mechanism whose
  `Receive` returns an error; assert F4 emits an ERROR command before
  closing (verify via byte spy on raw), and the constructor returns
  wrapped error.

### 7.2 Unit — post-handshake traffic (`conn_test.go`)

- **TestPostHandshakeRoundTripNULL** — single FrameMessage of 1 KiB,
  bytes round-trip exactly.
- **TestPostHandshakeRoundTripPLAIN** — same.
- **TestPostHandshakeRoundTripCURVE** — same; additionally assert that
  the on-wire bytes are NOT the plaintext (via byte-counter / regex on
  a `tee`-spy raw).
- **TestPostHandshakeMultipart** — 3-frame MORE chain; receiver sees the
  MORE bit on frames 1 and 2, false on frame 3.
- **TestPostHandshakeCommandPassthrough** — write a `FrameCommand` with
  `Body=encoded SUBSCRIBE`; peer's `ReadFrame` returns the same
  FrameCommand verbatim.
- **TestPostHandshakePeerERROR** — peer writes an ERROR command; local
  `ReadFrame` returns `*ErrPeerError` with the parsed reason.
- **TestPostHandshakeWriteAfterClose** — Close, then WriteFrame; assert
  `errors.Is(err, net.ErrClosed)`.
- **TestPostHandshakeReadAfterClose** — Close, then ReadFrame; assert
  `errors.Is(err, net.ErrClosed)` or `errors.Is(err,
  io.ErrClosedPipe)`.
- **TestCloseUnblocksRead** — goroutine in ReadFrame; main calls Close;
  goroutine's Read returns within 100 ms with the right error.
- **TestWriteFrameConcurrent** — N=100 concurrent goroutines each
  writing a distinct FrameMessage; peer reads N frames; assert each
  frame's body is intact (no interleaving) and the multiset of bodies
  matches the multiset sent.
- **TestRaceDetectorClean** — full handshake + 100 concurrent
  WriteFrames + 100 ReadFrames + Close, run with `-race`.

### 7.3 Cross-mechanism conformance (`mech_test.go`)

Table-driven. One row per `(mech, side)` combination. Each row drives a
synthetic round-trip through `net.Pipe`, asserting:

- Handshake completes within K commands (NULL: 1, PLAIN: 4, CURVE: 4).
- `Done()` returns true exactly once.
- Post-handshake, the mech's `Wrap`/`Unwrap` invariants hold for a
  representative FrameMessage.
- `PeerMetadata` is non-nil and round-trips a known property.

This is the table that F5 will reuse as a smoke check for any new
mechanism added later.

### 7.4 Endpoint / wire layering tests

None. F4 does not parse endpoints (F3 owns that) and does not encode
frames (F1 owns that). The conformance is between F4 and the F2/F3
layers, exercised end-to-end above.

### 7.5 Interop tests against `libzmq` (`internal/conn/interop`, build tag `interop`)

Per §2 and the meta plan §6.

- **Container.** `libzmq` 4.3.5 (latest 4.3.x LTS at time of writing),
  pinned in a Dockerfile under `internal/conn/interop/Dockerfile`. The
  fixture exposes a small Python-or-C bridge that opens a libzmq socket
  of type `ZMQ_PAIR` with the specified mechanism and either dials our
  listener or accepts our dialer.
- **Pattern.** `Socket-Type` = `"PAIR"` injected into the metadata of
  both peers. PAIR is bidirectional, has no namespace or identity
  baggage, and is the simplest pattern for testing pure conn-layer
  behaviour. Production PAIR support lands in F5c; here it is a test
  fixture only.
- **Matrix.**
  - Mechanisms: NULL, PLAIN, CURVE.
  - Transports: `tcp` (`tcp://127.0.0.1:0` → bind, dial back), `ipc`
    (`ipc:///tmp/zmq4-interop-<test>.sock`). NOT `inproc` — libzmq runs
    out-of-process.
  - Directions: `our dialer ↔ libzmq listener`, `libzmq dialer ↔ our
    listener`.
  - Scenarios: `handshake-only` (assert handshake completes, then
    Close), `single-frame` (round-trip 1 KiB FrameMessage),
    `multipart-3` (round-trip 3-frame MORE chain).
  - 3 × 2 × 2 × 3 = **36 happy-path tests**.
- **Negative interop.**
  - `version-mismatch` — libzmq forced to advertise ZMTP 3.0 (via env
    var or wrapper); assert our side returns `ErrUnsupportedVersion`.
  - `mechanism-mismatch` — libzmq runs PLAIN, we run NULL; assert clean
    abort on both sides.
  - **2 negative tests.**
- **CI cadence.** Nightly. On-demand via `go test -tags interop
  ./internal/conn/interop/...`. Not gating on every push (Docker startup
  is slow).
- **Phase tag gate.** All 38 interop tests must pass before
  `phase-4-conn-complete` is tagged.

Helpers under `internal/conn/interop/fixture/`:

- `fixture.LibzmqPair(t, mech, transport, ourSide) (endpoint string,
  cleanup func())` — spins the container, returns the endpoint to
  bind/dial against.
- `fixture.WithSocketTypeMetadata(mech, "PAIR")` — wraps a mech
  constructor to pre-populate the right metadata property. Each F2
  package will gain a tiny test helper exposing this; the helper sits
  in `_test.go` files so it does not enter the production surface.

### 7.6 What is **not** tested in F4

- Reconnect under endpoint failure — F5.
- HWM, queue overflow, monitoring events — F5/F6.
- Heartbeat timing (PING idle-detect) — F6.
- inproc interop with libzmq — impossible (intra-process). Self-loop
  tests in §7.2 cover inproc paths.
- Performance benchmarks — F4 is glue; codec lives in F1, transport in
  F3. No alloc budget pin per §4.4.
- Fuzzing — codec fuzzing lives in F1; F4 has no novel parser.

### 7.7 Done criteria

- All §7.1–§7.3 unit tests pass on `linux/amd64` and `darwin/arm64`.
- `go test -race ./internal/conn/...` clean.
- §7.5 interop suite (38 tests) green in nightly CI; manual run before
  tagging.
- `go vet ./internal/conn/...` clean.
- `staticcheck ./internal/conn/...` clean.
- `modernize -fix ./internal/conn/...` produces no diff (run before
  phase tag, per memory `feedback_modernize_after_phase`).
- Spec §1–§7 fully implemented; §9 open questions remain open or are
  explicitly closed.
- F2 amendments (§2.1) merged: `Name() string` on five mech states;
  spec docs updated in F2a/F2b/F2c.

## 8. Open questions

1. **Concurrent greeting send.** §6.1 picks asymmetric send ordering
   (client-first) for inproc-deadlock-safety. A short-lived per-side
   send goroutine would symmetrise this and shave 1 RTT off TCP
   connect under high latency. Reopen if benchmarks (post-F5) show
   connect time dominated by greeting.
2. **Phase-A greeting helper in `internal/wire`.** F4 hand-rolls the
   11-byte signature+version-major read inline. A
   `wire.ReadGreetingSignature(io.Reader) error` helper would be tidier
   and let F1 amend `ReadGreeting` to reuse it. Defer until F4 is in;
   amendment to `01-zmtp-wire-protocol.md` if added.
3. **`ErrNoDeadline` strictness.** Some callers (test fixtures, simple
   demos) might prefer F4 to apply a generous default if ctx has no
   deadline. The strict policy (require explicit deadline) is chosen
   to surface F2b §3's "MUST set a deadline" as an API-level enforced
   contract. Reopen only on concrete usability complaints from F5.
4. **`MessageCommandName` constant promotion.** F4 needs the literal
   `"MESSAGE"` to identify CURVE-encrypted data frames in the
   post-handshake stream. Currently it lives as a private constant in
   `internal/security/curve`. Three options: (a) leave a shadow
   constant in `internal/conn` (simplest, picked for initial impl);
   (b) promote to `wire.MessageCommandName` (symmetric with
   `ReadyCommandName`, `ErrorCommandName`, etc. — F1 amendment); (c)
   add a `Mechanism.IsTrafficData(f wire.Frame) bool` method (over-
   engineered). Defer to F4 review; (b) is the most likely landing.
5. **Mid-traffic ERROR sender on our side.** F4 does not currently
   emit ERROR commands after the handshake completes — only during
   handshake on local mech failure. RFC 23 §6 allows mid-traffic
   ERROR. Use case (auth revocation, fatal protocol error in F5) may
   surface in F6. No L4 work without a concrete trigger.
6. **Drain-on-Close.** Close is bezceremonial: in-flight WriteFrame
   may return partial-write errors, in-flight ReadFrame may return
   `net.ErrClosed`. F5 owns linger semantics; F4's Close is "release
   the FD now". Documented; no action.
7. **Inproc as-server bit for symmetric mech.** Two NULL "clients"
   (both `as-server=0`) on inproc handshake successfully because NULL
   is symmetric per RFC 23 §3.3.2. Edge case with no practical
   significance; covered by `TestRoleConflictNULLIgnored`.
8. **PeerMetadata mutability.** F4 returns `wire.Metadata` from
   `mech.PeerMetadata` without copying. F2 spec mandates read-only.
   F5 callers MUST NOT mutate. Documented in §3.3.
9. **Greeting filler validation.** RFC 23 §3.2 says bytes 33–63 are
   filler (any value). F4 does not validate filler — consistent with
   `wire.DecodeGreeting`. No action.
10. **Skeleton ordering deviation.** The meta-overview §5 skeleton
    suggests `state machines → error model`. F2a/F2b/F2c/F3 reverse
    this; F4 follows the established sibling pattern (error model
    before state machines). Per F3 §9.16 this is intentional.
11. **`SetReadDeadline` / `SetWriteDeadline` on `*Conn`.** Not
    exposed; F5 must use `Close` for cancellation. If a future F5
    pattern (e.g. timed REQ retry) needs per-call deadlines, expose
    delegating methods. Defer to F5 design.
12. **CURVE FrameMessage reception.** §6.4 says CURVE should never see
    a FrameMessage post-handshake (peer encrypts data into MESSAGE
    commands). If a misbehaving peer sends a plain FrameMessage, F4
    forwards it to `mech.Unwrap` which yields a CURVE-specific error.
    Whether that should map to a dedicated F4 sentinel
    (`ErrUnencryptedFrame`?) is a judgement call; defer.
13. **F5/F4 close ordering.** When F5 wants to drop a conn while
    another goroutine is mid-`WriteFrame`, the writer's Wrap call may
    have already allocated a fresh body slice (CURVE) that is then
    discarded by Close. Memory cost is negligible (one short-lived
    allocation); documented for completeness.

## 9. References

- [RFC 23/ZMTP — ZeroMQ Message Transport Protocol 3.1](https://rfc.zeromq.org/spec/23/) §3 (greeting + mechanism), §4 (handshake), §5 (traffic), §6 (ERROR).
- [RFC 24/PLAIN](https://rfc.zeromq.org/spec/24/) — referenced by F2b.
- [RFC 25/ZMTP-CURVE](https://rfc.zeromq.org/spec/25/) — encryption applies only to MESSAGE commands.
- [RFC 26/CURVEZMQ](https://rfc.zeromq.org/spec/26/) — referenced by F2c.
- [RFC 37/ZMTP](https://rfc.zeromq.org/spec/37/) — security mechanism framing (parent of F2a/F2b/F2c).
- libzmq man pages: [`zmq_socket(3)`](http://api.zeromq.org/4-3:zmq-socket) (PAIR), [`zmq_setsockopt(3)`](http://api.zeromq.org/4-3:zmq-setsockopt) (handshake-related options).
- Project specs:
  - `00-meta-overview.md` §3 (layering), §4 (phase pipeline), §6 (testing strategy).
  - `00b-memory-model.md` (boundary ownership, alias rules).
  - `01-zmtp-wire-protocol.md` §Frames, §Commands, §7 (buffer ownership).
  - `02a-security-null.md`, `02b-security-plain.md`, `02c-security-curve.md` (mechanism state machines and amendments).
  - `03-transports.md` §4.4 (blocking semantics), §5.4 (inproc scope).
- Go stdlib: `net.Conn`, `net.Conn.SetDeadline`, `net.Pipe`,
  `context.Context`.
