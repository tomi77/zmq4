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

F4 work also lands two **additive amendments to F1** and one to **F2**
(detailed in §2.1 and Open Q §9.2/§9.4):

- F1 gains `wire.MessageCommandName = "MESSAGE"` (symmetric with
  `ReadyCommandName` / `ErrorCommandName`). F2c stops shadow-defining it.
- F1 gains `wire.ReadGreetingPhaseA(io.Reader) error` helper used by
  F4's lockstep greeting reader; F1's existing `ReadGreeting` is
  refactored to use it.
- F2 (`security.Mechanism`) gains `Name() string`, implemented trivially
  by all five existing states.

All three are additive on frozen surfaces — frozen tags
`phase-1-wire-complete`, `phase-2a/2b/2c-…-complete` remain valid.

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
| ZMTP 3.0 / 2.0 / 1.0 fallback | **No.** Per `00-meta-overview.md` §7, only 3.1. Peer with version major ≠ 3 → wrapped `wire.ErrUnsupportedVersion`. |
| Socket-type compatibility check (RFC 23 §2.4 metadata semantics) | **No.** F4 ferries `Socket-Type` and other metadata properties; semantic compatibility (e.g. `REQ` may only talk to `REP`/`ROUTER`) lives in F5. |
| ZAP (RFC 27) authentication for PLAIN/CURVE | **No.** Mechanism-level. F2b exposes an `Authenticator` callback (`plain.Authenticator`); F2c does not yet have an equivalent. F6 will provide ZAP-backed implementations for both. |

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
//   wire.MessageCommandName    → mech.Unwrap (CURVE post-handshake data).
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
// determined by the mechanism). The returned Metadata is a defensive
// clone made at handshake completion (§4.2): it is owned by *Conn,
// stable for the lifetime of the *Conn, and decoupled from the
// mechanism. Callers MUST NOT mutate it (no enforcement; convention).
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
// inproc, the addr.Network() is "inproc" per F3 §5.4. Stable for the
// lifetime of the *Conn including post-Close (stdlib net.Conn permits
// addr access after Close).
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
    fr       *wire.FrameReader   // post-handshake reader, capped at cfg.maxFrameBodySize
    fw       *wire.FrameWriter   // shared by handshake and post-handshake (no per-frame cap)
    mech     security.Mechanism
    peerMeta wire.Metadata       // defensive clone snapshotted at handshake done

    writeMu  sync.Mutex          // serialises WriteFrame; never held across Wrap

    closeMu  sync.Mutex
    closed   bool                // set under closeMu by Close
}
```

The closeMu/closed pair (instead of `sync.Once` plus a channel) keeps the
closed-check inline with the read/write path's existing critical section
choices. Close itself is idempotent.

**FrameReader lifecycle.** `wire.FrameReader.maxBodySize` is set at
construction and cannot be re-tuned (F1 §`FrameReader`). F4 therefore
uses **two distinct FrameReaders**:

1. A **transient handshake FrameReader**, constructed inside the
   handshake driver via `wire.NewFrameReader(raw,
   wire.WithMaxBodySize(cfg.maxHandshakeCommandSize))`, used for the
   handshake command exchange and discarded once `mech.Done()`.
2. A **post-handshake FrameReader** (`c.fr`), constructed *after* the
   handshake completes via
   `wire.NewFrameReader(raw, wire.WithMaxBodySize(cfg.maxFrameBodySize))`,
   stashed on the `*Conn`, and used by `ReadFrame` for the lifetime of
   the conn.

This split keeps the security cap (small handshake frames) and the
data cap (large post-handshake messages) as two independent invariants.
Both readers share the same underlying `raw` byte stream; the
transient reader is dropped before the persistent one is created so
there is no concurrent `Read` race.

`fw` is stateless apart from the underlying writer reference and is
constructed once at the start of the handshake; it is reused
post-handshake.

**peerMeta defensive clone.** At handshake done, F4 calls
`seccommon.CloneMetadata(mech.PeerMetadata())` (helper from F2c) and
stores the result in `c.peerMeta`. This decouples the *Conn from
mechanism lifetime — F5 may discard the mechanism reference for GC
without invalidating `c.PeerMetadata()`. Cost is one allocation per
handshake; functionally negligible.

### 4.3 Greeting helpers

F4 sends the full 64-byte greeting via `wire.WriteGreeting`, then reads
in two phases (lockstep, §6.1). Per the decision in Open Q §9.2 (made
in spec review 2026-05-06), F4 work lands an additive F1 amendment:

```go
// internal/wire (new export)
//
// ReadGreetingPhaseA reads the first 11 bytes of a ZMTP 3.1 greeting
// (signature 10 B + version major 1 B), validates them, and returns.
// Truncated input → io.ErrUnexpectedEOF. Bad signature →
// ErrInvalidSignature. Major version != 0x03 → ErrUnsupportedVersion.
func ReadGreetingPhaseA(r io.Reader) error
```

`ReadGreeting` is refactored to call `ReadGreetingPhaseA` followed by
reading the remaining 53 bytes and calling the existing
`DecodeGreeting`. F4 §6.1 step 1–2 (phase-A read + validate) becomes
one helper call; step 3–4 (read remaining 53 B + DecodeGreeting) stays
inline so F4 can short-circuit on phase-A failure without paying for
the remaining read. The phase-B buffer is a stack-allocated 53-byte
array in the handshake function.

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

**Version mismatch.** F4 deliberately does NOT define a
`conn.ErrUnsupportedVersion`. The wire layer already exports
`wire.ErrUnsupportedVersion` (returned by `wire.DecodeGreeting` when
version major or minor does not match 3.1). F4 wraps that sentinel via
`%w` in two places: (a) the phase-A early major-version check (§6.1
step 2), and (b) the phase-B `DecodeGreeting` call (§6.1 step 4). F5
checks `errors.Is(err, wire.ErrUnsupportedVersion)`. One sentinel, one
condition.

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
1. err := wire.ReadGreetingPhaseA(raw)
   on signature failure → wrap wire.ErrInvalidSignature as ErrInvalidGreeting.
   on version major != 0x03 → wrap wire.ErrUnsupportedVersion (forwarded via %w).
   abort BEFORE reading the remaining 53 bytes.
2. io.ReadFull(raw, rest[:53])
3. // Reconstruct the full 64-byte buffer for DecodeGreeting:
   var buf [wire.GreetingSize]byte
   buf[0] = 0xFF                       // already validated by ReadGreetingPhaseA
   // bytes 1..8 are zero (post-validation)
   buf[9] = 0x7F
   buf[10] = 0x03
   copy(buf[11:], rest[:])
   peerG, err := wire.DecodeGreeting(buf[:])
   (validates minor == 0x01 — wraps wire.ErrUnsupportedVersion if not;
    validates mechanism format and as-server in {0,1}; F4 forwards via %w)
4. if peerG.Mechanism != mech.Name() → ErrMechanismMismatch.
5. if mech.Name() ∈ {"PLAIN", "CURVE"}:
        if peerG.AsServer == ourSide {
            ErrRoleConflict
        }
   if mech.Name() == "NULL":
        // ignore as-server (RFC 23 §3.3.2: no semantic meaning).
```

(Alternative: have `ReadGreetingPhaseA` return the raw 11 bytes and
splice them with the 53-byte remainder before `DecodeGreeting`. Same
effect; spec leaves the reconstruction shape to the implementer.)

**Send/receive ordering.** The two sides are not symmetric:

- **Client (active):** send full greeting → read peer greeting (lockstep).
- **Server (passive):** read peer greeting (lockstep) → send full greeting.

The asymmetry exists to avoid deadlock on inproc. `net.Pipe` (F3's
backing for inproc per §5.4) is **fully synchronous** — a `Write` of N
bytes blocks until the peer's `Read` consumes all N. If both sides
attempted to `Write` their greeting first, both would block in `Write`
with neither side reading, deadlocking the handshake. The asymmetric
ordering pins at least one side in `Read` while the other is in
`Write` at all times: the server's first system call is `Read`, which
matches the client's `Write` of its 64-byte greeting. Once the
client's bytes have flowed, the server `Write`s its greeting and the
client (now in phase-A `Read`) consumes those bytes.

For tcp/ipc the kernel buffer accepts 64 B without blocking, so the
ordering is functionally equivalent; the asymmetry is required only
for inproc correctness. Open Q §9.1 notes that a short-lived send
goroutine could symmetrise this and shave 1 RTT off the TCP connect
path under high latency.

### 6.2 Handshake driver — active (client)

After greeting succeeds, F4 has a working `fw` (FrameWriter on raw) and
constructs a transient handshake FrameReader `hsfr` capped at
`cfg.maxHandshakeCommandSize`:

```
0. hsfr := wire.NewFrameReader(raw, wire.WithMaxBodySize(cfg.maxHandshakeCommandSize))
1. cmd, err := mech.Start()
   if err:
       // Greeting succeeded so fw is usable. Emit ERROR before aborting so
       // the peer sees a clean termination instead of an unexplained EOF.
       emitERROR(fw, err.Error())   // best-effort; ignore Write error
       return ErrHandshakeFail wrapping err.
2. body, _ := wire.EncodeCommand(cmd)
   fw.WriteFrame(wire.Frame{Kind: FrameCommand, Body: body})
3. loop:
     f, err := hsfr.ReadFrame()
       err handling: io.EOF / io.ErrUnexpectedEOF → ErrHandshakeFail wrapping "peer closed mid-handshake".
                     wire.ErrFrameTooLarge → ErrCommandTooLarge.
                     other → forward via %w.
     if f.Kind != wire.FrameCommand: ErrUnexpectedFrame.
     cmd, err := wire.ParseCommand(f.Body)
       err → ErrHandshakeFail wrapping the parse error.
     if cmd.Name == wire.ErrorCommandName:
        ec, _ := wire.ParseError(cmd)
        return ErrHandshakeFail wrapping "peer ERROR: " + ec.Reason.
     enforceMetadataCap(cmd, cfg.maxMetadataSize):
       For metadata-bearing commands (READY for NULL/PLAIN/CURVE; INITIATE
       for PLAIN/CURVE per F2b §2/F2c §3), len(cmd.Data) > cap → emit ERROR;
       abort with ErrMetadataTooLarge. The cap is on the wire-level body
       (cmd.Data), not on plaintext metadata — for CURVE INITIATE that body
       is encrypted (cookie + vouch box + sealed metadata blob), so the cap
       acts as a wire-allocation bound and only implicitly bounds the
       plaintext metadata size (which is ≤ ciphertext size). This is
       defensible because the goal of the cap is to prevent unbounded
       allocation before decryption, not to enforce a plaintext-policy
       limit. Non-metadata-bearing commands (HELLO, WELCOME) skip this
       check; their body sizes are bounded by the per-command FrameReader
       cap above.
     out, done, err := mech.Receive(cmd)
     if err:
        emitERROR(fw, err.Error())
        return ErrHandshakeFail wrapping err.
     if out != nil:
        body, _ := wire.EncodeCommand(*out)
        fw.WriteFrame(wire.Frame{Kind: FrameCommand, Body: body})
     if done: break.
4. // hsfr falls out of scope; build the persistent post-handshake reader.
   c.fr = wire.NewFrameReader(raw, wire.WithMaxBodySize(cfg.maxFrameBodySize))
   c.peerMeta = seccommon.CloneMetadata(mech.PeerMetadata())
5. return *Conn
```

`emitERROR(fw, reason)` is an internal helper that builds an ERROR
command body via `wire.ErrorCommand{Reason: reason}.Encode()`,
encodes it via `wire.EncodeCommand`, and calls
`fw.WriteFrame(wire.Frame{Kind: FrameCommand, Body: body})`. Errors
from the write are intentionally swallowed (the conn is being torn
down anyway).

### 6.3 Handshake driver — passive (server)

Same as §6.2 starting from step 0, then jumping straight into the loop
(step 3) — no `Start()` call. The first `hsfr.ReadFrame` reads the
client's first handshake command. All other steps (metadata cap,
command cap, ERROR detection, mech-emitted ERROR on failure,
post-handshake FrameReader construction, peerMeta clone) are
identical.

`mech.Receive` may return `done=true` while also returning a non-nil
`out`. F4 emits `out` first, then breaks the loop. This is the
server's terminal frame for PLAIN (`server.go:111-112`) and CURVE
(`server.go:203-204`).

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
case wire.MessageCommandName:
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

`wire.MessageCommandName` is added to F1 as part of F4 work (additive
amendment — see Open Q §9.4 for rationale). It mirrors the existing
`wire.ReadyCommandName`, `wire.ErrorCommandName`, etc.; the same string
`"MESSAGE"` is currently a private constant in `internal/security/curve`
and the F4 amendment promotes it to the wire layer where the other
ZMTP command names live. F2c will then reference the wire constant
instead of redefining it.

**No ERROR-on-malformed-peer.** When `wire.ParseCommand` fails on a
post-handshake FrameCommand body, F4 returns the wrapped parse error
to F5 and does NOT emit a wire-level ERROR back to the peer. RFC 23
§6 permits but does not mandate this; emitting ERROR here would
require write-path access from the read goroutine and complicates the
goroutine model (see §6.8). F5 owns connection close on protocol
violation; if that policy needs to change, it is an Open Q for F5
design, not F4.

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

**Partial-write / Close race.** A concurrent `Close` may complete
between the `closed` check (under `writeMu`) and the `fw.WriteFrame`
call's underlying syscall. In that case the write returns
`net.ErrClosed` (or `io.ErrClosedPipe` for inproc) or a partial-write
error mid-frame. Both surface via the `WriteFrame` return value; F5
treats either as "conn died, drop it". F4 makes no atomicity
guarantee across the closed-check and the syscall — the
`writeMu`/`closed` pair only serialises *between* WriteFrame calls,
not against Close.

### 6.6 Context cancellation watcher

Both constructors run for the duration of the handshake. To honour
`ctx`:

```
1. require ctx.Deadline non-zero; else ErrNoDeadline (raw untouched).
2. raw.SetDeadline(ctx-deadline-time)
3. done := make(chan struct{})
   var wg sync.WaitGroup
   wg.Add(1)
4. go func() {
       defer wg.Done()
       select {
       case <-ctx.Done():
           raw.SetDeadline(time.Unix(1, 0))   // unblock any in-flight I/O
       case <-done:
           // handshake finished; let watcher exit.
       }
   }()
5. run handshake; on completion or error, close(done); wg.Wait().
6. on success: raw.SetDeadline(time.Time{}); return *Conn.
7. on error: raw.Close(); return wrapped error.
```

The `wg.Wait()` after `close(done)` is **load-bearing**, not defensive.
Without it, the watcher's `select` arm might pick `<-ctx.Done()` (if
cancel races with handshake completion) and call `SetDeadline(past)`
*after* step 6 cleared the deadline. The post-handshake `*Conn` would
then have a stuck past deadline and the next `ReadFrame` would return
`os.ErrDeadlineExceeded` despite no actual error. Waiting for the
watcher to exit before clearing the deadline closes that race: the
watcher is guaranteed to have observed `<-done` and skipped the
SetDeadline path before the main goroutine clears it.

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
  assert `errors.Is(err, wire.ErrUnsupportedVersion)` and early abort
  (assert via byte counter that the remaining 53 bytes are NOT read).
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
- **TestHandshakeMechStartError** — inject a mock `ClientMechanism`
  whose `Start` returns an error post-greeting; assert F4 emits an
  ERROR command before closing and returns wrapped `ErrHandshakeFail`.
- **TestHandshakeUnexpectedFrame** — peer sends a `FrameMessage`
  during the handshake exchange (not a `FrameCommand`); assert
  `errors.Is(err, ErrUnexpectedFrame)`.
- **TestGreetingFillerIgnored** — peer sends a greeting whose filler
  bytes (33–63) are non-zero garbage; assert the handshake proceeds
  normally. Pins the §9.9 decision against future regressions where
  someone might tighten filler validation.

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
- **TestPostHandshakeMalformedCommand** — peer writes a `FrameCommand`
  with a junk body (zero-length, missing name, non-letter chars in
  name); assert `ReadFrame` returns an error wrapping
  `wire.ErrInvalidCommand` with the `"conn: bad post-handshake
  command"` prefix; assert F4 does NOT emit an ERROR back per §6.4.
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
- **Metadata independence:** after handshake, holding a reference to
  `c.PeerMetadata()` and dropping all references to the original
  `mech` (forcing GC) does not invalidate the metadata. Pins the §4.2
  defensive-clone decision against a future regression that aliases
  mech-owned bytes.

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
    var or wrapper); assert our side returns wrapped `wire.ErrUnsupportedVersion`.
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
- F1 amendments merged: `wire.MessageCommandName` constant added;
  `wire.ReadGreetingPhaseA` helper added with `ReadGreeting`
  refactored to use it; spec doc updated in
  `01-zmtp-wire-protocol.md`.
- F2 amendments (§2.1) merged: `Name() string` on five mech states;
  spec docs updated in F2a/F2b/F2c. F2c stops shadow-defining
  `messageCommandName` and references the wire constant.

## 8. Open questions

1. **Concurrent greeting send.** §6.1 picks asymmetric send ordering
   (client-first) for inproc-deadlock-safety. A short-lived per-side
   send goroutine would symmetrise this and shave 1 RTT off TCP
   connect under high latency. Reopen if benchmarks (post-F5) show
   connect time dominated by greeting.
2. **Phase-A greeting helper in `internal/wire`.** F4 hand-rolls the
   11-byte signature+version-major read inline. **Decision (2026-05-06,
   in spec review):** promote a `wire.ReadGreetingPhaseA(io.Reader)
   error` helper as part of F4 work — additive amendment to
   `01-zmtp-wire-protocol.md`. The helper reads 11 bytes, validates
   signature + version major, returns wrapped `wire.ErrInvalidSignature`
   or `wire.ErrUnsupportedVersion`. F1's `ReadGreeting` is refactored to
   call `ReadGreetingPhaseA` followed by reading the remaining 53
   bytes. F4 §6.1 step 1–2 then becomes one helper call.
3. **`ErrNoDeadline` strictness.** Some callers (test fixtures, simple
   demos) might prefer F4 to apply a generous default if ctx has no
   deadline. The strict policy (require explicit deadline) is chosen
   to surface F2b §3's "MUST set a deadline" as an API-level enforced
   contract. Reopen only on concrete usability complaints from F5.
4. **`MessageCommandName` constant promotion.** F4 needs the literal
   `"MESSAGE"` to identify CURVE-encrypted data frames in the
   post-handshake stream. **Decision (2026-05-06, in spec review):**
   promote `wire.MessageCommandName = "MESSAGE"` as part of F4 work —
   additive amendment to `01-zmtp-wire-protocol.md`, symmetric with
   `wire.ReadyCommandName`, `wire.ErrorCommandName`, etc. F2c will
   reference the wire constant instead of redefining
   `messageCommandName` privately. The "shadow constant in conn" and
   "Mechanism.IsTrafficData" alternatives are rejected — wire layer is
   the canonical home for ZMTP command names.
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
8. **PeerMetadata mutability.** F4 returns a defensive clone (§4.2)
   so the *Conn does not depend on the mechanism's lifetime. Callers
   MUST NOT mutate; convention only, not enforced. Reopen if
   benchmarks show the clone matters under high connect rate.
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
