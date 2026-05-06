# 03 — Transports (Phase 3)

> **Status:** implemented, frozen for F4+.
> **Author:** Tomasz Rup
> **Date:** 2026-05-05
> **Layer:** L3 — `internal/transport`
> **Depends on:** standard library `net` only.
> **Consumed by:** F4 (connection layer).

## 1. Summary

This phase delivers `internal/transport`: pure-Go listener/dialer abstractions
for the three ZMTP-supported transports — `tcp`, `ipc` (Unix domain sockets),
and `inproc` (in-process pipes). It is a thin, I/O-aware wrapper over the
standard `net` package; it does not understand ZMTP framing, security
mechanisms, or socket-type semantics — those layers (F1, F2, F5) sit on top
via F4 (connection layer).

The public surface is two opener functions plus a parser, with three
sentinels:

```go
func Listen(ctx context.Context, endpoint string) (net.Listener, error)
func Dial(ctx context.Context, endpoint string) (net.Conn, error)
func ParseEndpoint(endpoint string) (scheme, addr string, err error)

var (
    ErrEndpointMalformed  = errors.New("transport: malformed endpoint")
    ErrSchemeUnknown      = errors.New("transport: unknown scheme")
    ErrInprocAlreadyBound = errors.New("transport: inproc name already bound")
)
```

Subpackages (`internal/transport/{tcp,ipc,inproc}`) own per-scheme logic and
are testable in isolation. The top-level package only parses URIs and
dispatches.

Forbidden dependencies (per `00-meta-overview.md` §3): `internal/wire`,
`internal/security`, `socket`. Allowed: standard library only. No `cgo`.

This phase does not yet exercise interop with `libzmq` — the spec defers all
cross-implementation testing to F4 per `00-meta-overview.md` §4.

## 2. Mapping to RFC 23/ZMTP 3.1

ZMTP itself is transport-agnostic — it describes the byte stream, not how it
gets onto the wire. The list of supported transports comes informally from
RFC 23 §2 ("ZMTP runs over TCP and similar reliable byte-stream transports")
and from libzmq endpoint conventions (`zmq_tcp(7)`, `zmq_ipc(7)`,
`zmq_inproc(7)`).

| Aspect | F3 covers |
|--------|-----------|
| `tcp://` endpoints, including IPv4/IPv6 and wildcard bind | **Yes**. |
| `ipc://` endpoints (Unix domain sockets) | **Yes** on Unix. Returns `ErrSchemeUnknown` on Windows (build-tag stub). |
| `inproc://` endpoints (in-process namespace) | **Yes**, process-global, blocking-until-bound semantics. |
| Endpoint URI parsing | **Yes**, restricted to the grammar in §3. |
| `TCP_NODELAY` | **Yes**, set unconditionally on dialled and accepted TCP conns (libzmq parity). |
| `SO_KEEPALIVE`, keepalive intervals, linger, `SO_REUSEADDR` | **No** beyond stdlib defaults. F4 may set per-conn options. |
| Interface-name binds (`tcp://eth0:5555`), abstract Unix (`ipc://@abstract`), auto-temp ipc (`ipc://*`), auto-name inproc (`inproc://#auto`) | **No** — Open Question §9. |
| Connection lifecycle, ZMTP greeting, security handshake | **No** — F4. |
| HWM, monitoring, polling, ZAP | **No** — F5/F6. |

## 3. Endpoint URI grammar

Endpoints follow the libzmq convention: `<scheme>://<addr>`. The grammar
accepted by F3:

```abnf
endpoint    = scheme "://" addr
scheme      = "tcp" / "ipc" / "inproc"
addr        = tcp-addr / ipc-addr / inproc-addr

tcp-addr    = host ":" port
host        = ipv4 / ipv6-bracket / dnsname / "*"
ipv6-bracket = "[" ipv6 "]"
port        = 1*5DIGIT / "*"      ; numeric port: 1..65535 inclusive.
                                  ; "*" = ephemeral (rewritten to 0).
                                  ; Numeric port 0 is malformed — only "*"
                                  ; denotes ephemeral.

ipc-addr    = 1*VCHAR             ; opaque non-empty string; passed verbatim to
                                  ; net.UnixAddr. NUL, newline, and any byte
                                  ; that net.UnixAddr rejects produce
                                  ; ErrEndpointMalformed (validation deferred
                                  ; to net during Listen/Dial).
inproc-addr = 1*VCHAR             ; opaque non-empty string. No platform
                                  ; restrictions — inproc is in-memory.
```

The grammar uses `VCHAR` (visible ASCII 0x21–0x7E) as a working approximation
of "no NUL/whitespace"; in practice the parser accepts any non-empty addr and
defers byte-level validation to the underlying `net` call (for ipc) or the
in-memory map key comparison (for inproc).

Examples:

| Endpoint | Meaning |
|----------|---------|
| `tcp://127.0.0.1:5555` | bind/dial concrete IPv4 address. |
| `tcp://[::1]:5555` | bind/dial concrete IPv6 address. |
| `tcp://*:5555` | bind on `0.0.0.0:5555` (IPv4-only by default; F3 does not bind dual-stack `[::]:5555` automatically — see Open Q §9). |
| `tcp://*:*` | bind on `0.0.0.0:0`; actual port readable via `Listener.Addr().(*net.TCPAddr).Port`. |
| `tcp://example.com:5555` | Dial only — DNS lookup honoured under `ctx`. |
| `ipc:///tmp/zmq.sock` | absolute Unix domain socket path. |
| `ipc://relative/path.sock` | relative path. |
| `inproc://my-service` | opaque name in process-global namespace. |

`ErrEndpointMalformed` is returned for: missing `://`, empty scheme, empty
addr, missing port for `tcp`, port out of range, malformed IPv6 bracket.
`ErrSchemeUnknown` is returned for any scheme outside `{tcp, ipc, inproc}`.

## 4. Public interface

All public API lives in `internal/transport`. Subpackages are also `internal/`
and consumed exclusively by the facade (and by their own tests).

### 4.1 Top-level facade (`internal/transport`)

```go
package transport

// Listen opens a listener for endpoint. Endpoint syntax is described in §3.
//
// Concrete return type per scheme (callers MUST treat as net.Listener; the
// concrete types are documented for implementer reference, not type-switch):
//   tcp    : a thin wrapper around *net.TCPListener that applies
//            SetNoDelay(true) on each accepted conn.
//   ipc    : *net.UnixListener (with SetUnlinkOnClose(true), file mode 0600).
//   inproc : an unexported type implementing net.Listener.
//
// The context is plumbed into net.ListenConfig.Listen for the tcp scheme
// (where it influences any address resolution net performs) and is unused for
// ipc and inproc (their Listen does not block). Listen returns before the
// listener accepts any connection.
func Listen(ctx context.Context, endpoint string) (net.Listener, error)

// Dial opens a single connection to endpoint. Behaviour per scheme:
//   tcp    : net.Dialer.DialContext("tcp", addr); honours ctx for DNS+connect.
//   ipc    : net.Dialer.DialContext("unix", path); honours ctx.
//   inproc : blocks until either (a) a Listen on the matching name produces a
//            paired connection, or (b) ctx is cancelled. See §7.
//
// The returned net.Conn has an unspecified concrete type per scheme. Callers
// MUST NOT type-switch on it for behaviour — only the net.Conn surface is
// guaranteed.
func Dial(ctx context.Context, endpoint string) (net.Conn, error)

// ParseEndpoint exposes the §3 parser for callers that want to inspect a URI
// without opening a connection. Returns the scheme and scheme-native addr, or
// ErrEndpointMalformed / ErrSchemeUnknown.
func ParseEndpoint(endpoint string) (scheme, addr string, err error)
```

Sentinels per §6.

### 4.2 Subpackage shapes

Each subpackage is small and uniform:

```go
package tcp
func Listen(ctx context.Context, addr string) (*net.TCPListener, error)
func Dial(ctx context.Context, addr string) (*net.TCPConn, error)

package ipc // build tag: !windows
func Listen(ctx context.Context, path string) (*net.UnixListener, error)
func Dial(ctx context.Context, path string) (*net.UnixConn, error)

package inproc
func Listen(ctx context.Context, name string) (net.Listener, error)
func Dial(ctx context.Context, name string) (net.Conn, error)
```

Subpackages take the **scheme-native** address (`host:port`, `path`, `name`)
— not the URI. The facade is the only place that parses URIs; subpackages are
testable without any URI dependency.

### 4.3 Why this shape

- **`net.Conn` / `net.Listener` directly.** ZeroMQ does not need TLS-tunnelled
  conns or arbitrary middleware (CURVE encrypts inside ZMTP, not at the
  transport). Using stdlib interfaces removes a custom abstraction layer and
  lets F4 use any helper that consumes `net.Conn` (`bufio.Reader`,
  `net.Buffers`, deadline-aware reads, etc.).
- **Two-function facade.** F4 is the only consumer; it always has a parsed
  endpoint URI on hand. A scheme registry is unnecessary — three known schemes
  hardcoded in the dispatcher beats a public `Register` API we won't extend.
- **Subpackage isolation.** Mirrors F2's `internal/security/{null,plain,curve}`
  layout. Lets each transport be tested without going through the URI parser.
- **`context.Context` everywhere.** Standard Go idiom. F4 carries a connection
  context which is the cancellation channel for both DNS resolution and inproc
  pairing.

### 4.4 Blocking semantics

The `net.Conn` interface intentionally does not pin blocking behaviour; F3
does, so F4 can rely on uniform observable behaviour across schemes. The
guarantees below are part of the public contract of `transport.Dial` /
`transport.Listen`.

#### Read

For all schemes, `Read(p []byte)` blocks until **at least one** of the
following occurs:

| Event | Return |
|-------|--------|
| ≥1 byte arrives from peer | `(n>0, nil)`; `n` may be < `len(p)`. |
| Peer closes its write side (or the whole conn) | once buffered data is drained, `(0, io.EOF)`. |
| Local `Close()` is called | `(0, err)` where `errors.Is(err, net.ErrClosed)` holds for `tcp`/`ipc`. For `inproc` (backed by `net.Pipe`), the error is `io.ErrClosedPipe`; tests MUST accept either via `errors.Is(err, net.ErrClosed) \|\| errors.Is(err, io.ErrClosedPipe)`. |
| Read deadline (set via `SetReadDeadline` or `SetDeadline`) expires | `(0, err)` where `errors.Is(err, os.ErrDeadlineExceeded)` holds; the deadline is sticky and subsequent Reads also fail until the deadline is cleared (`SetReadDeadline(time.Time{})`). |

#### Write

For all schemes, `Write(p []byte)` blocks until **at least one** of the
following occurs:

| Event | Return |
|-------|--------|
| All `len(p)` bytes are committed to the conn (delivered to peer for `inproc`; queued in kernel send buffer for `tcp`/`ipc`) | `(len(p), nil)`. |
| Local or peer `Close()` (during the write) | `(n<len(p), err)` where `n` reflects bytes committed before close; `err` follows the same `net.ErrClosed` / `io.ErrClosedPipe` rule as Read. |
| Write deadline (set via `SetWriteDeadline` or `SetDeadline`) expires | `(n, err)` with `errors.Is(err, os.ErrDeadlineExceeded)`; partial writes are reported by `n`. |

#### Backpressure

- **`tcp`, `ipc`** — backpressure provided by kernel send/receive buffers.
  Write blocks when the peer's receive buffer is full and not draining.
- **`inproc`** — backpressure is **synchronous**: `net.Pipe` has no internal
  buffer. A `Write` of `N` bytes blocks until the peer's `Read` has consumed
  all `N` bytes (in one or more calls). This means `Write` and `Read` on
  paired conns are matched one-to-one in **bytes**, not in calls. Callers
  that need buffered semantics must wrap with `bufio.Writer` /
  `bufio.Reader`.

#### Goroutine-safety

`net.Conn` permits one goroutine reading and one goroutine writing
concurrently on the same conn. F3 preserves this for all three schemes.
Concurrent reads from two goroutines, or concurrent writes from two
goroutines, are not safe.

#### Deadlines on `inproc`

`net.Pipe`'s deadline support is **first-class**, not emulated: stdlib
implements `Set{Read,Write,}Deadline` natively via internal goroutine /
channel coordination. F4 may rely on deadlines for handshake stall detection
(per `02b-security-plain.md` §3) without additional wrapping for inproc.

## 5. Internal data structures

### 5.1 Endpoint parser (`internal/transport/endpoint.go`)

Deterministic, allocation-light, no regex. Pseudocode:

```go
func ParseEndpoint(ep string) (scheme, addr string, err error) {
    i := strings.Index(ep, "://")
    if i <= 0 || i+3 == len(ep) {
        return "", "", fmt.Errorf("%w: %q", ErrEndpointMalformed, ep)
    }
    scheme, addr = ep[:i], ep[i+3:]
    switch scheme {
    case "tcp", "ipc", "inproc":
        return scheme, addr, nil
    default:
        return "", "", fmt.Errorf("%w: scheme %q", ErrSchemeUnknown, scheme)
    }
}
```

Scheme-specific validation (port range, IPv6 brackets, non-empty path/name)
lives in the subpackages — they own their address grammar. `ParseEndpoint`
guarantees only the split.

### 5.2 TCP (`internal/transport/tcp`)

Stateless. Address normalisation:

| Input | Resolved |
|-------|----------|
| `host:port` | passed through verbatim. |
| `*:port` | rewritten to `0.0.0.0:port` (Go defaults dual-stack). |
| `*:*` or `host:*` | rewritten with port `0` (ephemeral). |
| `[ipv6]:port` | passed through; `net` parses bracketed form. |

`Listen` defers to `(&net.ListenConfig{}).Listen(ctx, "tcp", resolved)`. `Dial`
defers to `(&net.Dialer{}).DialContext(ctx, "tcp", addr)`. Returned
`*net.TCPConn` has `SetNoDelay(true)` applied unconditionally (libzmq parity);
all other socket options are F4's call.

Returned `*net.TCPListener.Accept()` produces `*net.TCPConn` directly; the
package wraps it only to apply `SetNoDelay(true)` before returning to the
caller of `Listener.Accept()`. The wrapper is a thin `net.Listener` that
delegates everything except `Accept`.

### 5.3 IPC (`internal/transport/ipc`)

Build tag: `//go:build !windows`. A sibling `ipc_windows.go` provides stubs
returning `ErrSchemeUnknown` so the package compiles everywhere.

`Listen(ctx, path)`:
1. `addr := &net.UnixAddr{Name: path, Net: "unix"}`
2. `lis, err := net.ListenUnix("unix", addr)` (errors propagate).
3. `lis.SetUnlinkOnClose(true)`.
4. `os.Chmod(path, 0o600)` to override umask. If chmod fails, `lis.Close()` is
   called (which unlinks) and the chmod error is returned.
5. Return `lis`.

**Chmod window (security note).** Between step 2 and step 4, the socket file
exists at the umask-derived mode (typically `0666 & ~umask`, often `0644` or
`0664`). On a multi-user host an attacker can `connect(2)` during that window
and then send bytes that the listener will accept after `Listen` returns. The
window is tiny (microseconds on a modern kernel) but real. F3 ships with this
window documented; closing it cleanly requires a `bind`-into-private-tempdir
+ `rename` dance (or platform-specific FD-mode tricks not exposed by Go's
`net`). Tracked as Open Question §9.

`Dial(ctx, path)` defers to `(&net.Dialer{}).DialContext(ctx, "unix", path)`.

The package does not attempt stale-socket cleanup; rebind on a stale ipc file
returns wrapped `EADDRINUSE`. See §9 Open Question 1.

### 5.4 inproc (`internal/transport/inproc`)

Process-global registry holding bound listeners and dialers waiting for a
bind. All registry mutations happen under a single registry mutex; no nested
locks. Per-listener state has its own mutex used only for the accept queue.

**Process scope.** The registry is per-OS-process. Subprocesses spawned via
`os/exec` do **not** share an inproc namespace with the parent.

```go
var registry = struct {
    mu      sync.Mutex
    bound   map[string]*inprocListener
    pending map[string][]*pendingDial      // FIFO order — see §7
}{
    bound:   make(map[string]*inprocListener),
    pending: make(map[string][]*pendingDial),
}

type inprocListener struct {
    name string

    qmu    sync.Mutex
    queue  []net.Conn          // unbounded FIFO of accept-side conns
                               // awaiting Accept(). Memory pressure is
                               // bounded by the caller's Dial rate; see
                               // Open Q §9.
    notify chan struct{}       // cap 1; signalled when queue grows or
                               // closed transitions to true.

    closed chan struct{}       // Close() closes this exactly once.
    once   sync.Once
}

type pendingDial struct {
    // ready is cap-1 buffered so Listen-drain can deliver without blocking.
    // Exactly one of (Listen-drain delivery) and (Dial cancellation cleanup)
    // takes the value; see §7.4 for the race resolution.
    ready chan acceptResult
}

type acceptResult struct {
    conn net.Conn // the dial-side end of a fresh net.Pipe pair
}

type inprocAddr struct{ name string }

func (a inprocAddr) Network() string { return "inproc" }
func (a inprocAddr) String() string  { return a.name }
```

The connection pair is `net.Pipe()` — synchronous, full `net.Conn` including
`Set{Read,Write,}Deadline`. F4 sets deadlines as required; L3 imposes none.

`acceptResult` deliberately has no `err` field: a Listen-drain only signals
success. Dial failure paths (ctx cancellation) flow through `ctx.Err()`
without using `pd.ready`.

### 5.5 Allocation profile

F3 imposes no allocation budgets. The codec layers (F1/F2) own
allocation-sensitive paths; transport allocations come from `net`'s buffers
and are out of project control. No `testing.AllocsPerRun` pin is required.

## 6. Error model

Three sentinels, all wrapped via `fmt.Errorf("...: %w", ...)` with endpoint
context:

```go
var (
    ErrEndpointMalformed  = errors.New("transport: malformed endpoint")
    ErrSchemeUnknown      = errors.New("transport: unknown scheme")
    ErrInprocAlreadyBound = errors.New("transport: inproc name already bound")
)
```

| Sentinel | Returned by |
|----------|-------------|
| `ErrEndpointMalformed` | `ParseEndpoint` for URI-level errors; subpackage `Listen`/`Dial` for scheme-native addr errors (empty path, port out of range, port `0` ambiguity, IPv6 bracket mismatch). The same sentinel covers both layers — F3 does not split into `ErrAddrMalformed` because callers see a single API surface. |
| `ErrSchemeUnknown` | `ParseEndpoint`. Also returned by `ipc.Listen`/`ipc.Dial` on Windows via the build-tag stub. |
| `ErrInprocAlreadyBound` | `inproc.Listen` when the name is already bound. |

Every other failure mode is propagated unchanged or `%w`-wrapped:

- `*net.OpError`, `net.ErrClosed`, `os.ErrDeadlineExceeded` from stdlib calls.
- `syscall.EADDRINUSE` (TCP port collision, ipc stale socket).
- `context.DeadlineExceeded`, `context.Canceled` from `Dial` cancellation.

`errors.Is(err, net.ErrClosed)` and `errors.As(err, &op *net.OpError)` work as
expected throughout. F3 does not introduce new error types — only sentinels.

## 7. State machine — inproc only

TCP and IPC are stateless wrappers. `inproc` owns the only F3 state machine.

### 7.1 Per-name registry state

```
   ┌────────────┐  Listen(n)        ┌──────────┐  Close()       ┌────────────┐
   │  Unbound   │ ────────────────► │  Bound   │ ─────────────► │  Unbound   │
   │ (no entry) │                   │ (in map) │                │ (no entry) │
   └─────┬──────┘                   └──────────┘                └────────────┘
         │  Listen(n) again on Bound ─► ErrInprocAlreadyBound
         │
         ▼
   pending[n] grows on each Dial(n)
         │
         └─ when Listen(n) fires ─► drain pending[n], pair each waiter
                                    with a fresh net.Pipe()
```

Re-binding the same name after `Close` returns to **Unbound**, then a new
`Listen` transitions to **Bound** again.

### 7.2 Per-Dial waiter state

```
   Dial(ctx, n) ──► [enqueue in pending[n]] ─┬─► Listen(n) drains   ─► (conn, nil)
                                             │
                                             ├─► ctx.Done()         ─► (nil, ctx.Err())
                                             │
                                             └─── (no other transitions)
```

Critically, **a pending Dial does not return on Listener.Close()**. Close
releases the name; waiters survive in `pending[n]` and pair with the *next*
`Listen(n)`. This connect-blocks-until-bind semantics is intentional: it
keeps the API robust under bind churn (the common pattern of "transient
listener restart" does not poison in-flight Dials).

### 7.3 Accept lifecycle

`Accept()` on an `inprocListener` is a loop:

```
1. Lock listener.qmu.
2. If queue is non-empty:
     conn := queue[0]; queue = queue[1:]
     unlock; return conn, nil.
3. If closed channel is closed (checked via non-blocking select; `closed` is
   never received-from while holding qmu):
     unlock; return nil, net.ErrClosed.

   Note: step 2 runs before step 3, so any conn already enqueued before Close
   is still delivered to a subsequent Accept call. ErrClosed is only returned
   once the queue is drained.
4. Unlock.
5. select { case <-listener.notify: goto 1; case <-listener.closed: goto 1 }
   (The shared `notify` channel is signalled by both queue-grow and Close;
    a spurious wake just retries the lock-and-check.)
```

`Listen-drain` and post-bind `Dial` both enqueue conns by:

```
1. Lock listener.qmu.
2. Append conn to queue.
3. Try non-blocking send on listener.notify (cap-1 buffered: drop if already
   pending).
4. Unlock.
```

The unbounded `queue` means `Dial` post-bind never blocks on Accept
back-pressure. Memory pressure under a misbehaving caller is acknowledged in
Open Question §9.

`Listener.Addr()` returns `inprocAddr{name}` — `Network() == "inproc"`,
`String() == name`. Stable across Close.

### 7.4 Listener.Close semantics

`Close()` on an `inprocListener`:
1. Acquire `registry.mu`.
2. If `registry.bound[name] == this`, delete the entry. (A subsequent re-Listen
   may have already replaced it; in that case Close leaves the new entry
   untouched.)
3. Release `registry.mu`.
4. `once.Do(close(this.closed))` — closes the channel exactly once; ignore
   subsequent Close calls (matches `net.Listener` convention).
5. Non-blocking signal `this.notify` so any goroutine in `Accept` step 5 wakes
   up and observes step 4 via `<-this.closed`.
6. Already-accepted conns are owned by their caller and unaffected.
7. **Pending dialers on the same name are not signalled** (see §7.2):
   `pending[name]` belongs to the registry, not to this listener instance, and
   waiters survive across Close → re-Listen cycles.

### 7.5 Dial cancellation race

This is the subtle path. A pending Dial selects on `pd.ready` and `ctx.Done()`
*after* releasing `registry.mu`. A concurrent `Listen` may drain `pd` between
those two events. The race resolution:

`pd.ready` is **cap-1 buffered**, so Listen-drain's send is always
non-blocking and the conn is committed even if the dialer is mid-cancel.
The dial goroutine, after `select`:

```go
select {
case res := <-pd.ready:
    // Drained: pd is no longer in pending[name]. Return the conn.
    return res.conn, nil

case <-ctx.Done():
    // Cancellation racing with drain. Reacquire registry.mu, then:
    //   a) try to remove pd from pending[name] (slice scan)
    //   b) if pd was already drained (not found in pending[name]), do a
    //      non-blocking receive from pd.ready: if a conn was delivered,
    //      Close(both ends).
    registry.mu.Lock()
    found := removeFromPending(name, pd)   // returns true if removed
    registry.mu.Unlock()

    if !found {
        // Drained while we were cancelling. Drain pd.ready.
        select {
        case res := <-pd.ready:
            res.conn.Close()                // closes the dial side
            // The accept side is already in the listener's queue. The
            // listener will Accept it normally; its first Read will return
            // io.EOF because we just closed the dial side. F4 treats this
            // as an immediately-closed connection, which is the correct
            // observable.
        default:
            // Cannot happen: if `pd` is not in pending[name] then
            // Listen-drain (§7.7) already removed it from the snapshot
            // under registry.mu and committed the cap-1 non-blocking send
            // before its registry.mu.Unlock. Our registry.mu.Lock here
            // happens-after that unlock, so the send is visible. Default
            // branch is defensive; return ctx.Err() if reached.
        }
    }
    return nil, ctx.Err()
}
```

The accept-side of any orphaned pipe is delivered to the listener as a
normal accepted conn whose first `Read` yields `io.EOF`. F4 will see this as
"peer disconnected before sending greeting" and discard it via standard
connection-error handling. **No goroutine leak; no fd leak; no duplicated
conn delivery.**

### 7.6 Listen-drain order

Listen drains `pending[name]` in **FIFO** order. Older waiters pair first.
This is deterministic for tests; matches `libzmq`'s in-order pairing where
applicable. Implementation: `pending[name]` is a slice appended-to by Dial
and traversed front-to-back by Listen-drain.

### 7.7 Listen-drain off-lock

Listen does not pair conns under `registry.mu`:

1. Lock `registry.mu`.
2. If `bound[name]` is set, return `ErrInprocAlreadyBound`.
3. Construct listener; set `bound[name] = listener`.
4. Snapshot `drainSnap := pending[name]`; clear `pending[name]`.
5. Unlock `registry.mu`.
6. For each `pd` in `drainSnap` (FIFO): `a, b := net.Pipe()`; enqueue `a` on
   listener (per §7.3); non-blocking send `acceptResult{conn: b}` on
   `pd.ready`.
7. Return listener.

Step 6 may run inline (typical case: small `drainSnap`) or, for very large
drains, in a spawned goroutine — implementation choice. Either way Listen
returns a usable listener after step 5; Accept will block until step 6
enqueues the first conn.

### 7.8 Goroutine safety

`registry.mu` guards `bound` and `pending`. `listener.qmu` guards
`listener.queue`. The two locks are never held simultaneously. `select` on
`pd.ready` / `ctx.Done()` happens with no lock held. `go test -race` is
mandatory and gating on the F3 done criteria (§8.8).

## 8. Test plan

### 8.1 Unit tests per scheme (`{tcp,ipc,inproc}/*_test.go`)

Each scheme covers the same baseline:

- `TestListenDialRoundTrip` — bind, dial, send N bytes, recv N bytes, equal.
- `TestListenAlreadyBound` — second bind on same address returns `EADDRINUSE`
  (tcp/ipc) or `ErrInprocAlreadyBound` (inproc).
- `TestCloseUnblocksAccept` — goroutine `Accept`, main `Close`, accept returns
  `net.ErrClosed`.
- `TestCloseUnblocksRead` — peer closes, reader returns `io.EOF`.
- `TestDeadline` — `SetReadDeadline(past)`; Read returns
  `os.ErrDeadlineExceeded`.

### 8.2 TCP-specific (`tcp/tcp_test.go`)

- `TestListenWildcardHost` — `*:port` resolves to `0.0.0.0:port`.
- `TestListenWildcardPort` — `*:*` → ephemeral; assert
  `Listener.Addr().(*net.TCPAddr).Port != 0`.
- `TestListenIPv6Bracket` — `[::1]:0` binds to IPv6 loopback.
- `TestDialIPv6` — dial via `[::1]:port` and round-trip.
- `TestNoDelaySet` — accept a conn, type-assert `*net.TCPConn`, confirm
  `TCP_NODELAY` flag (via `syscall.GetsockoptInt` in a Linux-tagged helper, or
  by behavioural timing test as fallback).

### 8.3 IPC-specific (`ipc/ipc_test.go`, `//go:build !windows`)

- `TestUnlinkOnClose` — after Close, `os.Stat(path)` returns
  `os.ErrNotExist`.
- `TestFileMode0600` — post-Listen, `os.Stat(path).Mode().Perm() == 0o600`.
- `TestStaleSocketRebind` — bind, simulate process crash by removing the
  listener struct without unlinking, second bind returns wrapped
  `EADDRINUSE`. Documents current behaviour; auto-cleanup deferred (§9.1).
- Windows stub (`ipc_windows_test.go`) — assert both `Listen` and `Dial`
  return `ErrSchemeUnknown`.

### 8.4 inproc-specific (`inproc/inproc_test.go`)

- `TestConnectBlocksUntilBind` — goroutine A dials, sleeps 50 ms, asserts
  Dial has not yet returned; goroutine B Listens; A's Dial completes;
  round-trip succeeds.
- `TestConnectCancelledByContext` — Dial with
  `ctx, _ := context.WithTimeout(parent, 10ms)`; assert
  `errors.Is(err, context.DeadlineExceeded)`.
- `TestBindRebindAfterClose` — Listen, Close, Listen — second Listen
  succeeds.
- `TestAlreadyBound` — Listen, Listen — second returns
  `ErrInprocAlreadyBound`.
- `TestPendingDialSurvivesCloseAndRebind` — Dial blocks; concurrent Listen
  immediately followed by Close releases the name but does not wake the
  Dial; a later Listen pairs the still-pending Dial.
- `TestRaceDetectorClean` — 100 concurrent Dial+Listen+Close cycles with
  `-race`.

### 8.5 Cross-transport conformance (`transport_test.go`)

Table-driven over all three schemes. Each row is a
`(scheme, bindEndpoint, dialEndpointFactory)` triple
(`dialEndpointFactory` because `tcp://*:0` needs the post-bind port).
Asserts:

- Round-trip 1 KiB and 1 MiB.
- Closing the listener releases pending Accept with `net.ErrClosed`.
- Peer-close: one side calls `Close`, the other side's `Read` returns
  `io.EOF` (note: `net.Pipe` does not implement true half-close — closing one
  side closes the conn for both directions on that side).
- `Dial` after listener Close is implementation-defined per scheme (tcp:
  `ECONNREFUSED`-class error; ipc: `ENOENT`-class; inproc: blocks per §7.2)
  — each scheme asserts its own expected behaviour, not a unified one.

### 8.6 Endpoint parser (`endpoint_test.go`)

Table-driven valid / invalid URI pairs. Required cases:

- Valid: each example from §3.
- Invalid: empty, no scheme, no `://`, empty addr after scheme, unknown
  scheme, non-numeric port, numeric port `0` (rejected as malformed; only
  `*` denotes ephemeral — see §3), port > 65535, IPv6 missing closing
  bracket, addr with no host before colon.
- Per invalid case, `errors.Is(err, ErrEndpointMalformed)` or
  `errors.Is(err, ErrSchemeUnknown)` matches expectation.

### 8.7 What is **not** tested in F3

- Interop with `libzmq` — deferred to F4 per `00-meta-overview.md` §4.
- ZMTP framing on top of the transport — F4.
- TLS, keepalive intervals, custom socket options — F4 may add.
- Performance benchmarks — no codec; alloc budgets do not apply (§5.5).
- Fuzzing the URI parser — low ROI; the grammar is tiny and hand-tabled.
- Property-based tests — F3 has no encoded structures to round-trip.

### 8.8 Done criteria

- All required tests pass on `linux/amd64` and `darwin/arm64`.
- `ipc` package excluded on `windows/amd64` via build tag; Windows stub test
  passes.
- `go test -race ./internal/transport/...` clean.
- `go vet ./internal/transport/...` clean.
- `staticcheck ./internal/transport/...` clean.
- `modernize -fix ./internal/transport/...` produces no diff (run before
  phase tag).
- Spec sections 1–8 fully implemented; §9 open questions remain open or are
  explicitly closed.

## 9. Open questions

1. **Stale ipc socket cleanup.** If a previous process left an ipc socket
   file behind, current behaviour returns wrapped `EADDRINUSE` on bind.
   `libzmq` optionally auto-removes. Defer to F4 (or a post-F3 amendment) —
   the knob belongs with other socket options.
2. **TCP keepalive defaults.** F3 sets only `TCP_NODELAY`. `libzmq` exposes
   `tcp_keepalive`, `tcp_keepalive_idle`, `tcp_keepalive_intvl`,
   `tcp_keepalive_cnt`. These belong with other connection options;
   deferred to F4.
3. **Interface-name binds (`tcp://eth0:5555`).** `libzmq` parity feature; not
   implemented. Reopen if any libzmq interop test in F4 requires it.
4. **Linux abstract Unix sockets (`ipc://@abstract`).** Not implemented;
   Linux-only. Reopen if F4 demands.
5. **Auto-temp ipc (`ipc://*`) and auto-name inproc (`inproc://#auto`).** Not
   implemented. Tests can supply unique names via `t.Name()` plus a counter
   helper.
6. **inproc HWM.** Currently `net.Pipe()` is synchronous — no buffer.
   `libzmq` has per-socket HWM affecting inproc pipes. HWM in our model is
   an L5 socket-queue concern, not L3 transport; no F3 change. Reconsider
   if F5 design requires deeper buffering at the transport layer.
7. **Windows ipc.** F3 stubs out. A real Windows IPC story (Named Pipes via
   `\\.\pipe\name`?) is a separate spec, ideally bundled with any future
   Windows interop.
8. **Subpackage `Dial` blocking semantics for inproc must match facade.**
   Trivially yes today since the facade just delegates. Called out as an
   Open question only so future amendments that give the facade richer
   behaviour (e.g. retry with backoff) cannot accidentally diverge.
9. **TCP wildcard dual-stack.** `tcp://*:port` binds IPv4 only. `libzmq`
   exposes `ipv6=1` to bind both. F3 picks the conservative IPv4-only
   default; F4 may add the knob.
10. **`TCP_NODELAY` opt-out.** F3 sets `TCP_NODELAY` unconditionally for
    libzmq parity. Some workloads (large bulk transfers) may want Nagle on.
    Belongs with other socket options in F4.
11. **ipc chmod window.** §5.3 documents the umask-window between
    `ListenUnix` and `os.Chmod`. Closing it cleanly likely requires
    bind-into-private-tempdir + `rename`. Not a blocker for F3 but should be
    addressed before any production deployment scenario.
12. **inproc `pending[name]` unbounded growth.** A misbehaving caller can
    enqueue Dials forever on an unbound name, leaking goroutines + channel
    state. Need either a registry-level cap (returning a new sentinel) or
    per-Dial cancellation by parent context. F4 supplies cancellation; F3
    relies on the caller's ctx discipline.
13. **inproc `Listener.queue` unbounded growth.** Symmetric concern: post-bind
    Dials enqueue without back-pressure. If Accept is slow, memory grows.
    Same resolution path as Q12 — caller cancellation upstream.
14. **`ParseEndpoint` stability.** Exposed for F4 but lives under `internal/`.
    If F5/F6 needs to surface a parsed endpoint to user-facing diagnostics,
    `ParseEndpoint` (or an equivalent) must be promoted to public. Defer.
15. **inproc cross-process scope.** Made explicit in §5.4: registry is
    per-OS-process, `os/exec` children do not share a namespace. Tests in
    F4/F5 that span processes must use `tcp` or `ipc`. No code change for F3.
16. **Skeleton ordering deviation.** `00-meta-overview.md` §5 lists
    `state machines → error model`. F2a/F2b/F2c order error model first, and
    F3 follows that established sibling pattern. The meta skeleton is
    advisory; sibling consistency wins.

## 10. References

- [RFC 23/ZMTP — ZeroMQ Message Transport Protocol 3.1](https://rfc.zeromq.org/spec/23/) §2 (transports list).
- libzmq man pages: [`zmq_tcp(7)`](http://api.zeromq.org/4-3:zmq-tcp),
  [`zmq_ipc(7)`](http://api.zeromq.org/4-3:zmq-ipc),
  [`zmq_inproc(7)`](http://api.zeromq.org/4-3:zmq-inproc).
- Project specs: `00-meta-overview.md` §3 (layering rules), §4 (phase
  pipeline); `00b-memory-model.md` (boundary ownership).
- Go stdlib: `net.ListenConfig`, `net.Dialer.DialContext`,
  `net.UnixListener.SetUnlinkOnClose`, `net.Pipe`.
