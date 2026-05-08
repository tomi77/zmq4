# 05a — Socket layer: REQ / REP / ROUTER / DEALER (Phase 5a)

> **Status:** design approved, implementation pending.
> **Author:** Tomasz Rup
> **Date:** 2026-05-08
> **Layer:** L5 — `zmq4` (root package)
> **Depends on:** F1 (`internal/wire`), F2a/F2b/F2c (`internal/security`),
> F3 (`internal/transport`), F4 (`internal/conn`).
> **Consumed by:** application code (public API surface).

## 1. Summary

This phase delivers the first four public socket types in the root `zmq4`
package: `REQ`, `REP`, `DEALER`, and `ROUTER`. Together they implement the
**request-reply pattern** defined in RFC 28/REQREP.

F5a is the first phase that produces a user-visible, end-to-end-usable API.
It wires together all lower layers: F3 (`internal/transport`) dials/listens,
F4 (`internal/conn`) runs the ZMTP greeting and security handshake, and F5a
adds the socket-type semantics — routing envelopes, sequencing constraints,
identity management — that RFC 28 requires.

The public surface is four socket types and a shared options API:

```go
func NewREQ(opts ...Option) *REQ
func NewREP(opts ...Option) *REP
func NewDEALER(opts ...Option) *DEALER
func NewROUTER(opts ...Option) *ROUTER

// Each socket type implements Bind, Connect, Send, Recv, Close.
// Option constructors: WithNULL, WithPLAIN, WithPLAINServer,
// WithCURVE, WithCURVEServer, WithIdentity, WithHandshakeTimeout.
```

What F5a explicitly does **not** do:

- **No PUB/SUB/XPUB/XSUB.** Topic filtering and fan-out semantics are F5b.
- **No PUSH/PULL/PAIR.** Pipeline and exclusive-pair semantics are F5c.
- **No ZAP.** ZAP-backed authenticators are F6. F5a passes a plain
  `plain.Authenticator` callback (same as F2b tests do today).
- **No heartbeat.** PING/PONG operational heartbeat is F6.
- **No HWM.** Per-pipe queue size limits are F5/F6; F5a uses unbounded
  channels as a first pass. Open Q §9.1.
- **No auto-reconnect.** A pipe is dropped on read error; reconnection
  logic is deferred. Open Q §9.2.
- **No monitoring events.** Socket monitoring (RFC 23 §5 monitoring
  commands) is F6.

Forbidden dependencies (per `00-meta-overview.md` §3): none — L5 is the
top layer. All internal packages are available. No `cgo`.

This phase removes the scaffold in `socket.go` (which was marked
"F5 will replace the internals") and replaces it with the real implementation.
The `Message` type in `message.go` is kept unchanged.

**Package location decision.** The meta-overview architecture diagram shows
`socket/` as the L5 package path, but F5a deliberately places the
implementation in the **root `zmq4` package** (the module path is
`github.com/tomi77/zmq4`). Rationale: a single import is idiomatic Go
(`net/http` does not split into `net/http/server`); the root package is
already the documented home for `Message` and the scaffold; and no other Go
package in this module needs to import F5a (it is the public top). The
meta-overview §3 layer table is updated accordingly; `socket/` as a directory
name is retired.

## 2. Mapping to RFC 28/REQREP

| RFC 28 § | F5a covers |
|----------|-----------|
| §2 REQ socket — alternating Send/Recv, empty delimiter prepend/strip | **Yes** — enforced via state machine. |
| §2 REP socket — alternating Recv/Send, routing envelope preservation | **Yes** — envelope stored per Recv, prepended on Send. |
| §2 DEALER socket — async, round-robin send, fair-queue recv | **Yes** — no state machine constraint. |
| §2 ROUTER socket — identity routing, identity frame prepend/strip | **Yes** — identity from peer metadata or generated UUID. |
| §2 Compatible pairs (REQ↔REP, REQ↔ROUTER, DEALER↔REP, DEALER↔ROUTER, DEALER↔DEALER) | **Yes** — checked against `Socket-Type` from peer READY metadata; incompatible peers rejected at handshake time. |
| §2.4 Socket-Type metadata property | **Yes** — populated in local READY before handshake. |
| §2.4 Identity metadata property | **Yes** (ROUTER reads it from peers; settable via `WithIdentity`). |
| §2 REQ strict-sequencing error (double Send / double Recv) | **Yes** — `ErrState` returned immediately. |
| §2 ROUTER — drop message if identity unknown (vs. error) | **Yes** — `ErrNoRoute` returned on Send to unknown identity. |
| Multi-hop routing (ROUTER↔DEALER↔ROUTER chains) | **Yes** (implicit — envelope is opaque bytes passed through). |
| ZAP integration for PLAIN/CURVE authentication | **No** — F6. |
| Monitoring events, HWM, polling | **No** — F6. |

## 3. Public interface

All public API lives in the root `zmq4` package.

### 3.1 Options

```go
// Option configures a socket at construction time.
type Option func(*socketConfig)

// WithNULL selects the NULL security mechanism (no authentication, no
// encryption). This is the default if no security option is provided.
func WithNULL() Option

// WithPLAIN configures PLAIN client-side credentials. Use on the
// connecting side (Connect). username and password are UTF-8 strings;
// they are passed verbatim to plain.NewClient.
func WithPLAIN(username, password string) Option

// WithPLAINServer configures PLAIN server-side authentication. Use on
// the listening side (Bind). auth is called once per connecting peer;
// returning a non-nil error rejects the peer with an ERROR command.
func WithPLAINServer(auth plain.Authenticator) Option

// WithCURVE configures CURVE client-side keys. Use on the connecting
// side (Connect).
func WithCURVE(opts curve.ClientOptions) Option

// WithCURVEServer configures CURVE server-side keys. Use on the
// listening side (Bind).
func WithCURVEServer(opts curve.ServerOptions) Option

// WithIdentity sets the local socket identity advertised in the
// handshake READY metadata (the Identity property). If not set, the
// identity property is omitted (peers that care — e.g. ROUTER — will
// generate a random UUID for this peer). May be up to 255 bytes.
// Panics if len(id) == 0 || len(id) > 255.
func WithIdentity(id []byte) Option

// WithHandshakeTimeout sets the per-connection handshake deadline.
// Default: 5 s. Applied via context.WithTimeout for each Dial/Accept.
// Panics if d <= 0.
func WithHandshakeTimeout(d time.Duration) Option
```

Only one security option may be set per socket. Providing two security
options panics at construction time.

Bind-side and Connect-side security options are checked at use time:
`WithPLAINServer` on a socket that only ever calls `Connect` returns
`ErrSecurityMismatch` at the first `Connect` call. This is not a
compile-time error because the same socket may both Bind and Connect
(legal in ZMTP for DEALER/ROUTER patterns).

### 3.2 REQ

```go
// REQ is a request socket. It pairs with REP and ROUTER peers.
//
// Send and Recv alternate strictly: after a successful Send, the socket
// is in "sent" state and must Recv before sending again. Violating this
// order returns ErrState.
//
// REQ transparently prepends an empty delimiter frame on Send and strips
// it on Recv, hiding the ZMTP routing envelope from the caller.
type REQ struct { /* opaque */ }

func NewREQ(opts ...Option) *REQ

// Bind opens a listener on endpoint and begins accepting peers
// asynchronously. Multiple Bind calls on the same socket are allowed;
// each opens an independent listener. Bind is non-blocking after the
// listener is established; new connections are accepted in the
// background.
func (s *REQ) Bind(ctx context.Context, endpoint string) error

// Connect dials endpoint, runs the ZMTP handshake, and registers the
// resulting connection as a new pipe. Connect is non-blocking after the
// handshake succeeds. The handshake uses ctx for its deadline;
// WithHandshakeTimeout applies if ctx carries no deadline.
func (s *REQ) Connect(ctx context.Context, endpoint string) error

// Send selects one available pipe (round-robin among idle peers), wraps
// msg in a routing envelope (empty delimiter prepend), and sends it. If
// no pipes are available, Send blocks until one becomes available or ctx
// is done.
//
// Returns ErrState if the socket is in "sent" state (waiting for Recv).
// Returns ErrClosed if Close has been called.
func (s *REQ) Send(ctx context.Context, msg Message) error

// Recv waits for a reply on the pipe that was last used by Send, strips
// the routing envelope (empty delimiter), and returns the payload. If
// the peer closes the connection before replying, Recv returns io.EOF.
//
// Returns ErrState if the socket is in "idle" state (no pending Send).
// Returns ErrClosed if Close has been called.
func (s *REQ) Recv(ctx context.Context) (Message, error)

// Close stops all acceptor goroutines, closes all pipes, and frees
// resources. Idempotent. In-flight Send/Recv unblock with ErrClosed.
func (s *REQ) Close() error
```

### 3.3 REP

```go
// REP is a reply socket. It pairs with REQ and DEALER peers.
//
// Recv and Send alternate strictly: after a successful Recv, the socket
// is in "recv" state and must Send before receiving again. Violating
// this order returns ErrState.
//
// REP transparently preserves the routing envelope received from the
// peer and prepends it to the reply on Send, hiding the envelope from
// the caller. The caller sees only the application payload.
type REP struct { /* opaque */ }

func NewREP(opts ...Option) *REP

func (s *REP) Bind(ctx context.Context, endpoint string) error
func (s *REP) Connect(ctx context.Context, endpoint string) error

// Recv fair-queues across all connected pipes. Returns the application
// payload (routing envelope stripped). Records the pipe and envelope
// internally for the subsequent Send.
func (s *REP) Recv(ctx context.Context) (Message, error)

// Send prepends the stored routing envelope and sends the reply on the
// pipe that delivered the last Recv. Returns ErrState if called before
// Recv.
func (s *REP) Send(ctx context.Context, msg Message) error

func (s *REP) Close() error
```

### 3.4 DEALER

```go
// DEALER is an asynchronous request socket. It pairs with REP and
// ROUTER peers and, unlike REQ, imposes no sequencing constraint. DEALER
// does not add or strip routing envelopes — the caller is responsible
// for framing.
//
// Send uses round-robin across connected pipes. Recv fair-queues from
// all pipes.
type DEALER struct { /* opaque */ }

func NewDEALER(opts ...Option) *DEALER

func (s *DEALER) Bind(ctx context.Context, endpoint string) error
func (s *DEALER) Connect(ctx context.Context, endpoint string) error

// Send round-robins across pipes. Blocks until a pipe is ready or ctx
// is done. Returns ErrClosed after Close.
func (s *DEALER) Send(ctx context.Context, msg Message) error

// Recv fair-queues across pipes. Blocks until a message arrives or ctx
// is done. Returns ErrClosed after Close.
func (s *DEALER) Recv(ctx context.Context) (Message, error)

func (s *DEALER) Close() error
```

### 3.5 ROUTER

```go
// ROUTER is an identity-routing socket. It pairs with REQ, DEALER, and
// other ROUTER peers.
//
// Every incoming message has the peer's identity prepended as msg[0].
// Every outgoing message must have the target peer's identity as msg[0];
// ROUTER routes to the matching pipe and strips msg[0] before sending.
//
// Peer identity is taken from the Identity metadata property in the
// handshake READY. If the peer does not advertise an identity, ROUTER
// generates a random 5-byte UUID.
type ROUTER struct { /* opaque */ }

func NewROUTER(opts ...Option) *ROUTER

func (s *ROUTER) Bind(ctx context.Context, endpoint string) error
func (s *ROUTER) Connect(ctx context.Context, endpoint string) error

// Recv fair-queues across all pipes. Returns a message where msg[0] is
// the sender's identity. msg[0] is a freshly allocated, caller-owned
// slice (it does not alias any internal buffer).
func (s *ROUTER) Recv(ctx context.Context) (Message, error)

// Send routes the message to the pipe identified by msg[0]. Strips
// msg[0] before sending the remaining frames on the wire. Returns
// ErrNoRoute if no pipe with that identity is connected.
func (s *ROUTER) Send(ctx context.Context, msg Message) error

func (s *ROUTER) Close() error
```

### 3.6 Why this shape

- **Four distinct types, not one Socket with an enum.** Each type's
  `Send`/`Recv` signature is identical, but the invariants differ —
  REQ/REP enforce alternating order, ROUTER requires msg[0] identity.
  Distinct types let godoc and compiler signal incorrect usage context.
- **No common exported interface.** An exported `Socket` interface would
  unify the four types, but callers would lose the type-specific
  invariant documentation. F5b/F5c will add more types; if a common
  interface emerges naturally, it can be added additively.
- **`context.Context` on Send/Recv.** Cancellation composability is more
  important than syntactic brevity. The context propagates into the
  inbound channel `select`, blocking Send's pipe-selection, and
  blocking Recv's fair-queue.
- **Bind is non-blocking; Connect is handshake-synchronous.** Bind
  returns as soon as the listener is open (the OS port is claimed);
  background goroutines handle Accept + handshake. Connect blocks for
  the handshake duration so the caller knows the connection succeeded
  (or failed) before the first Send. This matches libzmq behavior.
- **WithHandshakeTimeout instead of per-call ctx deadline.** The
  handshake ctx is internal; application code passes ctx only to
  Send/Recv. Separating the two deadlines (infra vs application) avoids
  an application cancel interrupting a background accept/dial.

## 4. Internal data structures

### 4.1 socketConfig (`options.go`)

```go
type socketConfig struct {
    // clientMechFactory builds a security.ClientMechanism for a Connect
    // (active/client-side) handshake.
    clientMechFactory func(socketType string) (security.ClientMechanism, error)
    // serverMechFactory builds a security.Mechanism for a Bind/Accept
    // (passive/server-side) handshake.
    serverMechFactory func(socketType string) (security.Mechanism, error)
    identity          []byte          // local Identity metadata value; nil = omit
    handshakeTimeout  time.Duration   // default 5 s
}
```

Two factory functions — one per role — eliminate the type-assertion
needed to pass the result to `conn.ClientHandshake` (which requires
`security.ClientMechanism`) vs `conn.ServerHandshake` (which requires
`security.Mechanism`). F4's API is strictly typed on role; F5a's
factories mirror that split.

`newSocketConfig(opts)` applies options and panics if two security
options are provided. Default factories produce `null.NewState` for both
roles (NULL mechanism is symmetric — `null.State` implements both
`security.Mechanism` and `security.ClientMechanism`).

### 4.2 pipe (`pipe.go`)

```go
// pipe represents one live ZMTP connection inside a socket.
type pipe struct {
    conn     *conn.Conn
    identity []byte        // peer identity (ROUTER use; stable after construction)
    inCh     chan Message  // reader goroutine → socket inbound multiplexer
    closeCh  chan struct{}  // closed by socket to signal reader goroutine to stop
    wg       sync.WaitGroup
}
```

**Reader goroutine:** calls `pipe.conn.ReadFrame()` in a loop,
accumulates a multipart message (frames with `More=true` followed by
one with `More=false`), then sends the assembled `Message` to `inCh`.
On any error (including `ErrClosed` after socket Close), the goroutine
closes `inCh` and exits.

**inCh capacity:** 64 (fixed constant for F5a). Open Q §9.1 tracks
per-pipe HWM. Unbounded channels are rejected — they mask back-pressure
bugs early.

**pipe lifecycle:**
1. Constructed by `newPipe(conn, identity)`.
2. `pipe.start()` launches the reader goroutine.
3. Socket's `pipeSet.add(p)` registers it.
4. On reader goroutine exit (peer closed or error): `pipeSet.remove(p)`;
   `p.conn.Close()` if not already closed.
5. Socket's `Close()` calls `p.conn.Close()` + drains `inCh` for all
   pipes; waits for all reader goroutines via `p.wg.Wait()`.

### 4.3 pipeSet (`pipe.go`)

```go
type pipeSet struct {
    mu    sync.Mutex
    pipes []*pipe
    // robin is the next-send index for round-robin (DEALER/REQ).
    robin int
}

func (ps *pipeSet) add(p *pipe)
func (ps *pipeSet) remove(p *pipe)
func (ps *pipeSet) next() *pipe          // round-robin; nil if empty
func (ps *pipeSet) byIdentity(id []byte) *pipe  // ROUTER lookup
func (ps *pipeSet) all() []*pipe         // snapshot for fair-queue select
func (ps *pipeSet) len() int
```

`byIdentity` does a linear scan (pipe counts are small in practice;
ROUTER performance is dominated by network I/O). Open Q §9.3.

### 4.4 socketBase (`base.go`)

```go
// socketBase holds the shared goroutine and lifecycle machinery used by
// all four socket types. Each concrete type embeds socketBase.
type socketBase struct {
    cfg      *socketConfig
    pipes    *pipeSet
    closeCh  chan struct{}  // closed by Close()
    closeOnce sync.Once
    wg       sync.WaitGroup  // tracks acceptor goroutines
}
```

`socketBase.bind(ctx, endpoint, socketType string)`:
1. Calls `transport.Listen(ctx, endpoint)` → `net.Listener`.
2. Launches acceptor goroutine (`sb.wg.Add(1)`). Returns immediately
   after listener is open (non-blocking).
3. Acceptor loop:
   - `ln.Accept()` → raw `net.Conn`.
   - `sb.wg.Add(1)` (track handshake goroutine). Launch handshake
     goroutine: `defer sb.wg.Done()` at top.
   - Handshake goroutine: build handshake ctx via
     `context.WithTimeout(context.Background(), cfg.handshakeTimeout)`.
     Note: a fresh `Background()` ctx is used so a caller-cancelled
     `ctx` from Bind does not abort in-flight handshakes. Call
     `conn.ServerHandshake(hsCtx, raw, cfg.serverMechFactory(socketType))`.
     On failure: `raw.Close()`, return (error is silently dropped —
     use F6 monitoring to surface these). On success: validate
     socket-type compatibility (§4.5). On incompatible peer:
     `c.Close()`, return (silently dropped). On compatible: create
     pipe, `pipes.add(p)`, `p.start()`, signal `pipeAdded` (§4.7).
4. Acceptor goroutine exits when `closeCh` is closed (via
   `ln.Close()`). All tracked handshake goroutines are waited via
   `sb.wg.Wait()` in `close()`.

`socketBase.connect(ctx context.Context, endpoint, socketType string)`:
1. Calls `transport.Dial(ctx, endpoint)` → raw `net.Conn`.
2. Builds handshake ctx: always creates a child context with
   `cfg.handshakeTimeout` as deadline, inheriting `ctx`'s cancellation:
   `hsCtx, cancel := context.WithTimeout(ctx, cfg.handshakeTimeout)`.
   This ensures F4's `ErrNoDeadline` is never triggered even when `ctx`
   carries a cancellation but no deadline.
3. `conn.ClientHandshake(hsCtx, raw, cfg.clientMechFactory(socketType))`.
4. Validate socket-type compatibility (§4.5). On incompatible:
   `c.Close()`, return `ErrIncompatiblePeer`.
5. Create pipe, `pipes.add(p)`, `p.start()`, signal `pipeAdded` (§4.7).
6. Return nil. Blocking — caller knows connection succeeded before
   the first Send.

`socketBase.close()`:
1. `closeOnce.Do(close(closeCh))`.
2. Close all pipes' `conn` (unblocks reader goroutines).
3. `sb.wg.Wait()` — waits for both acceptor goroutines AND all
   handshake goroutines (all tracked via the same `wg`).
4. Pipe reader goroutines exit when `conn.Close()` unblocks their
   `ReadFrame`; waited via `pipe.wg`.

### 4.5 Socket-Type compatibility check

After handshake, `PeerMetadata()["Socket-Type"]` is compared against
the allowed peer types for the local socket type:

| Local | Allowed peer Socket-Types |
|-------|--------------------------|
| REQ | `"REP"`, `"ROUTER"` |
| REP | `"REQ"`, `"DEALER"` |
| DEALER | `"REP"`, `"ROUTER"`, `"DEALER"` |
| ROUTER | `"REQ"`, `"DEALER"`, `"ROUTER"` |

On incompatibility: close the `*conn.Conn` (raw conn close causes the
peer to observe EOF). No ERROR command is sent — F4's `*Conn` does not
expose a mid-traffic ERROR sender, and the RFC permits closing without
one. **For Connect**: return `ErrIncompatiblePeer` to the caller
synchronously. **For Bind/Accept**: the error is silently dropped and
the connection is closed; no error propagates to Bind's caller (Bind
returns after the listener opens, not after each accept). A future F6
monitoring hook will surface these drops.

`TestIncompatiblePeerRejected` (§7.3) tests the Connect path only,
where the error is observable synchronously.

If the peer omits `Socket-Type` (empty string): accepted without
check. This is permissive — some ZeroMQ versions omit the property.
Open Q §9.4.

### 4.6 Identity assignment (ROUTER)

```go
func peerIdentity(meta wire.Metadata) []byte {
    if id, ok := meta["Identity"]; ok && len(id) > 0 {
        return []byte(id)
    }
    return randomIdentity() // 5 raw bytes from crypto/rand
}
```

`randomIdentity` reads 5 bytes from `crypto/rand.Read`. The identity
is stored as raw bytes (not hex-encoded), matching libzmq's convention.
ROUTER stores it in `pipe.identity` at pipe construction time; it is
stable for the pipe lifetime.

### 4.7 pipeAdded notification (`pipe.go`)

```go
// pipeSet gains a notification channel that senders wait on when no
// pipes are available.
type pipeSet struct {
    mu      sync.Mutex
    pipes   []*pipe
    robin   int
    // added is closed and recreated each time a pipe is added.
    // Senders select on it to wake from a "no pipe" wait.
    added   chan struct{}
}
```

When `pipeSet.add(p)` is called, it closes the current `added` channel
(waking any goroutines blocked on it) and creates a fresh replacement.
Senders that find no pipe do:

```go
for {
    p := ps.next()
    if p != nil {
        // send on p
        return
    }
    added := ps.currentAdded()  // read under mu
    select {
    case <-added:   // a pipe was added; retry
    case <-ctx.Done():
        return ctx.Err()
    case <-closeCh:
        return ErrClosed
    }
}
```

This replaces the `time.Ticker` polling described in the first draft.
No goroutine spins; the channel fires exactly once per `add`, with no
busy-wait between adds. The channel is recreated (not reset) so
previously waiting goroutines that observed `added` before it was
closed do not race.

## 5. State machines

### 5.1 REQ state machine

States: **idle** (initial) | **sent**

```
idle ──Send(msg)──────► sent
                          │
sent ──Recv()──────────► idle
sent ──activePipe dies─► idle  (Recv returns io.EOF or conn-layer error)
idle ──Recv()──────────► ErrState (returned immediately)
sent ──Send()──────────► ErrState (returned immediately)
```

The `pipe` used by Send is stored in `req.activePipe`. Recv reads
exclusively from `req.activePipe.inCh`. Both state and activePipe are
protected by `req.mu sync.Mutex`.

When the reader goroutine for `req.activePipe` exits (peer close or
network error), it closes `pipe.inCh`. Recv detects the closed channel
and returns the associated error (typically `io.EOF` or a conn-layer
error), then transitions back to idle and clears `activePipe`. The
application must reconnect and retry. Open Q §9.6.

**Envelope management in REQ:**
- `Send`: prepends one empty frame (`wire.Frame{Kind: FrameMessage, More: true, Body: nil}`) before the first payload frame.
- `Recv`: reads frames until the first empty delimiter, then collects
  remaining frames as the application payload. The empty delimiter is
  discarded.

### 5.2 REP state machine

States: **idle** (initial) | **recv**

```
idle ──Recv()────► recv  (stores envelope + pipe)
recv ──Send()────► idle  (sends envelope + payload)
recv ──Recv()────► ErrState
idle ──Send()────► ErrState
```

The routing envelope is `[]wire.Frame` — all frames from the start of
the multipart message up to and including the empty delimiter. The
payload is the frames after the delimiter.

`rep.envelope` and `rep.envPipe *pipe` are set on transition to
`recv` and cleared on transition back to `idle`. Protected by
`rep.mu`.

**Envelope reconstruction in REP:**
- `Recv` from any pipe; strip everything up to and including the first
  empty frame into `rep.envelope`; return remaining frames as `Message`.
- `Send`: prepend `rep.envelope` frames (all with `More=true`) before
  the reply frames; send on `rep.envPipe`.

### 5.3 DEALER state machine

No state machine. Send and Recv are independent; no sequencing
constraint.

**Send:** `ps.next()` → round-robin pipe; write all frames via
`pipe.conn.WriteFrame`. If no pipes are available, block using the
`pipeAdded` notification channel (§4.7) — no polling, no ticker.

**Recv:** `select` over all `pipe.inCh` plus `ctx.Done()` and
`closeCh`. Go runtime randomises which ready channel is chosen,
providing fair-queue behaviour. Because `all()` returns a snapshot,
new pipes added after the select starts are not included in that
particular Recv call — the next call picks them up. When the snapshot
is empty (zero pipes), only `ctx.Done()` and `closeCh` arms are
present in the select; this is valid Go — the select blocks until one
of those fires, which is the correct behaviour (no pipes = block until
cancelled or closed).

### 5.4 ROUTER state machine

No state machine. Send and Recv are independent.

**Recv:** same `select`-based fair-queue as DEALER. Before returning,
prepends a **fresh copy** of `pipe.identity` as `msg[0]`:
`append([]byte(nil), p.identity...)`. This satisfies the memory model
in `00b-memory-model.md`: every value returned across an upward layer
boundary is caller-owned. The copy is one allocation per received
message — negligible relative to network I/O.

**Send:** `ps.byIdentity(msg[0])` → if nil, return `ErrNoRoute`;
else write `msg[1:]` frames via `pipe.conn.WriteFrame`.

## 6. Error model

### 6.1 Sentinels (`errors.go`)

```go
var (
    ErrClosed            = errors.New("zmq4: socket closed")
    ErrState             = errors.New("zmq4: operation out of sequence")
    ErrNoRoute           = errors.New("zmq4: no route to peer")
    ErrIncompatiblePeer  = errors.New("zmq4: incompatible peer socket type")
    ErrSecurityMismatch  = errors.New("zmq4: security option not valid for this role")
    ErrNoIdentity        = errors.New("zmq4: ROUTER Send requires non-empty msg[0]")
)
```

All errors are wrapped via `fmt.Errorf("%w: ...", sentinel, ...)` with
context where useful (e.g., `ErrNoRoute` includes the unknown identity
hex). F6 users can `errors.Is`-discriminate.

### 6.2 Errors from lower layers

Errors from `conn.ReadFrame`, `conn.WriteFrame`, `conn.ClientHandshake`,
`conn.ServerHandshake`, `transport.Listen`, `transport.Dial` are
forwarded via `%w`. Relevant sentinels remain identifiable:

- `io.EOF` — clean peer close between messages. Reader goroutine treats
  this as pipe death (removes pipe from pipeSet).
- `conn.ErrHandshakeFail` — handshake failed; `Connect` returns it.
- `conn.ErrMechanismMismatch`, `conn.ErrRoleConflict` — forwarded.
- `transport.ErrSchemeUnknown` — forwarded from `Bind`/`Connect`.
- `context.Canceled`, `context.DeadlineExceeded` — forwarded from
  `Send`/`Recv` select and from `Connect`.

### 6.3 Scaffold removal

The existing `socket.go` scaffold (`NewSocket`, `Socket`, `Recv`,
`RecvMsg`, `Send`, `SendMsg`, `RecvFrame`, `SendFrame`,
`zeroCopyReader`) is deleted by F5a. Its existing tests
(`socket_test.go`) are deleted alongside it. The `Message` type in
`message.go` is kept.

The `zeroCopyReader` zero-copy path is not carried forward to F5a.
Socket-layer `Recv` allocates fresh message bodies (same as F1's
`FrameReader`). A zero-copy opt-in path may return in F6 if profiling
shows it matters.

## 7. Test plan

### 7.1 Unit — REQ/REP (`req_rep_test.go`)

Each test uses a `net.Pipe()`-backed `*conn.Conn` pair (NULL mechanism,
no real network) assembled via a test helper
`connPair(t, socketType1, socketType2 string) (*conn.Conn, *conn.Conn)`.
The helper constructs two `null.State` instances with the given
`Socket-Type` values injected into each side's handshake READY metadata,
runs `conn.ClientHandshake` / `conn.ServerHandshake` on a `net.Pipe()`
pair, and returns the resulting `*conn.Conn` values. This ensures the
socket-type compatibility check (§4.5) sees the correct metadata without
requiring a real transport.

- **TestREQREPRoundTrip** — single Send/Recv cycle; assert payload
  round-trips exactly.
- **TestREQREPMultiRoundTrips** — N=10 sequential round-trips on one
  pair; assert payloads in order.
- **TestREQREPMultipartPayload** — 3-part message; assert all parts
  round-trip; assert caller never sees the empty delimiter.
- **TestREQDoubleState** — REQ Send twice → second Send returns
  `errors.Is(err, ErrState)`. REQ Recv before Send → `ErrState`.
- **TestREPDoubleState** — REP Send before Recv → `ErrState`. REP Recv
  twice → `ErrState`.
- **TestREQRecvAfterPeerClose** — REP closes connection after REQ
  sends; REQ Recv returns `io.EOF` or `conn`-layer error.
- **TestREQCtxCancelSend** — no pipes connected; ctx canceled before
  any pipe appears; Send returns `context.Canceled`.
- **TestREQCtxCancelRecv** — REQ sent, peer stalls; ctx canceled; Recv
  returns `context.Canceled`.
- **TestREPFairQueue** — N=3 REQ peers; REP Recv round-robins across
  all three (assert all three are served within N×3 calls).
- **TestREPNoDelimiterFromDEALER** — DEALER sends a 2-frame message
  without an empty delimiter; REP Recv must treat all frames as payload
  (empty envelope); REP Send returns the reply to DEALER; DEALER Recv
  sees the reply without modification. Pins the §5.2 edge case for
  direct DEALER↔REP connections per OQ§9.7 (resolved: permissive, no
  delimiter = empty envelope).

### 7.2 Unit — DEALER/ROUTER (`dealer_router_test.go`)

- **TestDEALERROUTERRoundTrip** — DEALER sends msg; ROUTER Recv sees
  identity+msg; ROUTER sends reply to identity; DEALER Recv sees reply.
- **TestROUTERIdentityInMsg** — assert `msg[0]` matches the identity
  sent in the peer's handshake metadata.
- **TestROUTERAutoIdentity** — peer sends no Identity metadata; ROUTER
  assigns a 5-byte random identity; assert it is stable across multiple
  Recv calls from the same pipe.
- **TestROUTERNoRoute** — ROUTER Send with unknown identity → `ErrNoRoute`.
- **TestROUTERNoIdentityFrame** — ROUTER Send with `len(msg) == 0` →
  `ErrNoIdentity`.
- **TestDEALERRoundRobin** — DEALER with N=3 ROUTER peers; N×3 Sends;
  assert each peer received exactly N messages.
- **TestDEALERFairQueue** — N=3 ROUTER peers each send one message;
  DEALER Recv collects all 3; assert each is returned exactly once.
- **TestDEALERCtxCancel** — no pipes; ctx canceled; Send returns
  `context.Canceled`.
- **TestROUTERCtxCancel** — no messages arriving; ctx canceled; Recv
  returns `context.Canceled`.

### 7.3 Unit — lifecycle (`lifecycle_test.go`)

- **TestCloseUnblocksSend** — goroutine blocked in Send; Close called;
  Send returns `ErrClosed` within 100 ms.
- **TestCloseUnblocksRecv** — goroutine blocked in Recv; Close called;
  Recv returns `ErrClosed` within 100 ms.
- **TestCloseIdempotent** — Close called twice; second returns nil.
- **TestBindAcceptsMultiplePeers** — REP Bind; N=5 REQ peers connect;
  all 5 successfully exchange one round-trip.
- **TestIncompatiblePeerRejected** — REQ tries to connect to a raw
  socket that sends `Socket-Type = "PUB"` in READY; `Connect` (or the
  first subsequent `Send`) returns `ErrIncompatiblePeer`.

### 7.4 Integration — transport combinations (`integration_test.go`, build tag `integration`)

Table-driven. One row per `(socket-type pair × transport × security
mechanism)`.

- Socket-type pairs: `REQ/REP`, `DEALER/ROUTER`.
- Transports: `tcp`, `ipc`, `inproc`.
- Mechanisms: `NULL`, `PLAIN`, `CURVE`.
- Directions: Bind first / Connect second (the only ordering tested
  here; libzmq tests both).
- Scenario: one Send/Recv round-trip.

3 transports × 3 mechanisms × 2 socket-type pairs = **18 integration
tests**.

Run via: `go test -tags integration ./...`

### 7.5 Interop tests against `libzmq` (`socket/interop`, build tag `interop`)

Per `00-meta-overview.md` §6. `libzmq` 4.3.5 container (same Dockerfile
as F4 interop, extended with Python `pyzmq`).

- **Directions:** `our Bind ↔ libzmq Connect`, `libzmq Bind ↔ our
  Connect`.
- **Socket-type pairs:** `REQ/REP`, `DEALER/ROUTER`.
- **Mechanisms:** `NULL`, `PLAIN`, `CURVE`.
- **Transports:** `tcp`, `ipc`. (Not `inproc` — libzmq runs
  out-of-process.)
- **Scenarios:** single-frame round-trip, multipart (3-frame) round-trip.

2 directions × 2 pairs × 3 mechanisms × 2 transports × 2 scenarios =
**48 happy-path interop tests**.

Negative interop (reusing F4's bridge with adapted socket types):
- `mechanism-mismatch`: our NULL ↔ libzmq PLAIN → both sides abort.
- `incompatible-socket-type`: our REQ ↔ libzmq PUB → connection
  rejected or ignored on both sides.

**2 negative tests.** Total: **50 interop tests.**

CI cadence: nightly + on demand. Not gating every push.

### 7.6 Race detector

`go test -race ./...` is mandatory and gating. Multi-goroutine tests
(`TestBindAcceptsMultiplePeers`, `TestDEALERRoundRobin`,
`TestDEALERFairQueue`, `TestREPFairQueue`) are the primary race targets.

### 7.7 Done criteria

- All §7.1–§7.3 unit tests pass on `linux/amd64` and `darwin/arm64`.
- §7.4 integration tests (18) green.
- `go test -race ./...` clean.
- §7.5 interop suite (50 tests) green in nightly CI; manual run before
  tagging.
- `go vet ./...` clean.
- `staticcheck ./...` clean.
- `modernize -fix ./...` produces no diff (run before phase tag, per
  memory `feedback_modernize_after_phase`).
- Spec §1–§7 fully implemented; §9 open questions remain open or are
  explicitly closed.
- Scaffold `socket.go` and `socket_test.go` deleted.
- `00-meta-overview.md` updated: F5a status flipped to complete, phase
  tag `phase-5a-reqrep-complete` added.

## 8. File structure

### Files created

| Path | Responsibility |
|------|----------------|
| `errors.go` | Sentinels: `ErrClosed`, `ErrState`, `ErrNoRoute`, `ErrIncompatiblePeer`, `ErrSecurityMismatch`, `ErrNoIdentity`. |
| `options.go` | `Option`, `socketConfig` (`clientMechFactory`, `serverMechFactory`, `identity`, `handshakeTimeout`), `WithNULL`, `WithPLAIN`, `WithPLAINServer`, `WithCURVE`, `WithCURVEServer`, `WithIdentity`, `WithHandshakeTimeout`. |
| `pipe.go` | `pipe`, `pipeSet` (with `added chan struct{}` for send-wait notification), reader goroutine, `randomIdentity`. |
| `base.go` | `socketBase`, `bind`, `connect`, `close`, socket-type compatibility check. |
| `req.go` | `REQ` struct + `NewREQ`, `Bind`, `Connect`, `Send`, `Recv`, `Close`. |
| `rep.go` | `REP` struct + `NewREP`, `Bind`, `Connect`, `Send`, `Recv`, `Close`. |
| `dealer.go` | `DEALER` struct + `NewDEALER`, `Bind`, `Connect`, `Send`, `Recv`, `Close`. |
| `router.go` | `ROUTER` struct + `NewROUTER`, `Bind`, `Connect`, `Send`, `Recv`, `Close`. |
| `req_rep_test.go` | §7.1 unit tests. |
| `dealer_router_test.go` | §7.2 unit tests. |
| `lifecycle_test.go` | §7.3 lifecycle tests. |
| `integration_test.go` | §7.4 integration tests (build tag `integration`). |
| `interop/interop_test.go` | §7.5 interop tests (build tag `interop`). Placed under `interop/` (not `socket/interop/` — root package owns the interop suite). |

### Files deleted

| Path | Reason |
|------|--------|
| `socket.go` | Scaffold replaced by F5a real implementation. |
| `socket_test.go` | Tests for the deleted scaffold. |

### Files modified

| Path | Change |
|------|--------|
| `doc.go` | Update package-level godoc to describe the real API (socket types, options, memory contract). |
| `docs/specs/00-meta-overview.md` | Update F5a status to "implementation pending"; add file-structure note. |

## 9. Open questions

1. **HWM (high-water mark).** `pipe.inCh` is buffered at 64 in F5a.
   The correct per-pipe queue size is socket-policy (F5/F6). A
   `WithInboundHWM(n int) Option` could be added in F5a already, but
   the non-blocking / blocking behaviour on overflow (drop vs block vs
   error) requires a design decision best deferred to F6 when the full
   HWM surface is clear.

2. **Auto-reconnect.** When a pipe's reader goroutine exits due to a
   peer close or network error, F5a simply removes the pipe. ZeroMQ
   sockets reconnect automatically (with exponential backoff) when a
   `Connect`ed endpoint drops. This is out of scope for F5a and requires
   a reconnect-manager design in F5 or F6.

3. **ROUTER identity map performance.** `pipeSet.byIdentity` is O(n)
   linear scan. For sockets with many peers (broker patterns), a
   `map[string]*pipe` protected by a `sync.RWMutex` would be O(1). Add
   the map if benchmarks (post-F5a) show it matters.

4. **Missing Socket-Type from peer.** F5a accepts peers that omit
   `Socket-Type`. RFC 23 §2.4 says the property SHOULD be present but
   does not MUST. This is permissive; if it causes problems in
   production (e.g., misbehaving peers accepted silently), tighten to
   `ErrIncompatiblePeer` in F5b.

5. **DEALER send-wait on empty pipeSet.** ~~Polling approach.~~
   **Resolved:** `pipeAdded chan struct{}` in `pipeSet` (§4.7). No
   polling; senders block on the channel and wake on each `add`. Closed.

6. **REQ re-send after pipe failure.** If the pipe used by REQ's Send
   drops before Recv, REQ is stuck in "sent" state with no valid pipe.
   RFC 28 does not mandate re-send. F5a: when the reader goroutine for
   `req.activePipe` exits, `pipe.inCh` is closed. Recv detects the
   close and returns `io.EOF` (or the conn-layer error), then
   transitions back to idle. The application must reconnect and retry.
   State machine diagram in §5.1 reflects this. Open (documented, no
   auto-reconnect in F5a).

7. **Envelope delimiter position (DEALER→REP).** **Resolved:** REP Recv
   must handle missing delimiter — treat all frames as payload, empty
   envelope. Pinned by `TestREPNoDelimiterFromDEALER` in §7.1. Closed.

8. **ROUTER→ROUTER patterns.** RFC 28 permits ROUTER↔ROUTER connections
   (for broker-to-broker). F5a supports this as a side-effect of the
   compatibility table, but no tests cover ROUTER↔ROUTER directly. Add
   a `TestROUTERROUTERRoundTrip` if interop reveals issues.

9. **Scaffold compat.** The `NewSocket` function in the deleted scaffold
   has no external users (this is a new project). If any internal test
   file imports it, update those tests during scaffold removal.

10. **Skeleton ordering deviation.** Following F4's precedent (§9.10 of
    the F4 spec), this spec places the error model before state machines.
    Intentional; consistent with sibling specs.

## 10. References

- [RFC 28/REQREP — Request-Reply Pattern](https://rfc.zeromq.org/spec/28/)
- [RFC 23/ZMTP — ZeroMQ Message Transport Protocol 3.1](https://rfc.zeromq.org/spec/23/) §2.4 (metadata), §5 (traffic frames).
- Project specs:
  - `00-meta-overview.md` §3 (layering), §4 (phase pipeline), §6 (testing strategy).
  - `00b-memory-model.md` (boundary ownership).
  - `01-zmtp-wire-protocol.md` §Frames, §Commands, §7 (buffer ownership).
  - `02a-security-null.md`, `02b-security-plain.md`, `02c-security-curve.md` (mechanism interfaces).
  - `03-transports.md` §4 (Listen/Dial), §5.4 (inproc scope).
  - `04-connection-layer.md` §3 (Conn API), §4.2 (PeerMetadata defensive clone), §5 (error model).
- libzmq man pages: [`zmq_socket(3)`](http://api.zeromq.org/4-3:zmq-socket) (REQ, REP, DEALER, ROUTER), [`zmq_connect(3)`](http://api.zeromq.org/4-3:zmq-connect), [`zmq_bind(3)`](http://api.zeromq.org/4-3:zmq-bind).
- Go stdlib: `context.Context`, `crypto/rand`, `net.Pipe`, `sync.Mutex`.
