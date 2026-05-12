# F6d — Polling design

**Date:** 2026-05-12  
**Author:** Tomasz Rup  
**Status:** draft (rev 3 — post spec-review fixes)

---

## 1. Goal

Add a `Poller` object to the `zmq4` package — the Go-idiomatic equivalent of
`zmq_poll`. Users register sockets with an event mask (POLLIN / POLLOUT), then
call `Poll(timeout)` to block until one or more sockets are ready.

---

## 2. Constraints

- Poller object style (not channel-select helpers, not bare zmq_poll function).
- Events: `POLLIN` and `POLLOUT` only. `POLLERR` omitted — errors surface
  through Go's `error` return values.
- Only `zmq4` sockets; no `net.Conn` / raw file-descriptor support.
- Not thread-safe — one goroutine owns a Poller. Consistent with libzmq's
  own "sockets are not thread-safe" rule.
- PUB/XPUB POLLOUT is not supported in F6d. PUB/XPUB use an internal
  `pubPipeSet` (not `socketBase.pipes`) for outbound messages; polling that
  set requires separate work. POLLIN on PUB always returns no events
  (correct — PUB is send-only).
- POLLOUT behaviour is undefined for sockets with `sndHWM == 0` (unbuffered
  `outCh`, `cap == 0`). The Phase 1 check `len(outCh) < cap(outCh)` reduces
  to `0 < 0 = false`; Phase 2 wait on `outReady` blocks indefinitely. Users
  must not register POLLOUT on zero-HWM sockets. This is documented but not
  enforced at runtime.

---

## 3. Public API

```go
// Events is a bitmask of polling events.
type Events uint32

const (
    POLLIN  Events = 1 // socket has at least one message ready to receive
    POLLOUT Events = 2 // socket can accept at least one outbound message
)

// Event is returned by Poll for each socket that matched its registered mask.
type Event struct {
    Socket any    // the value passed to Poller.Add
    Events Events // subset of the registered mask that fired
}

// Poller groups sockets and blocks until one or more become ready.
// Not thread-safe.
type Poller struct{ items []pollEntry }

// NewPoller returns an empty Poller.
func NewPoller() *Poller

// Add registers s with event mask e.
// Returns ErrNotSocket if s is not a zmq4 socket type.
// Returns ErrAlreadyRegistered if s was already added.
// Returns ErrInvalidEvents if e is zero.
func (p *Poller) Add(s any, e Events) error

// Update replaces the event mask for an already-registered socket.
// Returns ErrNotRegistered if s was never added.
// Returns ErrInvalidEvents if e is zero.
func (p *Poller) Update(s any, e Events) error

// Remove unregisters s.
// Returns ErrNotRegistered if s was never added.
func (p *Poller) Remove(s any) error

// Poll blocks until at least one registered socket satisfies its event mask,
// then returns all sockets that are ready at that moment.
//
//   timeout < 0  → block indefinitely (no timeout case in the internal select)
//   timeout = 0  → non-blocking snapshot (Phase 1 only)
//   timeout > 0  → block up to timeout; returns (nil, nil) when expired
//
// Returns (nil, ErrClosed) when any registered socket is closed during the call.
// Returns (nil, nil) immediately when no sockets are registered.
func (p *Poller) Poll(timeout time.Duration) ([]Event, error)
```

Sentinel errors added to `errors.go` (note: `ErrClosed` already exists there
and must NOT be re-declared):

```go
var (
    ErrNotSocket         = errors.New("zmq4: value is not a zmq4 socket")
    ErrAlreadyRegistered = errors.New("zmq4: socket already registered with poller")
    ErrNotRegistered     = errors.New("zmq4: socket not registered with poller")
    ErrInvalidEvents     = errors.New("zmq4: event mask must not be zero")
)
```

---

## 4. Internal changes

### 4.1 `pipe` — `inReady` and `outReady` channels

```go
type pipe struct {
    // ... existing fields unchanged ...
    inReady  chan struct{} // capacity 1; poked by readLoop after each inCh enqueue
    outReady chan struct{} // capacity 1; poked by writeLoop after each outCh drain
}
```

`newPipe` initialises both: `inReady: make(chan struct{}, 1)`,
`outReady: make(chan struct{}, 1)`.

`readLoop` pokes `inReady` non-blocking after each `inCh <- msg`:

```go
case p.inCh <- msg:
    select {
    case p.inReady <- struct{}{}:
    default:
    }
```

`writeLoop` pokes `outReady` non-blocking after each successful write:

```go
case msg := <-p.outCh:
    if err := sendFrames(p.conn, msg); err != nil {
        p.conn.Close()
        return
    }
    select {
    case p.outReady <- struct{}{}:
    default:
    }
```

Neither `inReady` nor `outReady` is explicitly closed on pipe exit. Stale
signals from dead pipes cause Phase 1 to re-run (which excludes dead pipes via
`pipeSet.all()`), then Phase 2 is rebuilt without the dead pipe's channels.

### 4.2 Socket access — `asPollBase` type switch

Concrete socket types embed `socketBase` as a **named field** (`base socketBase`),
so `*socketBase` methods are NOT promoted to the outer type. `poller.go` uses a
package-level helper to access the base without touching any concrete socket file:

```go
func asPollBase(s any) (*socketBase, bool) {
    switch v := s.(type) {
    case *REQ:    return &v.base, true
    case *REP:    return &v.base, true
    case *DEALER: return &v.base, true
    case *ROUTER: return &v.base, true
    case *PUB:    return &v.base, true
    case *SUB:    return &v.base, true
    case *XPUB:   return &v.base, true
    case *XSUB:   return &v.base, true
    case *PUSH:   return &v.base, true
    case *PULL:   return &v.base, true
    case *PAIR:   return &v.base, true
    default:      return nil, false
    }
}
```

`Poller.Add` returns `ErrNotSocket` when `asPollBase` returns `false`.

---

## 5. `Poll()` mechanics — two-phase algorithm

`Poll` runs Phase 1, then Phase 2 in a loop. Phase 2 is never entered when
`timeout == 0`.

### Pre-check — zero registered sockets

If `len(p.items) == 0`, return `(nil, nil)` immediately before either phase.
This avoids a degenerate `reflect.Select` with only a timeout case.

### Phase 1 — non-blocking snapshot

```
for each registered entry:
    sb := asPollBase(entry.socket)
    pipes := sb.pipes.all()        // live snapshot only
    var got Events
    if entry.events & POLLIN != 0:
        for each pipe in pipes:
            if len(pipe.inCh) > 0: got |= POLLIN; break
    if entry.events & POLLOUT != 0:
        for each pipe in pipes:
            if len(pipe.outCh) < cap(pipe.outCh): got |= POLLOUT; break
    if got != 0: append Event{entry.socket, got} to ready
return ready if len(ready) > 0
```

Phase 1 always uses `pipeSet.all()` which returns only live pipes (dead pipes
are removed by `readLoop` on exit). There is no stale-pipe false-positive.

### Phase 2 — blocking `reflect.Select` loop

Entered when Phase 1 found nothing and `timeout != 0`. Implemented as a loop:

```
deadline := time.Now().Add(timeout)  // only when timeout > 0
loop:
    build cases:
        case 0: time.After(remaining); nil if timeout < 0
        for each POLLIN entry:
            pipes := sb.pipes.all()
            if len(pipes) == 0:
                add pipeSet.currentAdded() case (tagged: wakeup-rebuild)
            else:
                for each pipe: add pipe.inReady case (tagged: wakeup-phase1)
        for each POLLOUT entry:
            pipes := sb.pipes.all()
            if len(pipes) == 0:
                add pipeSet.currentAdded() case (tagged: wakeup-rebuild)
            else:
                for each pipe: add pipe.outReady case (tagged: wakeup-phase1)
        for each registered entry:
            add sb.closeCh case (one case per entry, tagged: close)

    chosen, _ = reflect.Select(cases)

    switch tag of chosen:
        timeout:         return (nil, nil)
        close:           return (nil, ErrClosed)
        wakeup-rebuild:  goto loop   // new pipe arrived; rebuild cases
        wakeup-phase1:   run Phase 1
                         if len(ready) > 0: return ready
                         else: goto loop   // stale signal (dead pipe); rebuild and retry
```

**`currentAdded()` rationale:** `pipeSet.currentAdded()` returns a channel that
is closed (and replaced) every time a new pipe is added. Selecting on it
unblocks when a new peer connects — at which point Phase 2 rebuilds its case
list to include the new pipe's `inReady`/`outReady`. This applies to **any**
socket (POLLIN or POLLOUT) with zero current pipes — both need to wake up when
a peer arrives. This mirrors the pattern already used in `socketBase.recvAny`.

**`closeCh` count:** one `reflect.SelectCase` per registered socket entry, each
using that socket's own `sb.closeCh`. If any one socket closes, `ErrClosed` is
returned immediately.

**`timeout < 0`:** the timeout case slot is set to a nil channel
(`reflect.SelectCase` with a nil `Chan` value), which blocks forever in
`reflect.Select`. The `(nil, nil)` timeout return is therefore unreachable when
`timeout < 0`.

**After wakeup-phase1, Phase 1 returns nothing:** this happens when the signal
was from a dead pipe (`inReady`/`outReady` had a buffered struct{} from before
the pipe died). Phase 1 uses the live `pipeSet.all()` snapshot, finds nothing,
and Phase 2 rebuilds its cases (now excluding the dead pipe). No infinite spin:
each stale signal is consumed exactly once, and the dead pipe is gone from the
next `pipeSet.all()` snapshot.

---

## 6. Files

| File | Action |
|---|---|
| `poller.go` | New — `Events`, `POLLIN`, `POLLOUT`, `Event`, `Poller`, `NewPoller`, `Add`, `Update`, `Remove`, `Poll`, `asPollBase` |
| `pipe.go` | Add `inReady`, `outReady` fields; update `newPipe`; poke in `readLoop` and `writeLoop` |
| `errors.go` | Add 4 new sentinel errors (`ErrNotSocket`, `ErrAlreadyRegistered`, `ErrNotRegistered`, `ErrInvalidEvents`) |
| `poller_test.go` | New — unit + integration tests |

`base.go` — no changes.  
Concrete socket files — no changes.

---

## 7. Test plan

### Unit tests (`poller_test.go`)

- `Add` / `Remove` / `Update` round-trips; all error paths (`ErrNotSocket`,
  `ErrAlreadyRegistered`, `ErrNotRegistered`, `ErrInvalidEvents`).
- `Poll(0)` on socket with no peers → `(nil, nil)`.
- POLLIN non-blocking: pre-load `inCh` on a pipe, `Poll(0)` → POLLIN event.
- POLLOUT non-blocking: `outCh` not full, `Poll(0)` → POLLOUT event.
- POLLOUT non-blocking: `outCh` at full capacity, `Poll(0)` → no event.
- POLLOUT on socket with no peers, `Poll(0)` → `(nil, nil)` (empty pipe list,
  no POLLOUT check fires).

### Integration tests (inproc)

- PUSH→PULL: Poll on PULL with POLLIN; PUSH sends; Poll unblocks → POLLIN event.
- Multiple sockets ready simultaneously → all in one Poll result.
- Timeout: `Poll(50ms)` with no activity → `(nil, nil)` after ~50ms.
- Blocking indefinitely: `timeout < 0` + goroutine sends after 10ms → Poll returns.
- Poll on closed socket → `ErrClosed`.
- POLLOUT at HWM (Block policy): fill outCh, Poll POLLOUT blocks, consumer
  drains → Poll unblocks and returns POLLOUT event.
- Mixed POLLIN+POLLOUT mask on same socket → both bits set in `Event.Events`.
- POLLIN on socket with no peers: Poll blocks, peer connects and sends →
  Poll returns POLLIN event (exercises `currentAdded()` path).
