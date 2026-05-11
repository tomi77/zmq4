# 06c — Socket monitoring events (Phase F6c)

> **Status:** design approved, implementation pending.
> **Author:** Tomasz Rup
> **Date:** 2026-05-11
> **Layer:** L5 — `zmq4` (root package)
> **Depends on:** F1–F5c (all prior phases), F6a (HWM / socketBase shape),
> F6b (ZAP / socketConfig pattern).
> **Consumed by:** application code (public API surface).

## 1. Summary

F6c adds a channel-based socket monitoring API that lets callers observe
connection lifecycle events: when a listener opens, when connections are
accepted or established, when handshakes succeed or fail, and when connections
or the socket itself are closed.

The API follows the same Option-function pattern as HWM and ZAP: a single
`WithMonitor(ch chan<- SocketEvent)` option wires a caller-owned channel into
`socketConfig`. The `socketBase` emits events on that channel at the relevant
lifecycle points; events are dropped (non-blocking) when the channel is full.
When the socket closes, the channel receives `EventMonitorStopped` and is then
closed by the socket, enabling `for ev := range ch` consumer loops.

What F6c explicitly does **not** do:

- **No `ConnectDelayed` / `ConnectRetried`.** Auto-reconnect is not implemented;
  these events require a retry loop that does not exist yet. Deferred to F6d or later.
- **No fan-out.** A single monitor channel per socket; caller builds fan-out if needed.
- **No ZMQ-wire monitor socket.** The API is Go-native; no `inproc://` PAIR socket.
- **No file descriptor events.** Not applicable in pure Go.
- **No per-event filtering.** All events are delivered; caller discards unwanted ones.

## 2. Mapping to specifications

There is no RFC governing socket monitoring. The event set is modelled on
`zmq_socket_monitor(3)` from libzmq 4.3, restricted to the subset reachable
from the current architecture (set B from the design discussion; set C deferred):

| libzmq event constant | F6c `EventType` | Notes |
|-----------------------|-----------------|-------|
| `ZMQ_EVENT_LISTENING` | `EventListening` | |
| `ZMQ_EVENT_BIND_FAILED` | `EventBindFailed` | |
| `ZMQ_EVENT_ACCEPTED` | `EventAccepted` | Raw TCP accept, before handshake. |
| `ZMQ_EVENT_ACCEPT_FAILED` | `EventAcceptFailed` | |
| `ZMQ_EVENT_CONNECTED` | `EventConnected` | After `transport.Dial`, before handshake. |
| `ZMQ_EVENT_CONNECT_FAILED` | `EventConnectFailed` | Dial error only. |
| `ZMQ_EVENT_HANDSHAKE_SUCCEEDED` | `EventHandshakeSucceeded` | Both client and server sides. |
| `ZMQ_EVENT_HANDSHAKE_FAILED_*` | `EventHandshakeFailed` | Collapsed into one type + `Err`. |
| `ZMQ_EVENT_DISCONNECTED` | `EventDisconnected` | Peer-initiated / unexpected drop. |
| `ZMQ_EVENT_CLOSED` | `EventClosed` | Per-pipe, during socket.Close(). |
| `ZMQ_EVENT_MONITOR_STOPPED` | `EventMonitorStopped` | Last event; channel closed after. |

## 3. Public interface

All public API lives in the root `zmq4` package.

### 3.1 `EventType` and `SocketEvent`

New file: `event.go`.

```go
// EventType identifies the kind of lifecycle event a socket emitted.
type EventType int

const (
    // EventListening is emitted when Bind() establishes a listener.
    EventListening EventType = iota + 1
    // EventBindFailed is emitted when Bind() fails to establish a listener.
    EventBindFailed
    // EventAccepted is emitted when a raw incoming connection is accepted,
    // before the ZMTP handshake starts.
    EventAccepted
    // EventAcceptFailed is emitted when the accept loop encounters an error.
    EventAcceptFailed
    // EventConnected is emitted after transport.Dial succeeds, before the
    // ZMTP handshake starts.
    EventConnected
    // EventConnectFailed is emitted when transport.Dial fails.
    EventConnectFailed
    // EventHandshakeSucceeded is emitted when a ZMTP handshake completes
    // successfully, on both the client and server side.
    EventHandshakeSucceeded
    // EventHandshakeFailed is emitted when a ZMTP handshake fails.
    // Err carries the underlying error.
    EventHandshakeFailed
    // EventDisconnected is emitted when a pipe is removed due to an unexpected
    // peer-initiated connection drop (I/O error while socket is still open).
    EventDisconnected
    // EventClosed is emitted once per pipe during socket.Close(), before
    // EventMonitorStopped.
    EventClosed
    // EventMonitorStopped is the final event. The socket closes the monitor
    // channel immediately after emitting it. Consumers using
    //   for ev := range ch { … }
    // will have their loop terminate naturally.
    EventMonitorStopped
)

// SocketEvent is a lifecycle event emitted by a socket to its monitor channel.
type SocketEvent struct {
    Type     EventType
    Endpoint string // transport address: "tcp://host:port" for Bind/Connect,
                    // "host:port" for accepted connections.
    Err      error  // non-nil for *Failed and EventHandshakeFailed events.
}
```

### 3.2 `WithMonitor` option

Added to `options.go`.

```go
// WithMonitor wires ch as the monitoring channel for this socket. The socket
// emits a SocketEvent for each lifecycle transition (connection accepted,
// handshake outcome, disconnect, etc.). When the socket closes, it emits
// EventMonitorStopped and then closes ch.
//
// The caller owns ch and must not close it. Events are dropped (without
// blocking) when ch is full; use a buffered channel sized to the expected
// burst to avoid drops. A nil ch is a no-op.
func WithMonitor(ch chan<- SocketEvent) Option {
    return func(cfg *socketConfig) { cfg.monitorCh = ch }
}
```

`socketConfig` gains one field:

```go
monitorCh chan<- SocketEvent // nil when monitoring is disabled
```

## 4. Internal implementation

### 4.1 `emit` helper (`base.go`)

```go
// emit sends ev to the monitor channel if one is configured.
// Non-blocking: events are dropped when the channel is full.
func (sb *socketBase) emit(ev SocketEvent) {
    if sb.cfg.monitorCh == nil {
        return
    }
    select {
    case sb.cfg.monitorCh <- ev:
    default:
    }
}
```

Zero overhead when `monitorCh == nil` (single nil-pointer check, inlineable).

### 4.2 Emission points (`base.go`)

| Call site | Condition | Event emitted | Endpoint value |
|-----------|-----------|---------------|----------------|
| `bind()` | listener opened | `EventListening` | argument `endpoint` |
| `bind()` | listener error | `EventBindFailed` + `Err` | argument `endpoint` |
| `acceptLoop()` | `ln.Accept()` error | `EventAcceptFailed` + `Err` | `ln.Addr().String()` |
| `doServerHandshake()` | before handshake | `EventAccepted` | `raw.RemoteAddr().String()` |
| `doServerHandshake()` | handshake OK | `EventHandshakeSucceeded` | `raw.RemoteAddr().String()` |
| `doServerHandshake()` | handshake error | `EventHandshakeFailed` + `Err` | `raw.RemoteAddr().String()` |
| `connect()` | dial OK | `EventConnected` | argument `endpoint` |
| `connect()` | dial error | `EventConnectFailed` + `Err` | argument `endpoint` |
| `connect()` | handshake OK | `EventHandshakeSucceeded` | argument `endpoint` |
| `connect()` | handshake error | `EventHandshakeFailed` + `Err` | argument `endpoint` |

### 4.3 Disconnect detection (`pipe.go`)

`pipe` gains an optional callback field:

```go
onDisconnect func(addr string) // called when pipe exits due to peer drop
```

Set in `addConn` (only when `monitorCh != nil`):

```go
if sb.cfg.monitorCh != nil {
    p.onDisconnect = func(addr string) {
        sb.emit(SocketEvent{Type: EventDisconnected, Endpoint: addr})
    }
}
```

`readLoop`'s deferred cleanup distinguishes peer-drop from socket-close by
checking whether `closeCh` is already closed at the time of exit:

```go
defer func() {
    ps.remove(p)
    if p.onDisconnect != nil {
        select {
        case <-closeCh:
            // socket is shutting down — EventClosed emitted by close()
        default:
            // unexpected peer drop
            p.onDisconnect(p.conn.RemoteAddr().String())
        }
    }
}()
```

### 4.4 Socket close sequence (`base.go — close()`)

After the existing shutdown logic (pipes closed, `wg.Wait()`), the following
runs inside the `closeOnce.Do` block:

```go
if sb.cfg.monitorCh != nil {
    for _, p := range sb.pipes.all() {
        sb.emit(SocketEvent{
            Type:     EventClosed,
            Endpoint: p.conn.RemoteAddr().String(),
        })
    }
    sb.emit(SocketEvent{Type: EventMonitorStopped})
    close(sb.cfg.monitorCh)
}
```

`EventClosed` is emitted once per pipe that was alive at shutdown time.
`EventMonitorStopped` is always the last event, emitted immediately before
the channel is closed.

## 5. Error model

- Monitoring errors (full channel) are silent drops. The monitor channel is
  best-effort; it must not affect socket correctness.
- `WithMonitor(nil)` is a no-op; `emit` is a no-op when `monitorCh == nil`.
- The channel is closed exactly once, inside `closeOnce.Do`, so there is no
  risk of double-close panics.
- Callers that close the channel themselves will panic on the next event send;
  this is a documented misuse (godoc of `WithMonitor` explicitly forbids it).

## 6. Test plan

### Unit tests (new file `event_test.go`)

| Test | What it verifies |
|------|-----------------|
| `TestWithMonitorStoresChannel` | `WithMonitor(ch)` sets `cfg.monitorCh == ch`. |
| `TestEmitNoopWhenNil` | `emit()` does not panic when `monitorCh == nil`. |
| `TestEmitDropsWhenFull` | `emit()` does not block when channel capacity is 0 (unbuffered / full). |
| `TestEmitDeliversWhenSpace` | `emit()` delivers the event when the channel has capacity. |

### Integration tests (new file `monitor_test.go`)

All tests use `inproc://` transport (no external deps, no port allocation).

| Test | Scenario | Expected event sequence |
|------|----------|------------------------|
| `TestMonitorBind` | `Bind()` on a fresh socket | `EventListening` |
| `TestMonitorBindFailed` | `Bind()` with invalid endpoint | `EventBindFailed` + `Err != nil` |
| `TestMonitorConnect` | server binds, client connects (NULL) | server: `EventListening`, `EventAccepted`, `EventHandshakeSucceeded`; client: `EventConnected`, `EventHandshakeSucceeded` |
| `TestMonitorHandshakeFailed` | PLAIN server + NULL client | server: `EventAccepted`, `EventHandshakeFailed` + `Err != nil` |
| `TestMonitorDisconnected` | client connects, then client socket closed | server sees `EventDisconnected` for that pipe |
| `TestMonitorClose` | socket with two connected peers then `Close()` | `EventClosed` ×2, `EventMonitorStopped`; channel closed (range terminates) |
| `TestMonitorDropsOnFull` | cap-1 channel, rapid bind+connect+close | no deadlock, no panic |

### Non-goals for testing

- No interop tests against libzmq — monitoring is API-level, not wire-level.
- No benchmark — emit is a non-blocking channel send with a nil-guard; no
  regression risk.

## 7. Open questions

None. All decisions resolved during design review (2026-05-11).
