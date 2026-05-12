# F7a — API Stabilization

**Date:** 2026-05-12
**Author:** Tomasz Rup
**Status:** draft (rev 4 — post spec-review fixes)

---

## 1. Goal

Make three targeted, breaking API improvements before tagging v1.0:

1. `Subscribe`/`Unsubscribe` accept `string` instead of `[]byte`.
2. Add `NewMsg` / `NewStringMsg` constructor helpers for `Message`.
3. Add `Frames()`, `Frame(i int)`, and `String()` convenience methods on `Message`.

No socket-interface changes, no new error types, no changes to `Option`, `Poller`,
`OverflowPolicy`, or event types.

---

## 2. Changes

### 2.1 `Subscribe` / `Unsubscribe` — `string` parameter

**Affected files:** `sub.go`, `xsub.go`, `cmd/main.go` (call-site update)

**Before:**
```go
func (s *SUB)  Subscribe(topic []byte) error
func (s *SUB)  Unsubscribe(topic []byte) error
func (s *XSUB) Subscribe(topic []byte) error
func (s *XSUB) Unsubscribe(topic []byte) error
```

**After:**
```go
func (s *SUB)  Subscribe(topic string) error
func (s *SUB)  Unsubscribe(topic string) error
func (s *XSUB) Subscribe(topic string) error
func (s *XSUB) Unsubscribe(topic string) error
```

**Rationale:** Topics in practice are always human-readable strings (e.g. `"orders"`,
`"prices.EUR"`). Requiring `[]byte` forces callers to write
`sub.Subscribe([]byte("orders"))` for the overwhelmingly common case.

**Implementation note:** Each implementation converts with `[]byte(topic)` before
passing to the internal wire layer — no semantic change.

**Empty topic (`""`)** continues to subscribe to all messages, matching existing
behaviour. The previous API's `nil` (valid `[]byte`, used as subscribe-all in some
call sites) has no `string` equivalent — all `nil` call sites must be migrated to
`""`. Affected call sites: `pub_sub_test.go` (1×), `interop/interop_test.go` (2×),
`cmd/main.go` (1×, uses `[]byte("")` which migrates to `""`).

**Godoc update:** The following comments must be updated to replace references to
`nil` and `[]byte` with `""` and `string`:
- Type-level comment on `SUB` (`sub.go`) — `Subscribe(nil) = subscribe-all` → `Subscribe("") = subscribe-all`
- Method comment on `SUB.Subscribe` — `topic == nil or []byte{} subscribes to all messages` → `topic == "" subscribes to all messages`
- Method comments on `SUB.Unsubscribe`, `XSUB.Subscribe`, `XSUB.Unsubscribe`

---

### 2.2 `Message` constructor helpers

**Affected file:** `message.go`

```go
// NewMsg returns a Message composed of the given frames.
// NewMsg() with no arguments returns an empty Message.
func NewMsg(frames ...[]byte) Message { return Message(frames) }

// NewStringMsg returns a Message whose frames are the UTF-8 encodings of
// the given strings.
func NewStringMsg(frames ...string) Message {
    msg := make(Message, len(frames))
    for i, s := range frames {
        msg[i] = []byte(s)
    }
    return msg
}
```

**Rationale:** The current `Message{[]byte("hello")}` literal is verbose in the
common single-frame case. Helpers allow `zmq4.NewMsg(data)` and
`zmq4.NewStringMsg("hello")`.

**Backward compatibility:** `Message{[]byte("x")}` and `Message(frames)` continue
to work — `Message` remains `[][]byte`.

---

### 2.3 `Message` convenience methods

**Affected file:** `message.go`

```go
// Frames returns the number of frames in the message.
func (m Message) Frames() int { return len(m) }

// Frame returns the i-th frame. Panics if i is out of range, matching the
// behaviour of a plain slice index expression.
func (m Message) Frame(i int) []byte { return m[i] }

// String returns the first frame decoded as a UTF-8 string.
// Returns "" for an empty message.
func (m Message) String() string {
    if len(m) == 0 {
        return ""
    }
    return string(m[0])
}
```

**Rationale:**
- `Frames()` is a named alias for `len(msg)` — useful when passing a `Message` to
  a function that only sees the `Message` type and not the underlying slice.
- `Frame(i)` mirrors the slice-index panic semantics intentionally; callers that
  need bounds checking can use `if i < msg.Frames()`.
- `String()` covers the dominant single-frame text use case without requiring a
  type assertion or a cast at the call site. For multi-frame messages, only frame 0
  is returned — this is a documented, deliberate simplification.

---

## 3. Files

| File | Action |
|---|---|
| `sub.go` | Change `Subscribe([]byte)` and `Unsubscribe([]byte)` to `string`; update godoc |
| `xsub.go` | Change `Subscribe([]byte)` and `Unsubscribe([]byte)` to `string`; update godoc |
| `message.go` | Add `NewMsg`, `NewStringMsg`, `Frames`, `Frame`, `String` |
| `cmd/main.go` | Migrate `Subscribe([]byte(""))` → `Subscribe("")` (1 call site) |
| `pub_sub_test.go` | Migrate all `Subscribe`/`Unsubscribe` call sites (nil + []byte(...) wraps) |
| `xpub_xsub_test.go` | Migrate all `Subscribe`/`Unsubscribe` call sites (5 call sites) |
| `integration_test.go` | Migrate all `Subscribe` call sites (3 call sites) |
| `lifecycle_test.go` | Migrate `Subscribe([]byte("x"))` → `Subscribe("x")` (1 call site) |
| `interop/interop_test.go` | Migrate `Subscribe(nil)` (2×) → `Subscribe("")` |

---

## 4. Breaking changes

| Symbol | Old signature | New signature |
|---|---|---|
| `SUB.Subscribe` | `([]byte) error` | `(string) error` |
| `SUB.Unsubscribe` | `([]byte) error` | `(string) error` |
| `XSUB.Subscribe` | `([]byte) error` | `(string) error` |
| `XSUB.Unsubscribe` | `([]byte) error` | `(string) error` |

All other exported symbols are additive (new functions/methods) — no breakage.

---

## 5. Test plan

### Unit tests (add to existing `message_test.go`, `package zmq4`)

- `NewMsg()` → empty `Message`
- `NewMsg([]byte("a"), []byte("b"))` → two-frame message, correct content
- `NewStringMsg("x", "y")` → frames equal `[]byte("x")`, `[]byte("y")`
- `Message{}.Frames()` → 0
- `Message{[]byte("a"), []byte("b")}.Frames()` → 2
- `Message{[]byte("hello")}.Frame(0)` → `[]byte("hello")`
- `Message{[]byte("hello")}.Frame(1)` → panics (tested with `recover`)
- `Message{[]byte("hello")}.Frame(-1)` → panics (tested with `recover`)
- `Message{}.String()` → `""`
- `Message{[]byte("hi")}.String()` → `"hi"`
- `Message{[]byte("a"), []byte("b")}.String()` → `"a"` (only frame 0)

### Call-site migration

- Migrate all `Subscribe(nil)` / `Unsubscribe(nil)` → `Subscribe("")` / `Unsubscribe("")`
  in `pub_sub_test.go` and `interop/interop_test.go`.
- Migrate `Subscribe([]byte(""))` → `Subscribe("")` in `cmd/main.go`.
- Any remaining `Subscribe([]byte(...))` call sites → remove the `[]byte(...)` cast.

### Integration tests (existing suite)

- Run full suite (`go test -race -count=1 ./...`) — all pass.
