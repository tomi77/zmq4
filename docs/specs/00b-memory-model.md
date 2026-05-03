# 00b — Memory Model

> **Status:** approved design, pre-implementation
> **Author:** Tomasz Rup
> **Date:** 2026-05-03

This document defines the memory ownership philosophy for `github.com/tomi77/zmq4`.
It applies to all layers (L1–L5) and must be read before implementing L3, L4, or L5.

---

## 1. The Two-Tier Contract

The library exposes two levels of API:

| Tier | Contract | Who it is for |
|------|----------|---------------|
| **Safe (default)** | All returned values are owned by the caller. Caller may retain, mutate, or free freely. | Most users |
| **Zero-copy (opt-in)** | Returned values alias internal buffers. Valid only until the next `*Frame` call on the same socket. | Performance-sensitive users |

The default tier requires no special care. The opt-in tier is accessed through
methods whose name ends in `Frame` and is documented explicitly at every call site.

---

## 2. Layer Ownership Contracts

```
┌──────────────────────────────────────────────────────────────┐
│ L1 wire          BORROWS                                      │
│   DecodeFrame, ParseCommand, ParseReady                       │
│   → returned types alias the caller's input buffer           │
│   → caller owns the buffer and its lifetime                   │
│   → Clone() is the explicit detachment mechanism             │
├──────────────────────────────────────────────────────────────┤
│ L2 security      OWNS (at ingress boundary)                   │
│   State.Receive() copies data out of the incoming Command     │
│   PeerMetadata() returns an owned slice                       │
│   → nothing from L1 escapes upward without a copy            │
├──────────────────────────────────────────────────────────────┤
│ L4 conn          OWNS (at egress boundary)                    │
│   May use aliased frames internally                           │
│   → passes only owned frames up to L5                        │
├──────────────────────────────────────────────────────────────┤
│ L5 socket        SAFE DEFAULT + OPT-IN ZERO-COPY             │
│   Recv()      → []byte        owned                          │
│   RecvMsg()   → Message       owned ([][]byte)               │
│   RecvFrame() → wire.Frame    borrowed, opt-in               │
└──────────────────────────────────────────────────────────────┘
```

Rule: **every upward layer boundary passes owned data**. Aliasing is an
internal implementation detail and must not leak upward except through
explicitly named opt-in methods.

---

## 3. Public Types

### `Message`

```go
// Message is an ordered sequence of message parts (frames).
// Each part is an owned byte slice; callers may retain and mutate freely.
type Message [][]byte
```

### `wire.Frame` (opt-in only)

`wire.Frame.Body` aliases the connection's read buffer when produced by
`RecvFrame`. The caller must not retain it past the next `RecvFrame` call
without calling `Clone()`.

---

## 4. Public API (L5)

### Safe default

```go
// Recv receives a single-part message. The returned slice is owned by the caller.
func (s *Socket) Recv() ([]byte, error)

// RecvMsg receives a multi-part message. Each part is owned by the caller.
func (s *Socket) RecvMsg() (Message, error)

// Send sends a single-part message.
func (s *Socket) Send(data []byte) error

// SendMsg sends a multi-part message.
func (s *Socket) SendMsg(msg Message) error
```

### Opt-in zero-copy

```go
// RecvFrame receives one wire frame. Frame.Body aliases the connection's
// read buffer; valid only until the next RecvFrame call on this socket.
// Call [wire.Frame.Clone] to detach if you need to retain it longer.
func (s *Socket) RecvFrame() (wire.Frame, error)

// SendFrame sends one wire frame without copying Frame.Body.
func (s *Socket) SendFrame(f wire.Frame) error
```

Multipart zero-copy is not provided as a dedicated method. Callers compose
multipart zero-copy messages by calling `RecvFrame` in a loop and inspecting
`frame.More`.

---

## 5. Naming Convention

| Suffix | Contract | Tier |
|--------|----------|------|
| none | owned — caller may do anything | safe default |
| `Msg` | owned, multipart | safe default |
| `Frame` | borrowed — aliases internal buffer | opt-in zero-copy |

This convention is grepowalny: `grep -rn 'Frame()' ./...` finds every
opt-in call site.

---

## 6. Documentation Convention

Safe methods require no special annotation — owned is the default.

Every `*Frame` method must include three elements in its godoc:
1. What it aliases (`connection's read buffer`)
2. When it becomes invalid (`next RecvFrame call on this socket`)
3. How to escape (`Call [wire.Frame.Clone] to detach`)

Package-level `doc.go` for the `zmq4` package must include a "Memory
ownership" paragraph summarising the two-tier contract (see Section 1).

---

## 7. Testing Strategy

### Safe API — mutation tests

Verify that mutating a returned value does not affect the socket's internal
state. Pattern: send a value, receive it, overwrite the received bytes, send
the same value again, receive again and assert correctness.

Required tests:
- `TestRecvReturnsOwnedSlice`
- `TestRecvMsgPartsAreOwned`

### Opt-in API — aliasing and Clone tests

Verify the aliasing contract and that `Clone()` breaks it.

Required tests:
- `TestRecvFrameBodyAliasesBuffer`
- `TestRecvFrameCloneDetaches`
- `TestRecvFrameInvalidAfterNextCall` (negative / documentation test)

Existing L1 clone tests (`TestFrameCloneDetachesFromSource`, etc.) are not
duplicated here — L5 tests verify the user-visible contract, not the
implementation.

---

## 8. Lint Guard

CI enforces the convention by rejecting `*Frame` methods that return `[]byte`:

```bash
# in CI script
grep -rn 'Frame().*\[\]byte' ./...
# must produce no output
```

---

## 9. Relationship to Other Specs

This document is a cross-cutting design constraint. Each phase spec
(`01-zmtp-wire-protocol.md`, `02a-security-null.md`, etc.) inherits these
contracts. Any deviation requires an explicit note in the relevant spec.
