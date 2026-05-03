# Memory Model (00b) Implementation Plan

> **For Claude:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the cross-cutting memory ownership contract from spec `docs/specs/00b-memory-model.md` — `Message` type, minimal `Socket` scaffold, 5 required ownership tests, and CI lint guard.

**Architecture:** Root `package zmq4` gets `Message`, `Socket`, and `doc.go`. `Socket` wraps a `net.Conn`: safe-default methods (`Recv`/`RecvMsg`/`Send`/`SendMsg`) delegate to existing `wire.FrameReader`/`FrameWriter` which already allocate fresh slices. The opt-in `RecvFrame` uses a private `zeroCopyReader` that reuses one `[]byte` buffer, so successive calls alias the same backing array. Tests drive two sockets over `net.Pipe()`.

**Tech Stack:** Go 1.26, `internal/wire` (FrameReader, FrameWriter, Frame, Clone), `net.Pipe` for tests, GitHub Actions for CI.

---

## Chunk 1: Root package scaffold

### Task 1: Package documentation

**Files:**
- Create: `doc.go`

- [ ] **Step 1: Write the file**

```go
// Package zmq4 provides a pure-Go implementation of the ZeroMQ core protocol
// stack (ZMTP 3.1).
//
// # Memory ownership
//
// The library follows a two-tier memory contract.
//
// Safe default (all methods without a "Frame" suffix): every value returned to
// the caller is owned by the caller.  It may be retained, mutated, or freed
// without affecting the socket's internal state.
//
// Opt-in zero-copy (methods whose name ends in "Frame"): the returned
// [wire.Frame].Body aliases the socket's internal read buffer.  It is valid
// only until the next *Frame call on the same socket.  Call [wire.Frame.Clone]
// to detach the body into a fresh, caller-owned slice before that point.
//
// Every upward layer boundary passes owned data.  Aliasing is an internal
// implementation detail that only surfaces through the explicitly named *Frame
// methods.
package zmq4
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./...
```
Expected: compiles (only doc.go exists, no errors).

- [ ] **Step 3: Commit**

```bash
git add doc.go
git commit -m "feat: add zmq4 package doc with memory ownership paragraph"
```

---

### Task 2: Message type

**Files:**
- Create: `message.go`

- [ ] **Step 1: Write the failing test**

Create `message_test.go`:

```go
package zmq4_test

import (
    "testing"

    "github.com/tomi77/zmq4"
)

func TestMessageIsSliceOfSlices(t *testing.T) {
    msg := zmq4.Message{[]byte("hello"), []byte("world")}
    if len(msg) != 2 {
        t.Fatalf("want 2 parts, got %d", len(msg))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test -run TestMessageIsSliceOfSlices ./...
```
Expected: FAIL — `undefined: zmq4.Message`.

- [ ] **Step 3: Write minimal implementation**

Create `message.go`:

```go
package zmq4

// Message is an ordered sequence of message parts.
// Each part is an owned byte slice; callers may retain and mutate freely.
type Message [][]byte
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test -run TestMessageIsSliceOfSlices ./...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add message.go message_test.go
git commit -m "feat: add Message type to root zmq4 package"
```

---

## Chunk 2: Socket scaffold

### Task 3: Socket type with safe-default API

**Files:**
- Create: `socket.go`

The `Socket` wraps a `net.Conn`.  In F5 the internals will be replaced with
full connection management; the public method signatures defined here are the
stable contract.

- [ ] **Step 1: Write the failing test (API surface check)**

Append to `socket_test.go` (create the file):

```go
package zmq4_test

import (
    "net"
    "testing"

    "github.com/tomi77/zmq4"
)

func TestSocketAPIExists(t *testing.T) {
    c1, c2 := net.Pipe()
    defer c1.Close()
    defer c2.Close()

    s := zmq4.NewSocket(c1)
    _ = s  // Recv, RecvMsg, Send, SendMsg, RecvFrame, SendFrame must exist
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test -run TestSocketAPIExists ./...
```
Expected: FAIL — `undefined: zmq4.NewSocket`.

- [ ] **Step 3: Write the implementation**

Create `socket.go`:

```go
package zmq4

import (
    "encoding/binary"
    "io"
    "net"

    "github.com/tomi77/zmq4/internal/wire"
)

// Socket is a ZeroMQ socket.
//
// The current implementation is a minimal scaffold that directly wraps a
// net.Conn.  F5 will replace the internals with full connection management,
// routing, and socket-type semantics while keeping this method set.
type Socket struct {
    conn net.Conn
    fr   *wire.FrameReader
    fw   *wire.FrameWriter
    zcr  zeroCopyReader
}

// NewSocket wraps conn in a Socket.  Intended for testing and low-level use;
// F5 will add type-specific constructors (NewREQ, NewREP, etc.).
func NewSocket(conn net.Conn) *Socket {
    return &Socket{
        conn: conn,
        fr:   wire.NewFrameReader(conn),
        fw:   wire.NewFrameWriter(conn),
        zcr:  zeroCopyReader{r: conn},
    }
}

// Recv receives a single-part message. The returned slice is owned by the caller.
func (s *Socket) Recv() ([]byte, error) {
    f, err := s.fr.ReadFrame()
    if err != nil {
        return nil, err
    }
    // FrameReader.ReadFrame already allocates a fresh slice for Body,
    // so no extra copy is needed here.
    return f.Body, nil
}

// RecvMsg receives a multi-part message. Each part is owned by the caller.
func (s *Socket) RecvMsg() (Message, error) {
    var msg Message
    for {
        f, err := s.fr.ReadFrame()
        if err != nil {
            return nil, err
        }
        msg = append(msg, f.Body)
        if !f.More {
            break
        }
    }
    return msg, nil
}

// Send sends a single-part message.
func (s *Socket) Send(data []byte) error {
    return s.fw.WriteFrame(wire.Frame{Kind: wire.FrameMessage, Body: data})
}

// SendMsg sends a multi-part message.
func (s *Socket) SendMsg(msg Message) error {
    for i, part := range msg {
        more := i < len(msg)-1
        if err := s.fw.WriteFrame(wire.Frame{Kind: wire.FrameMessage, More: more, Body: part}); err != nil {
            return err
        }
    }
    return nil
}

// RecvFrame receives one wire frame. Frame.Body aliases the socket's internal
// read buffer; it is valid only until the next RecvFrame call on this socket.
// Call [wire.Frame.Clone] to detach if you need to retain it longer.
func (s *Socket) RecvFrame() (wire.Frame, error) {
    return s.zcr.readFrame()
}

// SendFrame sends one wire frame without copying Frame.Body.
func (s *Socket) SendFrame(f wire.Frame) error {
    return s.fw.WriteFrame(f)
}

// zeroCopyReader reads ZMTP 3.1 message frames reusing a single body buffer.
// Successive calls alias the same backing array, so a frame's Body is valid
// only until the next readFrame call.
type zeroCopyReader struct {
    r      io.Reader
    header [9]byte
    body   []byte
}

func (z *zeroCopyReader) readFrame() (wire.Frame, error) {
    if _, err := io.ReadFull(z.r, z.header[:1]); err != nil {
        return wire.Frame{}, err
    }
    flags := z.header[0]
    more := flags&0x01 != 0
    long := flags&0x02 != 0

    var size uint64
    if long {
        if _, err := io.ReadFull(z.r, z.header[:8]); err != nil {
            return wire.Frame{}, mapEOF(err)
        }
        size = binary.BigEndian.Uint64(z.header[:8])
    } else {
        if _, err := io.ReadFull(z.r, z.header[:1]); err != nil {
            return wire.Frame{}, mapEOF(err)
        }
        size = uint64(z.header[0])
    }

    if size > wire.MaxFrameBodySize {
        return wire.Frame{}, wire.ErrFrameTooLarge
    }

    if uint64(cap(z.body)) >= size {
        z.body = z.body[:size]
    } else {
        z.body = make([]byte, size)
    }
    if size > 0 {
        if _, err := io.ReadFull(z.r, z.body); err != nil {
            return wire.Frame{}, mapEOF(err)
        }
    }
    return wire.Frame{Kind: wire.FrameMessage, More: more, Body: z.body}, nil
}

func mapEOF(err error) error {
    if err == io.EOF {
        return io.ErrUnexpectedEOF
    }
    return err
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test -run TestSocketAPIExists ./...
```
Expected: PASS.

- [ ] **Step 5: Run full test suite**

```bash
go test ./...
```
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add socket.go socket_test.go
git commit -m "feat: add Socket scaffold with safe-default and zero-copy API"
```

---

## Chunk 3: Memory ownership tests (spec §7)

### Task 4: Safe API — mutation tests

**Files:**
- Modify: `socket_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `socket_test.go`:

```go
// TestRecvReturnsOwnedSlice verifies that mutating a Recv result does not
// affect the socket's internal state: the same payload can be received again
// unmodified.
func TestRecvReturnsOwnedSlice(t *testing.T) {
    c1, c2 := net.Pipe()
    defer c1.Close()
    defer c2.Close()
    sender := zmq4.NewSocket(c1)
    receiver := zmq4.NewSocket(c2)

    payload := []byte("hello")

    // First round-trip.
    if err := sender.Send(payload); err != nil {
        t.Fatal(err)
    }
    got, err := receiver.Recv()
    if err != nil {
        t.Fatal(err)
    }
    if string(got) != "hello" {
        t.Fatalf("want %q, got %q", "hello", got)
    }

    // Mutate the received slice — must not affect socket internals.
    for i := range got {
        got[i] = 'X'
    }

    // Second round-trip — payload must arrive intact.
    if err := sender.Send(payload); err != nil {
        t.Fatal(err)
    }
    got2, err := receiver.Recv()
    if err != nil {
        t.Fatal(err)
    }
    if string(got2) != "hello" {
        t.Fatalf("mutation of first Recv result corrupted second receive: got %q", got2)
    }
}

// TestRecvMsgPartsAreOwned verifies that mutating parts of a RecvMsg result
// does not affect subsequent receives.
func TestRecvMsgPartsAreOwned(t *testing.T) {
    c1, c2 := net.Pipe()
    defer c1.Close()
    defer c2.Close()
    sender := zmq4.NewSocket(c1)
    receiver := zmq4.NewSocket(c2)

    want := zmq4.Message{[]byte("part1"), []byte("part2")}

    if err := sender.SendMsg(want); err != nil {
        t.Fatal(err)
    }
    got, err := receiver.RecvMsg()
    if err != nil {
        t.Fatal(err)
    }
    if len(got) != 2 {
        t.Fatalf("want 2 parts, got %d", len(got))
    }

    // Mutate all parts.
    for _, part := range got {
        for i := range part {
            part[i] = 'X'
        }
    }

    // Receive again — must still get original content.
    if err := sender.SendMsg(want); err != nil {
        t.Fatal(err)
    }
    got2, err := receiver.RecvMsg()
    if err != nil {
        t.Fatal(err)
    }
    if string(got2[0]) != "part1" || string(got2[1]) != "part2" {
        t.Fatalf("mutation of first RecvMsg result corrupted second receive: got %q %q", got2[0], got2[1])
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
go test -race -run "TestRecvReturnsOwnedSlice|TestRecvMsgPartsAreOwned" ./...
```
Expected: PASS (FrameReader already allocates fresh slices, so owned contract holds).

- [ ] **Step 3: Commit**

```bash
git add socket_test.go
git commit -m "test: add TestRecvReturnsOwnedSlice and TestRecvMsgPartsAreOwned"
```

---

### Task 5: Opt-in API — aliasing and Clone tests

**Files:**
- Modify: `socket_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `socket_test.go`:

```go
// TestRecvFrameBodyAliasesBuffer verifies that successive RecvFrame calls
// reuse the same backing array, i.e., the first frame's Body is overwritten
// by the second call.
func TestRecvFrameBodyAliasesBuffer(t *testing.T) {
    c1, c2 := net.Pipe()
    defer c1.Close()
    defer c2.Close()
    sender := zmq4.NewSocket(c1)
    receiver := zmq4.NewSocket(c2)

    if err := sender.Send([]byte("first")); err != nil {
        t.Fatal(err)
    }
    f1, err := receiver.RecvFrame()
    if err != nil {
        t.Fatal(err)
    }
    if string(f1.Body) != "first" {
        t.Fatalf("want %q, got %q", "first", f1.Body)
    }
    // Remember the pointer to detect aliasing.
    ptr1 := &f1.Body[0]

    if err := sender.Send([]byte("secnd")); err != nil { // same length as "first"
        t.Fatal(err)
    }
    f2, err := receiver.RecvFrame()
    if err != nil {
        t.Fatal(err)
    }
    if string(f2.Body) != "secnd" {
        t.Fatalf("want %q, got %q", "secnd", f2.Body)
    }

    // Both frames share the same backing array.
    if &f2.Body[0] != ptr1 {
        t.Error("RecvFrame did not reuse buffer: f1 and f2 point to different backing arrays")
    }
    // As a consequence, f1.Body now contains the second frame's data.
    if string(f1.Body) != "secnd" {
        t.Errorf("f1.Body was not overwritten by second RecvFrame: still %q", f1.Body)
    }
}

// TestRecvFrameCloneDetaches verifies that Clone produces an independent copy
// that is unaffected by subsequent RecvFrame calls.
func TestRecvFrameCloneDetaches(t *testing.T) {
    c1, c2 := net.Pipe()
    defer c1.Close()
    defer c2.Close()
    sender := zmq4.NewSocket(c1)
    receiver := zmq4.NewSocket(c2)

    if err := sender.Send([]byte("hello")); err != nil {
        t.Fatal(err)
    }
    f1, err := receiver.RecvFrame()
    if err != nil {
        t.Fatal(err)
    }
    cloned := f1.Clone()

    if err := sender.Send([]byte("world")); err != nil {
        t.Fatal(err)
    }
    _, err = receiver.RecvFrame()
    if err != nil {
        t.Fatal(err)
    }

    // cloned is detached — must still hold "hello".
    if string(cloned.Body) != "hello" {
        t.Errorf("Clone did not detach: cloned.Body = %q, want %q", cloned.Body, "hello")
    }
}

// TestRecvFrameInvalidAfterNextCall documents that a frame's Body aliases
// the socket's buffer and becomes undefined after the next RecvFrame call.
// This test intentionally demonstrates (not catches) the aliasing behaviour.
func TestRecvFrameInvalidAfterNextCall(t *testing.T) {
    c1, c2 := net.Pipe()
    defer c1.Close()
    defer c2.Close()
    sender := zmq4.NewSocket(c1)
    receiver := zmq4.NewSocket(c2)

    if err := sender.Send([]byte("first")); err != nil {
        t.Fatal(err)
    }
    f1, err := receiver.RecvFrame()
    if err != nil {
        t.Fatal(err)
    }
    _ = f1 // Body valid here.

    // After the next RecvFrame, f1.Body is undefined — do not use it.
    if err := sender.Send([]byte("second")); err != nil {
        t.Fatal(err)
    }
    _, err = receiver.RecvFrame()
    if err != nil {
        t.Fatal(err)
    }
    // We do NOT assert anything about f1.Body here: it may or may not have
    // changed.  The point is that callers MUST NOT rely on it remaining valid.
    t.Log("aliasing contract holds: f1.Body must not be used after second RecvFrame")
}
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
go test -race -run "TestRecvFrame" ./...
```
Expected: PASS — `zeroCopyReader` reuses `z.body`, so pointer equality holds for equal-size frames.

- [ ] **Step 3: Commit**

```bash
git add socket_test.go
git commit -m "test: add RecvFrame aliasing and Clone tests (spec 00b §7)"
```

---

## Chunk 4: CI lint guard

### Task 6: Add lint guard to CI

**Files:**
- Modify: `.github/workflows/ci.yml`

The lint guard (spec §8) rejects `*Frame` methods that return `[]byte`.  A `*Frame` method returning `[]byte` would silently break the naming convention (Frame suffix = borrowed, not owned).

- [ ] **Step 1: Add the lint step**

Add after the `go vet` step in `.github/workflows/ci.yml`:

```yaml
      - name: lint-guard (Frame methods must not return []byte)
        run: |
          count=$(grep -rn 'Frame().*\[\]byte' --include='*.go' . | grep -v '_test.go' | wc -l)
          if [ "$count" -ne 0 ]; then
            echo "ERROR: *Frame methods returning []byte violate the naming convention:"
            grep -rn 'Frame().*\[\]byte' --include='*.go' . | grep -v '_test.go'
            exit 1
          fi
```

- [ ] **Step 2: Verify locally**

```bash
count=$(grep -rn 'Frame().*\[\]byte' --include='*.go' . | grep -v '_test.go' | wc -l)
echo "violations: $count"
```
Expected: `violations: 0`.

- [ ] **Step 3: Run full test suite one last time**

```bash
go test -race -count=1 ./...
```
Expected: all pass.

- [ ] **Step 4: Run modernize**

```bash
modernize -fix ./...
```
Expected: no output (or only whitespace/comment fixes — review each one).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add lint guard rejecting Frame() methods that return []byte"
```
