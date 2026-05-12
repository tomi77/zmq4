# F7a API Stabilization — Implementation Plan

> **For Claude:** REQUIRED: Use `superpowers:subagent-driven-development` (if subagents available) or `superpowers:executing-plans` to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Three targeted breaking API improvements before v1.0: `Subscribe`/`Unsubscribe` accept `string`; add `NewMsg`/`NewStringMsg` constructors; add `Frames`/`Frame`/`String` methods on `Message`.

**Architecture:** All changes are additive or in-place signature swaps within `message.go`, `sub.go`, and `xsub.go`. Task 3 includes a mechanical call-site migration across test and cmd files — compile failure is the test.

**Tech Stack:** Pure Go 1.26, stdlib only. No new deps.

**Spec:** `docs/superpowers/specs/2026-05-12-f7a-api-stabilization-design.md`

**Decisions baked in:**
- `NewMsg()` with no args returns `Message{}` (valid empty message).
- `Frame(i)` panics on out-of-bounds — matches plain `m[i]` semantics.
- `String()` returns `""` on empty message, frame 0 decoded as UTF-8 otherwise.
- `Subscribe("")` = subscribe-all (replaces `Subscribe(nil)`).
- **No `modernize -fix` per task.** Run only in Task 4 (done-criteria sweep).
- **Phase tag:** `phase-7a-api-stabilization-complete` after Task 4.

---

## Chunk 1: Message API + Subscribe signature

### Task 1: `message.go` — constructor helpers

**Files:**
- Modify: `message.go`
- Modify: `message_test.go` (add tests)

- [ ] **Step 1: Write failing tests in `message_test.go`**

Append to the end of the existing `message_test.go` (package `zmq4`):

```go
func TestNewMsgEmpty(t *testing.T) {
	m := NewMsg()
	if len(m) != 0 {
		t.Fatalf("want empty, got %v", m)
	}
}

func TestNewMsgFrames(t *testing.T) {
	m := NewMsg([]byte("a"), []byte("b"))
	if len(m) != 2 {
		t.Fatalf("want 2 frames, got %d", len(m))
	}
	if string(m[0]) != "a" || string(m[1]) != "b" {
		t.Fatalf("unexpected content: %v", m)
	}
}

func TestNewStringMsg(t *testing.T) {
	m := NewStringMsg("x", "y")
	if len(m) != 2 {
		t.Fatalf("want 2 frames, got %d", len(m))
	}
	if !bytes.Equal(m[0], []byte("x")) || !bytes.Equal(m[1], []byte("y")) {
		t.Fatalf("unexpected content: %v", m)
	}
}
```

If `message_test.go` doesn't already import `"bytes"`, add it to the import block.

- [ ] **Step 2: Run tests to confirm they fail**

```
go test -run "TestNewMsg|TestNewStringMsg" -count=1 .
```

Expected: compile error — `NewMsg` / `NewStringMsg` undefined.

- [ ] **Step 3: Add constructors to `message.go`**

Append to `message.go`:

```go
// NewMsg returns a Message composed of the given frames.
// Called with no arguments it returns an empty Message.
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

- [ ] **Step 4: Run tests to confirm they pass**

```
go test -run "TestNewMsg|TestNewStringMsg" -count=1 .
```

Expected: PASS.

- [ ] **Step 5: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add message.go message_test.go
git commit -m "feat(F7a): NewMsg / NewStringMsg constructor helpers"
```

---

### Task 2: `message.go` — convenience methods

**Files:**
- Modify: `message.go`
- Modify: `message_test.go` (add tests)

- [ ] **Step 1: Write failing tests — append to `message_test.go`**

```go
func TestMessageFrames(t *testing.T) {
	if Message{}.Frames() != 0 {
		t.Fatal("empty message: want 0")
	}
	m := Message{[]byte("a"), []byte("b")}
	if m.Frames() != 2 {
		t.Fatalf("want 2, got %d", m.Frames())
	}
}

func TestMessageFrame(t *testing.T) {
	m := Message{[]byte("hello")}
	if !bytes.Equal(m.Frame(0), []byte("hello")) {
		t.Fatalf("Frame(0): got %v", m.Frame(0))
	}
}

func TestMessageFramePanicsOutOfBounds(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	Message{[]byte("x")}.Frame(1)
}

func TestMessageFramePanicsNegative(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	Message{[]byte("x")}.Frame(-1)
}

func TestMessageString(t *testing.T) {
	if (Message{}).String() != "" {
		t.Fatal("empty message: want empty string")
	}
	if Message{[]byte("hi")}.String() != "hi" {
		t.Fatalf("single frame: want 'hi'")
	}
	// Multi-frame: only frame 0.
	if Message{[]byte("a"), []byte("b")}.String() != "a" {
		t.Fatal("multi-frame: want 'a' (frame 0 only)")
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```
go test -run "TestMessageFrames|TestMessageFrame|TestMessageString" -count=1 .
```

Expected: compile error — methods undefined.

- [ ] **Step 3: Add methods to `message.go`**

Append to `message.go`:

```go
// Frames returns the number of frames in the message.
func (m Message) Frames() int { return len(m) }

// Frame returns the i-th frame. Panics if i is out of range, matching the
// behaviour of a plain slice index expression.
func (m Message) Frame(i int) []byte { return m[i] }

// String returns the first frame decoded as a UTF-8 string.
// Returns "" for an empty message. For multi-frame messages only frame 0
// is returned.
func (m Message) String() string {
	if len(m) == 0 {
		return ""
	}
	return string(m[0])
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```
go test -run "TestMessageFrames|TestMessageFrame|TestMessageString" -count=1 .
```

Expected: PASS.

- [ ] **Step 5: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add message.go message_test.go
git commit -m "feat(F7a): Message.Frames / Frame / String convenience methods"
```

---

### Task 3: `sub.go` / `xsub.go` — `Subscribe(string)` + call-site migration

**Files:**
- Modify: `sub.go`
- Modify: `xsub.go`
- Migrate: `pub_sub_test.go`, `xpub_xsub_test.go`, `integration_test.go`, `lifecycle_test.go`, `interop/interop_test.go`, `cmd/main.go`

The signature change breaks compilation. The correct workflow is: change signatures first, then fix all call sites, then verify compilation and tests.

- [ ] **Step 1: Change signatures in `sub.go`**

Change the `Subscribe` signature and update its godoc (two places):

Old type-level comment on `SUB` (`sub.go` line ~54):
```go
// SUB is a subscribe socket. It fair-queues messages from connected PUB/XPUB
// peers that match at least one active subscription. Subscribe(nil) = subscribe-all.
```
→
```go
// SUB is a subscribe socket. It fair-queues messages from connected PUB/XPUB
// peers that match at least one active subscription. Subscribe("") = subscribe-all.
```

Old `Subscribe` method (`sub.go` line ~93–96):
```go
// Subscribe adds topic to the subscription list (ref-counted). On the first
// reference, sends a subscription frame to all connected peers.
// topic == nil or []byte{} subscribes to all messages.
func (s *SUB) Subscribe(topic []byte) error {
```
→
```go
// Subscribe adds topic to the subscription list (ref-counted). On the first
// reference, sends a subscription frame to all connected peers.
// topic == "" subscribes to all messages.
func (s *SUB) Subscribe(topic string) error {
```

Inside `Subscribe`, the internal call uses `[]byte(topic)`:
```go
	if !s.state.add([]byte(topic)) {
		return nil
	}
	f := subFrame(0x01, []byte(topic))
```

Old `Unsubscribe` method (`sub.go` line ~114):
```go
func (s *SUB) Unsubscribe(topic []byte) error {
```
→
```go
func (s *SUB) Unsubscribe(topic string) error {
```

Inside `Unsubscribe`, the internal call uses `[]byte(topic)`:
```go
	if !s.state.remove([]byte(topic)) {
		return nil
	}
	f := subFrame(0x00, []byte(topic))
```

- [ ] **Step 2: Change signatures in `xsub.go`**

Old `Subscribe` method (`xsub.go` line ~50):
```go
func (s *XSUB) Subscribe(topic []byte) error {
```
→
```go
func (s *XSUB) Subscribe(topic string) error {
```

Inside, use `[]byte(topic)`:
```go
	if !s.state.add([]byte(topic)) {
		return nil
	}
	f := subFrame(0x01, []byte(topic))
```

Old `Unsubscribe` method (`xsub.go` line ~67):
```go
func (s *XSUB) Unsubscribe(topic []byte) error {
```
→
```go
func (s *XSUB) Unsubscribe(topic string) error {
```

Inside, use `[]byte(topic)`:
```go
	if !s.state.remove([]byte(topic)) {
		return nil
	}
	f := subFrame(0x00, []byte(topic))
```

- [ ] **Step 3: Verify the package itself compiles**

```
go build .
```

Expected: PASS (no test files yet migrated — they don't affect `go build .`).

- [ ] **Step 4: Migrate call sites in `pub_sub_test.go`** (8 call sites)

Apply the following three migration patterns throughout the file:

| Pattern | Replace with |
|---|---|
| `Subscribe(nil)` | `Subscribe("")` |
| `Subscribe([]byte("literal"))` | `Subscribe("literal")` |
| `Unsubscribe([]byte("literal"))` | `Unsubscribe("literal")` |

Specific lines to change:
- Line 62: `sub.Subscribe([]byte("hello"))` → `sub.Subscribe("hello")`
- Line 127: `sub.Subscribe(nil)` → `sub.Subscribe("")`
- Line 167: `subA.Subscribe([]byte("a"))` → `subA.Subscribe("a")`
- Line 174: `subB.Subscribe([]byte("b"))` → `subB.Subscribe("b")`
- Line 220: `sub.Subscribe([]byte("x"))` → `sub.Subscribe("x")`
- Line 221: `sub.Subscribe([]byte("x"))` → `sub.Subscribe("x")`
- Line 222: `sub.Unsubscribe([]byte("x"))` → `sub.Unsubscribe("x")`
- Line 234: `sub.Unsubscribe([]byte("x"))` → `sub.Unsubscribe("x")`

- [ ] **Step 5: Migrate call sites in `xpub_xsub_test.go`** (5 call sites)

- Line 41: `xsub.Subscribe([]byte("foo"))` → `xsub.Subscribe("foo")`
- Line 76: `xsub.Subscribe([]byte("bar"))` → `xsub.Subscribe("bar")`
- Line 83: `xsub.Unsubscribe([]byte("bar"))` → `xsub.Unsubscribe("bar")`
- Line 112: `xsub.Subscribe([]byte("news"))` → `xsub.Subscribe("news")`
- Line 202: `sub.Subscribe([]byte("data"))` → `sub.Subscribe("data")`

- [ ] **Step 6: Migrate call sites in `integration_test.go`** (3 call sites)

- Line 250: `sub.Subscribe([]byte("ping"))` → `sub.Subscribe("ping")`
- Line 281: `xsub.Subscribe([]byte("news"))` → `xsub.Subscribe("news")`
- Line 454: `sub.Subscribe([]byte(""))` → `sub.Subscribe("")`

- [ ] **Step 7: Migrate call site in `lifecycle_test.go`** (1 call site)

- Line 126: `sub.Subscribe([]byte("x"))` → `sub.Subscribe("x")`

- [ ] **Step 8: Migrate call sites in `interop/interop_test.go`** (2 call sites)

- Line 451: `sub.Subscribe(nil)` → `sub.Subscribe("")`
- Line 508: `xsub.Subscribe(nil)` → `xsub.Subscribe("")`

- [ ] **Step 9: Migrate call site in `cmd/main.go`** (1 call site)

- Line 16: `sub.Subscribe([]byte(""))` → `sub.Subscribe("")`

- [ ] **Step 10: Verify everything compiles**

```
go build ./...
```

Expected: PASS (no compile errors).

- [ ] **Step 11: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 12: Commit**

```bash
git add sub.go xsub.go pub_sub_test.go xpub_xsub_test.go \
        integration_test.go lifecycle_test.go \
        interop/interop_test.go cmd/main.go
git commit -m "feat(F7a): Subscribe/Unsubscribe accept string; migrate all call sites"
```

---

## Chunk 2: Finalization

### Task 4: modernize, staticcheck, meta-overview, phase tag

**Files:**
- Modify: `docs/specs/00-meta-overview.md`

- [ ] **Step 1: Run `modernize -fix`**

```
modernize -fix ./...
```

- [ ] **Step 2: Run staticcheck**

```
staticcheck ./...
```

Fix any warnings before proceeding.

- [ ] **Step 3: Commit modernize output (if any changes)**

```bash
git add -u
git commit -m "chore(F7a): modernize -fix"
```

(Skip if no changes.)

- [ ] **Step 4: Run full suite one final time**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 5: Update `docs/specs/00-meta-overview.md`**

In the status line at the top, change:

```
> **Status:** living document. F1, F2a, F2b, F2c, F3, F4, F5a, F5b, F5c, F6a, F6b, F6c, and F6d complete
> and tagged (`phase-1-wire-complete`, `phase-2a-null-complete`,
> `phase-2b-plain-complete`, `phase-2c-curve-complete`,
> `phase-3-transport-complete`, `phase-4-conn-complete`,
> `phase-5a-reqrep-complete`, `phase-5b-pubsub-complete`,
> `phase-5c-pipeline-pair-complete`, `phase-6a-hwm-complete`,
> `phase-6b-zap-complete`, `phase-6c-monitoring-complete`,
> `phase-6d-polling-complete`).
```

to:

```
> **Status:** living document. F1, F2a, F2b, F2c, F3, F4, F5a, F5b, F5c, F6a, F6b, F6c, F6d, and F7a complete
> and tagged (`phase-1-wire-complete`, `phase-2a-null-complete`,
> `phase-2b-plain-complete`, `phase-2c-curve-complete`,
> `phase-3-transport-complete`, `phase-4-conn-complete`,
> `phase-5a-reqrep-complete`, `phase-5b-pubsub-complete`,
> `phase-5c-pipeline-pair-complete`, `phase-6a-hwm-complete`,
> `phase-6b-zap-complete`, `phase-6c-monitoring-complete`,
> `phase-6d-polling-complete`, `phase-7a-api-stabilization-complete`).
```

In the phase table, add a new row after the F6d row:

```
| F7a | — | API stabilization: `Subscribe(string)`, `NewMsg`/`NewStringMsg`, `Message` methods. | Unit + compile-time migration. | **Complete** — tagged `phase-7a-api-stabilization-complete`. |
```

- [ ] **Step 6: Commit meta-overview update**

```bash
git add docs/specs/00-meta-overview.md
git commit -m "docs(F7a): update meta-overview — F7a complete"
```

- [ ] **Step 7: Tag the phase**

```bash
git tag phase-7a-api-stabilization-complete
```
