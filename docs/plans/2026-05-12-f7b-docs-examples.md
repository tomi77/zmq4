# F7b Documentation and Examples — Implementation Plan

> **For Claude:** REQUIRED: Use `superpowers:subagent-driven-development` (if subagents available) or `superpowers:executing-plans` to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add production-quality godoc, `Example*` test functions, standalone example programs, and an updated README before tagging v1.0.

**Architecture:** Four independent areas: (1) godoc gap-fill in `errors.go`; (2) `Example*` functions in `example_*_test.go` files (compiled + run by `go test`); (3) standalone runnable programs under `examples/`; (4) `README.md` rewrite + meta-overview update + phase tag. No API changes.

**Tech Stack:** Pure Go 1.26, stdlib only. No new deps.

**Spec:** `docs/superpowers/specs/2026-05-12-f7b-docs-examples-design.md`

**Decisions baked in:**
- `Example*` functions use `inproc://` transport — fast, no network, no port conflicts.
- Deterministic examples (REQ/REP, PUSH/PULL, PAIR, ROUTER/DEALER) carry `// Output:` comment.
- PUB/SUB uses `time.Sleep(10 ms)` for subscription propagation (standard in this codebase).
- XPUB example shows the subscription-frame feature, not a proxy — single `// Output:`.
- Standalone programs use `net.Listen(":0")` helper to allocate a free TCP port.
- CURVE example imports `internal/security/curve` directly (same module — allowed by Go).
- **No `modernize -fix` per task.** Run only in Task 16 (done-criteria sweep).
- **Phase tag:** `phase-7b-docs-examples-complete` after Task 17.

---

## Chunk 1: Godoc

### Task 1: Add godoc comments to `errors.go`

**Files:**
- Modify: `errors.go`

- [ ] **Step 1: Run staticcheck to capture the baseline**

```
staticcheck ./...
```

Note any `ST1020`/`ST1021` warnings. Expected: multiple "exported var … should have comment" messages for every error in `errors.go`.

- [ ] **Step 2: Add doc comments in `errors.go`**

Replace the current `var (…)` block with:

```go
var (
	// ErrClosed is returned by any socket operation after the socket is closed.
	ErrClosed = errors.New("zmq4: socket closed")

	// ErrState is returned when an operation is called out of sequence
	// (e.g. REQ sends twice without an intervening Recv).
	ErrState = errors.New("zmq4: operation out of sequence")

	// ErrNoRoute is returned when no connected peer is available for routing.
	ErrNoRoute = errors.New("zmq4: no route to peer")

	// ErrIncompatiblePeer is returned when the remote socket type is not
	// compatible with the local socket type.
	ErrIncompatiblePeer = errors.New("zmq4: incompatible peer socket type")

	// ErrSecurityMismatch is returned when a security option is not valid for
	// the socket's role (e.g. a client-side option on a Bind socket).
	ErrSecurityMismatch = errors.New("zmq4: security option not valid for this role")

	// ErrNoIdentity is returned by ROUTER.Send when msg[0] (the identity frame)
	// is empty.
	ErrNoIdentity = errors.New("zmq4: ROUTER Send requires non-empty msg[0]")

	// ErrNoTopic is returned by PUB/XPUB.Send when the message has no frames
	// (a topic prefix is required).
	ErrNoTopic = errors.New("zmq4: PUB/XPUB Send requires at least one frame (topic)")

	// ErrPairAlreadyConnected is returned when a second peer tries to connect
	// to a PAIR socket that already has an active peer.
	ErrPairAlreadyConnected = errors.New("zmq4: PAIR socket already has a peer")

	// ErrNotSocket is returned by Poller methods when the value passed is not
	// a recognised zmq4 socket type.
	ErrNotSocket = errors.New("zmq4: value is not a zmq4 socket")

	// ErrAlreadyRegistered is returned by Poller.Add when the socket is already
	// registered with this Poller.
	ErrAlreadyRegistered = errors.New("zmq4: socket already registered with poller")

	// ErrNotRegistered is returned by Poller.Remove and Poller.Update when the
	// socket is not registered with this Poller.
	ErrNotRegistered = errors.New("zmq4: socket not registered with poller")

	// ErrInvalidEvents is returned by Poller.Add and Poller.Update when the
	// event mask is zero.
	ErrInvalidEvents = errors.New("zmq4: event mask must not be zero")
)
```

- [ ] **Step 3: Run staticcheck again**

```
staticcheck ./...
go vet ./...
```

Expected: zero `ST1020`/`ST1021` warnings. Overall: zero diagnostics.

- [ ] **Step 4: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add errors.go
git commit -m "docs(F7b): godoc comments for all exported error vars"
```

---

## Chunk 2: Example* functions

All example files go in the root package as `package zmq4_test`.
All use `inproc://` — no TCP, no port conflicts.
Imports needed in most files: `"context"`, `"fmt"`, `"github.com/tomi77/zmq4"`.

---

### Task 2: REQ/REP example

**Files:**
- Create: `example_reqrep_test.go`

- [ ] **Step 1: Create `example_reqrep_test.go`**

```go
package zmq4_test

import (
	"context"
	"fmt"

	"github.com/tomi77/zmq4"
)

// Example_reqrep demonstrates the Request-Reply pattern (RFC 28).
// REQ sends a request; REP receives it, prints it, and sends a reply.
func Example_reqrep() {
	ctx := context.Background()

	rep := zmq4.NewREP(zmq4.WithNULL())
	if err := rep.Bind(ctx, "inproc://ex-reqrep"); err != nil {
		return
	}
	defer rep.Close()

	req := zmq4.NewREQ(zmq4.WithNULL())
	if err := req.Connect(ctx, "inproc://ex-reqrep"); err != nil {
		return
	}
	defer req.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		msg, err := rep.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("REP received:", msg.String())
		_ = rep.Send(ctx, zmq4.NewStringMsg("pong"))
	}()

	if err := req.Send(ctx, zmq4.NewStringMsg("ping")); err != nil {
		return
	}
	reply, err := req.Recv(ctx)
	if err == nil {
		fmt.Println("REQ received:", reply.String())
	}
	<-done
	// Output:
	// REP received: ping
	// REQ received: pong
}
```

- [ ] **Step 2: Run the example**

```
go test -run Example_reqrep -v .
```

Expected: PASS with output matching `// Output:`.

- [ ] **Step 3: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add example_reqrep_test.go
git commit -m "docs(F7b): Example_reqrep"
```

---

### Task 3: PUSH/PULL example

**Files:**
- Create: `example_pipeline_test.go`

- [ ] **Step 1: Create `example_pipeline_test.go`**

```go
package zmq4_test

import (
	"context"
	"fmt"

	"github.com/tomi77/zmq4"
)

// Example_pipeline demonstrates the Pipeline pattern (RFC 30).
// PUSH distributes tasks; PULL receives them.
func Example_pipeline() {
	ctx := context.Background()

	pull := zmq4.NewPULL(zmq4.WithNULL())
	if err := pull.Bind(ctx, "inproc://ex-pipeline"); err != nil {
		return
	}
	defer pull.Close()

	push := zmq4.NewPUSH(zmq4.WithNULL())
	if err := push.Connect(ctx, "inproc://ex-pipeline"); err != nil {
		return
	}
	defer push.Close()

	if err := push.Send(ctx, zmq4.NewStringMsg("task-1")); err != nil {
		return
	}
	msg, err := pull.Recv(ctx)
	if err == nil {
		fmt.Println("PULL received:", msg.String())
	}
	// Output:
	// PULL received: task-1
}
```

- [ ] **Step 2: Run the example**

```
go test -run Example_pipeline -v .
```

Expected: PASS.

- [ ] **Step 3: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add example_pipeline_test.go
git commit -m "docs(F7b): Example_pipeline"
```

---

### Task 4: PAIR example

**Files:**
- Create: `example_pair_test.go`

- [ ] **Step 1: Create `example_pair_test.go`**

```go
package zmq4_test

import (
	"context"
	"fmt"

	"github.com/tomi77/zmq4"
)

// Example_pair demonstrates the Exclusive-Pair pattern (RFC 31).
// Two PAIR sockets form a single bidirectional channel.
func Example_pair() {
	ctx := context.Background()

	a := zmq4.NewPAIR(zmq4.WithNULL())
	if err := a.Bind(ctx, "inproc://ex-pair"); err != nil {
		return
	}
	defer a.Close()

	b := zmq4.NewPAIR(zmq4.WithNULL())
	if err := b.Connect(ctx, "inproc://ex-pair"); err != nil {
		return
	}
	defer b.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		msg, err := b.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("B received:", msg.String())
		_ = b.Send(ctx, zmq4.NewStringMsg("pong"))
	}()

	if err := a.Send(ctx, zmq4.NewStringMsg("ping")); err != nil {
		return
	}
	reply, err := a.Recv(ctx)
	if err == nil {
		fmt.Println("A received:", reply.String())
	}
	<-done
	// Output:
	// B received: ping
	// A received: pong
}
```

- [ ] **Step 2: Run the example**

```
go test -run Example_pair -v .
```

Expected: PASS.

- [ ] **Step 3: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add example_pair_test.go
git commit -m "docs(F7b): Example_pair"
```

---

### Task 5: ROUTER/DEALER example

**Files:**
- Create: `example_router_dealer_test.go`

- [ ] **Step 1: Create `example_router_dealer_test.go`**

```go
package zmq4_test

import (
	"context"
	"fmt"

	"github.com/tomi77/zmq4"
)

// Example_routerDealer demonstrates asynchronous request-reply via ROUTER+DEALER.
// DEALER sends a message carrying its identity; ROUTER routes the reply back.
func Example_routerDealer() {
	ctx := context.Background()

	router := zmq4.NewROUTER(zmq4.WithNULL())
	if err := router.Bind(ctx, "inproc://ex-router-dealer"); err != nil {
		return
	}
	defer router.Close()

	dealer := zmq4.NewDEALER(zmq4.WithNULL(), zmq4.WithIdentity([]byte("worker-1")))
	if err := dealer.Connect(ctx, "inproc://ex-router-dealer"); err != nil {
		return
	}
	defer dealer.Close()

	// DEALER sends a task.
	if err := dealer.Send(ctx, zmq4.NewStringMsg("task")); err != nil {
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		reply, err := dealer.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("DEALER received:", reply.String())
	}()

	// ROUTER receives [identity, payload...].
	msg, err := router.Recv(ctx)
	if err != nil || msg.Frames() < 2 {
		return
	}
	identity := msg.Frame(0)
	payload := msg.Frame(msg.Frames() - 1)
	fmt.Printf("ROUTER received from %q: %s\n", string(identity), string(payload))

	// Reply: prepend the identity so ROUTER routes it back.
	_ = router.Send(ctx, zmq4.NewMsg(identity, []byte("done")))
	<-done
	// Output:
	// ROUTER received from "worker-1": task
	// DEALER received: done
}
```

- [ ] **Step 2: Run the example**

```
go test -run Example_routerDealer -v .
```

Expected: PASS.

- [ ] **Step 3: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add example_router_dealer_test.go
git commit -m "docs(F7b): Example_routerDealer"
```

---

### Task 6: PUB/SUB example

**Files:**
- Create: `example_pubsub_test.go`

- [ ] **Step 1: Create `example_pubsub_test.go`**

```go
package zmq4_test

import (
	"context"
	"fmt"
	"time"

	"github.com/tomi77/zmq4"
)

// Example_pubsub demonstrates the Publish-Subscribe pattern (RFC 29).
// SUB subscribes to a topic prefix; PUB broadcasts to all matching subscribers.
func Example_pubsub() {
	ctx := context.Background()

	pub := zmq4.NewPUB(zmq4.WithNULL())
	if err := pub.Bind(ctx, "inproc://ex-pubsub"); err != nil {
		return
	}
	defer pub.Close()

	sub := zmq4.NewSUB(zmq4.WithNULL())
	if err := sub.Connect(ctx, "inproc://ex-pubsub"); err != nil {
		return
	}
	defer sub.Close()
	if err := sub.Subscribe("news"); err != nil {
		return
	}

	// Allow the subscription frame to propagate before publishing.
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		msg, err := sub.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("SUB received:", msg.String())
	}()

	_ = pub.Send(ctx, zmq4.NewStringMsg("news:flash"))
	<-done
	// Output:
	// SUB received: news:flash
}
```

- [ ] **Step 2: Run the example**

```
go test -run Example_pubsub -v .
```

Expected: PASS. (The 10 ms sleep is sufficient for inproc subscription propagation.)

- [ ] **Step 3: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add example_pubsub_test.go
git commit -m "docs(F7b): Example_pubsub"
```

---

### Task 7: XPUB/XSUB example

**Files:**
- Create: `example_xpubxsub_test.go`

- [ ] **Step 1: Create `example_xpubxsub_test.go`**

```go
package zmq4_test

import (
	"context"
	"fmt"

	"github.com/tomi77/zmq4"
)

// ExampleXPUB_recvSubscription demonstrates the extended Publish-Subscribe
// pattern. Unlike PUB, XPUB can receive subscription frames from subscribers,
// enabling dynamic subscription management and proxy topologies.
func ExampleXPUB_recvSubscription() {
	ctx := context.Background()

	xpub := zmq4.NewXPUB(zmq4.WithNULL())
	if err := xpub.Bind(ctx, "inproc://ex-xpub"); err != nil {
		return
	}
	defer xpub.Close()

	xsub := zmq4.NewXSUB(zmq4.WithNULL())
	if err := xsub.Connect(ctx, "inproc://ex-xpub"); err != nil {
		return
	}
	defer xsub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// XSUB.Subscribe sends a raw subscription frame upstream to XPUB.
		_ = xsub.Subscribe("prices")
	}()

	// XPUB.Recv returns the raw subscription frame: byte 0x01 + topic.
	frame, err := xpub.Recv(ctx)
	<-done
	if err != nil || frame.Frames() == 0 || len(frame.Frame(0)) == 0 {
		return
	}
	raw := frame.Frame(0)
	if raw[0] == 0x01 {
		fmt.Printf("XPUB sees subscribe for topic %q\n", string(raw[1:]))
	}
	// Output:
	// XPUB sees subscribe for topic "prices"
}
```

- [ ] **Step 2: Run the example**

```
go test -run ExampleXPUB_recvSubscription -v .
```

Expected: PASS.

- [ ] **Step 3: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add example_xpubxsub_test.go
git commit -m "docs(F7b): ExampleXPUB_recvSubscription"
```

---

## Chunk 3: Standalone programs

All programs live under `examples/`. They use a `freePort()` helper to pick an
available TCP port at startup (avoids hardcoded port conflicts). Each compiles
with `go build ./examples/<name>/` and runs with `go run ./examples/<name>/`.

The helper (copy into each program that needs TCP):

```go
func freePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic("freePort: " + err.Error())
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}
```

---

### Task 8: `examples/hello-world/main.go` (REQ/REP)

**Files:**
- Create: `examples/hello-world/main.go`

- [ ] **Step 1: Create `examples/hello-world/main.go`**

```go
// hello-world demonstrates the Request-Reply pattern (RFC 28).
// Run: go run ./examples/hello-world/
package main

import (
	"context"
	"fmt"
	"net"

	"github.com/tomi77/zmq4"
)

func main() {
	ctx := context.Background()
	ep := freePort()

	rep := zmq4.NewREP(zmq4.WithNULL())
	if err := rep.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer rep.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		req := zmq4.NewREQ(zmq4.WithNULL())
		if err := req.Connect(ctx, ep); err != nil {
			return
		}
		defer req.Close()

		if err := req.Send(ctx, zmq4.NewStringMsg("Hello")); err != nil {
			return
		}
		msg, err := req.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("Client received:", msg.String())
	}()

	msg, err := rep.Recv(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Server received:", msg.String())
	if err := rep.Send(ctx, zmq4.NewStringMsg("World")); err != nil {
		panic(err)
	}
	<-done
}

func freePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}
```

- [ ] **Step 2: Build and run**

```
go build ./examples/hello-world/
go run ./examples/hello-world/
```

Expected output:
```
Server received: Hello
Client received: World
```

- [ ] **Step 3: Verify all examples compile**

```
go build ./examples/...
```

(Only hello-world exists so far — that's fine.)

- [ ] **Step 4: Commit**

```bash
git add examples/hello-world/main.go
git commit -m "docs(F7b): examples/hello-world — REQ/REP"
```

---

### Task 9: `examples/pubsub/main.go` (PUB/SUB)

**Files:**
- Create: `examples/pubsub/main.go`

- [ ] **Step 1: Create `examples/pubsub/main.go`**

```go
// pubsub demonstrates the Publish-Subscribe pattern (RFC 29).
// Run: go run ./examples/pubsub/
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/tomi77/zmq4"
)

func main() {
	ctx := context.Background()
	ep := freePort()

	pub := zmq4.NewPUB(zmq4.WithNULL())
	if err := pub.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer pub.Close()

	sub := zmq4.NewSUB(zmq4.WithNULL())
	if err := sub.Connect(ctx, ep); err != nil {
		panic(err)
	}
	defer sub.Close()
	if err := sub.Subscribe("prices"); err != nil {
		panic(err)
	}

	// Allow subscription to propagate.
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		msg, err := sub.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("Subscriber received:", msg.String())
	}()

	topics := []string{"prices:EUR/USD:1.0850", "news:ignored", "prices:BTC/USD:60000"}
	for _, t := range topics {
		if err := pub.Send(ctx, zmq4.NewStringMsg(t)); err != nil {
			panic(err)
		}
		fmt.Println("Publisher sent:", t)
	}
	<-done
}

func freePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}
```

- [ ] **Step 2: Build**

```
go build ./examples/pubsub/
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add examples/pubsub/main.go
git commit -m "docs(F7b): examples/pubsub — PUB/SUB topic filtering"
```

---

### Task 10: `examples/pipeline/main.go` (PUSH/PULL)

**Files:**
- Create: `examples/pipeline/main.go`

- [ ] **Step 1: Create `examples/pipeline/main.go`**

```go
// pipeline demonstrates the Pipeline pattern (RFC 30).
// A ventilator (PUSH) distributes tasks; workers (PULL) receive them.
// Run: go run ./examples/pipeline/
package main

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/tomi77/zmq4"
)

func main() {
	ctx := context.Background()
	ep := freePort()

	push := zmq4.NewPUSH(zmq4.WithNULL())
	if err := push.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer push.Close()

	const workers = 3
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pull := zmq4.NewPULL(zmq4.WithNULL())
			if err := pull.Connect(ctx, ep); err != nil {
				return
			}
			defer pull.Close()
			msg, err := pull.Recv(ctx)
			if err != nil {
				return
			}
			fmt.Printf("Worker %d received: %s\n", id, msg.String())
		}(i + 1)
	}

	for i := range workers {
		task := fmt.Sprintf("task-%d", i+1)
		if err := push.Send(ctx, zmq4.NewStringMsg(task)); err != nil {
			panic(err)
		}
	}
	wg.Wait()
}

func freePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}
```

- [ ] **Step 2: Build**

```
go build ./examples/pipeline/
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add examples/pipeline/main.go
git commit -m "docs(F7b): examples/pipeline — PUSH/PULL"
```

---

### Task 11: `examples/pair/main.go` (PAIR)

**Files:**
- Create: `examples/pair/main.go`

- [ ] **Step 1: Create `examples/pair/main.go`**

```go
// pair demonstrates the Exclusive-Pair pattern (RFC 31).
// Two PAIR sockets form a single bidirectional channel between two peers.
// Run: go run ./examples/pair/
package main

import (
	"context"
	"fmt"
	"net"

	"github.com/tomi77/zmq4"
)

func main() {
	ctx := context.Background()
	ep := freePort()

	a := zmq4.NewPAIR(zmq4.WithNULL())
	if err := a.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer a.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		b := zmq4.NewPAIR(zmq4.WithNULL())
		if err := b.Connect(ctx, ep); err != nil {
			return
		}
		defer b.Close()

		msg, err := b.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("B received:", msg.String())
		_ = b.Send(ctx, zmq4.NewStringMsg("pong"))
	}()

	if err := a.Send(ctx, zmq4.NewStringMsg("ping")); err != nil {
		panic(err)
	}
	reply, err := a.Recv(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("A received:", reply.String())
	<-done
}

func freePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}
```

- [ ] **Step 2: Build**

```
go build ./examples/pair/
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add examples/pair/main.go
git commit -m "docs(F7b): examples/pair — PAIR bidirectional"
```

---

### Task 12: `examples/router-dealer/main.go` (ROUTER/DEALER)

**Files:**
- Create: `examples/router-dealer/main.go`

- [ ] **Step 1: Create `examples/router-dealer/main.go`**

```go
// router-dealer demonstrates asynchronous request-reply via ROUTER+DEALER.
// Unlike REQ/REP, DEALER does not enforce strict alternation, enabling
// pipelining and load-balancing patterns.
// Run: go run ./examples/router-dealer/
package main

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/tomi77/zmq4"
)

func main() {
	ctx := context.Background()
	ep := freePort()

	router := zmq4.NewROUTER(zmq4.WithNULL())
	if err := router.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer router.Close()

	const workers = 2
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("worker-%d", id+1)
			dealer := zmq4.NewDEALER(zmq4.WithNULL(), zmq4.WithIdentity([]byte(name)))
			if err := dealer.Connect(ctx, ep); err != nil {
				return
			}
			defer dealer.Close()

			if err := dealer.Send(ctx, zmq4.NewStringMsg("task")); err != nil {
				return
			}
			reply, err := dealer.Recv(ctx)
			if err != nil {
				return
			}
			fmt.Printf("%s received: %s\n", name, reply.String())
		}(i)
	}

	// Service two worker requests.
	for range workers {
		msg, err := router.Recv(ctx)
		if err != nil {
			panic(err)
		}
		if msg.Frames() < 2 {
			continue
		}
		identity := msg.Frame(0)
		payload := msg.Frame(msg.Frames() - 1)
		fmt.Printf("ROUTER received from %q: %s\n", string(identity), string(payload))
		_ = router.Send(ctx, zmq4.NewMsg(identity, []byte("done")))
	}
	wg.Wait()
}

func freePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}
```

- [ ] **Step 2: Build**

```
go build ./examples/router-dealer/
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add examples/router-dealer/main.go
git commit -m "docs(F7b): examples/router-dealer — ROUTER+DEALER async"
```

---

### Task 13: `examples/xpubxsub-proxy/main.go` (XPUB/XSUB forwarding proxy)

**Files:**
- Create: `examples/xpubxsub-proxy/main.go`

- [ ] **Step 1: Create `examples/xpubxsub-proxy/main.go`**

```go
// xpubxsub-proxy demonstrates a publish-subscribe forwarding proxy.
// Publishers connect to the XSUB frontend; subscribers connect to the XPUB backend.
// The proxy forwards messages and subscription frames between the two sides.
// Run: go run ./examples/xpubxsub-proxy/
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/tomi77/zmq4"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	frontEP := freePort() // publishers connect here (XSUB)
	backEP := freePort()  // subscribers connect here (XPUB)

	// Proxy frontend: XSUB receives from publishers.
	xsub := zmq4.NewXSUB(zmq4.WithNULL())
	if err := xsub.Bind(ctx, frontEP); err != nil {
		panic(err)
	}
	defer xsub.Close()

	// Proxy backend: XPUB forwards to subscribers.
	xpub := zmq4.NewXPUB(zmq4.WithNULL())
	if err := xpub.Bind(ctx, backEP); err != nil {
		panic(err)
	}
	defer xpub.Close()

	// Subscriber connects to the XPUB backend.
	sub := zmq4.NewSUB(zmq4.WithNULL())
	if err := sub.Connect(ctx, backEP); err != nil {
		panic(err)
	}
	defer sub.Close()
	if err := sub.Subscribe(""); err != nil { // subscribe-all
		panic(err)
	}

	// Proxy loop: forward subscription frames (XPUB→XSUB) and messages (XSUB→XPUB).
	// In production this runs in its own goroutine indefinitely.
	go func() {
		for {
			// Forward subscription frames from backend to frontend.
			subFrame, err := xpub.Recv(ctx)
			if err != nil {
				return
			}
			if err := xsub.Send(ctx, subFrame); err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			// Forward messages from frontend to backend.
			msg, err := xsub.Recv(ctx)
			if err != nil {
				return
			}
			if err := xpub.Send(ctx, msg); err != nil {
				return
			}
		}
	}()

	// Publisher connects to the XSUB frontend.
	pub := zmq4.NewPUB(zmq4.WithNULL())
	if err := pub.Connect(ctx, frontEP); err != nil {
		panic(err)
	}
	defer pub.Close()

	// Allow subscriptions to propagate through the proxy.
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		msg, err := sub.Recv(ctx)
		if err != nil {
			return
		}
		fmt.Println("Subscriber received:", msg.String())
	}()

	if err := pub.Send(ctx, zmq4.NewStringMsg("hello via proxy")); err != nil {
		panic(err)
	}
	<-done
}

func freePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}
```

- [ ] **Step 2: Build**

```
go build ./examples/xpubxsub-proxy/
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add examples/xpubxsub-proxy/main.go
git commit -m "docs(F7b): examples/xpubxsub-proxy — XPUB/XSUB forwarding proxy"
```

---

### Task 14: `examples/curve-security/main.go` (CURVE encryption)

**Files:**
- Create: `examples/curve-security/main.go`

The CURVE key generation API lives at `github.com/tomi77/zmq4/internal/security/curve`.
This package is `internal` but importable from within the same module.

- [ ] **Step 1: Create `examples/curve-security/main.go`**

```go
// curve-security demonstrates CURVE encryption and authentication (RFC 25/26).
// Keys are generated ephemerally at startup — no pre-shared key files needed.
// Run: go run ./examples/curve-security/
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"

	"github.com/tomi77/zmq4"
	"github.com/tomi77/zmq4/internal/security/curve"
)

func main() {
	ctx := context.Background()
	ep := freePort()

	// Generate long-term key pairs for server and client.
	serverPub, serverSec, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}
	defer serverSec.Zero()

	clientPub, clientSec, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}
	defer clientSec.Zero()

	// Server: REP with CURVE, accepts any client (no authorizer).
	serverOpts := curve.ServerOptions{
		OurPublicKey: serverPub,
		OurSecretKey: &serverSec,
		Authorizer:   curve.Authorizer(func(_ curve.PublicKey, _ interface{}) error { return nil }),
	}

	rep := zmq4.NewREP(zmq4.WithCURVEServer(serverOpts))
	if err := rep.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer rep.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Client: REQ with CURVE, using the server's public key for verification.
		clientOpts := curve.ClientOptions{
			ServerKey:    serverPub,
			OurPublicKey: clientPub,
			OurSecretKey: &clientSec,
		}
		req := zmq4.NewREQ(zmq4.WithCURVE(clientOpts))
		if err := req.Connect(ctx, ep); err != nil {
			fmt.Println("Connect error:", err)
			return
		}
		defer req.Close()

		if err := req.Send(ctx, zmq4.NewStringMsg("secret")); err != nil {
			fmt.Println("Send error:", err)
			return
		}
		msg, err := req.Recv(ctx)
		if err != nil {
			fmt.Println("Recv error:", err)
			return
		}
		fmt.Println("Client received:", msg.String())
	}()

	msg, err := rep.Recv(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Server received:", msg.String())
	if err := rep.Send(ctx, zmq4.NewStringMsg("acknowledged")); err != nil {
		panic(err)
	}
	<-done
}

func freePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}
```

**Note on `curve.Authorizer`:** Check the actual signature by looking at how it's used in `integration_test.go`. The authorizer in tests is `curve.Authorizer(func(_ curve.PublicKey, _ wire.Metadata) error { return nil })`. Import `wire` as needed: `github.com/tomi77/zmq4/internal/wire`.

If the `Authorizer` type requires `wire.Metadata`, update the import and parameter accordingly:

```go
import (
	...
	"github.com/tomi77/zmq4/internal/security/curve"
	"github.com/tomi77/zmq4/internal/wire"
)

serverOpts := curve.ServerOptions{
	OurPublicKey: serverPub,
	OurSecretKey: &serverSec,
	Authorizer:   curve.Authorizer(func(_ curve.PublicKey, _ wire.Metadata) error { return nil }),
}
```

- [ ] **Step 2: Check `curve.Authorizer` signature**

```
grep -n "type Authorizer\|func Authorizer" internal/security/curve/*.go
```

Adjust the import and function signature if `wire.Metadata` is required.

- [ ] **Step 3: Build**

```
go build ./examples/curve-security/
```

Expected: no errors.

- [ ] **Step 4: Build all examples**

```
go build ./examples/...
```

Expected: all seven programs compile cleanly.

- [ ] **Step 5: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add examples/curve-security/main.go
git commit -m "docs(F7b): examples/curve-security — CURVE encryption"
```

---

## Chunk 4: README + meta-overview + phase tag

### Task 15: Update `README.md`

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the full content of `README.md`**

```markdown
# zmq4

[![CI](https://github.com/tomi77/zmq4/actions/workflows/ci.yml/badge.svg)](https://github.com/tomi77/zmq4/actions/workflows/ci.yml)

Pure-Go [ZeroMQ](https://zeromq.org/) speaking [ZMTP 3.1](https://rfc.zeromq.org/spec/23/). No `cgo`. No `libzmq`.

## Installation

```sh
go get github.com/tomi77/zmq4@latest
```

## Quick start

```go
ctx := context.Background()

rep := zmq4.NewREP(zmq4.WithNULL())
_ = rep.Bind(ctx, "tcp://127.0.0.1:5555")
defer rep.Close()

req := zmq4.NewREQ(zmq4.WithNULL())
_ = req.Connect(ctx, "tcp://127.0.0.1:5555")
defer req.Close()

_ = req.Send(ctx, zmq4.NewStringMsg("Hello"))
msg, _ := rep.Recv(ctx)   // msg.String() == "Hello"
_ = rep.Send(ctx, zmq4.NewStringMsg("World"))
reply, _ := req.Recv(ctx) // reply.String() == "World"
```

## Socket patterns

### Request-Reply ([RFC 28](https://rfc.zeromq.org/spec/28/))

`REQ` → `REP`: strict alternating send/receive.
`DEALER` → `ROUTER`: async, no alternation constraint.

```go
rep := zmq4.NewREP()
req := zmq4.NewREQ()
```

See [`examples/hello-world/`](./examples/hello-world/) and [`examples/router-dealer/`](./examples/router-dealer/).

### Publish-Subscribe ([RFC 29](https://rfc.zeromq.org/spec/29/))

```go
pub := zmq4.NewPUB()
sub := zmq4.NewSUB()
_ = sub.Subscribe("prices") // subscribe to topic prefix
```

`XPUB`/`XSUB` extend the pattern: `XPUB` can inspect subscription frames; `XSUB` can send them manually — enabling forwarding proxies.

See [`examples/pubsub/`](./examples/pubsub/) and [`examples/xpubxsub-proxy/`](./examples/xpubxsub-proxy/).

### Pipeline ([RFC 30](https://rfc.zeromq.org/spec/30/))

```go
push := zmq4.NewPUSH()
pull := zmq4.NewPULL()
```

`PUSH` distributes tasks round-robin across all connected `PULL` workers.

See [`examples/pipeline/`](./examples/pipeline/).

### Exclusive Pair ([RFC 31](https://rfc.zeromq.org/spec/31/))

```go
a := zmq4.NewPAIR()
b := zmq4.NewPAIR()
```

Exactly one peer; bidirectional.

See [`examples/pair/`](./examples/pair/).

## Security

Select a mechanism via constructor options:

```go
// No authentication (default).
zmq4.NewREP(zmq4.WithNULL())

// PLAIN — username/password (RFC 24).
zmq4.NewREQ(zmq4.WithPLAIN("alice", "s3cr3t"))          // client
zmq4.NewREP(zmq4.WithPLAINServer(myAuthenticator))       // server

// CURVE — public-key encryption (RFC 25/26).
zmq4.NewREQ(zmq4.WithCURVE(clientOptions))               // client
zmq4.NewREP(zmq4.WithCURVEServer(serverOptions))         // server
```

See [`examples/curve-security/`](./examples/curve-security/) for a self-contained CURVE example.

## Non-goals (for now)

- Backwards compatibility with ZMTP 3.0 / 2.0 / 1.0.
- Draft socket types (`CLIENT`/`SERVER`, `RADIO`/`DISH`, `SCATTER`/`GATHER`, `STREAM`).
- Higher-level patterns (Majordomo, Clone, Freelance, Zyre) — those may live in separate modules later.

## Documentation

Full API reference: [pkg.go.dev/github.com/tomi77/zmq4](https://pkg.go.dev/github.com/tomi77/zmq4)

Design documents: [`docs/specs/`](./docs/specs/)

## License

[MIT](./LICENSE)
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs(F7b): rewrite README — installation, patterns, security"
```

---

### Task 16: modernize, staticcheck, final suite

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
git commit -m "chore(F7b): modernize -fix"
```

(Skip if no changes.)

- [ ] **Step 4: Run full suite**

```
go test -race -count=1 ./...
```

Expected: all pass.

---

### Task 17: Update meta-overview + phase tag

**Files:**
- Modify: `docs/specs/00-meta-overview.md`

- [ ] **Step 1: Update the status line at the top of `docs/specs/00-meta-overview.md`**

Change:

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

To:

```
> **Status:** living document. F1, F2a, F2b, F2c, F3, F4, F5a, F5b, F5c, F6a, F6b, F6c, F6d, F7a, and F7b complete
> and tagged (`phase-1-wire-complete`, `phase-2a-null-complete`,
> `phase-2b-plain-complete`, `phase-2c-curve-complete`,
> `phase-3-transport-complete`, `phase-4-conn-complete`,
> `phase-5a-reqrep-complete`, `phase-5b-pubsub-complete`,
> `phase-5c-pipeline-pair-complete`, `phase-6a-hwm-complete`,
> `phase-6b-zap-complete`, `phase-6c-monitoring-complete`,
> `phase-6d-polling-complete`, `phase-7a-api-stabilization-complete`,
> `phase-7b-docs-examples-complete`).
```

Also update the date: `(last updated 2026-05-12)` stays the same.

- [ ] **Step 2: Add F7b row to the phase table**

After the F7a row, add:

```
| F7b | — | Documentation and examples: godoc gap-fill, `Example*` functions for all socket types, standalone programs under `examples/`, README rewrite. | `go test -run Example ./...`, `go build ./examples/...`, `staticcheck ./...`. | **Complete** — tagged `phase-7b-docs-examples-complete`. |
```

- [ ] **Step 3: Commit meta-overview update**

```bash
git add docs/specs/00-meta-overview.md
git commit -m "docs(F7b): update meta-overview — F7b complete"
```

- [ ] **Step 4: Tag the phase**

```bash
git tag phase-7b-docs-examples-complete
```
