# F8 Benchmarks Implementation Plan

> **For Claude:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dodaj moduł `benchmarks/` mierzący przepustowość i latencję wszystkich wzorców gniazd dla tomi77/zmq4, go-zeromq/zmq4 i pebbe/zmq4.

**Architecture:** Osobny moduł Go (`benchmarks/`) z `replace` dyrektywą na lokalne `../`. Wspólny harness definiuje interfejsy `Socket` i `Adapter`; każda implementacja dostarcza adapter w osobnym pliku `_test.go`. Benchmarki iterują po adapterach × transportach × rozmiarach wiadomości.

**Tech Stack:** Go 1.26, `testing.B`, `benchstat`, `go-zeromq/zmq4`, `pebbe/zmq4` (cgo, build tag `libzmq`).

---

## Chunk 1: Szkielet modułu i harness

### Task 1: Utwórz strukturę katalogów i `doc.go`

**Files:**
- Create: `benchmarks/doc.go`
- Create: `benchmarks/scripts/compare.sh`

- [ ] **Krok 1: Utwórz `benchmarks/doc.go`**

```go
// Package bench contains cross-implementation benchmarks for zmq4.
package bench
```

- [ ] **Krok 2: Utwórz `benchmarks/scripts/compare.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== tomi77 vs go-zeromq ==="
go test -bench=. -benchmem -count=6 ./... 2>/dev/null \
  | tee /tmp/bench_all.txt

if command -v benchstat &>/dev/null; then
  grep '/tomi77/' /tmp/bench_all.txt > /tmp/bench_tomi77.txt
  grep '/gozeromq/' /tmp/bench_all.txt > /tmp/bench_gozeromq.txt
  benchstat /tmp/bench_tomi77.txt /tmp/bench_gozeromq.txt
else
  echo "Install benchstat: go install golang.org/x/perf/cmd/benchstat@latest"
fi
```

```bash
chmod +x benchmarks/scripts/compare.sh
```

- [ ] **Krok 3: Commit**

```bash
git add benchmarks/doc.go benchmarks/scripts/compare.sh
git commit -m "chore(F8): scaffold benchmarks module directory"
```

---

### Task 2: Utwórz `benchmarks/go.mod`

**Files:**
- Create: `benchmarks/go.mod`

- [ ] **Krok 1: Zainicjuj moduł**

```bash
cd benchmarks
go mod init github.com/tomi77/zmq4/benchmarks
go get github.com/go-zeromq/zmq4@latest
go mod edit -replace github.com/tomi77/zmq4=../
go get github.com/tomi77/zmq4@v0.0.0-00010101000000-000000000000
```

`go.mod` powinien zawierać:
```
module github.com/tomi77/zmq4/benchmarks

go 1.26

require (
    github.com/go-zeromq/zmq4 v0.x.x
    github.com/tomi77/zmq4 v0.0.0-00010101000000-000000000000
)

replace github.com/tomi77/zmq4 => ../
```

Pebbe dodamy dopiero w Task 9 (wymaga libzmq na CI).

- [ ] **Krok 2: Weryfikacja**

```bash
cd benchmarks && go build ./...
```

Oczekiwane: brak błędów (pakiet `bench` jest pusty poza `doc.go`).

- [ ] **Krok 3: Commit**

```bash
git add benchmarks/go.mod benchmarks/go.sum
git commit -m "chore(F8): add benchmarks go.mod with go-zeromq dependency"
```

---

### Task 3: Napisz harness (`benchmarks/harness_test.go`)

**Files:**
- Create: `benchmarks/harness_test.go`

- [ ] **Krok 1: Napisz plik**

```go
package bench_test

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// ErrNotSupported zwraca adapter gdy dany transport jest nieobsługiwany.
var ErrNotSupported = errors.New("transport not supported")

// Socket — minimalny interfejs wspólny dla wszystkich wzorców.
type Socket interface {
	Send(msg []byte) error
	Recv() ([]byte, error)
	Close() error
}

// Adapter — każda implementacja dostarcza jeden egzemplarz.
type Adapter interface {
	Name() string
	// Każda metoda zwraca (bind_socket, connect_socket, cleanup, err).
	// Zwróć ErrNotSupported jeśli transport jest nieobsługiwany.
	PushPull(addr string) (Socket, Socket, func(), error)
	ReqRep(addr string) (Socket, Socket, func(), error)
	PubSub(addr string, topic []byte) (Socket, Socket, func(), error)
	Pair(addr string) (Socket, Socket, func(), error)
}

var adapters []Adapter

func registerAdapter(a Adapter) { adapters = append(adapters, a) }

var inprocCounter atomic.Int64

func inprocAddr() string {
	return fmt.Sprintf("inproc://bench-%d", inprocCounter.Add(1))
}

func tcpAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := l.Addr().String()
	l.Close()
	return "tcp://" + addr
}

var benchTransports = []struct {
	name    string
	addrFn  func() string
}{
	{"inproc", inprocAddr},
	{"tcp", tcpAddr},
}

var benchSizes = []int{64, 1024, 65536, 1 << 20}

func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return "1MiB"
	case n >= 1<<16:
		return "64KiB"
	case n >= 1<<10:
		return "1KiB"
	default:
		return "64B"
	}
}

// benchThroughput mierzy przepustowość: sender wysyła b.N wiadomości,
// receiver czyta w goroutine.
func benchThroughput(b *testing.B, sender, receiver Socket, msgSize int) {
	b.Helper()
	msg := make([]byte, msgSize)
	for i := range msg {
		msg[i] = 0x42
	}
	b.SetBytes(int64(msgSize))
	b.ReportAllocs()

	errCh := make(chan error, 1)
	go func() {
		for i := 0; i < b.N; i++ {
			if _, err := receiver.Recv(); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sender.Send(msg); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if err := <-errCh; err != nil {
		b.Fatal(err)
	}
}

// benchRoundTrip mierzy latencję round-trip: req wysyła + czeka na odpowiedź,
// rep echo-pętla w goroutine.
func benchRoundTrip(b *testing.B, req, rep Socket, msgSize int) {
	b.Helper()
	msg := make([]byte, msgSize)
	for i := range msg {
		msg[i] = 0x42
	}
	b.SetBytes(int64(msgSize * 2))
	b.ReportAllocs()

	// Rep echo-goroutine
	go func() {
		for {
			data, err := rep.Recv()
			if err != nil {
				return
			}
			if err := rep.Send(data); err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := req.Send(msg); err != nil {
			b.Fatal(err)
		}
		if _, err := req.Recv(); err != nil {
			b.Fatal(err)
		}
	}
}

// waitReady daje czas na propagację połączenia/subskrypcji.
func waitReady(d time.Duration) { time.Sleep(d) }

// skipIfNotSupported pomija benchmark gdy adapter nie obsługuje transportu.
func skipIfNotSupported(b *testing.B, err error) bool {
	b.Helper()
	if errors.Is(err, ErrNotSupported) {
		b.Skipf("adapter does not support this transport")
		return true
	}
	return false
}
```

- [ ] **Krok 2: Sprawdź kompilację**

```bash
cd benchmarks && go test -run=^$ ./...
```

Oczekiwane: `[no test files]` lub `ok` — brak błędów kompilacji.

- [ ] **Krok 3: Commit**

```bash
git add benchmarks/harness_test.go
git commit -m "feat(F8): add benchmark harness interfaces and helpers"
```

---

## Chunk 2: Funkcje benchmarkujące

### Task 4: PUSH/PULL (`benchmarks/push_pull_bench_test.go`)

**Files:**
- Create: `benchmarks/push_pull_bench_test.go`

- [ ] **Krok 1: Napisz plik**

```go
package bench_test

import "testing"

func BenchmarkPushPull(b *testing.B) {
	for _, a := range adapters {
		b.Run(a.Name(), func(b *testing.B) {
			for _, tr := range benchTransports {
				b.Run(tr.name, func(b *testing.B) {
					for _, sz := range benchSizes {
						b.Run(humanSize(sz), func(b *testing.B) {
							push, pull, cleanup, err := a.PushPull(tr.addrFn())
							if skipIfNotSupported(b, err) {
								return
							}
							if err != nil {
								b.Fatalf("PushPull setup: %v", err)
							}
							defer cleanup()
							waitReady(5 * 1e6) // 5ms
							benchThroughput(b, push, pull, sz)
						})
					}
				})
			}
		})
	}
}
```

- [ ] **Krok 2: Weryfikacja kompilacji**

```bash
cd benchmarks && go test -run=^$ ./...
```

- [ ] **Krok 3: Commit**

```bash
git add benchmarks/push_pull_bench_test.go
git commit -m "feat(F8): add PUSH/PULL benchmark"
```

---

### Task 5: REQ/REP (`benchmarks/req_rep_bench_test.go`)

**Files:**
- Create: `benchmarks/req_rep_bench_test.go`

- [ ] **Krok 1: Napisz plik**

```go
package bench_test

import "testing"

func BenchmarkReqRep(b *testing.B) {
	for _, a := range adapters {
		b.Run(a.Name(), func(b *testing.B) {
			for _, tr := range benchTransports {
				b.Run(tr.name, func(b *testing.B) {
					for _, sz := range benchSizes {
						b.Run(humanSize(sz), func(b *testing.B) {
							req, rep, cleanup, err := a.ReqRep(tr.addrFn())
							if skipIfNotSupported(b, err) {
								return
							}
							if err != nil {
								b.Fatalf("ReqRep setup: %v", err)
							}
							defer cleanup()
							waitReady(5 * 1e6)
							benchRoundTrip(b, req, rep, sz)
						})
					}
				})
			}
		})
	}
}
```

- [ ] **Krok 2: Weryfikacja**

```bash
cd benchmarks && go test -run=^$ ./...
```

- [ ] **Krok 3: Commit**

```bash
git add benchmarks/req_rep_bench_test.go
git commit -m "feat(F8): add REQ/REP benchmark"
```

---

### Task 6: PUB/SUB (`benchmarks/pub_sub_bench_test.go`)

**Files:**
- Create: `benchmarks/pub_sub_bench_test.go`

- [ ] **Krok 1: Napisz plik**

```go
package bench_test

import "testing"

func BenchmarkPubSub(b *testing.B) {
	topic := []byte("bench")
	for _, a := range adapters {
		b.Run(a.Name(), func(b *testing.B) {
			for _, tr := range benchTransports {
				b.Run(tr.name, func(b *testing.B) {
					for _, sz := range benchSizes {
						b.Run(humanSize(sz), func(b *testing.B) {
							pub, sub, cleanup, err := a.PubSub(tr.addrFn(), topic)
							if skipIfNotSupported(b, err) {
								return
							}
							if err != nil {
								b.Fatalf("PubSub setup: %v", err)
							}
							defer cleanup()
							// Dłuższy czas na propagację subskrypcji.
							waitReady(50 * 1e6) // 50ms
							benchThroughput(b, pub, sub, sz)
						})
					}
				})
			}
		})
	}
}
```

- [ ] **Krok 2: Weryfikacja**

```bash
cd benchmarks && go test -run=^$ ./...
```

- [ ] **Krok 3: Commit**

```bash
git add benchmarks/pub_sub_bench_test.go
git commit -m "feat(F8): add PUB/SUB benchmark"
```

---

### Task 7: PAIR (`benchmarks/pair_bench_test.go`)

**Files:**
- Create: `benchmarks/pair_bench_test.go`

- [ ] **Krok 1: Napisz plik**

```go
package bench_test

import "testing"

func BenchmarkPair(b *testing.B) {
	for _, a := range adapters {
		b.Run(a.Name(), func(b *testing.B) {
			for _, tr := range benchTransports {
				b.Run(tr.name, func(b *testing.B) {
					for _, sz := range benchSizes {
						b.Run(humanSize(sz), func(b *testing.B) {
							a1, a2, cleanup, err := a.Pair(tr.addrFn())
							if skipIfNotSupported(b, err) {
								return
							}
							if err != nil {
								b.Fatalf("Pair setup: %v", err)
							}
							defer cleanup()
							waitReady(5 * 1e6)
							// PAIR: mierzymy throughput w jednym kierunku.
							benchThroughput(b, a1, a2, sz)
						})
					}
				})
			}
		})
	}
}
```

- [ ] **Krok 2: Weryfikacja**

```bash
cd benchmarks && go test -run=^$ ./...
```

- [ ] **Krok 3: Commit**

```bash
git add benchmarks/pair_bench_test.go
git commit -m "feat(F8): add PAIR benchmark"
```

---

## Chunk 3: Adaptery

### Task 8: Adapter tomi77/zmq4 (`benchmarks/tomi77_test.go`)

**Files:**
- Create: `benchmarks/tomi77_test.go`

tomi77 API: `zmq4.NewPUSH/PULL/REQ/REP/PUB/SUB/PAIR(opts...)`, `s.Bind(ctx, addr)`, `s.Connect(ctx, addr)`, `s.Send(ctx, zmq4.NewMsg(data))`, `s.Recv(ctx)` → `(Message, error)`, `m.Frame(0)` → `[]byte`, `sub.Subscribe(string)`.

- [ ] **Krok 1: Napisz plik**

```go
package bench_test

import (
	"context"
	"fmt"

	zmq4 "github.com/tomi77/zmq4"
)

func init() { registerAdapter(tomi77Adapter{}) }

type tomi77Adapter struct{}

func (tomi77Adapter) Name() string { return "tomi77" }

// tomi77Socket opakowuje dowolny socket tomi77 w interfejs Socket.
type tomi77Socket struct {
	send func([]byte) error
	recv func() ([]byte, error)
	close func() error
}

func (s *tomi77Socket) Send(msg []byte) error       { return s.send(msg) }
func (s *tomi77Socket) Recv() ([]byte, error)       { return s.recv() }
func (s *tomi77Socket) Close() error                { return s.close() }

func (tomi77Adapter) PushPull(addr string) (Socket, Socket, func(), error) {
	ctx := context.Background()
	push := zmq4.NewPUSH()
	pull := zmq4.NewPULL()
	if err := push.Bind(ctx, addr); err != nil {
		return nil, nil, nil, fmt.Errorf("push bind: %w", err)
	}
	if err := pull.Connect(ctx, addr); err != nil {
		push.Close()
		return nil, nil, nil, fmt.Errorf("pull connect: %w", err)
	}
	sender := &tomi77Socket{
		send:  func(b []byte) error { return push.Send(ctx, zmq4.NewMsg(b)) },
		recv:  func() ([]byte, error) { panic("push cannot recv") },
		close: push.Close,
	}
	receiver := &tomi77Socket{
		send:  func(b []byte) error { panic("pull cannot send") },
		recv:  func() ([]byte, error) { m, err := pull.Recv(ctx); if err != nil { return nil, err }; return m.Frame(0), nil },
		close: pull.Close,
	}
	cleanup := func() { push.Close(); pull.Close() }
	return sender, receiver, cleanup, nil
}

func (tomi77Adapter) ReqRep(addr string) (Socket, Socket, func(), error) {
	ctx := context.Background()
	req := zmq4.NewREQ()
	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, addr); err != nil {
		return nil, nil, nil, fmt.Errorf("rep bind: %w", err)
	}
	if err := req.Connect(ctx, addr); err != nil {
		rep.Close()
		return nil, nil, nil, fmt.Errorf("req connect: %w", err)
	}
	reqSock := &tomi77Socket{
		send:  func(b []byte) error { return req.Send(ctx, zmq4.NewMsg(b)) },
		recv:  func() ([]byte, error) { m, err := req.Recv(ctx); if err != nil { return nil, err }; return m.Frame(0), nil },
		close: req.Close,
	}
	repSock := &tomi77Socket{
		send:  func(b []byte) error { return rep.Send(ctx, zmq4.NewMsg(b)) },
		recv:  func() ([]byte, error) { m, err := rep.Recv(ctx); if err != nil { return nil, err }; return m.Frame(0), nil },
		close: rep.Close,
	}
	cleanup := func() { req.Close(); rep.Close() }
	return reqSock, repSock, cleanup, nil
}

func (tomi77Adapter) PubSub(addr string, topic []byte) (Socket, Socket, func(), error) {
	ctx := context.Background()
	pub := zmq4.NewPUB()
	sub := zmq4.NewSUB()
	if err := pub.Bind(ctx, addr); err != nil {
		return nil, nil, nil, fmt.Errorf("pub bind: %w", err)
	}
	if err := sub.Connect(ctx, addr); err != nil {
		pub.Close()
		return nil, nil, nil, fmt.Errorf("sub connect: %w", err)
	}
	if err := sub.Subscribe(string(topic)); err != nil {
		pub.Close(); sub.Close()
		return nil, nil, nil, fmt.Errorf("subscribe: %w", err)
	}
	// PubSub: wiadomość zawiera prefix tematu + payload
	pubSock := &tomi77Socket{
		send: func(b []byte) error {
			frame := append(append([]byte(nil), topic...), b...)
			return pub.Send(ctx, zmq4.NewMsg(frame))
		},
		recv:  func() ([]byte, error) { panic("pub cannot recv") },
		close: pub.Close,
	}
	subSock := &tomi77Socket{
		send:  func(b []byte) error { panic("sub cannot send") },
		recv:  func() ([]byte, error) { m, err := sub.Recv(ctx); if err != nil { return nil, err }; return m.Frame(0), nil },
		close: sub.Close,
	}
	cleanup := func() { pub.Close(); sub.Close() }
	return pubSock, subSock, cleanup, nil
}

func (tomi77Adapter) Pair(addr string) (Socket, Socket, func(), error) {
	ctx := context.Background()
	a := zmq4.NewPAIR()
	c := zmq4.NewPAIR()
	if err := a.Bind(ctx, addr); err != nil {
		return nil, nil, nil, fmt.Errorf("pair bind: %w", err)
	}
	if err := c.Connect(ctx, addr); err != nil {
		a.Close()
		return nil, nil, nil, fmt.Errorf("pair connect: %w", err)
	}
	wrap := func(s interface {
		Send(context.Context, zmq4.Message) error
		Recv(context.Context) (zmq4.Message, error)
		Close() error
	}) *tomi77Socket {
		return &tomi77Socket{
			send:  func(b []byte) error { return s.Send(ctx, zmq4.NewMsg(b)) },
			recv:  func() ([]byte, error) { m, err := s.Recv(ctx); if err != nil { return nil, err }; return m.Frame(0), nil },
			close: s.Close,
		}
	}
	cleanup := func() { a.Close(); c.Close() }
	return wrap(a), wrap(c), cleanup, nil
}
```

Uwaga: `zmq4.NewPUB()` i `zmq4.NewSUB()` — sprawdź czy konstruktory nazywają się dokładnie tak samo jak PUSH/PULL (bez kontekstu). Jeśli API wymaga opcji zamiast braku argumentów, przekaż pusty zestaw opcji.

- [ ] **Krok 2: Skompiluj**

```bash
cd benchmarks && go build ./...
```

Oczekiwane: brak błędów.

- [ ] **Krok 3: Uruchom benchmarki (tylko tomi77, tylko PUSH/PULL, mały rozmiar)**

```bash
cd benchmarks && go test -bench=BenchmarkPushPull/tomi77/inproc/64B -benchtime=1s ./...
```

Oczekiwane: wyniki ns/op, brak panik.

- [ ] **Krok 4: Commit**

```bash
git add benchmarks/tomi77_test.go
git commit -m "feat(F8): add tomi77 benchmark adapter"
```

---

### Task 9: Adapter go-zeromq/zmq4 (`benchmarks/gozeromq_test.go`)

**Files:**
- Create: `benchmarks/gozeromq_test.go`

go-zeromq API: `zmq4.NewPush(ctx)`, `s.Listen(addr)`, `s.Dial(addr)`, `s.Send(zmq4.NewMsg(data))`, `s.Recv() (zmq4.Msg, error)`, `msg.Frames[0]` → `[]byte`, `s.SetOption(zmq4.OptionSubscribe, topic)`.

- [ ] **Krok 1: Napisz plik**

```go
package bench_test

import (
	"context"
	"fmt"

	gozmq "github.com/go-zeromq/zmq4"
)

func init() { registerAdapter(gozeromqAdapter{}) }

type gozeromqAdapter struct{}

func (gozeromqAdapter) Name() string { return "gozeromq" }

type gozeromqSocket struct {
	send  func([]byte) error
	recv  func() ([]byte, error)
	close func() error
}

func (s *gozeromqSocket) Send(msg []byte) error  { return s.send(msg) }
func (s *gozeromqSocket) Recv() ([]byte, error)  { return s.recv() }
func (s *gozeromqSocket) Close() error           { return s.close() }

func (gozeromqAdapter) PushPull(addr string) (Socket, Socket, func(), error) {
	ctx := context.Background()
	push := gozmq.NewPush(ctx)
	pull := gozmq.NewPull(ctx)
	if err := push.Listen(addr); err != nil {
		return nil, nil, nil, fmt.Errorf("push listen: %w", err)
	}
	if err := pull.Dial(addr); err != nil {
		push.Close()
		return nil, nil, nil, fmt.Errorf("pull dial: %w", err)
	}
	sender := &gozeromqSocket{
		send:  func(b []byte) error { return push.Send(gozmq.NewMsg(b)) },
		recv:  func() ([]byte, error) { panic("push cannot recv") },
		close: push.Close,
	}
	receiver := &gozeromqSocket{
		send:  func(b []byte) error { panic("pull cannot send") },
		recv:  func() ([]byte, error) { m, err := pull.Recv(); if err != nil { return nil, err }; return m.Frames[0], nil },
		close: pull.Close,
	}
	cleanup := func() { push.Close(); pull.Close() }
	return sender, receiver, cleanup, nil
}

func (gozeromqAdapter) ReqRep(addr string) (Socket, Socket, func(), error) {
	ctx := context.Background()
	rep := gozmq.NewRep(ctx)
	req := gozmq.NewReq(ctx)
	if err := rep.Listen(addr); err != nil {
		return nil, nil, nil, fmt.Errorf("rep listen: %w", err)
	}
	if err := req.Dial(addr); err != nil {
		rep.Close()
		return nil, nil, nil, fmt.Errorf("req dial: %w", err)
	}
	reqSock := &gozeromqSocket{
		send:  func(b []byte) error { return req.Send(gozmq.NewMsg(b)) },
		recv:  func() ([]byte, error) { m, err := req.Recv(); if err != nil { return nil, err }; return m.Frames[0], nil },
		close: req.Close,
	}
	repSock := &gozeromqSocket{
		send:  func(b []byte) error { return rep.Send(gozmq.NewMsg(b)) },
		recv:  func() ([]byte, error) { m, err := rep.Recv(); if err != nil { return nil, err }; return m.Frames[0], nil },
		close: rep.Close,
	}
	cleanup := func() { req.Close(); rep.Close() }
	return reqSock, repSock, cleanup, nil
}

func (gozeromqAdapter) PubSub(addr string, topic []byte) (Socket, Socket, func(), error) {
	ctx := context.Background()
	pub := gozmq.NewPub(ctx)
	sub := gozmq.NewSub(ctx)
	if err := pub.Listen(addr); err != nil {
		return nil, nil, nil, fmt.Errorf("pub listen: %w", err)
	}
	if err := sub.Dial(addr); err != nil {
		pub.Close()
		return nil, nil, nil, fmt.Errorf("sub dial: %w", err)
	}
	if err := sub.SetOption(gozmq.OptionSubscribe, string(topic)); err != nil {
		pub.Close(); sub.Close()
		return nil, nil, nil, fmt.Errorf("subscribe: %w", err)
	}
	pubSock := &gozeromqSocket{
		send: func(b []byte) error {
			frame := append(append([]byte(nil), topic...), b...)
			return pub.Send(gozmq.NewMsg(frame))
		},
		recv:  func() ([]byte, error) { panic("pub cannot recv") },
		close: pub.Close,
	}
	subSock := &gozeromqSocket{
		send:  func(b []byte) error { panic("sub cannot send") },
		recv:  func() ([]byte, error) { m, err := sub.Recv(); if err != nil { return nil, err }; return m.Frames[0], nil },
		close: sub.Close,
	}
	cleanup := func() { pub.Close(); sub.Close() }
	return pubSock, subSock, cleanup, nil
}

func (gozeromqAdapter) Pair(addr string) (Socket, Socket, func(), error) {
	ctx := context.Background()
	a := gozmq.NewPair(ctx)
	c := gozmq.NewPair(ctx)
	if err := a.Listen(addr); err != nil {
		return nil, nil, nil, fmt.Errorf("pair listen: %w", err)
	}
	if err := c.Dial(addr); err != nil {
		a.Close()
		return nil, nil, nil, fmt.Errorf("pair dial: %w", err)
	}
	wrap := func(s gozmq.Socket) *gozeromqSocket {
		return &gozeromqSocket{
			send:  func(b []byte) error { return s.Send(gozmq.NewMsg(b)) },
			recv:  func() ([]byte, error) { m, err := s.Recv(); if err != nil { return nil, err }; return m.Frames[0], nil },
			close: s.Close,
		}
	}
	cleanup := func() { a.Close(); c.Close() }
	return wrap(a), wrap(c), cleanup, nil
}
```

- [ ] **Krok 2: Skompiluj i uruchom**

```bash
cd benchmarks && go build ./...
go test -bench=BenchmarkPushPull/gozeromq/inproc/64B -benchtime=1s ./...
```

- [ ] **Krok 3: Commit**

```bash
git add benchmarks/gozeromq_test.go
git commit -m "feat(F8): add go-zeromq benchmark adapter"
```

---

### Task 10: Adapter pebbe/zmq4 (`benchmarks/pebbe_test.go`, build tag `libzmq`)

**Files:**
- Create: `benchmarks/pebbe_test.go`

pebbe API: `zmq4.NewSocket(zmq4.PUSH)` → `(*zmq4.Socket, error)`, `s.Bind(addr)`, `s.Connect(addr)`, `s.SendBytes(data, 0)`, `s.RecvBytes(0)`, `s.SetSubscribe(topic)`, `s.Close()`. Nie obsługuje `inproc` w tej samej formie — dla `inproc` zwróć `ErrNotSupported`.

- [ ] **Krok 1: Dodaj pebbe do go.mod**

```bash
cd benchmarks
go get github.com/pebbe/zmq4@latest
```

- [ ] **Krok 2: Napisz plik**

```go
//go:build libzmq

package bench_test

import (
	"fmt"

	pebbe "github.com/pebbe/zmq4"
)

func init() { registerAdapter(pebbeAdapter{}) }

type pebbeAdapter struct{}

func (pebbeAdapter) Name() string { return "pebbe" }

type pebbeSocket struct {
	send  func([]byte) error
	recv  func() ([]byte, error)
	close func() error
}

func (s *pebbeSocket) Send(msg []byte) error { return s.send(msg) }
func (s *pebbeSocket) Recv() ([]byte, error) { return s.recv() }
func (s *pebbeSocket) Close() error          { return s.close() }

func isInproc(addr string) bool {
	return len(addr) > 8 && addr[:8] == "inproc:/"
}

func (pebbeAdapter) PushPull(addr string) (Socket, Socket, func(), error) {
	if isInproc(addr) {
		return nil, nil, nil, ErrNotSupported
	}
	push, err := pebbe.NewSocket(pebbe.PUSH)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new PUSH: %w", err)
	}
	pull, err := pebbe.NewSocket(pebbe.PULL)
	if err != nil {
		push.Close()
		return nil, nil, nil, fmt.Errorf("new PULL: %w", err)
	}
	if err := push.Bind(addr); err != nil {
		push.Close(); pull.Close()
		return nil, nil, nil, fmt.Errorf("push bind: %w", err)
	}
	if err := pull.Connect(addr); err != nil {
		push.Close(); pull.Close()
		return nil, nil, nil, fmt.Errorf("pull connect: %w", err)
	}
	sender := &pebbeSocket{
		send:  func(b []byte) error { _, err := push.SendBytes(b, 0); return err },
		recv:  func() ([]byte, error) { panic("push cannot recv") },
		close: func() error { push.Close(); return nil },
	}
	receiver := &pebbeSocket{
		send:  func(b []byte) error { panic("pull cannot send") },
		recv:  func() ([]byte, error) { return pull.RecvBytes(0) },
		close: func() error { pull.Close(); return nil },
	}
	cleanup := func() { push.Close(); pull.Close() }
	return sender, receiver, cleanup, nil
}

func (pebbeAdapter) ReqRep(addr string) (Socket, Socket, func(), error) {
	if isInproc(addr) {
		return nil, nil, nil, ErrNotSupported
	}
	req, err := pebbe.NewSocket(pebbe.REQ)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new REQ: %w", err)
	}
	rep, err := pebbe.NewSocket(pebbe.REP)
	if err != nil {
		req.Close()
		return nil, nil, nil, fmt.Errorf("new REP: %w", err)
	}
	if err := rep.Bind(addr); err != nil {
		req.Close(); rep.Close()
		return nil, nil, nil, fmt.Errorf("rep bind: %w", err)
	}
	if err := req.Connect(addr); err != nil {
		req.Close(); rep.Close()
		return nil, nil, nil, fmt.Errorf("req connect: %w", err)
	}
	reqSock := &pebbeSocket{
		send:  func(b []byte) error { _, err := req.SendBytes(b, 0); return err },
		recv:  func() ([]byte, error) { return req.RecvBytes(0) },
		close: func() error { req.Close(); return nil },
	}
	repSock := &pebbeSocket{
		send:  func(b []byte) error { _, err := rep.SendBytes(b, 0); return err },
		recv:  func() ([]byte, error) { return rep.RecvBytes(0) },
		close: func() error { rep.Close(); return nil },
	}
	cleanup := func() { req.Close(); rep.Close() }
	return reqSock, repSock, cleanup, nil
}

func (pebbeAdapter) PubSub(addr string, topic []byte) (Socket, Socket, func(), error) {
	if isInproc(addr) {
		return nil, nil, nil, ErrNotSupported
	}
	pub, err := pebbe.NewSocket(pebbe.PUB)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new PUB: %w", err)
	}
	sub, err := pebbe.NewSocket(pebbe.SUB)
	if err != nil {
		pub.Close()
		return nil, nil, nil, fmt.Errorf("new SUB: %w", err)
	}
	if err := pub.Bind(addr); err != nil {
		pub.Close(); sub.Close()
		return nil, nil, nil, fmt.Errorf("pub bind: %w", err)
	}
	if err := sub.Connect(addr); err != nil {
		pub.Close(); sub.Close()
		return nil, nil, nil, fmt.Errorf("sub connect: %w", err)
	}
	if err := sub.SetSubscribe(string(topic)); err != nil {
		pub.Close(); sub.Close()
		return nil, nil, nil, fmt.Errorf("subscribe: %w", err)
	}
	pubSock := &pebbeSocket{
		send: func(b []byte) error {
			frame := append(append([]byte(nil), topic...), b...)
			_, err := pub.SendBytes(frame, 0)
			return err
		},
		recv:  func() ([]byte, error) { panic("pub cannot recv") },
		close: func() error { pub.Close(); return nil },
	}
	subSock := &pebbeSocket{
		send:  func(b []byte) error { panic("sub cannot send") },
		recv:  func() ([]byte, error) { return sub.RecvBytes(0) },
		close: func() error { sub.Close(); return nil },
	}
	cleanup := func() { pub.Close(); sub.Close() }
	return pubSock, subSock, cleanup, nil
}

func (pebbeAdapter) Pair(addr string) (Socket, Socket, func(), error) {
	if isInproc(addr) {
		return nil, nil, nil, ErrNotSupported
	}
	a, err := pebbe.NewSocket(pebbe.PAIR)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new PAIR a: %w", err)
	}
	c, err := pebbe.NewSocket(pebbe.PAIR)
	if err != nil {
		a.Close()
		return nil, nil, nil, fmt.Errorf("new PAIR c: %w", err)
	}
	if err := a.Bind(addr); err != nil {
		a.Close(); c.Close()
		return nil, nil, nil, fmt.Errorf("pair bind: %w", err)
	}
	if err := c.Connect(addr); err != nil {
		a.Close(); c.Close()
		return nil, nil, nil, fmt.Errorf("pair connect: %w", err)
	}
	wrap := func(s *pebbe.Socket) *pebbeSocket {
		return &pebbeSocket{
			send:  func(b []byte) error { _, err := s.SendBytes(b, 0); return err },
			recv:  func() ([]byte, error) { return s.RecvBytes(0) },
			close: func() error { s.Close(); return nil },
		}
	}
	cleanup := func() { a.Close(); c.Close() }
	return wrap(a), wrap(c), cleanup, nil
}
```

- [ ] **Krok 3: Sprawdź kompilację bez tagu (pebbe nie kompiluje się)**

```bash
cd benchmarks && go build ./...
```

Oczekiwane: brak błędów — `pebbe_test.go` wykluczone przez build tag.

- [ ] **Krok 4: Sprawdź kompilację z tagiem (wymaga libzmq)**

```bash
cd benchmarks && go build -tags libzmq ./...
```

Oczekiwane: brak błędów (jeśli libzmq zainstalowane). Jeśli niedostępne — pomiń ten krok.

- [ ] **Krok 5: Commit**

```bash
git add benchmarks/pebbe_test.go benchmarks/go.mod benchmarks/go.sum
git commit -m "feat(F8): add pebbe/zmq4 benchmark adapter (build tag: libzmq)"
```

---

## Chunk 4: Smoke test i finalizacja

### Task 11: Smoke test — uruchom wszystkie benchmarki

- [ ] **Krok 1: Uruchom krótki przebieg (tomi77 + gozeromq)**

```bash
cd benchmarks && go test -bench=. -benchtime=100ms ./...
```

Oczekiwane: brak panik, każdy benchmark produkuje wyniki (ns/op, B/op, allocs/op). Benchmarki `pebbe` pominięte bez tagu.

- [ ] **Krok 2: Sprawdź czy wszystkie wzorce działają**

Wyniki powinny zawierać linie dla każdego z:
```
BenchmarkPushPull/tomi77/inproc/64B
BenchmarkPushPull/tomi77/tcp/64B
BenchmarkPushPull/gozeromq/inproc/64B
BenchmarkReqRep/tomi77/...
BenchmarkPubSub/tomi77/...
BenchmarkPair/tomi77/...
```

- [ ] **Krok 3: Pełny przebieg (do benchstat)**

```bash
cd benchmarks && go test -bench=. -benchmem -count=6 ./... | tee /tmp/bench_results.txt
```

- [ ] **Krok 4: Commit końcowy**

```bash
git add benchmarks/
git commit -m "feat(F8): complete benchmarks module — all patterns, two transports, three impls"
```

---

## Uwagi implementacyjne

**go-zeromq inproc:** go-zeromq/zmq4 używa własnego transportu inproc (Go channels). Może wymagać specjalnego formatu adresu lub nie obsługiwać tego transportu — jeśli `Listen("inproc://...")` zwraca błąd, dodaj `ErrNotSupported`.

**tomi77 PUB/SUB inproc:** `inproc` w tomi77 jest synchroniczny. Subskrypcja jest wysyłana po `Connect`, więc 5ms `waitReady` może być niewystarczające — zwiększ do 50ms jeśli benchmarki nie dostają wiadomości.

**Port race w TCP:** `tcpAddr()` zwalnia port przed `Bind`. Przy równoległych benchmarkach możliwy konflikt. Jeśli pojawi się `address already in use`, dodaj `time.Sleep(1ms)` retry lub użyj unikalnego prefiksu IP (`127.x.0.1` gdzie `x` = counter).

**pebbe/zmq4 close:** `pebbe.Socket.Close()` jest `void`. Wrapper zwraca `nil`.

**Rozmiar PUB frame:** `Send` wysyła `topic + payload` jako jeden frame. `Sub.Recv` zwraca cały frame (topic + payload). Jeśli `benchThroughput` liczy tylko bajty payloadu, wyniki będą nieco zaniżone o `len(topic)`. Do porównania między implementacjami to nie ma znaczenia (wszystkie tak samo).
