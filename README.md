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

## Benchmarks

Measured on Apple M1 (darwin/arm64), Go 1.24.
Compared against [go-zeromq/zmq4](https://github.com/go-zeromq/zmq4) v0.17.0 and [pebbe/zmq4](https://github.com/pebbe/zmq4) v1.4.0 (cgo wrapper over libzmq 4.3.5).
`go-zeromq` and `pebbe` support TCP only (inproc skipped).

Each benchmark pattern runs in its own process (`-benchtime=3s -count=5`) so accumulated
GC pressure from earlier runs cannot skew later results. Numbers are medians across the 5
runs. Use `benchmarks/scripts/bench.sh` to reproduce.

```
cd benchmarks && ./scripts/bench.sh           # tomi77 + go-zeromq
cd benchmarks && ./scripts/bench.sh -tags libzmq  # include pebbe (requires libzmq)
```

### PAIR · one-way throughput (MB/s)

| Message size | tomi77 inproc | tomi77 tcp | go-zeromq tcp | pebbe tcp |
|---|--:|--:|--:|--:|
| 64 B   |         186 |    25.8 |     8.8 |   174   |
| 1 KiB  |       2 945 |   355   |   129   | 1 434   |
| 64 KiB |     169 237 | 4 514   | 3 570   | 3 445   |
| 1 MiB  | 2 603 733 † | 6 303   | 6 345   | 4 844   |

### PUSH/PULL · one-way throughput (MB/s)

| Message size | tomi77 inproc | tomi77 tcp | go-zeromq tcp | pebbe tcp |
|---|--:|--:|--:|--:|
| 64 B   |         159 |    15.5 |     7.4 |   175   |
| 1 KiB  |       2 837 |   254   |   101   | 1 367   |
| 64 KiB |     160 138 | 4 915   | 3 345   | 3 326   |
| 1 MiB  | 2 986 952 † | 7 160   | 6 332   | 4 849   |

### PUB/SUB · send-side throughput (MB/s) ‡

| Message size | tomi77 inproc | tomi77 tcp | go-zeromq tcp | pebbe tcp |
|---|--:|--:|--:|--:|
| 64 B   |   571   |   464   |    72.8 | n/a § |
| 1 KiB  | 2 182   | 1 473   |   705   | n/a § |
| 64 KiB | 6 177   | 6 014   |   926   | n/a § |
| 1 MiB  | 4 153   | 10 370  | 1 749   | n/a § |

† Inproc messages are delivered as Go channel values without copying bytes through
the wire — the reported MB/s reflects message-rate × size and is not bounded by memory
bandwidth.  
‡ PUB drops messages when the outbound queue is full; numbers reflect send-side rate and
have high run-to-run variance (±2×) due to the interaction between drop policy and
goroutine scheduling.  
§ `pebbe/PubSub` triggers a libzmq internal assertion (`signaler.cpp:368`) under repeated close/reopen cycles and is excluded.

### REQ/REP · round-trip latency (µs/op)

| Message size | tomi77 inproc | tomi77 tcp | go-zeromq tcp | pebbe tcp |
|---|--:|--:|--:|--:|
| 64 B   |  1.38 |  27.7 |  39.8 |   84.8 |
| 1 KiB  |  1.38 |  27.5 |  38.7 |   88.7 |
| 64 KiB |  1.45 |  52.4 |  59.2 |  132.4 |
| 1 MiB  |  1.38 | 278   | 311   |  510   |

### Heap allocations per operation (tcp)

| Pattern   | tomi77 | go-zeromq | pebbe |
|---|--:|--:|--:|
| PAIR      |  3 | 26 | 1 |
| PUSH/PULL |  3 | 26 | 1 |
| PUB/SUB   | 4–5 | 10–17 | n/a |
| REQ/REP   |  8 | 32 | 4 |

## Non-goals (for now)

- Backwards compatibility with ZMTP 3.0 / 2.0 / 1.0.
- Draft socket types (`CLIENT`/`SERVER`, `RADIO`/`DISH`, `SCATTER`/`GATHER`, `STREAM`).
- Higher-level patterns (Majordomo, Clone, Freelance, Zyre) — those may live in separate modules later.

## Documentation

Full API reference: [pkg.go.dev/github.com/tomi77/zmq4](https://pkg.go.dev/github.com/tomi77/zmq4)

Design documents: [`docs/specs/`](./docs/specs/)

## License

[MIT](./LICENSE)
