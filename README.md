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

Measured on Apple M1 (darwin/arm64).
Compared against [go-zeromq/zmq4](https://github.com/go-zeromq/zmq4) v0.17.0 and [pebbe/zmq4](https://github.com/pebbe/zmq4) v1.4.0 (cgo wrapper over libzmq 4.3.5).
`go-zeromq` and `pebbe` support TCP only (inproc skipped).

```
# pure-Go only
cd benchmarks && go test -bench=. -benchtime=3s -benchmem
# include pebbe (requires libzmq)
cd benchmarks && go test -tags libzmq -bench=. -benchtime=3s -benchmem
```

### PAIR · one-way throughput (MB/s)

| Message size | tomi77 inproc | tomi77 tcp | go-zeromq tcp | pebbe tcp |
|---|--:|--:|--:|--:|
| 64 B   |    21.7 |    19.6 |     9.0 |   174   |
| 1 KiB  |   278   |   339   |   134   | 1 434   |
| 64 KiB | 3 977   | 2 928   | 3 928   | 3 445   |
| 1 MiB  | 6 257   | 5 467   | 6 363   | 4 844   |

### PUSH/PULL · one-way throughput (MB/s)

| Message size | tomi77 inproc | tomi77 tcp | go-zeromq tcp | pebbe tcp |
|---|--:|--:|--:|--:|
| 64 B   |    20.2 |    17.1 |     9.1 |   175   |
| 1 KiB  |   308   |   292   |   134   | 1 367   |
| 64 KiB | 4 041   | 3 347   | 3 759   | 3 326   |
| 1 MiB  | 6 990   | 4 802   | 6 315   | 4 849   |

### PUB/SUB · send-side throughput (MB/s) †

| Message size | tomi77 inproc | tomi77 tcp | go-zeromq tcp | pebbe tcp |
|---|--:|--:|--:|--:|
| 64 B   |    405  |    317  |    84.5 | n/a ‡ |
| 1 KiB  |  1 490  |  1 452  |   875   | n/a ‡ |
| 64 KiB |  5 998  |  6 041  | 1 260   | n/a ‡ |
| 1 MiB  | 10 754  | 11 420  | 2 609   | n/a ‡ |

† PUB drops messages when the outbound queue is full; numbers reflect send-side rate.  
‡ `pebbe/PubSub` triggers a libzmq internal assertion (`signaler.cpp:368`) under repeated close/reopen cycles and is excluded.

### REQ/REP · round-trip latency (µs/op)

| Message size | tomi77 inproc | tomi77 tcp | go-zeromq tcp | pebbe tcp |
|---|--:|--:|--:|--:|
| 64 B   |  10.7 |  36.1 |  38.0 |   84.8 |
| 1 KiB  |  10.7 |  38.5 |  40.5 |   88.7 |
| 64 KiB |  35.2 |  75.6 |  63.1 |  132.4 |
| 1 MiB  | 262   | 474   | 358   |  510   |

### Heap allocations per operation (tcp)

| Pattern   | tomi77 | go-zeromq | pebbe |
|---|--:|--:|--:|
| PAIR      |  8 | 26 | 1 |
| PUSH/PULL |  8 | 26 | 1 |
| PUB/SUB   | 5–9 | 10–54 | n/a |
| REQ/REP   | 20–21 | 32 | 4 |

## Non-goals (for now)

- Backwards compatibility with ZMTP 3.0 / 2.0 / 1.0.
- Draft socket types (`CLIENT`/`SERVER`, `RADIO`/`DISH`, `SCATTER`/`GATHER`, `STREAM`).
- Higher-level patterns (Majordomo, Clone, Freelance, Zyre) — those may live in separate modules later.

## Documentation

Full API reference: [pkg.go.dev/github.com/tomi77/zmq4](https://pkg.go.dev/github.com/tomi77/zmq4)

Design documents: [`docs/specs/`](./docs/specs/)

## License

[MIT](./LICENSE)
