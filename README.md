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
