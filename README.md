# zmq4

Pure-Go implementation of [ZeroMQ](https://zeromq.org/) speaking [ZMTP 3.1](https://rfc.zeromq.org/spec/23/).

> **Status:** early design phase. Nothing here is usable yet.

## Goals

- **Pure Go** — no `cgo`, no `libzmq` dependency.
- **Wire-level interoperability** with `libzmq` (≥ 4.2) speaking ZMTP 3.1.
- **Full coverage** of the core stack: ZMTP wire protocol, NULL/PLAIN/CURVE security, `tcp`/`ipc`/`inproc` transports, all standard socket types (`REQ`, `REP`, `ROUTER`, `DEALER`, `PUB`, `SUB`, `XPUB`, `XSUB`, `PUSH`, `PULL`, `PAIR`), ZAP authentication.
- **Layered, testable design** — each layer has its own spec, its own tests, and clear seams against the layers below it.

## Non-goals (for now)

- Backwards compatibility with ZMTP 3.0 / 2.0 / 1.0.
- Draft socket types (`CLIENT`/`SERVER`, `RADIO`/`DISH`, `SCATTER`/`GATHER`, `STREAM`).
- Higher-level patterns (Majordomo, Clone, Freelance, Zyre) — those may live in separate modules later.

## Documentation

- [`docs/specs/`](./docs/specs/) — design documents, one per phase.
- [`docs/specs/00-meta-overview.md`](./docs/specs/00-meta-overview.md) — overall project plan.

## License

[MIT](./LICENSE)
