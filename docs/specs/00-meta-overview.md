# 00 — Meta-overview

> **Status:** living document. F1 and F2a complete and tagged
> (`phase-1-wire-complete`, `phase-2a-null-complete`); F2b spec drafted
> (`docs/specs/02b-security-plain.md`), implementation pending; later
> phases pending.
> **Author:** Tomasz Rup
> **Date:** 2026-05-02 (last updated 2026-05-03)

This document defines the overall plan for `github.com/tomi77/zmq4`: a pure-Go
implementation of [ZeroMQ](https://zeromq.org/) that speaks
[ZMTP 3.1](https://rfc.zeromq.org/spec/23/) and interoperates with `libzmq`.

It is the parent document for every other spec in `docs/specs/`. Each phase
gets its own design doc, but they all inherit the structure, conventions, and
testing strategy defined here.

---

## 1. Purpose

Existing Go implementations of ZeroMQ are unsatisfactory:

- [`github.com/go-zeromq/zmq4`](https://github.com/go-zeromq/zmq4) — pure Go,
  but unmaintained for ~2 years and missing features.
- [`github.com/pebbe/zmq4`](https://github.com/pebbe/zmq4) — `cgo` wrapper
  around `libzmq`. Not pure Go.

This project aims to provide a maintained, pure-Go, full implementation of the
ZeroMQ core protocol stack, suitable for production use.

## 2. Scope

### In scope

- **ZMTP 3.1** (RFC 23/ZMTP) wire protocol.
- **Security mechanisms**: NULL (RFC 23), PLAIN (RFC 24), CURVE (RFC 25/26).
- **Transports**: `tcp`, `ipc` (Unix domain sockets), `inproc`.
- **Standard socket types**: `REQ`, `REP`, `ROUTER`, `DEALER`, `PUB`, `SUB`,
  `XPUB`, `XSUB`, `PUSH`, `PULL`, `PAIR`.
- **ZAP** (RFC 27) authentication protocol.
- **Operational features**: high-water marks, monitoring events, polling.
- **Wire-level interoperability** with `libzmq` ≥ 4.2 (verified in CI).

### Out of scope (for now)

- Backwards compatibility with ZMTP 3.0, 2.0, or 1.0.
- Draft socket types: `CLIENT`/`SERVER`, `RADIO`/`DISH`, `SCATTER`/`GATHER`,
  `STREAM`.
- Higher-level patterns: Majordomo (RFC 7), Titanic, Clone, Freelance, Zyre.
  These may be added later in separate modules.
- Exotic transports: `tipc`, `vmci`, `udp`, `pgm`/`epgm`.

## 3. Architecture

The implementation is organized as strict layers. Each layer depends only on
the ones below it, and exposes a narrow interface to the ones above it. This
is enforced by package boundaries (`internal/...`).

```
                 ┌──────────────────────────────────────────┐
   public API   │  socket/   (REQ/REP/PUB/SUB/PUSH/PULL/…)  │  F5
                 └─────────────────────┬────────────────────┘
                                       │
                 ┌─────────────────────▼────────────────────┐
                 │  internal/conn/   (connection lifecycle, │  F4
                 │   binds together wire+security+transport) │
                 └─────────────────────┬────────────────────┘
                          ┌────────────┼────────────┐
                          ▼            ▼            ▼
                 ┌───────────┐ ┌────────────┐ ┌────────────┐
                 │ internal/ │ │  internal/ │ │ internal/  │
                 │   wire/   │ │  security/ │ │ transport/ │
                 │  (F1)     │ │   (F2)     │ │   (F3)     │
                 └───────────┘ └────────────┘ └────────────┘
                       │
                 ┌─────▼─────┐
                 │   zap/    │  F6 (cross-cutting; consumed by security)
                 └───────────┘
```

### Layer responsibilities

| Layer | Package | Responsibility | Forbidden dependencies |
|-------|---------|----------------|------------------------|
| L1 | `internal/wire` | ZMTP framing & greeting codec. Pure functions over byte buffers. | I/O primitives (`net.Dial`/`net.Listen`/`net.Conn`/socket types), goroutines, time. Passive helpers from `net` (e.g. `net.Buffers` as a writev batcher around caller-provided `io.Writer`s) are allowed. |
| L2 | `internal/security` | NULL/PLAIN/CURVE handshake state machines. Pure logic. | All of `net`, goroutines, time. |
| L3 | `internal/transport` | Listener / dialer abstractions for `tcp`/`ipc`/`inproc`. | wire, security, socket |
| L4 | `internal/conn` | Connection lifecycle: drives wire+security on top of transport. | socket |
| L5 | `socket` | Socket-type semantics, public API surface. | — |
| L6 | `zap` | ZAP authentication protocol over `inproc`. | socket |

Anything that would require `cgo` is forbidden across all layers.

## 4. Phases

The project is built strictly **layer by layer**, bottom up. End-to-end
functionality only appears at Phase 4 — earlier phases are testable but not
yet usable from a user's perspective.

F2 (security mechanisms) was split into three independently-shipped sub-phases
F2a/F2b/F2c so each mechanism can be specced, reviewed, and frozen on its own
schedule without waiting for the others. The shared `Mechanism` interface is
deferred until all three concrete implementations exist (extracted in F2c).

| Phase | Spec | Scope | First testable as | Status |
|-------|------|-------|-------------------|--------|
| F1 | `01-zmtp-wire-protocol.md` | ZMTP 3.1: greeting, frames, multipart, traffic commands. **No I/O.** | Property + vector tests; vectors hand-crafted from RFC 23 ABNF using our own encoder. libzmq cross-validation deferred to F4 interop. | **Complete** — tagged `phase-1-wire-complete`. |
| F2a | `02a-security-null.md` | NULL handshake state machine. **No I/O.** | Unit + property + vector tests; vectors hand-crafted from RFC 37 §3 using F1's encoder. libzmq cross-validation deferred to F4 interop. | **Complete** — tagged `phase-2a-null-complete`. |
| F2b | `02b-security-plain.md` | PLAIN handshake state machine. **No I/O.** Asymmetric: `ClientState` + `ServerState`; server uses an `Authenticator` callback (ZAP integration deferred to F6). Promotes `wire.ParseMetadata` / `wire.EncodeMetadata` to public L1 (additive). | Same shape as F2a. | Spec drafted; implementation pending. |
| F2c | `02c-security-curve.md` | CURVE handshake state machine. **No I/O.** Extracts the shared `Mechanism` interface across F2a/F2b/F2c. | Same shape as F2a, plus crypto vectors. | Pending. |
| F3 | `03-transports.md` | `tcp`, `ipc`, `inproc` listener/dialer abstractions. | Self-loopback tests (our dialer ↔ our listener). | Pending. |
| F4 | `04-connection-layer.md` | Wire-up of F1+F2+F3. Handshake, frame stream, error handling. | **First live interop with `libzmq`** (NULL handshake, then PLAIN, then CURVE). | Pending. |
| F5a | `05a-sockets-reqrep.md` | `REQ`, `REP`, `ROUTER`, `DEALER`. | Interop with `libzmq` REQ/REP patterns. | Pending. |
| F5b | `05b-sockets-pubsub.md` | `PUB`, `SUB`, `XPUB`, `XSUB`. Topic filtering. | Interop with `libzmq` pub/sub patterns. | Pending. |
| F5c | `05c-sockets-pipeline-pair.md` | `PUSH`, `PULL`, `PAIR`. | Interop with `libzmq` pipeline/pair. | Pending. |
| F6 | `06-zap-monitoring.md` | ZAP auth, socket monitoring events, HWM tuning, polling. | Interop and full integration. | Pending. |

Each phase is gated: **the next phase does not start until the previous one
is merged with all its tests passing.**

## 5. Workflow per phase

For every phase:

1. **Design** — write `docs/specs/NN-<topic>.md`. Map every requirement to a
   specific RFC section. Cover: data structures, state machines, public/
   internal interfaces, error model, test plan.
2. **Approve** — design is reviewed and approved before any code is written.
3. **Plan** — break the design into TDD-sized tasks.
4. **Implement** — TDD per task. Red, green, refactor.
5. **Test**:
   - **Unit** tests inside the package.
   - **Integration** tests against earlier-phase packages.
   - **Interop** tests against `libzmq` (Phase 4 onwards).
6. **Review** — code review against the spec. Verify everything in the spec
   is implemented and tested.
7. **Merge** — only when all the above pass. Then the next phase begins.

The skeleton of every phase doc:

```
# NN — <Topic>
1. Status & summary
2. Mapping to RFC sections
3. Public interface (if any)
4. Internal data structures
5. State machines (where applicable)
6. Error model
7. Test plan
8. Open questions
```

## 6. Testing strategy

This is the core quality lever. Three complementary kinds of tests:

### Unit tests

Inside every package. Mock dependencies on lower layers. Run on every push.
Target: high coverage of state machines and codecs.

### Integration tests

Cross-package within this repo. E.g. `conn` integration test wires `wire` +
`security` + `transport` end-to-end without involving `libzmq`. Run on every
push.

### Interop tests against `libzmq`

The thing that catches **wire-format drift**. From Phase 4 onwards.

- `libzmq` runs in a **Docker container** (a known version, pinned in CI).
- Two directions: `our dialer ↔ libzmq listener`, and `libzmq dialer ↔ our
  listener`.
- For each socket type, exercise the canonical patterns (`REQ`/`REP` round
  trip, `PUB`/`SUB` filter delivery, `PUSH`/`PULL` round-robin, `PAIR`
  exclusive, `ROUTER`/`DEALER` multipart routing).
- Run nightly in CI plus on demand. Not a precondition for every push because
  Docker/`libzmq` startup is slow.

### Vector tests

Before we have full interop (i.e. during F1 and F2), we still pin codec
correctness against the RFC by:

- Hand-crafting wire-byte vectors derived directly from each RFC's ABNF
  (greeting, frames, NULL/PLAIN/CURVE handshake commands, sample message
  bodies) into `internal/<layer>/testdata/*.bin`. F2 vectors are built
  using F1's encoder so the two layers exercise each other.
- Asserting that our codec parses those bytes correctly.
- Asserting that our encoder produces byte-identical output for the same
  inputs.

This lets us validate L1 and L2 long before we have a working connection
layer. **libzmq cross-validation is deferred to F4 interop** — once a live
connection exists, captured `libzmq` ↔ `libzmq` traces can supplement the
hand-crafted vectors, but they are not a precondition for landing F1 or F2.

## 7. Meta decisions

| Decision | Choice | Notes |
|----------|--------|-------|
| Module path | `github.com/tomi77/zmq4` | Matches local `~/Projects/github.com/<user>/<repo>/` convention. |
| License | MIT | RFC 23 is GPLv3 but only restricts modifications **to the spec text itself**; implementations are free to choose any license. |
| Min. Go version | 1.26 | Matches the local toolchain; current stable release. |
| ZMTP version | 3.1 only | No fallback to 3.0/2.0/1.0. |
| External dependencies | Standard library only by default. | Crypto for CURVE: `golang.org/x/crypto/nacl/box` (well-audited). Anything else requires explicit justification in the relevant spec. |
| `cgo` | Forbidden everywhere. | This is the entire point of the project. |
| Default branch | `main` | — |

## 8. Glossary

- **ZMTP** — ZeroMQ Message Transport Protocol. The wire-level protocol
  spoken between two ZeroMQ peers. Defined in [RFC 23](https://rfc.zeromq.org/spec/23/).
- **Frame** — the smallest ZMTP unit. Two flavours: *messages* (carry user
  payload) and *commands* (carry protocol metadata).
- **Multipart message** — a logical message composed of multiple frames,
  delimited by the `MORE` flag.
- **Greeting** — the fixed-format byte sequence exchanged when a connection
  opens. Negotiates protocol version and security mechanism.
- **Mechanism** — security handshake type: `NULL`, `PLAIN`, or `CURVE`.
- **ZAP** — ZeroMQ Authentication Protocol. An `inproc` request/reply
  protocol that the security layer uses to authenticate peers.
  Defined in [RFC 27](https://rfc.zeromq.org/spec/27/).
- **HWM** — high-water mark. Per-pipe queue size limit.
- **Endpoint** — a transport-specific address, e.g. `tcp://127.0.0.1:5555`.
- **Pipe** — a unidirectional in-process queue between a socket and a
  connection.

## 9. References

- [RFC 23/ZMTP — ZeroMQ Message Transport Protocol 3.1](https://rfc.zeromq.org/spec/23/)
- [RFC 24/PLAIN — Clear-Text Authentication](https://rfc.zeromq.org/spec/24/)
- [RFC 25/ZMTP-CURVE — Securing ZMTP with CurveZMQ](https://rfc.zeromq.org/spec/25/)
- [RFC 26/CURVEZMQ — CurveZMQ Authenticated Encryption](https://rfc.zeromq.org/spec/26/)
- [RFC 27/ZAP — ZeroMQ Authentication Protocol](https://rfc.zeromq.org/spec/27/)
- [RFC 28/REQREP — Request-Reply Pattern](https://rfc.zeromq.org/spec/28/)
- [RFC 29/PUBSUB — Publish-Subscribe Pattern](https://rfc.zeromq.org/spec/29/)
- [RFC 30/PIPELINE — Pipeline Pattern](https://rfc.zeromq.org/spec/30/)
- [RFC 31/EXPAIR — Exclusive Pair Pattern](https://rfc.zeromq.org/spec/31/)
