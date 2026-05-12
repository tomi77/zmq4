# F7b — Documentation and Examples

**Date:** 2026-05-12
**Author:** Tomasz Rup
**Status:** approved

---

## 1. Goal

Ship production-quality documentation before tagging v1.0:

1. Fill every missing godoc comment for exported symbols in the root package and `zap/`.
2. Add `Example*` functions (godoc-rendered, `go test`-verified) for every socket type.
3. Add standalone runnable programs under `examples/` for every major pattern, including CURVE.
4. Update `README.md` to reflect the actual state of the project.

No API changes. No new types. No new exported symbols beyond the example files.

---

## 2. Godoc coverage

### 2.1 `errors.go`

All exported error variables currently lack doc comments. Add one per variable:

| Symbol | Comment |
|--------|---------|
| `ErrClosed` | Socket is closed; further operations return this error. |
| `ErrState` | Operation called out of sequence (e.g. REQ sent twice without Recv). |
| `ErrNoRoute` | No connected peer available for routing. |
| `ErrIncompatiblePeer` | Remote socket type is incompatible with the local socket type. |
| `ErrSecurityMismatch` | Security option not valid for this socket's role (e.g. client option on Bind side). |
| `ErrNoIdentity` | ROUTER Send requires a non-empty identity frame as msg[0]. |
| `ErrNoTopic` | PUB/XPUB Send requires at least one frame to use as topic prefix. |
| `ErrPairAlreadyConnected` | PAIR socket already has an active peer. |
| `ErrNotSocket` | Value passed to Poller is not a recognised zmq4 socket type. |
| `ErrAlreadyRegistered` | Socket is already registered with this Poller. |
| `ErrNotRegistered` | Socket is not registered with this Poller. |
| `ErrInvalidEvents` | Polling event mask must not be zero. |

### 2.2 `poller.go`

`POLLIN` and `POLLOUT` use inline `//` comments today, which Go treats as godoc for `const` values — no change needed. `Events`, `Event`, `Poller`, and the public methods already have comments. No changes required.

### 2.3 `zap/` package

`doc.go`, `handler.go`, and `router.go` already have full godoc. No changes required.

### 2.4 Verification

Run after all changes:

```
staticcheck ./...
go vet ./...
```

Expected: zero diagnostics (including `ST1020` / `ST1021`).

---

## 3. `Example*` functions

New files in the root package (`package zmq4_test`). All examples use `inproc://` transport so they run without network access and complete quickly. Examples use `context.Background()` and `defer socket.Close()`.

Each `Example*` function demonstrates the minimal happy path for that socket type — connect/bind, send, receive. Multi-step patterns (e.g. ROUTER routing) are shown in a single `Example` for the pair.

### 3.1 File list

| File | Functions |
|------|-----------|
| `example_reqrep_test.go` | `ExampleREQ`, `ExampleREP` (shown as a pair in one function) |
| `example_pubsub_test.go` | `ExamplePUB_subscribe` |
| `example_pipeline_test.go` | `ExamplePUSH`, `ExamplePULL` (shown as a pair) |
| `example_pair_test.go` | `ExamplePAIR` |
| `example_router_dealer_test.go` | `ExampleROUTER_dealer` |
| `example_xpubxsub_test.go` | `ExampleXPUB_proxy` |

### 3.2 Conventions

- Function names follow Go convention: `ExampleType_method` or `ExampleType` for top-level.
- Output comments (`// Output:`) only when output is deterministic. PUB/SUB and async patterns omit them.
- Synchronisation in examples uses channels or `time.Sleep` where unavoidable; prefer channels.
- Each file has a build tag: none (examples must compile and run in the standard test suite).

---

## 4. Standalone programs (`examples/`)

```
examples/
  hello-world/main.go          # REQ/REP "Hello World"
  pubsub/main.go               # PUB/SUB with topic filtering
  pipeline/main.go             # PUSH/PULL ventilator-worker-sink
  pair/main.go                 # PAIR bidirectional
  router-dealer/main.go        # async request-reply via ROUTER+DEALER
  xpubxsub-proxy/main.go       # XPUB/XSUB forwarding proxy
  curve-security/main.go       # CURVE encryption end-to-end
```

### 4.1 Conventions

- Each program: standalone `package main`, `go run ./examples/<name>/` works.
- Uses `tcp://127.0.0.1:0` with `net.Listen` to pick a free port, or `inproc://` where simpler.
- Prints a short header describing the pattern, then shows the message exchange.
- Header comment (first 3–5 lines) names the ZMQ pattern and links the RFC.
- No external dependencies beyond `github.com/tomi77/zmq4`.
- Programs exit cleanly (no infinite loops except `pipeline` worker which loops 5 iterations).

### 4.2 `curve-security/main.go`

Generates ephemeral key pairs at startup with `curve.GenerateKeyPair()`, sets up a CURVE REP server and REQ client, performs a round trip, prints the encrypted exchange confirmation. Does not require pre-shared keys in files.

---

## 5. README.md update

Replace the existing content with:

### Structure

1. **Badge** — CI status badge (`[![CI](…)](…)`)
2. **One-line description** — "Pure-Go ZeroMQ (ZMTP 3.1). No cgo. No libzmq."
3. **Installation** — `go get github.com/tomi77/zmq4@latest`
4. **Quick start** — REQ/REP snippet (≤ 15 lines)
5. **Socket patterns** — one subsection per pattern with a 3–5 line snippet and link to `examples/`; patterns: REQ/REP, PUB/SUB, PUSH/PULL, PAIR, ROUTER/DEALER, XPUB/XSUB
6. **Security** — NULL / PLAIN / CURVE option constructors with one-line examples each
7. **Non-goals** — preserved from current README
8. **Documentation** — link to `pkg.go.dev/github.com/tomi77/zmq4`
9. **License** — MIT

### Notes

- Snippets in README are illustrative (no `// Output:` contract); they mirror the `examples/` programs.
- Badge URL uses GitHub Actions workflow `ci.yml` (assumed path; adjust if different).

---

## 6. Test plan

| What | How |
|------|-----|
| Godoc completeness | `staticcheck ./...` (zero `ST1020`/`ST1021`), `go vet ./...` |
| `Example*` functions compile and pass | `go test -run Example ./...` |
| `Example*` functions with `// Output:` produce correct output | same `go test` run |
| Standalone programs compile | `go build ./examples/...` |
| Full suite unaffected | `go test -race -count=1 ./...` |

---

## 7. Phase tag

After all tasks pass: `phase-7b-docs-examples-complete`.

Meta-overview update: add F7b row to phase table; update status line to include F7b and the new tag.
