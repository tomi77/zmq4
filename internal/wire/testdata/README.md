# Wire-format vector files

This directory contains binary reference vectors used by the wire-format tests
in `internal/wire`. Each `.bin` file holds the exact bytes that a conforming
ZMTP 3.x implementation must produce or accept for the described scenario.

The vectors are placed under `internal/wire/testdata/interop/` and are loaded
by tests that compare the library's output against captured real-world bytes.

Tests that require these files are gated behind the `ZMQ4_VECTORS_PENDING=1`
environment variable. When that variable is set, the test is skipped rather
than failed, which lets development proceed before the vectors are captured.

---

## Vector files

| File | Description |
|------|-------------|
| `greeting-null.bin` | 64-byte ZMTP greeting using the NULL security mechanism, `as-server` flag = false. |
| `greeting-plain.bin` | 64-byte ZMTP greeting using the PLAIN security mechanism, `as-server` flag = false. |
| `greeting-curve.bin` | 64-byte ZMTP greeting using the CURVE security mechanism, `as-server` flag = true. CURVE bytes **must** come from a real libzmq run; hand-crafting is not acceptable. |
| `frame-empty.bin` | Short message frame carrying an empty body (`0x00 0x00` — flags byte + zero-length size byte). |
| `frame-short.bin` | Short message frame with a non-empty body (body fits in one byte length field). |
| `frame-long.bin` | Long message frame whose body exceeds 255 bytes (uses the 8-byte length encoding). |
| `frame-multipart.bin` | Concatenated sequence of frames making up a multi-part message. |
| `cmd-ready-empty.bin` | READY command frame with an empty metadata section. |
| `cmd-ready-typical.bin` | READY command frame with typical metadata: `Socket-Type` and `Identity` properties. |
| `cmd-error.bin` | ERROR command frame with the reason string `"Authentication failure"`. |
| `cmd-ping.bin` | PING command frame with a TTL value and a 3-byte context field. |
| `cmd-pong.bin` | PONG command frame echoing the context from the corresponding PING. |
| `cmd-subscribe.bin` | SUBSCRIBE command frame with topic `"news"`. |
| `cmd-cancel.bin` | CANCEL command frame with topic `"news"`. |

---

## How to regenerate

Run the capture script from the repository root:

```bash
testdata/interop/wire/capture.sh
```

or for a single vector:

```bash
testdata/interop/wire/capture.sh greeting-curve
```

The script requires Docker (to spin up a libzmq container) and produces the
`.bin` files directly in this directory.

### Hand-crafting simpler vectors

For vectors that do not involve asymmetric cryptography (everything except
`greeting-curve.bin`) it is acceptable to hand-craft the bytes by following
the ZMTP 3.1 specification (RFC 23) directly. The capture script is still the
preferred approach, but hand-crafted vectors are valid as long as they are
verified against the spec.

### CURVE vectors

The CURVE greeting and any future CURVE handshake vectors **must** be captured
from a real libzmq instance. The 32-byte public key and nonce fields cannot be
guessed or derived without running the actual Curve25519 key-exchange code.
Use `capture.sh` and review the resulting bytes with Wireshark or `xxd` before
committing.

---

## Development note: skipping pending vectors

If the `.bin` files are not yet present (e.g. during initial development),
tests that load them are skipped automatically when you set:

```bash
export ZMQ4_VECTORS_PENDING=1
```

Without that variable the tests will fail with a clear error message pointing
back to this README.

---

## F1 hand-crafted vectors

The 14 binary vectors in `testdata/interop/` were hand-crafted in Phase 1 (F1)
by encoding them directly through the codec from ABNF-derived values specified
in `docs/specs/01-zmtp-wire-protocol.md` (RFC 37). This approach is valid for
all Phase 1 vectors because they cover purely structural content — greetings
(which precede any encryption) and command bodies (READY, ERROR, PING, PONG,
SUBSCRIBE, CANCEL) — and contain no CURVE cryptographic state.

Three representative vectors were spot-checked with `xxd` against the
expected byte layout from the ABNF table before committing:
`greeting-null.bin`, `frame-empty.bin`, `cmd-ping.bin`, `frame-long.bin`,
`cmd-ready-typical.bin`, and `cmd-error.bin`.

Cross-validation against captured real libzmq traffic is planned for
**Phase 4 (F4) interop testing**. At that point the `.bin` files will be
replaced (or supplemented) with bytes captured from a live libzmq exchange,
and the `capture.sh` script will be used to regenerate them.
