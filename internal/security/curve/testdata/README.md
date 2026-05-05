# F2c CURVE handshake + traffic vectors

Each .bin file holds the **command body** (command-name + command-data)
of one CURVE wire-format unit. Vectors are reproduced byte-for-byte
under a deterministic ChaCha8 RNG seeded with a fixed 32-byte sequence
declared in `vector_test.go` (variable `vectorSeed`).

| File | Contents |
|------|----------|
| `curve-hello-empty.bin` | HELLO with deterministic c'/C'. |
| `curve-welcome.bin` | WELCOME with deterministic s'/S' and cookie. |
| `curve-initiate-empty-meta.bin` | INITIATE with no metadata. |
| `curve-initiate-with-socket-type.bin` | INITIATE with `Socket-Type=DEALER`. |
| `curve-ready-empty-meta.bin` | READY with no metadata. |
| `curve-ready-with-identity.bin` | READY with `Socket-Type=ROUTER` + 8-byte `Identity`. |
| `curve-message-empty.bin` | MESSAGE wrapping an empty (0-byte) frame body, sendNonce=1, More=false. |
| `curve-message-16b.bin` | MESSAGE wrapping a 16-byte frame, sendNonce=2. |
| `curve-message-more.bin` | MESSAGE wrapping a 4-byte frame, More=true, sendNonce=3. |
| `curve-error.bin` | ERROR with reason `"Authentication failed"`. |

The seed is identical across all vectors so a single deterministic run
produces every fixture. To regenerate, run the vector test with
`-update` (the test file contains an opt-in regenerator gated on a flag).
