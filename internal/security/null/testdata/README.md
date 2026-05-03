# F2a NULL handshake vectors

Hand-crafted from RFC 37 §3 using F1's encoder. Cross-validation against
libzmq is deferred to F4 interop, per `docs/specs/02a-security-null.md`
§8.

| File | Contents |
|------|----------|
| `null-ready-empty.bin` | `READY` with no metadata. |
| `null-ready-socket-type-req.bin` | `READY` with `Socket-Type=REQ`. |
| `null-ready-with-identity.bin` | `READY` with `Socket-Type=ROUTER` and 8-byte `Identity`. |
| `null-error.bin` | `ERROR` with reason `"Invalid client"` (RFC 37 §3.1 example). |

Each file holds the **command body** (command-name + command-data); the
outer FrameCommand framing is L1's concern.
