# F2b PLAIN handshake vectors

Hand-crafted from RFC 37 §3.2 using F1's encoder + F2b's HELLO codec.
Cross-validation against libzmq is deferred to F4 interop, per
`docs/specs/02b-security-plain.md` §8.

| File | Contents |
|------|----------|
| `plain-hello-empty.bin` | `HELLO` with empty username and password. |
| `plain-hello-creds.bin` | `HELLO` with `username="admin"`, `password="secret"`. |
| `plain-welcome.bin` | `WELCOME` with empty body. |
| `plain-initiate-empty.bin` | `INITIATE` with no metadata. |
| `plain-initiate-with-socket-type.bin` | `INITIATE` with `Socket-Type=DEALER`. |
| `plain-ready-with-identity.bin` | `READY` with `Socket-Type=ROUTER` and 8-byte `Identity`. |
| `plain-error-auth-failed.bin` | `ERROR` with reason `"Authentication failed"`. |

Each file holds the **command body** (command-name + command-data); the
outer FrameCommand framing is L1's concern.
