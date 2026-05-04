# 02c — CURVE security mechanism (Phase 2c)

> **Status:** draft, awaiting implementation.
> **Author:** Tomasz Rup
> **Date:** 2026-05-04
> **Layer:** L2 — `internal/security/curve` + cross-mechanism extraction
> in `internal/security` (root).
> **Depends on:** F1 (`internal/wire`), F2a (`internal/security/null`),
> F2b (`internal/security/plain`), `internal/security/metaclone`.
> **External dependencies (new):** `golang.org/x/crypto/nacl/box` and
> `golang.org/x/crypto/nacl/secretbox` (sanctioned in
> `00-meta-overview.md` §7).
> **Consumed by:** F4 (connection layer); F6 may later replace the
> `Authorizer` callback with a ZAP-backed implementation.

## 1. Summary

This phase delivers `internal/security/curve`: a pure, I/O-free pair of
state machines that drive the ZMTP 3.1 **CURVE** security handshake (RFC
37 §3.3 / RFC 26) and additionally encapsulate post-handshake traffic via
authenticated encryption.

CURVE differs fundamentally from NULL and PLAIN: the four-step handshake
(HELLO → WELCOME → INITIATE → READY) not only authenticates the client
but **derives session keys** that subsequently encrypt all ZMTP traffic
inside `MESSAGE` commands (RFC 26 §6). F2c therefore extends the
mechanism contract beyond "drive a handshake": each mechanism also
provides `Wrap` / `Unwrap` to transform application frames into and out
of their on-wire representation.

Concretely, F2c delivers four things:

1. `internal/security/curve` — `ClientState`, `ServerState`, typed
   keys, codec, nonce management, MESSAGE wrap/unwrap.
2. `internal/security` (root) — the shared `Mechanism` and
   `ClientMechanism` interfaces, extracted now that three concrete
   implementations exist to compare against.
3. **F2a/F2b amendments** — `null.State`, `plain.ClientState`, and
   `plain.ServerState` gain `Wrap` / `Unwrap` methods that pass frames
   through unchanged. Additive; no existing call site changes.
4. New external dependencies — `nacl/box` (asymmetric authenticated
   encryption for handshake and traffic) and `nacl/secretbox` (symmetric
   authenticated encryption for the WELCOME cookie).

The state machines:

- Do not touch sockets, files, timers, or goroutines.
- Do not do framing — that is L1's job (F1).
- Do not invoke ZAP — server-side authorization is delegated to a
  caller-supplied `Authorizer` callback. F6 will provide a ZAP-backed
  authorizer.
- Do not interpret metadata semantics (e.g. Socket-Type compatibility) —
  that is the socket layer's job (F5).
- **Read entropy through an injectable `io.Reader`** so vector tests can
  produce byte-identical output. Production paths default to
  `crypto/rand.Reader`.

## 2. Mapping to RFC 37/ZMTP 3.1 and RFC 26/CurveZMQ

| RFC section | F2c covers |
|-------------|------------|
| RFC 37 §3 Security mechanisms — generic | **Yes** (handshake driver shape, `READY` / `ERROR` command handling, peer-initiated abort). |
| RFC 37 §3.1 NULL mechanism | **F2a** (already shipped). |
| RFC 37 §3.2 PLAIN mechanism | **F2b** (already shipped). |
| RFC 37 §3.3 CURVE mechanism | **Yes** (HELLO ↔ WELCOME ↔ INITIATE ↔ READY). |
| RFC 37 §2.4 Metadata properties | **Pass-through only.** Security ferries metadata; semantic validation lives in F5. |
| RFC 26 §3 Cryptographic primitives | **Yes** — Curve25519, XSalsa20, Poly1305 via NaCl `box` / `secretbox`. |
| RFC 26 §4 Wire-level handshake (5 commands) | **Yes** for the four standard commands; CurveZMQ's optional `ERROR` is covered by RFC 37's generic ERROR. |
| RFC 26 §5 Cookie & nonce derivation | **Yes**. Server is RFC-stateless — cookie is sealed under a per-handshake `cookie-key` and decrypted on INITIATE. |
| RFC 26 §6 MESSAGE post-handshake encryption | **Yes** — `Wrap` / `Unwrap` produce/consume `MESSAGE` commands carrying `box`-encrypted frames. |
| RFC 32 Z85 ASCII armor | **Out of scope.** Long-term keys are exchanged as raw 32-byte values; Z85 is a user-facing concern (CLI flags, env vars, config files) handled by F5/F6 or the application. Test files use binary or hex; no Z85 helpers leak from L2. |
| ZAP (RFC 27) authentication hook for CURVE | **Out of scope.** Replaced by a caller-supplied `Authorizer` callback. F6 will provide a ZAP-backed authorizer that satisfies the same callback. |
| RFC 26 mention of "anonymous CURVE" | **Out of scope.** Both peers MUST present long-term keypairs. |

### 2.1 F2a / F2b amendments

`null.State`, `plain.ClientState`, and `plain.ServerState` each gain
two methods:

```go
// Wrap returns f unchanged. NULL/PLAIN do no traffic encapsulation.
func (s *State)       Wrap(f wire.Frame) (wire.Frame, error)
func (s *State)       Unwrap(f wire.Frame) (wire.Frame, error)
// (and identically on plain.ClientState, plain.ServerState)
```

Both return `ErrNotDone` if called before the handshake completes,
matching the CURVE contract. This change is additive: no existing F2a/F2b
type or function changes, and the frozen public surface (per the tags
`phase-2a-null-complete` and `phase-2b-plain-complete`) keeps the same
semantics. Recorded as an amendment note in `00-meta-overview.md`
("F2a/F2b amendments — Wrap/Unwrap added by F2c"), not as a re-tag.

The shared sentinels (`ErrNotDone`, `ErrClosed`) live in
`internal/security` (root) so all three mechanisms reference the same
errors.

### 2.2 Meta-overview update

`docs/specs/00-meta-overview.md` §7 currently says external dependencies
require "explicit justification in the relevant spec" and pre-approves
`golang.org/x/crypto/nacl/box` for CURVE. F2c adds `nacl/secretbox` to
that list (used solely for the WELCOME cookie inner box). Both are part
of the same `golang.org/x/crypto` module — one `require` directive in
`go.mod`. F2c is the first phase to introduce a non-stdlib dependency.

## 3. ABNF reference

CURVE uses five command names (RFC 26 §4, RFC 37 §3.3) plus the generic
`ERROR`:

```abnf
hello       = command-size %d5 "HELLO" version padding hello-client
              hello-nonce hello-box
version     = %x1 %x0                        ; 2 bytes: major=1, minor=0
padding     = 72%x00                         ; 72 reserved zero bytes
hello-client = 32OCTET                       ; C'  client transient pub
hello-nonce  = 8OCTET                        ; short-nonce
hello-box    = 80OCTET                       ; box [64*0x00] under
                                             ;   nonce  = "CurveZMQHELLO---"|nonce
                                             ;   peer   = S  (server long-term pub)
                                             ;   ours   = c' (client transient sec)

welcome     = command-size %d7 "WELCOME"
              welcome-nonce welcome-box
welcome-nonce = 16OCTET                      ; long-nonce
welcome-box   = 144OCTET                     ; box [S' || cookie] under
                                             ;   nonce  = "WELCOME-"|nonce
                                             ;   peer   = C' (client transient pub)
                                             ;   ours   = s  (server long-term sec)
                                             ; where:
                                             ;   S'     = 32 OCTET (server transient pub)
                                             ;   cookie = 16 OCTET cookie-nonce ||
                                             ;            80 OCTET secretbox under cookie-key
                                             ;            of (C' || s')

initiate    = command-size %d8 "INITIATE"
              cookie initiate-nonce initiate-box
cookie         = 96OCTET                     ; echoed verbatim from welcome
initiate-nonce = 8OCTET                      ; short-nonce
initiate-box   = (96 + 32 + metadata-len + 16) OCTET
                                             ; box [vouch || C || metadata] under
                                             ;   nonce  = "CurveZMQINITIATE"|nonce
                                             ;   peer   = S' (server transient pub)
                                             ;   ours   = c' (client transient sec)
                                             ; vouch    = 16 OCTET vouch-nonce ||
                                             ;            80 OCTET box[C' || S] under
                                             ;            "VOUCH---"|vouch-nonce, S, c
                                             ; C        = 32 OCTET (client long-term pub)
                                             ; metadata = same as RFC 37 §2.4

ready       = command-size %d5 "READY"
              ready-nonce ready-box
ready-nonce = 8OCTET                         ; short-nonce
ready-box   = (metadata-len + 16) OCTET      ; box [metadata] under
                                             ;   nonce  = "CurveZMQREADY---"|nonce
                                             ;   peer   = C' (client transient pub)
                                             ;   ours   = s' (server transient sec)

message     = command-size %d7 "MESSAGE"
              message-nonce message-box
message-nonce = 8OCTET                       ; short-nonce, monotonic per direction
message-box   = (1 + payload-len + 16) OCTET ; box [flags || payload] under
                                             ;   nonce  = "CurveZMQMESSAGEC"|nonce  (client→server)
                                             ;   nonce  = "CurveZMQMESSAGES"|nonce  (server→client)
                                             ;   peer   = peer transient pub
                                             ;   ours   = our transient sec
                                             ; flags    = 1 OCTET, bit 0 = MORE

error       = command-size %d5 "ERROR" reason
reason      = OCTET 0*255VCHAR
```

Where:

- `metadata-len` is the byte length of the encoded metadata payload per
  RFC 37 §2.4 (concatenation of property records; no length prefix at
  the metadata level — the surrounding box length defines the boundary).
- `payload-len` is the byte length of the original (unwrapped) frame
  body — the application-supplied bytes the sender passed to `Wrap`.
- All short-nonce fields encode the 64-bit counter as **big-endian
  uint64** on the wire (matching libzmq; see §5.5).
- All long-nonce fields (16 OCTET) carry uniformly random bytes
  generated via the configured `rand` source — no counter, no replay
  tracking; uniqueness rests on 128 bits of entropy.

Step-by-step:

```
client → server : HELLO       (C', sealed zeros)
client ← server : WELCOME     (S', cookie)                | ERROR
client → server : INITIATE    (cookie, vouch, C, metadata)| ERROR
client ← server : READY       (metadata)                  | ERROR
both directions : MESSAGE     (encrypted frames + counters), forever
```

Either party MAY abort at any point by sending `ERROR` with a reason.
After `ERROR`, the connection is terminated; no further commands are
exchanged.

A peer that stops responding mid-handshake leaves the state machine
waiting indefinitely. **Detecting and aborting a stalled handshake is
F4's responsibility.**

Neither `INITIATE` nor `READY` places an upper bound on metadata size;
**enforcing limits on metadata size is F4's responsibility.**

Ordering is **strict request/response** through `READY`. After `READY`,
MESSAGE commands flow full-duplex.

## 4. Public interface

Two packages contribute exports:

- `internal/security` (root) — the cross-mechanism interfaces.
- `internal/security/curve` — CURVE's concrete state machines, key
  types, and error sentinels.

### 4.1 `internal/security` — Mechanism interfaces

```go
package security

import "github.com/tomi77/zmq4/internal/wire"

// Mechanism drives one side of a ZMTP 3.1 security handshake and
// post-handshake traffic encapsulation. Single-shot per connection:
// once Done() returns true (or any method returns an error), the
// Mechanism must not be reused.
//
// All methods are NOT goroutine-safe. F4 owns sequencing.
type Mechanism interface {
    // Receive consumes one peer command and advances the handshake.
    // After Done(), Receive MUST NOT be called.
    //
    // The wrapping/sentinel/lifecycle conventions are documented in the
    // implementing package (null, plain, curve).
    Receive(cmd wire.Command) (out *wire.Command, done bool, err error)

    // Wrap transforms one outgoing application frame into its on-wire
    // form. Valid only after Done(); otherwise returns ErrNotDone.
    //
    //   NULL/PLAIN: returns f unchanged.
    //   CURVE:      returns wire.Frame{ Kind: FrameCommand, More: false,
    //               Body: encodeCommand(MESSAGE | short-nonce | box(...)) }.
    //               f.More is preserved INSIDE the encrypted payload as
    //               the inner flags byte (bit 0 == MORE); the outer
    //               wire.Frame.More is always false because the MESSAGE
    //               command itself is a single non-MORE wire unit.
    //
    // Wrap operates on a single frame. Multi-frame logical messages
    // (linked via MORE) are wrapped one frame at a time: each frame
    // becomes its own MESSAGE command with its own nonce.
    //
    // The returned Frame's Body is freshly allocated and owned by the
    // caller. Wrap consumes f synchronously: it MUST read whatever it
    // needs from f.Body before returning and MUST NOT retain or mutate
    // any reference to f. The caller is therefore free to reuse, mutate,
    // or release f.Body the instant Wrap returns.
    Wrap(f wire.Frame) (wire.Frame, error)

    // Unwrap inverts Wrap.
    //
    //   NULL/PLAIN: returns f unchanged.
    //   CURVE:      f MUST be a FrameCommand whose body parses as a
    //               MESSAGE command; the box is opened, the inner flags
    //               byte is split out, and a wire.Frame is returned
    //               whose Kind is FrameMessage, More is recovered from
    //               the inner flags byte (bit 0), and Body is the
    //               decrypted payload.
    //
    // The returned Frame's Body is freshly allocated and independent of
    // f. Unwrap consumes f synchronously: same lifetime rule as Wrap —
    // the caller may reuse f.Body immediately upon return.
    Unwrap(f wire.Frame) (wire.Frame, error)

    // Done reports whether the handshake completed successfully.
    Done() bool

    // PeerMetadata returns the metadata advertised by the peer in its
    // handshake. Valid only after Done(). The returned Metadata aliases
    // an internal buffer; callers MUST NOT mutate it.
    PeerMetadata() wire.Metadata
}

// ClientMechanism is a Mechanism with an active-side initialization
// step. Implemented by null.State, plain.ClientState, curve.ClientState.
// Server-side states (plain.ServerState, curve.ServerState) implement
// only Mechanism.
//
// F4 obtains a Mechanism / ClientMechanism by calling the per-package
// constructor; the active side (driven by greeting.AsServer == false
// for the dialer, AsServer == true for the listener — see ZMTP) calls
// Start() exactly once before entering the Receive loop.
type ClientMechanism interface {
    Mechanism
    Start() (wire.Command, error)
}
```

A small, separate file `internal/security/errors.go` defines
cross-mechanism sentinels:

```go
package security

import "errors"

// ErrNotDone is returned by Wrap/Unwrap if the handshake has not
// completed.
var ErrNotDone = errors.New("security: handshake not done")

// ErrClosed is returned by every method after Close has been called
// (CURVE-only; NULL/PLAIN have no Close).
var ErrClosed = errors.New("security: state closed")
```

### 4.2 `internal/security/curve` — keys and constructors

```go
package curve

import (
    "io"

    "github.com/tomi77/zmq4/internal/wire"
)

// PublicKey is a 32-byte Curve25519 public key. Values are safe to log,
// store, and transmit.
type PublicKey [32]byte

// SecretKey is a 32-byte Curve25519 secret key. Sensitive material;
// callers SHOULD call Zero() when no longer needed. Implements Stringer
// returning "[REDACTED]" so accidental %v formatting does not leak the
// bytes (also implements GoString for %#v).
//
// String/GoString use POINTER receivers so a formatting call never
// triggers an implicit value copy of the 32 bytes onto another stack.
type SecretKey [32]byte

func (s *SecretKey) Zero()           { clear(s[:]) }
func (*SecretKey) String() string    { return "[REDACTED]" }
func (*SecretKey) GoString() string  { return "curve.SecretKey([REDACTED])" }

// SharedKey is a 32-byte precomputed NaCl box key (the X25519 shared
// secret) ready for nacl/box.SealAfterPrecomputation. Same redaction
// and Zero() semantics as SecretKey, including pointer-receiver
// formatting.
type SharedKey [32]byte

func (s *SharedKey) Zero()           { clear(s[:]) }
func (*SharedKey) String() string    { return "[REDACTED]" }
func (*SharedKey) GoString() string  { return "curve.SharedKey([REDACTED])" }

// GenerateKeyPair returns a freshly generated long-term keypair. rng
// supplies entropy; pass nil to use crypto/rand.Reader. Returns an
// error only if rng.Read fails.
func GenerateKeyPair(rng io.Reader) (PublicKey, SecretKey, error)

// ClientOptions configures a CURVE ClientState.
type ClientOptions struct {
    // ServerKey is the server's long-term public key. Required.
    ServerKey PublicKey

    // OurPublicKey is this client's long-term public key. Required.
    OurPublicKey PublicKey

    // OurSecretKey is this client's long-term secret key. Required.
    // Referenced (not copied); the caller owns its lifetime. ClientState
    // does NOT zero OurSecretKey on Close — the caller decides when the
    // long-term secret is no longer needed.
    OurSecretKey *SecretKey

    // LocalMetadata is sent in INITIATE. Referenced, not copied; same
    // lifetime rules as plain.NewClient.
    LocalMetadata wire.Metadata

    // Rand supplies entropy for the transient keypair, vouch nonce, and
    // MESSAGE nonce randomization. Pass nil to use crypto/rand.Reader.
    // Tests may inject a deterministic source for byte-exact vector
    // tests.
    Rand io.Reader
}

// NewClient constructs a CURVE ClientState. Errors:
//   ErrInvalidOptions  — zero ServerKey/OurPublicKey, nil OurSecretKey.
//   ErrCryptoRand      — Rand.Read failed during transient keypair
//                        generation.
func NewClient(opts ClientOptions) (*ClientState, error)

// ServerOptions configures a CURVE ServerState.
type ServerOptions struct {
    OurPublicKey  PublicKey
    OurSecretKey  *SecretKey  // referenced; caller owns lifetime
    LocalMetadata wire.Metadata

    // Authorizer decides whether a client's long-term public key is
    // allowed to connect. Required; NewServer panics if nil. See §4.4.
    Authorizer Authorizer

    // Rand supplies entropy for the transient keypair, cookie key,
    // cookie nonce, welcome nonce, ready nonce, and MESSAGE nonces.
    // Pass nil for crypto/rand.Reader.
    Rand io.Reader
}

// NewServer constructs a CURVE ServerState. Panics if opts.Authorizer
// is nil — calling NewServer without an Authorizer is always a
// programming error. Returns:
//   ErrInvalidOptions  — zero OurPublicKey, nil OurSecretKey.
//   ErrCryptoRand      — Rand.Read failed during initialization.
func NewServer(opts ServerOptions) (*ServerState, error)
```

### 4.3 `ClientState`

```go
// ClientState drives the client side of a CURVE handshake and traffic
// encapsulation. Single-shot.
type ClientState struct { /* unexported */ }

// Start emits HELLO. Must be called exactly once before Receive.
//
//   ErrAlreadyStarted — second call.
//   ErrAlreadyFailed  — previous error has put state into FAILED.
//   ErrClosed         — Close was called.
func (c *ClientState) Start() (wire.Command, error)

// Receive consumes one peer command and advances the state machine.
//
//   step 2: cmd=WELCOME ⇒ out=INITIATE, done=false, err=nil.
//   step 4: cmd=READY   ⇒ out=nil,      done=true,  err=nil.
//   any:    cmd=ERROR   ⇒ out=nil, done=false, err=ErrPeerError(reason).
//
// Lifecycle and malformed-* errors are listed in §6.
func (c *ClientState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error)

// PeerMetadata returns the metadata the server sent in READY. Valid
// only after Done(). Aliases an internal buffer; callers MUST NOT mutate.
func (c *ClientState) PeerMetadata() wire.Metadata

// PeerPublicKey returns the server's long-term public key (== ServerKey
// from ClientOptions). Provided for symmetry with ServerState.
func (c *ClientState) PeerPublicKey() PublicKey

// Done reports whether the handshake has completed.
func (c *ClientState) Done() bool

// Wrap encapsulates an outgoing frame as MESSAGE. See Mechanism.Wrap.
// Each call advances the send nonce counter. Returns ErrNonceExhausted
// if the counter would wrap past 2^64-1.
func (c *ClientState) Wrap(f wire.Frame) (wire.Frame, error)

// Unwrap decrypts an incoming MESSAGE. See Mechanism.Unwrap. Each
// successful call advances the receive nonce check; replays or out-of-
// order short-nonces are rejected with ErrNonceReused.
func (c *ClientState) Unwrap(f wire.Frame) (wire.Frame, error)

// Close zeros the transient secret key and any retained shared keys.
// Idempotent. After Close, every method returns ErrClosed. Long-term
// keys passed in via ClientOptions are NOT zeroed — the caller owns
// that lifetime.
func (c *ClientState) Close()
```

### 4.4 `ServerState` and `Authorizer`

```go
// Authorizer decides whether a client's long-term public key is allowed
// to connect.
//
// CONTRACT
//
//   When called:
//     Exactly once per ServerState, synchronously inside Receive on the
//     INITIATE step (step 3), AFTER:
//       - the INITIATE box has opened cleanly under the server transient
//         secret + client transient public (cryptographically authenticated
//         possession of c' by the peer);
//       - the vouch box has opened cleanly under the client long-term
//         public (cryptographically authenticated possession of c by the
//         peer);
//     i.e. clientPublicKey is the long-term public key of a peer that
//     has demonstrably proven knowledge of the matching secret.
//
//   Error → ERROR mapping:
//     Returning nil ⇒ server replies READY, transitions to DONE.
//     Returning a non-nil error ⇒ Receive returns
//       (out=&wire.Command{Name: "ERROR", Data: ...sanitized...}, false,
//       ErrAuthRejected) wrapping err. The Data field already encodes
//       the ABNF reason (1-byte length prefix omitted by ERROR's wire
//       format; see RFC 37 §3) so the caller writes `*out` to the
//       connection verbatim, then closes the connection.
//     sanitizeReason replaces any non-VCHAR byte with '?', then truncates
//       to 255 bytes (RFC 37 §3 ABNF). The build of `out` is performed
//       by L2; the caller does not construct ERROR commands.
//
//   Blocking:
//     The Authorizer runs synchronously inside Receive. It MAY block —
//     ZAP queries (F6), database lookups, and remote authorization
//     services are all valid implementations. F2c does NOT provide a
//     cancellation path: there is no context.Context parameter and
//     Receive cannot be interrupted from another goroutine. A slow
//     Authorizer therefore stalls the connection until it returns.
//     Implementers SHOULD enforce their own timeout (e.g. wrap the
//     ZAP query with context.WithTimeout). F6's ZAP-backed Authorizer
//     is expected to do exactly this. If a future caller requires
//     external cancellation, the Authorizer signature can be widened
//     additively to take a context.Context — deferred until F6 says
//     it needs one.
//
//   Forbidden:
//     The Authorizer MUST NOT do I/O on the same connection, take locks
//     held by F4's read/write loop, or call back into the State. The
//     State is single-threaded by contract; re-entrant calls would
//     corrupt its internal step/nonce counters and are unrecoverable.
//
//   Trust:
//     clientPublicKey is the only field that has been cryptographically
//     authenticated by the time the Authorizer runs.
//
//     peerMetadata is UNTRUSTED: it is the sender-controlled byte sequence
//     ferried through INITIATE by L2. Properties such as Identity,
//     Resource, Socket-Type are sender-supplied strings; the only thing
//     L2 has verified is that the bytes were authored by the holder of
//     clientPublicKey's matching secret. Authorizers MUST make access
//     decisions on clientPublicKey alone. Metadata is acceptable as input
//     to logging, routing, or telemetry — never to authentication or
//     authorization.
//
//   Lifetime:
//     clientPublicKey is a 32-byte value (passed by value; the
//     Authorizer may retain it freely).
//     peerMetadata aliases an internal buffer that is valid only for
//     the duration of the call. If the implementation needs to keep
//     it past return, it MUST Clone.
type Authorizer func(clientPublicKey PublicKey, peerMetadata wire.Metadata) error

// ServerState drives the server side of a CURVE handshake and traffic
// encapsulation. Single-shot.
type ServerState struct { /* unexported */ }

// Receive consumes one peer command and advances the state machine.
// Server has no Start — it is purely reactive.
//
//   step 1: cmd=HELLO,    valid box ⇒ out=WELCOME,  done=false, err=nil.
//   step 1: cmd=HELLO,    bad box   ⇒ ErrBoxOpen.
//   step 3: cmd=INITIATE, all boxes open + auth(...)==nil
//                                   ⇒ out=READY, done=true, err=nil.
//   step 3: cmd=INITIATE, bad cookie    ⇒ ErrCookieMismatch.
//   step 3: cmd=INITIATE, bad outer box ⇒ ErrBoxOpen.
//   step 3: cmd=INITIATE, bad vouch     ⇒ ErrBoxOpen (vouch failure
//                                          indicates the peer does not
//                                          possess the long-term secret
//                                          matching the embedded long-
//                                          term public).
//   step 3: cmd=INITIATE, all boxes open + auth(...)!=nil
//                                   ⇒ out=ERROR(reason), done=false,
//                                     err=ErrAuthRejected.
//   any:    cmd=ERROR ⇒ out=nil, done=false, err=ErrPeerError(reason).
func (s *ServerState) Receive(cmd wire.Command) (out *wire.Command, done bool, err error)

// PeerPublicKey returns the client's long-term public key (the value
// passed to the Authorizer). Valid only after Done().
func (s *ServerState) PeerPublicKey() PublicKey

func (s *ServerState) PeerMetadata() wire.Metadata
func (s *ServerState) Done() bool
func (s *ServerState) Wrap(f wire.Frame) (wire.Frame, error)
func (s *ServerState) Unwrap(f wire.Frame) (wire.Frame, error)
func (s *ServerState) Close()
```

### 4.5 Why this shape

- **Two types per role, like F2b.** CURVE client and server have
  distinct state graphs (4 states vs 3 states) and distinct entry points
  (`Start` exists only on the client). Two types make every reachable
  state a compilable configuration.
- **Authorizer takes the long-term public key, not the metadata.** The
  long-term public key is the only cryptographically authenticated
  identity available at INITIATE time. Authorizer signature deliberately
  omits any path that would let an implementer treat metadata as
  authentic.
- **`Authorizer` is a `func`, not an interface.** Same reasoning as
  PLAIN: F2c has exactly two call sites — tests and (eventually) F6's
  ZAP-backed adapter. A single-method interface is premature. Promotion
  to an interface is mechanical if a third caller appears.
- **`out, err` both non-nil on auth-reject.** Identical to PLAIN: the
  caller sends `out` (ERROR) on the wire, then closes the connection.
- **`Close` exists only on CURVE.** NULL and PLAIN retain no sensitive
  material after the handshake. CURVE retains transient secret keys,
  shared keys, and the cookie key; these need explicit zeroization.
- **`Rand` is injectable.** CURVE handshake bytes are not
  byte-deterministic under a real RNG — every run produces different
  HELLO/WELCOME/INITIATE bytes. To pin the codec under vector tests,
  `Rand` is exposed as `io.Reader` and tests inject a seeded
  deterministic source. Production paths default to `crypto/rand.Reader`.
- **Server is RFC-stateless w.r.t. cookie.** RFC 26 §5 prescribes a
  cookie-key + sealed cookie design so a server need not retain
  per-handshake state between WELCOME and INITIATE. We follow that
  shape — `cookie-key` is a fresh `SecretKey`-sized symmetric key
  generated in `NewServer`, used to `secretbox` the inner `(c' || s')`
  pair, and verified on INITIATE by re-opening. Cookie mismatch is a
  hard fail (`ErrCookieMismatch`). We additionally retain `s'` in
  `ServerState` for ergonomic access; the cookie-derived value is
  compared to the in-state value and any mismatch is treated as an
  attempted replay/forgery.

### 4.6 Symmetry with sibling specs

| Aspect | `null.State` | `plain.ClientState` | `plain.ServerState` | `curve.ClientState` | `curve.ServerState` |
|--------|--------------|---------------------|---------------------|---------------------|---------------------|
| Implements `ClientMechanism` | yes | yes | no | yes | no |
| Implements `Mechanism` | yes | yes | yes | yes | yes |
| `Start` | yes | yes | **no** | yes | **no** |
| Number of `Receive` steps to DONE | 1 | 2 | 2 | 2 (WELCOME, READY) | 2 (HELLO, INITIATE) |
| `Wrap`/`Unwrap` | passthrough | passthrough | passthrough | encrypts MESSAGE | encrypts MESSAGE |
| `Close` | n/a | n/a | n/a | yes | yes |
| External entropy | none | none | none | required (transient keys, nonces) | required (transient keys, cookie key, nonces) |

## 5. Internal data structures

### 5.1 Codec — `internal/security/curve/codec.go`

Constants:

```go
const (
    helloCommandName    = "HELLO"
    welcomeCommandName  = "WELCOME"
    initiateCommandName = "INITIATE"
    readyCommandName    = "READY"
    messageCommandName  = "MESSAGE"
    // ErrorCommandName comes from internal/wire (shared with NULL/PLAIN).
)

// Nonce prefixes (RFC 26 §3). Two shapes:
//   - Short-nonce prefixes are 16 B; on the wire the full 24-byte NaCl
//     nonce is prefix||short-nonce(8 B big-endian counter).
//   - Long-nonce prefixes are 8 B; on the wire the full 24-byte NaCl
//     nonce is prefix||long-nonce(16 B random).
// Trailing letter on MESSAGE prefixes encodes the SENDER role: "C" for
// client-sent, "S" for server-sent (per RFC 26 §6).
var (
    helloNoncePrefix    = [16]byte{'C','u','r','v','e','Z','M','Q','H','E','L','L','O','-','-','-'}
    welcomeNoncePrefix  = [8]byte {'W','E','L','C','O','M','E','-'}     // + 16-byte long-nonce
    cookieNoncePrefix   = [8]byte {'C','O','O','K','I','E','-','-'}     // + 16-byte long-nonce
    vouchNoncePrefix    = [8]byte {'V','O','U','C','H','-','-','-'}     // + 16-byte long-nonce
    initiateNoncePrefix = [16]byte{'C','u','r','v','e','Z','M','Q','I','N','I','T','I','A','T','E'}
    readyNoncePrefix    = [16]byte{'C','u','r','v','e','Z','M','Q','R','E','A','D','Y','-','-','-'}
    messageClientPrefix = [16]byte{'C','u','r','v','e','Z','M','Q','M','E','S','S','A','G','E','C'}
    messageServerPrefix = [16]byte{'C','u','r','v','e','Z','M','Q','M','E','S','S','A','G','E','S'}
)
```

(Exact byte sequences are pinned in the spec because the wire format
depends on them. RFC 26 specifies the NUL-padded forms; the lexical
trailing `-` characters are RFC-prescribed.)

Pure encode/parse functions, one per command. They produce/consume
`wire.Command` (i.e. command name + body bytes), not `wire.Frame`:

```go
func encodeHello   (clientTransPub PublicKey, sharedKey *SharedKey,
                    nonce uint64, rand io.Reader)        (wire.Command, error)
func parseHello    (cmd wire.Command, sharedKey *SharedKey)
                                                          (clientTransPub PublicKey, err error)

func encodeWelcome (serverTransPub PublicKey, cookie [96]byte,
                    sharedKey *SharedKey, rand io.Reader)(wire.Command, error)
func parseWelcome  (cmd wire.Command, sharedKey *SharedKey)
                                                          (serverTransPub PublicKey, cookie [96]byte, err error)

func sealCookie    (clientTransPub PublicKey, serverTransSec SecretKey,
                    cookieKey *SecretKey, rand io.Reader) ([96]byte, error)
func openCookie    (cookie [96]byte, cookieKey *SecretKey)
                                                          (clientTransPub PublicKey, serverTransSec SecretKey, err error)

func encodeInitiate(cookie [96]byte, vouch [96]byte, clientLongPub PublicKey,
                    metadata wire.Metadata,
                    sharedKey *SharedKey, nonce uint64,
                    rand io.Reader)                       (wire.Command, error)
func parseInitiate (cmd wire.Command, sharedKey *SharedKey)
                                                          (cookie [96]byte, vouch [96]byte,
                                                           clientLongPub PublicKey,
                                                           metadata wire.Metadata, err error)

func encodeVouch   (clientTransPub PublicKey, serverLongPub PublicKey,
                    clientLongSec *SecretKey, rand io.Reader) ([96]byte, error)
func openVouch     (vouch [96]byte, clientLongPub PublicKey,
                    serverLongSec *SecretKey)             (clientTransPub PublicKey,
                                                           serverLongPub PublicKey, err error)

func encodeReady   (metadata wire.Metadata, sharedKey *SharedKey,
                    nonce uint64, rand io.Reader)        (wire.Command, error)
func parseReady    (cmd wire.Command, sharedKey *SharedKey)
                                                          (metadata wire.Metadata, err error)

// MESSAGE: the inner plaintext is (flags-byte || payload). Caller
// supplies the prefix (messageClientPrefix or messageServerPrefix) and
// the per-direction nonce counter.
func encodeMessage (flags byte, payload []byte,
                    sharedKey *SharedKey, prefix [16]byte,
                    nonce uint64)                         (wire.Command, error)
func parseMessage  (cmd wire.Command,
                    sharedKey *SharedKey, prefix [16]byte)
                                                          (flags byte, payload []byte,
                                                           shortNonce uint64, err error)
```

Codec functions own zero state. They call `nacl/box.SealAfterPrecomputation`
/ `OpenAfterPrecomputation` and `nacl/secretbox.Seal` / `Open`. They do
no I/O (no goroutines, no sleeps, no syscalls beyond `rand.Read`).

`metadata` is encoded/decoded via `wire.EncodeMetadata` /
`wire.ParseMetadata` (the F2b L1 exports). `parseInitiate` and
`parseReady` perform a defensive copy of metadata via
`metaclone.Clone` so the result is independent of the input buffer.

`sanitizeReason` (already in `plain`) is promoted to a shared
`internal/security/seccommon` package alongside `metaclone.Clone`
(which moves there too, exported as `seccommon.CloneMetadata`). All
three mechanisms then import `seccommon` for both helpers. The rename
is internal-package-only; no external API surface changes. F2c
implementation handles the rename in a dedicated commit before
landing CURVE code, so the move is reviewable independently from the
new functionality.

### 5.2 ClientState

```go
type ClientState struct {
    // Long-term identity (caller-owned).
    serverPub  PublicKey
    ourLongPub PublicKey
    ourLongSec *SecretKey

    // Transient identity (owned by ClientState; zeroed on Close).
    transPub PublicKey
    transSec SecretKey  // VALUE, zeroed in place

    // Precomputed shared keys.
    //
    //   handshakeShared = box.Precompute(serverPub, transSec) = c' × S.
    //                     Used for sealing HELLO and opening WELCOME
    //                     (NaCl box DH is symmetric in the pair).
    //   afterReady      = box.Precompute(peerTransPub, transSec) = c' × S'.
    //                     Computed after WELCOME opens and yields S'.
    //                     Used for sealing INITIATE, opening READY,
    //                     and Wrap/Unwrap of MESSAGE (post-handshake).
    //   vouchShared     = box.Precompute(serverPub, ourLongSec) = c × S.
    //                     The LONG-TERM × LONG-TERM shared key, used
    //                     exclusively to seal the vouch box inside
    //                     INITIATE. Computed eagerly in Start (so that
    //                     ourLongSec can be touched once and the secret
    //                     stays inside this State for the rest of the
    //                     handshake; the caller's *SecretKey is NOT
    //                     dereferenced again after Start).
    handshakeShared *SharedKey
    afterReady      *SharedKey
    vouchShared     *SharedKey

    // Local & peer metadata.
    local wire.Metadata
    peer  wire.Metadata

    // Nonce counters (per direction).
    sendNonce uint64 // MESSAGE counter, monotonic, starts at 1
    recvNonce uint64 // last successfully verified MESSAGE counter; 0 is
                     // the sentinel meaning "no MESSAGE accepted yet"
                     // (peers always start emitting at nonce 1, so the
                     // first valid received nonce is 1 > 0).

    // Step counters for the handshake. HELLO/INITIATE/READY use 8-byte
    // short-nonces; the vouch box uses a random 16-byte long-nonce
    // generated per-handshake (no counter, no replay tracking).
    helloNonce    uint64 // monotonic; starts at 1
    initiateNonce uint64 // monotonic; starts at 1

    // Lifecycle flags (mutually exclusive states derived from these).
    started, welcomeReceived, done, failed, closed bool

    // Entropy.
    rand io.Reader
}
```

Approximate footprint: ~280–320 bytes (stack + heap pointers excluded).
All slice/array fields with sensitive contents (`transSec`, all three
shared keys) are explicitly zeroed in `Close()`. The shared keys are
heap-allocated (`*SharedKey`) so caller-controlled lifetime is
straightforward; `transSec` is inline and zeroed via
`clear(c.transSec[:])`. `vouchShared` is computed in `Start` (so the
caller's `*SecretKey` is dereferenced exactly once at startup) and
zeroed at the end of `Receive(WELCOME)` immediately after the vouch
box has been sealed into INITIATE — it is not needed again. The field
stays nil-able so `Close` is idempotent.

### 5.3 ServerState

```go
type ServerState struct {
    // Long-term identity (caller-owned for ourLongSec).
    ourLongPub PublicKey
    ourLongSec *SecretKey

    // Transient identity (owned; zeroed on Close).
    transPub PublicKey
    transSec SecretKey

    // Cookie key (owned; zeroed on Close). Per-server-state, generated
    // in NewServer.
    cookieKey SecretKey

    // Authorizer (caller-supplied, never nil).
    authorizer Authorizer

    // Precomputed shared keys.
    handshakeShared *SharedKey  // s × C'   (used for parseHello, encodeWelcome)
    afterReady      *SharedKey  // s' × C'  (used for parseInitiate, encodeReady, MESSAGE)

    // Peer identity (after INITIATE).
    peerLongPub PublicKey
    peerTransPub PublicKey  // captured from HELLO

    // Local & peer metadata.
    local wire.Metadata
    peer  wire.Metadata

    // Nonce counters (per direction).
    sendNonce uint64
    recvNonce uint64

    welcomeNonce uint64
    readyNonce   uint64

    // Lifecycle flags.
    helloProcessed, done, failed, closed bool

    rand io.Reader
}
```

Approximate footprint: ~350–400 bytes.

### 5.4 Defensive copy of peer metadata

Same contract as F2a/F2b: peer metadata returned from `PeerMetadata()`
is independent of the input frame buffer. Implementation reuses
`metaclone.Clone`.

### 5.5 Nonce semantics

- **Handshake short-nonces** (HELLO, INITIATE, READY): the 8-byte
  short-nonce field on the wire carries a 64-bit counter encoded as
  **big-endian uint64** (matching libzmq; pinned in vector tests
  §8.4). The counter starts at 1 and increments per outbound message
  of that command type. Long-nonces (16-byte fields used by WELCOME,
  the cookie, and the vouch) are randomly generated via `rand` — no
  counter, no replay tracking; uniqueness rests on 128 bits of entropy.
- **MESSAGE nonces**: a per-direction monotonic 64-bit counter, also
  starting at 1, on-wire encoding identical to the handshake short-nonces
  (big-endian uint64). The receiver maintains `recvNonce`, initialized
  to 0 as a sentinel meaning "no MESSAGE accepted yet"; an incoming
  short-nonce must satisfy `incoming > recvNonce` (strict), otherwise
  `ErrNonceReused`. Because senders always start at 1, a
  freshly-handshaken peer's first received nonce satisfies `1 > 0` and
  is accepted. The receiver then advances `recvNonce = incoming`.
  This permits gaps (e.g. dropped UDP packets if/when transports add
  one) but rejects duplicates and reordering.
- **Counter exhaustion**: if a sender's `sendNonce` is about to wrap
  past 2^64-1, subsequent `Wrap` calls return `ErrNonceExhausted`. At
  10⁹ msgs/second this exhausts in 584 years; bound exists for
  defense-in-depth, not practical risk.

### 5.6 Allocation budget

Numeric budgets are pinned by `testing.AllocsPerRun` in
`alloc_budget_test.go` (see §8.5); §5.6 enumerates the expected sources
so the test thresholds are reviewable.

| Operation | Expected allocations | Notes |
|-----------|---------------------|-------|
| `ClientState.Wrap(f)` | 2 | one `[]byte` for `wire.Command.Data` (short-nonce + box ciphertext), one `[]byte` for the returned `wire.Frame.Body` (the encoded MESSAGE command). |
| `ClientState.Unwrap(f)` | 1 | one `[]byte` for the decrypted payload, returned as `wire.Frame.Body`. |
| `ServerState.Wrap` / `Unwrap` | identical to client | symmetric path. |
| `Start` (client) | ~3 | transient keypair (1), handshakeShared+vouchShared precomputed key buffers (2). |
| `Receive(WELCOME)` (client) | ~3 | afterReady precomputed key buffer (1), INITIATE ciphertext (1), encoded INITIATE command bytes (1). |
| `Receive(READY)` (client) | metadata clone budget | one slice header + one `Name` and one `Value` per peer property (matching F2a/F2b). Plaintext metadata buffer is reused, not retained. |
| `Receive(HELLO)` (server) | ~3 | analogous to client `Start` plus WELCOME ciphertext+encoded bytes. |
| `Receive(INITIATE)` (server) | metadata clone budget + 2 | metadata defensive copy (per F2a/F2b) plus READY ciphertext + encoded bytes. |

These are upper bounds the implementation must not exceed; pinning is
done by `testing.AllocsPerRun`. If a future implementation shaves an
allocation (e.g. a sync.Pool for ciphertext buffers), it lowers the
pinned threshold in the same commit — no allocation regressions.

## 6. Error model

Sentinel errors live in `internal/security/curve/errors.go` and are
wrapped via `fmt.Errorf("%w: ...", ErrXxx)`. Cross-mechanism sentinels
(`ErrNotDone`, `ErrClosed`) live in `internal/security` (root) per §4.1.

| Sentinel | Returned when |
|----------|---------------|
| `ErrInvalidOptions` | `NewClient`/`NewServer` with zero `ServerKey`/`OurPublicKey`, nil `OurSecretKey` pointer. A non-nil pointer pointing at a zero-valued `SecretKey` is **not** rejected — caller may legitimately reference an uninitialized key buffer that is filled in just before use. (NewServer with nil Authorizer panics.) |
| `ErrCryptoRand` | `Rand.Read` returned an error (transient keypair, nonce, or cookie key generation). |
| `ErrAlreadyStarted` | Client's `Start` called more than once. |
| `ErrNotStarted` | Client's `Receive` called before `Start`. |
| `ErrAlreadyDone` | `Start` or `Receive` called after a previous successful completion. (`Wrap`/`Unwrap` remain valid after Done — that is the whole point of post-handshake encryption.) |
| `ErrAlreadyFailed` | Any method called after a previous error. |
| `ErrUnexpectedCommand` | Peer sent a command whose name is not the one expected in the current state (and is not `ERROR`). |
| `ErrPeerError` | Peer sent an `ERROR` command. The wrapped string includes the peer's reason **as received** — bytes outside `0x21–0x7E` are not stripped before wrapping (the parse-side sanity check rejects sizes >255 with `ErrMalformed*`, but does not VCHAR-filter). Loggers and UIs SHOULD treat the wrapped reason as untrusted, peer-controlled input. |
| `ErrAuthRejected` | (Server only.) Authorizer returned a non-nil error for INITIATE. The wrapped string includes the authorizer's reason. Returned alongside a non-nil `out` containing the ERROR command to send. |
| `ErrMalformedHello` | Server: HELLO does not parse per RFC 26 §5.2 (wrong size, bad version, non-zero padding). |
| `ErrMalformedWelcome` | Client: WELCOME does not parse per §5.3 (wrong size). |
| `ErrMalformedInitiate` | Server: INITIATE outer structure does not parse per §5.4. |
| `ErrMalformedReady` | Client: READY outer structure does not parse per §5.5. |
| `ErrMalformedMessage` | Either: MESSAGE structure (size, command name) does not parse per §6. |
| `ErrBoxOpen` | `nacl/box.Open` (or `nacl/secretbox.Open`) returned `false` — auth tag failure. Wraps a description of which box failed (HELLO outer, WELCOME outer, INITIATE outer, vouch, READY, MESSAGE, cookie). |
| `ErrCookieMismatch` | INITIATE cookie opens but its inner `(c', s')` does not match this server's recorded handshake state. Indicates a forged or replayed INITIATE. |
| `ErrNonceReused` | Incoming MESSAGE short-nonce ≤ last recorded receive nonce. |
| `ErrNonceExhausted` | Outgoing send nonce would wrap past 2^64-1. |
| `security.ErrNotDone` | `Wrap`/`Unwrap` called before `Done()`. |
| `security.ErrClosed` | Any method called after `Close()`. |

**Server abort with notification.** When the server returns
`ErrAuthRejected`, the corresponding `out *wire.Command` contains the
ERROR command to send. Same convention as F2b. Malformed-* paths and
crypto-failure paths do **not** emit ERROR — they are treated as local
fatal errors and let F4 close the connection silently. Implementation
choice, revisable in F4 interop based on libzmq behavior.

**No panics**, except `NewServer(opts)` with `opts.Authorizer == nil` —
calling NewServer without an authorizer is always a programming error
caught at construction.

## 7. State machines

### 7.1 ClientState

```
                    ┌────────────────────────────────────────┐
                    │                INIT                     │
                    │ Start ⇒ derive c'/C', precompute        │
                    │         handshakeShared = c'×S,         │
                    │         vouchShared    = c×S            │
                    │         (touch *OurSecretKey once),     │
                    │         emit HELLO,                     │
                    │         transition to AWAIT_WELCOME     │
                    └─────────────────┬──────────────────────┘
                                      │
                                      ▼
                    ┌────────────────────────────────────────┐
                    │            AWAIT_WELCOME                │
                    │ Receive(WELCOME):                       │
                    │   open box (handshakeShared)            │
                    │   ⇒ extract S' + cookie                  │
                    │   ⇒ precompute c'×S' = afterReady       │
                    │   ⇒ seal vouch using vouchShared        │
                    │   ⇒ emit INITIATE,                      │
                    │   ⇒ ZERO vouchShared (no longer needed) │
                    │     transition to AWAIT_READY            │
                    │ Receive(ERROR)/malformed/box-fail        │
                    │   ⇒ FAILED                              │
                    └─────────────────┬──────────────────────┘
                                      │
                                      ▼
                    ┌────────────────────────────────────────┐
                    │             AWAIT_READY                 │
                    │ Receive(READY):                         │
                    │   open box (afterReady)                 │
                    │   ⇒ store peer metadata                 │
                    │   ⇒ DONE; Wrap/Unwrap now valid         │
                    │ Receive(ERROR)/malformed/box-fail        │
                    │   ⇒ FAILED                              │
                    └─────┬──────────────────┬───────────────┘
                          ▼                  ▼
                      ┌────────┐         ┌──────────┐
                      │  DONE  │         │  FAILED  │
                      └────────┘         └──────────┘
```

Five reachable configurations (INIT, AWAIT_WELCOME, AWAIT_READY, DONE,
FAILED). After Close, every configuration becomes CLOSED (returning
`ErrClosed` from any method).

### 7.2 ServerState

```
                    ┌────────────────────────────────────────┐
                    │            AWAIT_HELLO                  │
                    │ Receive(HELLO):                         │
                    │   open box (s×C')                        │
                    │   ⇒ store C' (peer transient pub)        │
                    │   ⇒ derive s'/S', precompute             │
                    │       s×C' = handshakeShared              │
                    │       s'×C' = afterReady                  │
                    │   ⇒ seal cookie (c'||s' under cookieKey) │
                    │   ⇒ emit WELCOME,                       │
                    │     transition to AWAIT_INITIATE         │
                    │ Receive(ERROR)/malformed/box-fail        │
                    │   ⇒ FAILED                              │
                    └─────────────────┬──────────────────────┘
                                      │
                                      ▼
                    ┌────────────────────────────────────────┐
                    │           AWAIT_INITIATE                │
                    │ Receive(INITIATE):                      │
                    │   open box (afterReady)                 │
                    │   open cookie (cookieKey)               │
                    │   verify cookie inner == (C', s')       │
                    │   open vouch under (s × peerLongPub)    │
                    │   verify vouch inner == (C', S)         │
                    │   call Authorizer(peerLongPub, meta)    │
                    │     err == nil  ⇒ emit READY (afterReady│
                    │                    box of meta), DONE   │
                    │     err != nil  ⇒ emit ERROR(reason),   │
                    │                    FAILED, return        │
                    │                    (out, ErrAuthRejected)│
                    │   any crypto/cookie failure ⇒ FAILED    │
                    │ Receive(ERROR)/malformed                │
                    │   ⇒ FAILED                              │
                    └─────┬──────────────────┬───────────────┘
                          ▼                  ▼
                      ┌────────┐         ┌──────────┐
                      │  DONE  │         │  FAILED  │
                      └────────┘         └──────────┘
```

Four reachable configurations + CLOSED. The auth-rejection edge is the
only place where the server emits both `out` and `err`.

## 8. Test plan

### 8.1 Unit tests

`internal/security/curve/client_test.go`:

- `NewClient` rejects zero ServerKey/OurPublicKey, nil OurSecretKey →
  `ErrInvalidOptions`.
- `NewClient` with failing `Rand` → `ErrCryptoRand`.
- `Start` from INIT → emits HELLO with valid box (verifiable by the
  test using a paired ServerState).
- `Start` from AWAIT_WELCOME → `ErrAlreadyStarted`.
- `Receive` from INIT → `ErrNotStarted`.
- `Receive(WELCOME)` happy path → `out=INITIATE`, `done=false`.
- `Receive(WELCOME with truncated cookie)` → `ErrMalformedWelcome`.
- `Receive(WELCOME with tampered ciphertext)` → `ErrBoxOpen`.
- `Receive(READY)` happy path → `done=true`, `PeerMetadata()` matches.
- `Receive(READY with tampered ciphertext)` → `ErrBoxOpen`.
- `Receive(ERROR)` from any state → `ErrPeerError`.
- `Receive(HELLO)` from AWAIT_WELCOME → `ErrUnexpectedCommand`.
- `Receive(*)` from DONE → `ErrAlreadyDone`.
- `Receive(*)` from FAILED → `ErrAlreadyFailed`.
- `Wrap`/`Unwrap` before `Done()` → `security.ErrNotDone`.
- After `Close()`: every method → `security.ErrClosed`.
- `Wrap` produces a FrameCommand with valid MESSAGE body; paired
  `Unwrap` on the peer recovers original frame.
- `Unwrap` of replayed MESSAGE → `ErrNonceReused`.
- `Wrap` after sendNonce overflow → `ErrNonceExhausted` (use a state
  with a pre-set high nonce; not exercised at full count).
- `PeerMetadata()` is independent of the input frame buffer.
- `SecretKey.String()` and `%v` format yield `"[REDACTED]"`.

`internal/security/curve/server_test.go`:

- `NewServer(...)` with nil Authorizer panics.
- `NewServer` with zero OurPublicKey, nil OurSecretKey →
  `ErrInvalidOptions`.
- `NewServer` with failing `Rand` → `ErrCryptoRand`.
- `Receive(HELLO)` happy path → `out=WELCOME`, `done=false`.
- `Receive(HELLO with bad version)` → `ErrMalformedHello`.
- `Receive(HELLO with non-zero padding)` → `ErrMalformedHello`.
- `Receive(HELLO with bad box)` → `ErrBoxOpen`.
- `Receive(INITIATE)` happy path → `out=READY`, `done=true`.
- `Receive(INITIATE with tampered outer ciphertext)` → `ErrBoxOpen`.
- `Receive(INITIATE with tampered cookie)` → `ErrBoxOpen` (cookie's
  own secretbox fails) OR `ErrCookieMismatch` (cookie opens but
  inner does not match).
- `Receive(INITIATE with tampered vouch)` → `ErrBoxOpen`.
- `Receive(INITIATE with valid crypto, auth rejects)` → `out=ERROR`,
  `err=ErrAuthRejected`. The reason in encoded ERROR matches the
  authorizer's error string (sanitized, ≤255 bytes).
- `Receive(INITIATE)` with auth that returns long error (>255 bytes) →
  reason in encoded ERROR is sanitized + truncated.
- `Receive(INITIATE)` with auth that returns reason containing non-VCHAR
  → reason has those bytes replaced with `'?'`.
- `Receive(INITIATE)` from AWAIT_HELLO → `ErrUnexpectedCommand`.
- `Receive(ERROR)` from any state → `ErrPeerError`.
- `Receive(*)` after DONE → `ErrAlreadyDone`.
- `Receive(*)` after auth-reject → `ErrAlreadyFailed`.
- After `Close()`: every method → `security.ErrClosed`.
- `Wrap`/`Unwrap` paired with peer ClientState round-trips.
- `PeerPublicKey()` after `Done()` returns the long-term public the
  Authorizer saw (and matches the keypair the test client used).

### 8.2 Mechanism interface conformance

`internal/security/mechanism_test.go`:

- Compile-time assertions:
  ```go
  var _ security.Mechanism       = (*null.State)(nil)
  var _ security.Mechanism       = (*plain.ClientState)(nil)
  var _ security.Mechanism       = (*plain.ServerState)(nil)
  var _ security.Mechanism       = (*curve.ClientState)(nil)
  var _ security.Mechanism       = (*curve.ServerState)(nil)
  var _ security.ClientMechanism = (*null.State)(nil)
  var _ security.ClientMechanism = (*plain.ClientState)(nil)
  var _ security.ClientMechanism = (*curve.ClientState)(nil)
  ```
- Run-time tests that the same `*testing.T` driver works against all
  five concrete types, parameterized by mechanism factory. Each test
  drives a full handshake-and-traffic round trip using only the
  `Mechanism` (and `ClientMechanism` for the active side) interface
  surface. This proves the abstraction is honest.

### 8.3 Property tests (`testing/quick`, MaxCount: 1000)

`internal/security/curve/handshake_property_test.go`:

- `TestCurveHappyPathProperty`:
  ```
  rng = rand.New(rand.NewSource(seed))
  cPub, cSec, _ = GenerateKeyPair(rng)
  sPub, sSec, _ = GenerateKeyPair(rng)
  mdC, mdS = randMetadata(rng), randMetadata(rng)

  client, _ = NewClient(ClientOptions{ ServerKey: sPub,
      OurPublicKey: cPub, OurSecretKey: &cSec, LocalMetadata: mdC, Rand: rng })
  server, _ = NewServer(ServerOptions{ OurPublicKey: sPub,
      OurSecretKey: &sSec, LocalMetadata: mdS,
      Authorizer: acceptAll, Rand: rng })

  hello, _ = client.Start()
  welcome, _, _ = server.Receive(hello)
  initiate, _, _ = client.Receive(*welcome)
  ready, done, _ = server.Receive(*initiate)
  require done
  out, done, _ = client.Receive(*ready)
  require done && out == nil
  require client.PeerMetadata() ≡ mdS
  require server.PeerMetadata() ≡ mdC
  require server.PeerPublicKey() == cPub

  // 100 round-trips of random frames.
  for i := 0; i < 100; i++ {
      f := randFrame(rng)
      wrapped, _ := client.Wrap(f)
      got, _    := server.Unwrap(wrapped)
      require got ≡ f

      f2 := randFrame(rng)
      wrapped2, _ := server.Wrap(f2)
      got2, _    := client.Unwrap(wrapped2)
      require got2 ≡ f2
  }
  ```

- `TestCurveAuthRejectProperty`: same setup, server with rejecting
  Authorizer. Verify server returns `(out=ERROR_cmd, err=ErrAuthRejected)`,
  reason equals the authorizer's error string, client.Receive of that
  ERROR returns `ErrPeerError` whose `.Error()` contains the reason,
  both states are FAILED.

- `TestCurveTamperRejection`: pick a random byte in a random handshake
  command, flip a random bit, deliver the tampered command. Verify that
  the recipient returns `ErrBoxOpen` (or `ErrMalformed*` if the tamper
  hits the structural prefix). 100 iterations.

- `TestCurveReplayRejection`: capture a valid `Wrap` output, deliver
  twice. Second delivery returns `ErrNonceReused`.

### 8.4 Vector tests (`testdata/curve/*.bin`)

CURVE byte output depends on entropy (transient keys, long-nonces,
cookie key). Vectors use a deterministic `rand` instantiated as
`math/rand/v2.NewChaCha8([32]byte{...})` (the seed bytes are pinned in
the test file). ChaCha8 is chosen because (a) it is in the Go standard
library, (b) it is reproducible across Go versions per the
`math/rand/v2` stability guarantee, and (c) it has enough state for
the multi-keypair workload of a CURVE handshake. `encodeXxx(...)` is
therefore reproducible byte-for-byte. Cross-validation against libzmq
is deferred to F4 interop, per `00-meta-overview.md` §6.

| File | Contents |
|------|----------|
| `curve-hello-empty.bin` | HELLO with deterministic c'/C' under deterministic seed. |
| `curve-welcome.bin` | WELCOME with deterministic s'/S' and cookie. |
| `curve-initiate-empty-meta.bin` | INITIATE with no metadata. |
| `curve-initiate-with-socket-type.bin` | INITIATE with `Socket-Type=DEALER`. |
| `curve-ready-empty-meta.bin` | READY with no metadata. |
| `curve-ready-with-identity.bin` | READY with `Socket-Type=ROUTER` + 8-byte `Identity`. |
| `curve-message-empty.bin` | MESSAGE wrapping an empty (0-byte) frame body, sendNonce=1, More=false. Pins the lower bound of the encrypted plaintext (single flags byte). |
| `curve-message-16b.bin` | MESSAGE wrapping a 16-byte frame, sendNonce=2. |
| `curve-message-more.bin` | MESSAGE wrapping a 4-byte frame with `More=true`, sendNonce=3. Pins the MORE-bit-into-flags-byte mapping. |
| `curve-error.bin` | ERROR with reason `"Authentication failed"`. |

Each vector is decoded via the appropriate `parse*` function (or
`Receive`) and re-encoded with the same deterministic seed to verify
byte equality. The seeds are pinned in the test file so any drift in
the encoder fails the byte-equality check.

The fixed RNG is exposed only to the `curve` test package via an
unexported helper; production paths default to `crypto/rand.Reader`.

### 8.5 Bench

`bench_test.go`:

- `BenchmarkClientHandshake` — full client round trip
  (`Start` → `Receive(WELCOME)` → `Receive(READY)`).
- `BenchmarkServerHandshake` — full server round trip
  (`Receive(HELLO)` → `Receive(INITIATE)`).
- `BenchmarkWrap` with `b.Run("64B" / "1KiB" / "64KiB" / "1MiB")`
  sub-benches — single-frame MESSAGE encrypt.
- `BenchmarkUnwrap` with the same sub-bench shape — single-frame
  MESSAGE decrypt.

All report `b.ReportAllocs()` and use `b.Loop()` per the project's
modernize convention. The numbers are informational; alloc counts are
pinned via `testing.AllocsPerRun` in a separate
`alloc_budget_test.go` (analogous to F2a/F2b).

### 8.6 What is **not** tested in F2c

- ZAP authentication paths (F6) — only the `Authorizer` callback shape
  is exercised.
- Socket-Type compatibility (F5).
- I/O errors / partial reads (F4).
- TLS or other transport-layer concerns.
- Concurrent use (single-threaded by contract; race detector enforces).
- libzmq cross-validation (deferred to F4 interop per
  `00-meta-overview.md` §6).
- Z85 encoding/decoding (out of L2 scope; tests use raw bytes).

### 8.7 Done criteria

- [ ] All unit tests pass.
- [ ] `Mechanism` / `ClientMechanism` conformance tests pass for all
      five concrete types.
- [ ] All four property tests pass 1000 iterations each.
- [ ] All 10 vector tests pass with byte equality under the pinned seed.
- [ ] `go vet ./...` clean.
- [ ] `staticcheck ./...` clean.
- [ ] `modernize -fix ./...` clean (no diff). [Per repository convention,
      run before tagging phase end.]
- [ ] `go test -race ./internal/security/curve/...` clean.
- [ ] `go test -race ./internal/security/...` clean (root package + the
      conformance tests across null/plain/curve).
- [ ] Benchmark allocs/op pinned via `testing.AllocsPerRun` for client
      handshake, server handshake, Wrap, and Unwrap.
- [ ] Phase tagged `phase-2c-curve-complete` only after all of the above.
- [ ] `00-meta-overview.md` §4 updated: F2c row → "Complete".
- [ ] `00-meta-overview.md` §7 updated: external dependencies row
      mentions both `nacl/box` and `nacl/secretbox` actually used.
- [ ] F2a/F2b amendment note added to `00-meta-overview.md` (under
      §4, alongside the existing "F1 amendments" subsection).

## 9. Open questions

None at draft time. Candidates worth flagging if they appear during
implementation or F4 interop:

- Whether the server should send ERROR on malformed INITIATE / failed
  cookie / failed vouch before closing (currently: no, treat as local
  fatal). Decision is reversible under the existing `(out, err)`
  contract.
- Whether `Authorizer` should receive additional parameters such as a
  `context.Context` (for cancellation) or transport context (e.g. peer
  address). Deferred until F6 says it needs one; the signature can be
  widened additively without breaking existing callers.
- Whether `Close` should also overwrite `OurSecretKey` despite caller
  ownership. Default: no (caller owns), but a doc-only flag could let
  callers opt in. Defer until a real caller asks.

Resolved during draft review:

- **Empty MESSAGE payload** — explicitly allowed; the inner plaintext
  is at minimum the 1-byte flags field. Pinned by
  `curve-message-empty.bin` in §8.4.
- **Multi-frame logical messages** — each ZMTP frame is wrapped
  independently (one MESSAGE command per frame, each with its own
  short-nonce). Documented in `Mechanism.Wrap`'s godoc (§4.1).
- **Authorizer cancellation** — F2c does not provide a cancellation
  path. Authorizers that may block long are responsible for their own
  timeout. Documented in `Authorizer`'s contract (§4.4).

## 10. References

- [RFC 37/ZMTP 3.1](https://rfc.zeromq.org/spec/37/) §3 (Security
  mechanisms), §3.3 (CURVE mechanism), §2.4 (Metadata).
- [RFC 25/ZMTP-CURVE](https://rfc.zeromq.org/spec/25/) — original
  CURVE specification (subsumed by RFC 37 §3.3 for ZMTP 3.1).
- [RFC 26/CurveZMQ](https://rfc.zeromq.org/spec/26/) — cryptographic
  primitives, command formats, cookie design, MESSAGE encryption.
- [RFC 27/ZAP](https://rfc.zeromq.org/spec/27/) — referenced for
  context; not implemented here. F6 will replace `Authorizer` with a
  ZAP-backed implementation.
- [RFC 32/Z85](https://rfc.zeromq.org/spec/32/) — referenced; out of
  L2 scope.
- [NaCl `crypto_box`](https://nacl.cr.yp.to/box.html) — public-key
  authenticated encryption used throughout CURVE handshake and traffic.
- [NaCl `crypto_secretbox`](https://nacl.cr.yp.to/secretbox.html) —
  symmetric authenticated encryption used for the WELCOME cookie.
- [`golang.org/x/crypto/nacl/box`](https://pkg.go.dev/golang.org/x/crypto/nacl/box)
  — Go binding consumed by F2c.
- [`golang.org/x/crypto/nacl/secretbox`](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox)
  — Go binding consumed by F2c.
- `docs/specs/01-zmtp-wire-protocol.md` — `READY` / `ERROR` wire format,
  `Frame` / `Command` / `Metadata` codec.
- `docs/specs/02a-security-null.md` — sibling spec, source of the
  symmetric `Mechanism`-shaped state machine.
- `docs/specs/02b-security-plain.md` — sibling spec, source of the
  asymmetric `ClientState`/`ServerState` split, the `Authenticator`
  callback shape (mirrored as `Authorizer`), and the `(out, err)`
  auth-reject convention.
- `docs/specs/00-meta-overview.md` — phase plan, layering rules,
  testing strategy.
