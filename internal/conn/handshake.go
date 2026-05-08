package conn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/wire"
)

// emitERROR is a best-effort ERROR-command emitter used by the handshake
// driver to inform the peer of a local abort before tearing down the
// conn. RFC 23 §6 caps the reason at one octet length prefix (255 B);
// emitERROR truncates silently. All write/encode errors are swallowed —
// the conn is being torn down regardless.
func emitERROR(fw *wire.FrameWriter, reason string) {
	if len(reason) > 255 {
		reason = reason[:255]
	}
	cmd, err := wire.ErrorCommand{Reason: reason}.Encode()
	if err != nil {
		return // truncation guarantees this branch is unreachable.
	}
	body, err := wire.EncodeCommand(cmd)
	if err != nil {
		return
	}
	_ = fw.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body})
}

// runWithCtxDeadline executes fn while a watcher goroutine bridges
// ctx cancellation to raw.SetDeadline. ctx MUST carry a deadline; if
// not, ErrNoDeadline is returned before raw is touched.
//
// On entry: raw.SetDeadline(ctx-deadline-time).
// During fn: a watcher goroutine selects on ctx.Done() and on a private
// done channel; if ctx.Done() fires first, the watcher pokes
// raw.SetDeadline(time.Unix(1,0)) to unblock any in-flight Read/Write.
// On fn return: close(done); wg.Wait() (load-bearing — see spec §6.6
// for the race rationale); raw.SetDeadline(time.Time{}) to clear.
//
// fn's return value is propagated unchanged. If both ctx fired and fn
// returned an error, fn's error is returned (the deadline-induced
// os.ErrDeadlineExceeded is the natural surface).
func runWithCtxDeadline(ctx context.Context, raw net.Conn, fn func() error) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ErrNoDeadline
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return err
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			_ = raw.SetDeadline(time.Unix(1, 0))
		case <-done:
		}
	}()

	err := fn()
	close(done)
	wg.Wait()                        // race fix: see spec §6.6.
	_ = raw.SetDeadline(time.Time{}) // clear deadline post-handshake.
	return err
}

// initiateCommandName is the ZMTP INITIATE command name. Duplicated from
// plain/codec.go and curve/codec.go because the wire package does not
// export it. Replace with wire.InitiateCommandName if wire ever adds it.
const initiateCommandName = "INITIATE"

// greetingRole tags the local side of a greeting exchange. Clients send
// synchronously before reading; servers queue their send in a goroutine
// and read immediately. The role also determines as-server for
// asymmetric mechanisms (PLAIN, CURVE).
type greetingRole int

const (
	greetingRoleClient greetingRole = 0 // as-server=false
	greetingRoleServer greetingRole = 1 // as-server=true
)

func (r greetingRole) asServer() bool { return r == greetingRoleServer }

// nameAware is the subset of security.Mechanism that greetingExchange
// uses. Lets tests substitute a tiny mock without constructing a real
// state machine.
type nameAware interface {
	Name() string
}

// greetingExchange runs the §6.1 lockstep greeting against raw. On
// success the mechanism name and role match the peer. On failure
// returns one of: ErrInvalidGreeting, wire.ErrUnsupportedVersion,
// ErrMechanismMismatch, ErrRoleConflict, or any I/O error wrapped.
//
// Asymmetric ordering (spec §6.1): the client sends its greeting
// synchronously before reading, so the server always has data to
// read. The server uses a fire-and-forget goroutine so that its
// write does not block when the peer has already torn down its read
// path (e.g. net.Pipe test helpers that write then exit). On TCP
// loopback the 64-byte greeting fits in the kernel buffer so the
// goroutine completes without blocking the peer's read.
func greetingExchange(raw net.Conn, role greetingRole, mech nameAware) error {
	ourGreeting := wire.Greeting{
		Mechanism: mech.Name(),
		AsServer:  role.asServer(),
	}

	// Client sends synchronously first (spec §6.1: client initiates).
	// Server queues its send in a goroutine so that two-server scenarios
	// (both connecting as server) and single-sided net.Pipe test helpers
	// do not deadlock; write errors are swallowed since any real I/O
	// failure surfaces on the read path below.
	if role == greetingRoleClient {
		if err := wire.WriteGreeting(raw, ourGreeting); err != nil {
			return err
		}
	} else {
		go func() { _ = wire.WriteGreeting(raw, ourGreeting) }()
	}

	// Both sides: read peer's greeting.
	if err := wire.ReadGreetingPhaseA(raw); err != nil {
		// Wrap signature failure as ErrInvalidGreeting; pass through
		// version-major failure (wire.ErrUnsupportedVersion).
		return wrapPhaseA(err)
	}
	// Reconstruct the validated phase-A bytes for DecodeGreeting.
	var buf [wire.GreetingSize]byte
	buf[0] = 0xFF
	buf[9] = 0x7F
	buf[10] = 0x03
	if _, err := io.ReadFull(raw, buf[11:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	peerG, err := wire.DecodeGreeting(buf[:])
	if err != nil {
		return err
	}
	if peerG.Mechanism != mech.Name() {
		return errMechMismatch(mech.Name(), peerG.Mechanism)
	}
	if mech.Name() != "NULL" {
		// Asymmetric mechanism: peer.AsServer must differ from ourSide.
		if peerG.AsServer == role.asServer() {
			return errRoleConflict(role.asServer(), peerG.AsServer)
		}
	}

	return nil
}

// wrapPhaseA classifies an error returned by ReadGreetingPhaseA. Bad
// signature → ErrInvalidGreeting wrapping the wire sentinel; version
// mismatch → forwarded as wire.ErrUnsupportedVersion. Truncation /
// other I/O errors pass through.
func wrapPhaseA(err error) error {
	if errors.Is(err, wire.ErrInvalidSignature) {
		return fmt.Errorf("%w: %v", ErrInvalidGreeting, err)
	}
	// wire.ErrUnsupportedVersion and I/O errors pass through unchanged.
	return err
}

func errMechMismatch(ours, theirs string) error {
	return fmt.Errorf("%w: ours=%q peer=%q", ErrMechanismMismatch, ours, theirs)
}

func errRoleConflict(ours, theirs bool) error {
	return fmt.Errorf("%w: ours=%t peer=%t", ErrRoleConflict, ours, theirs)
}

// runHandshakeLoop drives mech.Receive against frames read from raw
// until mech.Done() — or an error. Used by both ClientHandshake (after
// emitting Start()'s command) and ServerHandshake.
//
// Per spec §6.2:
//   - reads via a transient FrameReader capped at cfg.maxHandshakeCommandSize;
//   - rejects FrameMessage as ErrUnexpectedFrame;
//   - parses the command body; on parse error, returns wrapped
//     ErrHandshakeFail (and does NOT emit ERROR back — peer is already
//     malformed);
//   - on peer ERROR, returns wrapped ErrHandshakeFail with the reason;
//   - enforces metadata cap on READY/INITIATE commands; on overflow,
//     emits ERROR and returns ErrMetadataTooLarge;
//   - on mech.Receive error, emits ERROR and returns wrapped
//     ErrHandshakeFail.
//
// fw is the shared FrameWriter on raw (also used by emitERROR for
// abort signalling). mech is the local Mechanism (already constructed
// and, for the active side, already had Start() called by the caller).
func runHandshakeLoop(raw net.Conn, fw *wire.FrameWriter, mech security.Mechanism, cfg *config) error {
	hsfr := wire.NewFrameReader(raw, wire.WithMaxBodySize(int64(cfg.maxHandshakeCommandSize)))
	for {
		f, err := hsfr.ReadFrame()
		if err != nil {
			switch {
			case errors.Is(err, wire.ErrFrameTooLarge):
				return fmt.Errorf("%w: %v", ErrCommandTooLarge, err)
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
				return fmt.Errorf("%w: peer closed mid-handshake: %v", ErrHandshakeFail, err)
			default:
				return err
			}
		}
		if f.Kind != wire.FrameCommand {
			return fmt.Errorf("%w: got Kind=%v", ErrUnexpectedFrame, f.Kind)
		}
		cmd, err := wire.ParseCommand(f.Body)
		if err != nil {
			return fmt.Errorf("%w: parse: %v", ErrHandshakeFail, err)
		}
		if cmd.Name == wire.ErrorCommandName {
			ec, perr := wire.ParseError(cmd)
			if perr != nil {
				return fmt.Errorf("%w: malformed peer ERROR: %v", ErrHandshakeFail, perr)
			}
			return fmt.Errorf("%w: peer ERROR: %s", ErrHandshakeFail, ec.Reason)
		}
		if isMetadataBearing(cmd.Name) && len(cmd.Data) > cfg.maxMetadataSize {
			emitERROR(fw, "metadata exceeds cap")
			return fmt.Errorf("%w: %s body=%dB cap=%dB",
				ErrMetadataTooLarge, cmd.Name, len(cmd.Data), cfg.maxMetadataSize)
		}
		out, done, err := mech.Receive(cmd)
		if err != nil {
			emitERROR(fw, err.Error())
			return fmt.Errorf("%w: mech.Receive: %v", ErrHandshakeFail, err)
		}
		if out != nil {
			body, err := wire.EncodeCommand(*out)
			if err != nil {
				return fmt.Errorf("%w: encode mech out: %v", ErrHandshakeFail, err)
			}
			if err := fw.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body}); err != nil {
				return err
			}
		}
		if done {
			return nil
		}
	}
}

// isMetadataBearing reports whether a handshake command body parses as
// metadata properties. The metadata cap applies only to these.
//
// READY (NULL/PLAIN/CURVE) and INITIATE (PLAIN/CURVE) carry metadata;
// HELLO and WELCOME do not (they have mechanism-specific bodies). For
// CURVE, INITIATE's body is encrypted (cookie + vouch box + sealed
// metadata), so the cap acts as a wire-level allocation bound rather
// than a plaintext-size limit. See spec §6.2.
func isMetadataBearing(name string) bool {
	switch name {
	case wire.ReadyCommandName, initiateCommandName:
		return true
	default:
		return false
	}
}
