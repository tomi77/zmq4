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
	"github.com/tomi77/zmq4/internal/security/seccommon"
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
// For the server role the greeting write is queued in a goroutine
// (same reason as before). The returned channel closes when that
// goroutine's write finishes; callers that need to send further data
// on the same net.Conn (e.g. a symmetric-mech READY command) MUST
// wait on this channel before writing to preserve stream ordering on
// zero-buffer transports such as net.Pipe. For the client role the
// channel is nil (write already completed synchronously).
func greetingExchange(raw net.Conn, role greetingRole, mech nameAware) (<-chan struct{}, error) {
	ourGreeting := wire.Greeting{
		Mechanism: mech.Name(),
		AsServer:  role.asServer(),
	}

	// Client sends synchronously first (spec §6.1: client initiates).
	// Server queues its send in a goroutine so that two-server scenarios
	// (both connecting as server) and single-sided net.Pipe test helpers
	// do not deadlock; write errors are swallowed since any real I/O
	// failure surfaces on the read path below.
	var greetingDone <-chan struct{}
	if role == greetingRoleClient {
		if err := wire.WriteGreeting(raw, ourGreeting); err != nil {
			return nil, err
		}
	} else {
		ch := make(chan struct{})
		greetingDone = ch
		go func() {
			_ = wire.WriteGreeting(raw, ourGreeting)
			close(ch)
		}()
	}

	// Both sides: read peer's greeting.
	if err := wire.ReadGreetingPhaseA(raw); err != nil {
		// Wrap signature failure as ErrInvalidGreeting; pass through
		// version-major failure (wire.ErrUnsupportedVersion).
		return nil, wrapPhaseA(err)
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
		return nil, err
	}
	peerG, err := wire.DecodeGreeting(buf[:])
	if err != nil {
		return nil, err
	}
	if peerG.Mechanism != mech.Name() {
		return nil, errMechMismatch(mech.Name(), peerG.Mechanism)
	}
	if mech.Name() != "NULL" {
		// Asymmetric mechanism: peer.AsServer must differ from ourSide.
		if peerG.AsServer == role.asServer() {
			return nil, errRoleConflict(role.asServer(), peerG.AsServer)
		}
	}

	return greetingDone, nil
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

// ClientHandshake performs the ZMTP greeting and security handshake on
// the active side. raw is a connected net.Conn (typically the result of
// transport.Dial). mech is a configured ClientMechanism; F5 owns its
// construction and metadata setup.
//
// ctx MUST carry a deadline. Without one, ClientHandshake returns
// ErrNoDeadline before touching raw.
//
// On success, returns a *Conn ready for ReadFrame/WriteFrame; raw is
// owned by *Conn (Close releases it). On failure, raw is closed by F4
// and the error is returned (wrapped with %w).
func ClientHandshake(ctx context.Context, raw net.Conn,
	mech security.ClientMechanism, opts ...Option) (*Conn, error) {
	return doHandshake(ctx, raw, mech, mech, greetingRoleClient, opts)
}

// ServerHandshake performs the ZMTP greeting and security handshake on
// the passive side. Symmetric to ClientHandshake, taking the base
// Mechanism interface (no Start required).
func ServerHandshake(ctx context.Context, raw net.Conn,
	mech security.Mechanism, opts ...Option) (*Conn, error) {
	return doHandshake(ctx, raw, mech, nil, greetingRoleServer, opts)
}

// doHandshake is the shared implementation. activeMech is non-nil only
// for clients; when set, doHandshake calls activeMech.Start() between
// greeting and the loop.
func doHandshake(ctx context.Context, raw net.Conn,
	mech security.Mechanism, activeMech security.ClientMechanism,
	role greetingRole, opts []Option) (*Conn, error) {

	cfg := newConfig(opts)

	// Pre-deadline check: ErrNoDeadline must fire before raw is touched.
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrNoDeadline
	}

	var c *Conn
	err := runWithCtxDeadline(ctx, raw, func() error {
		// 1. Greeting (lockstep, asymmetric send order).
		greetingDone, err := greetingExchange(raw, role, mech)
		if err != nil {
			return err
		}
		// 2. Emit Start() if needed.
		// Client (activeMech != nil): send synchronously before entering the
		// receive loop (spec §6.2: active side initiates).
		// Server with a symmetric mechanism (NULL): Start() is also required,
		// but must be fired in a goroutine so that the two peers' READY frames
		// do not deadlock on net.Pipe's synchronous transport.
		fw := wire.NewFrameWriter(raw)
		if activeMech != nil {
			startCmd, err := activeMech.Start()
			if err != nil {
				emitERROR(fw, err.Error())
				return fmt.Errorf("%w: mech.Start: %v", ErrHandshakeFail, err)
			}
			body, err := wire.EncodeCommand(startCmd)
			if err != nil {
				return fmt.Errorf("%w: encode Start: %v", ErrHandshakeFail, err)
			}
			if err := fw.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body}); err != nil {
				return err
			}
		} else if cm, ok := mech.(security.ClientMechanism); ok {
			// Symmetric mechanism on the server side (NULL): fire Start() in a
			// goroutine. A goroutine is required because both peers initiate
			// simultaneously on a synchronous transport (net.Pipe): the server
			// cannot write before the client reads, and the client cannot read
			// before it finishes its own synchronous write and enters its receive
			// loop. The goroutine uses a private FrameWriter so it never shares
			// mutable FrameWriter state with fw; fw is reserved exclusively for
			// the server goroutine (runHandshakeLoop / emitERROR). net.Conn is
			// documented as safe for concurrent reads and writes.
			//
			// greetingDone serialises this write after the greeting write on
			// the same conn: on net.Pipe the two goroutine writes would otherwise
			// interleave non-deterministically, sending the READY bytes before
			// the greeting bytes and confusing the client (which reads 0x04
			// instead of the expected 0xFF signature byte).
			startCmd, err := cm.Start()
			if err != nil {
				return fmt.Errorf("%w: mech.Start: %v", ErrHandshakeFail, err)
			}
			body, err := wire.EncodeCommand(startCmd)
			if err != nil {
				return fmt.Errorf("%w: encode Start: %v", ErrHandshakeFail, err)
			}
			go func() {
				if greetingDone != nil {
					<-greetingDone
				}
				_ = wire.NewFrameWriter(raw).WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body})
			}()
		}
		// 3. Drive the loop.
		if err := runHandshakeLoop(raw, fw, mech, cfg); err != nil {
			return err
		}
		// 4. Build the post-handshake *Conn.
		peerMeta := seccommon.CloneMetadata(mech.PeerMetadata())
		if peerMeta == nil {
			peerMeta = wire.Metadata{}
		}
		c = &Conn{
			raw:      raw,
			fr:       wire.NewFrameReader(raw, wire.WithMaxBodySize(cfg.maxFrameBodySize)),
			fw:       fw,
			mech:     mech,
			peerMeta: peerMeta,
		}
		return nil
	})

	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}
