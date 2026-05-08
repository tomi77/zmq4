package conn

import (
	"context"
	"net"
	"sync"
	"time"

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
