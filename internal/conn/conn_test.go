package conn

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/null"
	"github.com/tomi77/zmq4/internal/wire"
)

// newPipeConn builds an unhandshaken *Conn around one end of a net.Pipe
// for testing the non-handshake surface. The mech is a fresh null state
// (it is never driven; the conn is post-construction synthetic).
func newPipeConn(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	ours, peer := net.Pipe()
	cfg := newConfig(nil)
	c := &Conn{
		raw:      ours,
		fr:       wire.NewFrameReader(ours, wire.WithMaxBodySize(cfg.maxFrameBodySize)),
		fw:       wire.NewFrameWriter(ours),
		mech:     null.New(nil),
		peerMeta: nil,
	}
	t.Cleanup(func() {
		_ = c.Close()
		_ = peer.Close()
	})
	return c, peer
}

func TestConnCloseIdempotent(t *testing.T) {
	c, _ := newPipeConn(t)
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestConnCloseClosesRaw(t *testing.T) {
	c, peer := newPipeConn(t)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Reading the peer side should now see EOF (or ErrClosedPipe — net.Pipe
	// closes both directions on one Close).
	buf := make([]byte, 1)
	_, err := peer.Read(buf)
	if err == nil {
		t.Fatalf("peer.Read after Close: nil error, want EOF/ErrClosedPipe")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("peer.Read after Close: %v, want io.EOF or io.ErrClosedPipe", err)
	}
}

func TestConnRemoteLocalAddrDelegate(t *testing.T) {
	c, peer := newPipeConn(t)
	if c.RemoteAddr() == nil {
		t.Errorf("RemoteAddr() = nil")
	}
	if c.LocalAddr() == nil {
		t.Errorf("LocalAddr() = nil")
	}
	// Both should equal the underlying conn's addrs.
	if c.RemoteAddr().String() != c.raw.RemoteAddr().String() {
		t.Errorf("RemoteAddr delegation mismatch")
	}
	if c.LocalAddr().String() != c.raw.LocalAddr().String() {
		t.Errorf("LocalAddr delegation mismatch")
	}
	_ = peer
}

func TestConnPeerMetadataReturnsStoredSlice(t *testing.T) {
	c, _ := newPipeConn(t)
	c.peerMeta = wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("PAIR")}}
	got := c.PeerMetadata()
	if len(got) != 1 || string(got[0].Name) != "Socket-Type" || string(got[0].Value) != "PAIR" {
		t.Fatalf("PeerMetadata() = %+v, want one Socket-Type=PAIR property", got)
	}
}

func TestPostHandshakeReadFrameNULL(t *testing.T) {
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	// Server writes one frame; client reads it.
	payload := bytes.Repeat([]byte{0xAB}, 1024)
	go func() {
		if err := s.WriteFrame(wire.Frame{Kind: wire.FrameMessage, Body: payload}); err != nil {
			t.Errorf("server WriteFrame: %v", err)
		}
	}()
	got, err := c.ReadFrame()
	if err != nil {
		t.Fatalf("client ReadFrame: %v", err)
	}
	if got.Kind != wire.FrameMessage {
		t.Errorf("Kind = %v, want FrameMessage", got.Kind)
	}
	if !bytes.Equal(got.Body, payload) {
		t.Errorf("body mismatch: got len=%d want len=%d", len(got.Body), len(payload))
	}
}

func TestPostHandshakeReadFramePeerERROR(t *testing.T) {
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	// Server emits a wire-level ERROR command. WriteFrame on a
	// FrameCommand bypasses mech.Wrap (per RFC 25 / spec §6.5), so the
	// public surface produces exactly the bytes a peer ERROR would.
	go func() {
		ec, _ := wire.ErrorCommand{Reason: "auth revoked"}.Encode()
		body, _ := wire.EncodeCommand(ec)
		if err := s.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body}); err != nil {
			t.Errorf("server WriteFrame: %v", err)
		}
	}()
	_, err := c.ReadFrame()
	var pe *ErrPeerError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want *ErrPeerError", err)
	}
	if pe.Reason != "auth revoked" {
		t.Errorf("Reason = %q, want %q", pe.Reason, "auth revoked")
	}
}

func TestPostHandshakeReadFrameCommandPassthrough(t *testing.T) {
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	// Server sends a SUBSCRIBE command (post-handshake traffic command).
	go func() {
		body, _ := wire.EncodeCommand(wire.Command{Name: wire.SubscribeCommandName, Data: []byte("topic.")})
		if err := s.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body}); err != nil {
			t.Errorf("server WriteFrame: %v", err)
		}
	}()
	got, err := c.ReadFrame()
	if err != nil {
		t.Fatalf("client ReadFrame: %v", err)
	}
	if got.Kind != wire.FrameCommand {
		t.Errorf("Kind = %v, want FrameCommand (pass-through)", got.Kind)
	}
	cmd, err := wire.ParseCommand(got.Body)
	if err != nil {
		t.Fatalf("ParseCommand: %v", err)
	}
	if cmd.Name != wire.SubscribeCommandName {
		t.Errorf("cmd.Name = %q, want %q", cmd.Name, wire.SubscribeCommandName)
	}
	if !bytes.Equal(cmd.Data, []byte("topic.")) {
		t.Errorf("cmd.Data = %q, want %q", cmd.Data, "topic.")
	}
}

func TestPostHandshakeReadFrameMalformedCommand(t *testing.T) {
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	// Server sends a FrameCommand with an empty body — wire.ParseCommand
	// rejects this (empty body → ErrInvalidCommand). WriteFrame bypasses
	// mech.Wrap on FrameCommand, so the empty body reaches the peer
	// verbatim. The connection may be torn down by cleanup before
	// WriteFrame returns (net.Buffers.WriteTo does a follow-up write for
	// the empty body), so io.ErrClosedPipe is an acceptable outcome.
	go func() {
		if err := s.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: []byte{}}); err != nil {
			if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("server WriteFrame: %v", err)
			}
		}
	}()
	_, err := c.ReadFrame()
	if err == nil {
		t.Fatalf("expected error from malformed command, got nil")
	}
	if !errors.Is(err, wire.ErrInvalidCommand) {
		t.Errorf("err = %v, want errors.Is(err, wire.ErrInvalidCommand)", err)
	}
	if !strings.Contains(err.Error(), "conn: bad post-handshake command") {
		t.Errorf("err message %q does not contain expected prefix", err.Error())
	}
}

func TestPostHandshakeWriteFrameNULL(t *testing.T) {
	// Round-trip via NULL: WriteFrame(client) → ReadFrame(server) verbatim.
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	payload := []byte("hello world")
	go func() {
		if err := c.WriteFrame(wire.Frame{Kind: wire.FrameMessage, Body: payload}); err != nil {
			t.Errorf("client WriteFrame: %v", err)
		}
	}()
	got, err := s.ReadFrame()
	if err != nil {
		t.Fatalf("server ReadFrame: %v", err)
	}
	if !bytes.Equal(got.Body, payload) {
		t.Errorf("body mismatch: got=%q want=%q", got.Body, payload)
	}
}

func TestPostHandshakeWriteFrameAfterClose(t *testing.T) {
	c, _, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := c.WriteFrame(wire.Frame{Kind: wire.FrameMessage, Body: []byte("x")})
	if err == nil {
		t.Fatalf("expected error from WriteFrame after Close")
	}
	if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("err = %v, want net.ErrClosed or io.ErrClosedPipe", err)
	}
}

func TestPostHandshakeWriteFrameCommandPassthrough(t *testing.T) {
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	body, _ := wire.EncodeCommand(wire.Command{Name: wire.CancelCommandName, Data: []byte("topic.")})
	go func() {
		// FrameCommand bypasses mech.Wrap — peer should see verbatim bytes.
		if err := c.WriteFrame(wire.Frame{Kind: wire.FrameCommand, Body: body}); err != nil {
			t.Errorf("client WriteFrame: %v", err)
		}
	}()
	got, err := s.ReadFrame()
	if err != nil {
		t.Fatalf("server ReadFrame: %v", err)
	}
	if got.Kind != wire.FrameCommand {
		t.Errorf("Kind = %v, want FrameCommand", got.Kind)
	}
	if !bytes.Equal(got.Body, body) {
		t.Errorf("body mismatch")
	}
}

func TestPostHandshakeWriteFrameConcurrent(t *testing.T) {
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	const N = 50
	// Server reader: collect N frames.
	gotBodies := make([][]byte, 0, N)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range N {
			f, err := s.ReadFrame()
			if err != nil {
				t.Errorf("server ReadFrame: %v", err)
				return
			}
			gotBodies = append(gotBodies, append([]byte(nil), f.Body...))
		}
	}()
	// N concurrent writers on client.
	var wg sync.WaitGroup
	wg.Add(N)
	for i := range N {
		go func() {
			defer wg.Done()
			payload := []byte{byte(i)}
			if err := c.WriteFrame(wire.Frame{Kind: wire.FrameMessage, Body: payload}); err != nil {
				t.Errorf("WriteFrame[%d]: %v", i, err)
			}
		}()
	}
	wg.Wait()
	<-done
	// Each frame's body must be intact (no interleaving). The SET of i
	// values seen must equal {0..N-1}.
	seen := make(map[byte]bool)
	for _, b := range gotBodies {
		if len(b) != 1 {
			t.Errorf("frame body len = %d, want 1 (concurrent write interleaved bytes!)", len(b))
		} else {
			seen[b[0]] = true
		}
	}
	for i := range N {
		if !seen[byte(i)] {
			t.Errorf("missing payload byte %d", i)
		}
	}
}

func TestPostHandshakeMultipart(t *testing.T) {
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	frames := []wire.Frame{
		{Kind: wire.FrameMessage, More: true, Body: []byte("part1")},
		{Kind: wire.FrameMessage, More: true, Body: []byte("part2")},
		{Kind: wire.FrameMessage, More: false, Body: []byte("part3")},
	}
	go func() {
		for _, f := range frames {
			if err := c.WriteFrame(f); err != nil {
				t.Errorf("WriteFrame: %v", err)
				return
			}
		}
	}()
	for i, want := range frames {
		got, err := s.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		if got.More != want.More {
			t.Errorf("frame %d: More = %v, want %v", i, got.More, want.More)
		}
		if !bytes.Equal(got.Body, want.Body) {
			t.Errorf("frame %d: body = %q, want %q", i, got.Body, want.Body)
		}
	}
}

func TestPostHandshakeCloseUnblocksRead(t *testing.T) {
	c, _, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := c.ReadFrame()
		readDone <- err
	}()
	// Give the reader a moment to enter the blocking syscall.
	time.Sleep(20 * time.Millisecond)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatalf("ReadFrame returned nil after Close; want error")
		}
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("err = %v, want net.ErrClosed or io.ErrClosedPipe", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("ReadFrame did not unblock within 500 ms after Close")
	}
}

func TestPostHandshakeReadAfterClose(t *testing.T) {
	c, _, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err := c.ReadFrame()
	if err == nil {
		t.Fatalf("ReadFrame after Close: nil, want error")
	}
	if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("err = %v, want net.ErrClosed or io.ErrClosedPipe", err)
	}
}

func TestPostHandshakeRaceDetectorClean(t *testing.T) {
	// Full round-trip + concurrent writes + Close. Run with -race in CI.
	c, s, cErr, sErr := runHandshakePair(t,
		func() security.ClientMechanism { return null.New(nil) },
		func() security.Mechanism { return null.New(nil) })
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: cErr=%v sErr=%v", cErr, sErr)
	}
	const N = 25
	var wg sync.WaitGroup
	wg.Add(N + 1)
	go func() {
		defer wg.Done()
		for range N {
			if _, err := s.ReadFrame(); err != nil {
				return
			}
		}
	}()
	for i := range N {
		go func() {
			defer wg.Done()
			_ = c.WriteFrame(wire.Frame{Kind: wire.FrameMessage, Body: []byte{byte(i)}})
		}()
	}
	wg.Wait()
	_ = c.Close()
	_ = s.Close()
}
