package security_test

import (
	"bytes"
	"testing"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/curve"
	"github.com/tomi77/zmq4/internal/security/null"
	"github.com/tomi77/zmq4/internal/security/plain"
	"github.com/tomi77/zmq4/internal/wire"
)

// Compile-time assertions: every concrete type implements the
// interfaces it claims to.
var (
	_ security.Mechanism       = (*null.State)(nil)
	_ security.Mechanism       = (*plain.ClientState)(nil)
	_ security.Mechanism       = (*plain.ServerState)(nil)
	_ security.Mechanism       = (*curve.ClientState)(nil)
	_ security.Mechanism       = (*curve.ServerState)(nil)
	_ security.ClientMechanism = (*null.State)(nil)
	_ security.ClientMechanism = (*plain.ClientState)(nil)
	_ security.ClientMechanism = (*curve.ClientState)(nil)
)

// TestMechanismInterfaceCompilesForAllTypes runs the compile-time
// assertions above; if the file builds, this test trivially passes.
func TestMechanismInterfaceCompilesForAllTypes(t *testing.T) {
	t.Log("compile-time assertions in interfaces_conformance_test.go ensure all five concrete types satisfy security.Mechanism (and ClientMechanism for active sides)")
}

// TestNullConformance drives a NULL handshake through the Mechanism
// interface only.
func TestNullConformance(t *testing.T) {
	a, b := null.New(nil), null.New(nil)
	driveSymmetricHandshake(t, a, b)
	wrapUnwrapRoundTrip(t, a, b)
}

// TestPlainConformance drives a PLAIN handshake through the
// Mechanism/ClientMechanism interfaces only.
func TestPlainConformance(t *testing.T) {
	c, err := plain.NewClient([]byte("u"), []byte("p"), nil)
	if err != nil {
		t.Fatalf("plain.NewClient: %v", err)
	}
	s := plain.NewServer(func(_, _ []byte) error { return nil }, nil)
	driveAsymmetricHandshake(t, c, s)
	// PLAIN's Wrap/Unwrap is pass-through; round trip just checks identity.
	wrapUnwrapRoundTrip(t, c, s)
}

// TestCurveConformance drives a CURVE handshake through the
// Mechanism/ClientMechanism interfaces only.
func TestCurveConformance(t *testing.T) {
	clientPub, clientSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	serverPub, serverSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	c, err := curve.NewClient(curve.ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	if err != nil {
		t.Fatalf("curve.NewClient: %v", err)
	}
	s, err := curve.NewServer(curve.ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ curve.PublicKey, _ wire.Metadata) error { return nil },
	})
	if err != nil {
		t.Fatalf("curve.NewServer: %v", err)
	}
	driveAsymmetricHandshake(t, c, s)
	wrapUnwrapRoundTrip(t, c, s)
}

// driveSymmetricHandshake handles NULL: both peers Start, swap READY.
func driveSymmetricHandshake(t *testing.T, a, b security.ClientMechanism) {
	t.Helper()
	cmdA, err := a.Start()
	if err != nil {
		t.Fatalf("a.Start: %v", err)
	}
	cmdB, err := b.Start()
	if err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	if _, _, err := a.Receive(cmdB); err != nil {
		t.Fatalf("a.Receive: %v", err)
	}
	if _, _, err := b.Receive(cmdA); err != nil {
		t.Fatalf("b.Receive: %v", err)
	}
	if !a.Done() || !b.Done() {
		t.Fatalf("Done() = a:%v b:%v, want both true", a.Done(), b.Done())
	}
}

// driveAsymmetricHandshake handles PLAIN/CURVE: HELLO ↔ WELCOME ↔
// INITIATE ↔ READY.
func driveAsymmetricHandshake(t *testing.T, c security.ClientMechanism, s security.Mechanism) {
	t.Helper()
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	welcome, done, err := s.Receive(hello)
	if err != nil || done || welcome == nil {
		t.Fatalf("server.Receive(HELLO): out=%v done=%v err=%v", welcome, done, err)
	}
	initiate, done, err := c.Receive(*welcome)
	if err != nil || done || initiate == nil {
		t.Fatalf("client.Receive(WELCOME): out=%v done=%v err=%v", initiate, done, err)
	}
	ready, done, err := s.Receive(*initiate)
	if err != nil || !done || ready == nil {
		t.Fatalf("server.Receive(INITIATE): out=%v done=%v err=%v", ready, done, err)
	}
	out, done, err := c.Receive(*ready)
	if err != nil || !done || out != nil {
		t.Fatalf("client.Receive(READY): out=%v done=%v err=%v", out, done, err)
	}
	if !c.Done() || !s.Done() {
		t.Fatalf("Done() = c:%v s:%v, want both true", c.Done(), s.Done())
	}
}

// wrapUnwrapRoundTrip exercises the Wrap/Unwrap surface on both sides
// after a successful handshake.
func wrapUnwrapRoundTrip(t *testing.T, c, s security.Mechanism) {
	t.Helper()
	for _, payload := range [][]byte{{}, []byte("hello"), bytes.Repeat([]byte{0x42}, 1024)} {
		f := wire.Frame{Kind: wire.FrameMessage, More: true, Body: payload}
		wrapped, err := c.Wrap(f)
		if err != nil {
			t.Fatalf("c.Wrap: %v", err)
		}
		got, err := s.Unwrap(wrapped)
		if err != nil {
			t.Fatalf("s.Unwrap: %v", err)
		}
		if got.Kind != wire.FrameMessage || got.More != f.More || !bytes.Equal(got.Body, f.Body) {
			t.Fatalf("client→server: got=%+v want=%+v", got, f)
		}

		f2 := wire.Frame{Kind: wire.FrameMessage, More: false, Body: payload}
		wrapped2, err := s.Wrap(f2)
		if err != nil {
			t.Fatalf("s.Wrap: %v", err)
		}
		got2, err := c.Unwrap(wrapped2)
		if err != nil {
			t.Fatalf("c.Unwrap: %v", err)
		}
		if got2.Kind != wire.FrameMessage || got2.More != f2.More || !bytes.Equal(got2.Body, f2.Body) {
			t.Fatalf("server→client: got=%+v want=%+v", got2, f2)
		}
	}
}
