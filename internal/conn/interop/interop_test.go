//go:build interop

package interop_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomi77/zmq4/internal/conn"
	"github.com/tomi77/zmq4/internal/conn/interop/fixture"
	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/security/curve"
	"github.com/tomi77/zmq4/internal/security/null"
	"github.com/tomi77/zmq4/internal/security/plain"
	"github.com/tomi77/zmq4/internal/transport"
	"github.com/tomi77/zmq4/internal/wire"
)

func TestMain(m *testing.M) {
	// Ensure the bridge image exists; skip the whole package on Docker absence.
	// (TestMain runs before any test; we use a fresh *testing.T proxy via t.Skip
	// inside individual tests for finer control. Simpler: just run, individual
	// tests will skip if Docker is not on PATH.)
	m.Run()
}

type interopRow struct {
	mech     fixture.Mechanism
	scheme   string // "tcp" or "ipc"
	dir      string // "we_dial" (we are dialer, libzmq listens) or "we_listen"
	scenario fixture.Scenario
}

// pairMetadata is the metadata both peers inject so libzmq accepts the
// session (libzmq requires Socket-Type).
func pairMetadata() wire.Metadata {
	name, value := fixture.PairMetadata()
	return wire.Metadata{{Name: name, Value: value}}
}

// makeOurMechClient builds the F4-side client mechanism for the row.
func makeOurMechClient(t *testing.T, row interopRow,
	curveServerPub, curveOurPub curve.PublicKey, curveOurSec curve.SecretKey) security.ClientMechanism {
	t.Helper()
	switch row.mech {
	case fixture.MechNULL:
		return null.New(pairMetadata())
	case fixture.MechPLAIN:
		c, err := plain.NewClient([]byte("user"), []byte("pass"), pairMetadata())
		if err != nil {
			t.Fatalf("plain.NewClient: %v", err)
		}
		return c
	case fixture.MechCURVE:
		c, err := curve.NewClient(curve.ClientOptions{
			ServerKey:     curveServerPub,
			OurPublicKey:  curveOurPub,
			OurSecretKey:  &curveOurSec,
			LocalMetadata: pairMetadata(),
		})
		if err != nil {
			t.Fatalf("curve.NewClient: %v", err)
		}
		return c
	}
	t.Fatalf("unknown mechanism %q", row.mech)
	return nil
}

// makeOurMechServer builds the F4-side server mechanism for the row.
func makeOurMechServer(t *testing.T, row interopRow,
	curveOurPub curve.PublicKey, curveOurSec curve.SecretKey) security.Mechanism {
	t.Helper()
	switch row.mech {
	case fixture.MechNULL:
		return null.New(pairMetadata())
	case fixture.MechPLAIN:
		return plain.NewServer(func(_, _ []byte) error { return nil }, pairMetadata())
	case fixture.MechCURVE:
		s, err := curve.NewServer(curve.ServerOptions{
			OurPublicKey:  curveOurPub,
			OurSecretKey:  &curveOurSec,
			Authorizer:    func(_ curve.PublicKey, _ wire.Metadata) error { return nil },
			LocalMetadata: pairMetadata(),
		})
		if err != nil {
			t.Fatalf("curve.NewServer: %v", err)
		}
		return s
	}
	t.Fatalf("unknown mechanism %q", row.mech)
	return nil
}

// fixtureSpec builds the libzmq side of the conversation.
// curveServerPub/Sec: our F4 server's key pair (used by libzmq-as-server in we_dial,
// and as the ServerKey libzmq-as-client must authenticate against in we_listen).
// curveClientPub/Sec: our F4 client's key pair (used by libzmq-as-client in we_listen).
func fixtureSpec(t *testing.T, row interopRow,
	curveServerPub curve.PublicKey, curveServerSec curve.SecretKey,
	curveClientPub curve.PublicKey, curveClientSec curve.SecretKey,
	endpoint string, role fixture.Role) fixture.Spec {
	t.Helper()
	spec := fixture.Spec{
		Role:      role,
		Endpoint:  endpoint,
		Mechanism: row.mech,
		Scenario:  row.scenario,
	}
	switch row.mech {
	case fixture.MechPLAIN:
		spec.PLAIN = fixture.PlainParams{User: "user", Pass: "pass"}
	case fixture.MechCURVE:
		// libzmq side acts as server when our side is dialer (we_dial),
		// and as client when our side is listener (we_listen).
		if row.dir == "we_dial" {
			spec.CURVE = fixture.CurveParams{
				IsServer:  true,
				PublicKey: z85(curveServerPub),
				SecretKey: z85([32]byte(curveServerSec)),
			}
		} else {
			spec.CURVE = fixture.CurveParams{
				IsServer:  false,
				ServerKey: z85(curveServerPub),           // our F4 server pub (libzmq must auth against this)
				PublicKey: z85(curveClientPub),           // libzmq's own pubkey
				SecretKey: z85([32]byte(curveClientSec)), // libzmq's own privkey
			}
		}
	}
	return spec
}

// z85 encodes a 32-byte CURVE key into Z85 printable (40 chars).
// libzmq accepts either binary or Z85 keys via curve_publickey /
// curve_secretkey, but Z85 is safer to ship through JSON.
//
// The inline implementation matches RFC 32/Z85: groups of 4 input
// bytes encode as 5 output chars from a fixed alphabet. Public-key
// length (32 B) is divisible by 4, so no padding is needed.
//
// Inlined here rather than imported from internal/security/curve
// because that package does not currently expose a Z85 encoder.
// Promoting one is a future F2c amendment; for F4 interop it is
// not worth the scope creep.
var z85Alphabet = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")

func z85(k [32]byte) string {
	const groupBytes = 4
	const groupChars = 5
	out := make([]byte, 0, len(k)/groupBytes*groupChars)
	for i := 0; i < len(k); i += groupBytes {
		v := uint32(k[i])<<24 | uint32(k[i+1])<<16 | uint32(k[i+2])<<8 | uint32(k[i+3])
		var chunk [5]byte
		for j := 4; j >= 0; j-- {
			chunk[j] = z85Alphabet[v%85]
			v /= 85
		}
		out = append(out, chunk[:]...)
	}
	return string(out)
}

func TestInteropHappyPath(t *testing.T) {
	fixture.EnsureDockerImage(t)

	clientPub, clientSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	serverPub, serverSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	mechs := []fixture.Mechanism{fixture.MechNULL, fixture.MechPLAIN, fixture.MechCURVE}
	schemes := []string{"tcp", "ipc"}
	dirs := []string{"we_dial", "we_listen"}
	scenarios := []fixture.Scenario{fixture.ScenarioHandshake, fixture.ScenarioSingle, fixture.ScenarioMultipart}

	for _, mech := range mechs {
		for _, scheme := range schemes {
			for _, dir := range dirs {
				for _, sc := range scenarios {
					row := interopRow{mech: mech, scheme: scheme, dir: dir, scenario: sc}
					name := fmt.Sprintf("%s/%s/%s/%s", row.mech, row.scheme, row.dir, row.scenario)
					t.Run(name, func(t *testing.T) {
						runInteropRow(t, row, clientPub, clientSec, serverPub, serverSec)
					})
				}
			}
		}
	}
}

func runInteropRow(t *testing.T, row interopRow,
	clientPub curve.PublicKey, clientSec curve.SecretKey,
	serverPub curve.PublicKey, serverSec curve.SecretKey) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var ourConn *conn.Conn
	if row.dir == "we_dial" {
		// libzmq listens on a wildcard port; we dial whatever it returns.
		bridgeEndpoint, sharedDir := allocLibzmqListenEndpoint(t, row.scheme)
		spec := fixtureSpec(t, row, serverPub, serverSec, clientPub, clientSec, bridgeEndpoint, fixture.RoleListener)
		spec.IPCBindMountHost = sharedDir
		peer := fixture.Start(t, spec)

		raw, err := transport.Dial(ctx, peer.ResolvedEndpoint)
		if err != nil {
			t.Fatalf("transport.Dial(%q): %v", peer.ResolvedEndpoint, err)
		}
		ourConn, err = conn.ClientHandshake(ctx, raw,
			makeOurMechClient(t, row, serverPub, clientPub, clientSec))
		if err != nil {
			t.Fatalf("ClientHandshake: %v", err)
		}
		defer ourConn.Close()
		// Drive scenario from our side; peer.Wait at end of function
		// confirms libzmq exited cleanly.
		runScenario(t, ctx, ourConn, row.scenario)
		peer.Wait(t, 5*time.Second)
		return
	}

	// we_listen: bind our listener FIRST, then start the bridge so it
	// dials a port we already own. This avoids a race where the bridge
	// dials a port we have not yet re-bound to.
	ourEndpoint, sharedDir := allocOurListenEndpoint(t, row.scheme)
	lis, err := transport.Listen(ctx, ourEndpoint)
	if err != nil {
		t.Fatalf("transport.Listen(%q): %v", ourEndpoint, err)
	}
	defer lis.Close()

	// For tcp the listener may have resolved the wildcard port; pull
	// the concrete address. For ipc the path is already concrete.
	bridgeEndpoint := ourEndpoint
	if row.scheme == "tcp" {
		bridgeEndpoint = "tcp://" + lis.Addr().String()
	}
	spec := fixtureSpec(t, row, serverPub, serverSec, clientPub, clientSec, bridgeEndpoint, fixture.RoleDialer)
	spec.IPCBindMountHost = sharedDir
	peer := fixture.Start(t, spec)

	// Now Accept the bridge's connection.
	type accepted struct {
		c   net.Conn
		err error
	}
	ach := make(chan accepted, 1)
	go func() {
		c, err := lis.Accept()
		ach <- accepted{c, err}
	}()
	var raw net.Conn
	select {
	case a := <-ach:
		if a.err != nil {
			t.Fatalf("Accept: %v", a.err)
		}
		raw = a.c
	case <-ctx.Done():
		t.Fatalf("Accept did not complete before ctx deadline")
	}

	ourConn, err = conn.ServerHandshake(ctx, raw,
		makeOurMechServer(t, row, serverPub, serverSec))
	if err != nil {
		t.Fatalf("ServerHandshake: %v", err)
	}
	defer ourConn.Close()

	runScenario(t, ctx, ourConn, row.scenario)
	peer.Wait(t, 5*time.Second)
}

// runScenario executes the requested traffic pattern from our side.
// libzmq is the echo peer in single/multipart scenarios.
func runScenario(t *testing.T, ctx context.Context, ourConn *conn.Conn, sc fixture.Scenario) {
	t.Helper()
	switch sc {
	case fixture.ScenarioHandshake:
		// Just having ourConn means the handshake completed.
	case fixture.ScenarioSingle:
		payload := bytes.Repeat([]byte{0x42}, 1024)
		if err := ourConn.WriteFrame(wire.Frame{Kind: wire.FrameMessage, Body: payload}); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
		got, err := ourConn.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if !bytes.Equal(got.Body, payload) {
			t.Errorf("echo body mismatch: len=%d want=%d", len(got.Body), len(payload))
		}
	case fixture.ScenarioMultipart:
		parts := [][]byte{[]byte("p1"), []byte("p2"), []byte("p3")}
		for i, p := range parts {
			more := i < len(parts)-1
			if err := ourConn.WriteFrame(wire.Frame{Kind: wire.FrameMessage, More: more, Body: p}); err != nil {
				t.Fatalf("WriteFrame[%d]: %v", i, err)
			}
		}
		for i, want := range parts {
			got, err := ourConn.ReadFrame()
			if err != nil {
				t.Fatalf("ReadFrame[%d]: %v", i, err)
			}
			wantMore := i < len(parts)-1
			if got.More != wantMore || !bytes.Equal(got.Body, want) {
				t.Errorf("part %d: got More=%v body=%q, want More=%v body=%q",
					i, got.More, got.Body, wantMore, want)
			}
		}
	}
	// ctx is not threaded into ReadFrame/WriteFrame yet; retained in the
	// signature so Task 22 error-path tests can share this helper unchanged.
	_ = ctx
}

// allocLibzmqListenEndpoint produces the endpoint string we hand to
// the bridge when libzmq is the listener. For tcp this is a
// 127.0.0.1:0 wildcard (libzmq fills in the concrete port and we
// pick it up via Peer.ResolvedEndpoint). For ipc this is a path
// inside a per-test directory which is also bind-mounted into the
// container so the UDS is visible on both sides.
//
// Returns the endpoint plus the host directory to bind-mount (empty
// for tcp).
func allocLibzmqListenEndpoint(t *testing.T, scheme string) (endpoint, sharedDir string) {
	t.Helper()
	switch scheme {
	case "tcp":
		return "tcp://127.0.0.1:0", ""
	case "ipc":
		// ipc subtests require Linux (fixture.Start skips on non-Linux).
		dir := t.TempDir()
		path := filepath.Join(dir, "zmq.sock")
		return "ipc://" + path, dir
	}
	t.Fatalf("unknown scheme %q", scheme)
	return "", ""
}

// allocOurListenEndpoint produces the endpoint we pass to
// transport.Listen on our side. For tcp this is `tcp://127.0.0.1:0`
// — transport.Listen will resolve the port; the caller pulls the
// concrete address from lis.Addr() afterwards. For ipc this is the
// same per-test-directory path as allocLibzmqListenEndpoint.
func allocOurListenEndpoint(t *testing.T, scheme string) (endpoint, sharedDir string) {
	t.Helper()
	switch scheme {
	case "tcp":
		return "tcp://127.0.0.1:0", ""
	case "ipc":
		dir := t.TempDir()
		path := filepath.Join(dir, "zmq.sock")
		return "ipc://" + path, dir
	}
	t.Fatalf("unknown scheme %q", scheme)
	return "", ""
}
