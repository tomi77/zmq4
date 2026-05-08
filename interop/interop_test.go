//go:build interop

// Package zmq4_interop_test contains F5a socket-level interop tests against
// a real libzmq peer running in a Docker container.
//
// These tests are gated by the "interop" build tag and require:
//   - Linux (fixture uses --network=host and host bind-mounts)
//   - Docker with the zmq4-interop-bridge:latest image
//
// Build and run:
//
//	docker build -t zmq4-interop-bridge:latest \
//	  -f internal/conn/interop/Dockerfile \
//	  internal/conn/interop/bridge
//	go test -race -tags interop -v ./interop/...
package zmq4_interop_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
	"github.com/tomi77/zmq4/internal/conn/interop/fixture"
	"github.com/tomi77/zmq4/internal/security/curve"
	"github.com/tomi77/zmq4/internal/security/plain"
	"github.com/tomi77/zmq4/internal/wire"
)

// ----------------------------------------------------------------------------
// Test matrix
// ----------------------------------------------------------------------------

type interopRow struct {
	dir      fixture.Role      // RoleDialer = Go dials; RoleListener = Go listens
	pair     string            // "reqrep" or "dealerrouter"
	mech     fixture.Mechanism
	scheme   string // "tcp" or "ipc"
	scenario fixture.Scenario  // ScenarioSingle or ScenarioMultipart
}

func buildMatrix() []interopRow {
	var rows []interopRow
	for _, dir := range []fixture.Role{fixture.RoleDialer, fixture.RoleListener} {
		for _, pair := range []string{"reqrep", "dealerrouter"} {
			for _, mech := range []fixture.Mechanism{fixture.MechNULL, fixture.MechPLAIN, fixture.MechCURVE} {
				for _, scheme := range []string{"tcp", "ipc"} {
					for _, sc := range []fixture.Scenario{fixture.ScenarioSingle, fixture.ScenarioMultipart} {
						rows = append(rows, interopRow{dir, pair, mech, scheme, sc})
					}
				}
			}
		}
	}
	return rows // 2×2×3×2×2 = 48
}

// goSocketType returns the Go socket type and the bridge socket type for a row.
//
// Mapping:
//
//	reqrep   + dialer   → Go=REQ,    bridge=REP
//	reqrep   + listener → Go=REP,    bridge=REQ
//	dealerrouter + dialer   → Go=DEALER, bridge=ROUTER
//	dealerrouter + listener → Go=ROUTER, bridge=DEALER
func socketTypeNames(row interopRow) (goType, bridgeType string) {
	switch row.pair + "+" + string(row.dir) {
	case "reqrep+dialer":
		return "REQ", "REP"
	case "reqrep+listener":
		return "REP", "REQ"
	case "dealerrouter+dialer":
		return "DEALER", "ROUTER"
	case "dealerrouter+listener":
		return "ROUTER", "DEALER"
	}
	panic("unhandled pair+dir: " + row.pair + "+" + string(row.dir))
}

// ----------------------------------------------------------------------------
// Top-level tests
// ----------------------------------------------------------------------------

func TestInterop(t *testing.T) {
	fixture.EnsureDockerImage(t)

	serverPub, serverSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	defer serverSec.Zero()
	clientPub, clientSec, err := curve.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	defer clientSec.Zero()

	for _, row := range buildMatrix() {
		row := row
		_, bridgeType := socketTypeNames(row)
		name := fmt.Sprintf("%s/%s/%s/%s/%s/%s", row.dir, row.pair, row.mech, row.scheme, bridgeType, row.scenario)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runInteropRow(t, row, serverPub, serverSec, clientPub, clientSec)
		})
	}
}

// TestInteropNegMechanismMismatch: Go REQ (NULL) → libzmq REP (PLAIN) → handshake error.
func TestInteropNegMechanismMismatch(t *testing.T) {
	fixture.EnsureDockerImage(t)

	spec := fixture.Spec{
		Role:       fixture.RoleListener,
		Endpoint:   "tcp://127.0.0.1:0",
		Mechanism:  fixture.MechPLAIN,
		Scenario:   fixture.ScenarioHandshake,
		SocketType: "REP",
		PLAIN:      fixture.PlainParams{User: "user", Pass: "pass"},
	}
	peer := fixture.Start(t, spec)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := zmq4.NewREQ()
	defer req.Close()
	err := req.Connect(ctx, peer.ResolvedEndpoint)
	if err == nil {
		t.Fatal("expected error when connecting with NULL to PLAIN server, got nil")
	}
}

// TestInteropNegIncompatiblePeer: Go REQ (NULL) → libzmq DEALER (NULL) → ErrIncompatiblePeer.
func TestInteropNegIncompatiblePeer(t *testing.T) {
	fixture.EnsureDockerImage(t)

	spec := fixture.Spec{
		Role:       fixture.RoleListener,
		Endpoint:   "tcp://127.0.0.1:0",
		Mechanism:  fixture.MechNULL,
		Scenario:   fixture.ScenarioHandshake,
		SocketType: "DEALER",
	}
	peer := fixture.Start(t, spec)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := zmq4.NewREQ()
	defer req.Close()
	err := req.Connect(ctx, peer.ResolvedEndpoint)
	if !errors.Is(err, zmq4.ErrIncompatiblePeer) {
		t.Fatalf("want ErrIncompatiblePeer, got %v", err)
	}
}

// ----------------------------------------------------------------------------
// Row runner
// ----------------------------------------------------------------------------

func runInteropRow(t *testing.T,
	row interopRow,
	serverPub curve.PublicKey, serverSec curve.SecretKey,
	clientPub curve.PublicKey, clientSec curve.SecretKey,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, bridgeType := socketTypeNames(row)

	// bridgeRole is opposite of Go's role.
	var bridgeRole fixture.Role
	if row.dir == fixture.RoleDialer {
		bridgeRole = fixture.RoleListener
	} else {
		bridgeRole = fixture.RoleDialer
	}

	// Build the bridge spec.
	spec := fixture.Spec{
		Mechanism:  row.mech,
		Scenario:   row.scenario,
		SocketType: bridgeType,
		Role:       bridgeRole,
	}

	// Security parameters.
	switch row.mech {
	case fixture.MechPLAIN:
		spec.PLAIN = fixture.PlainParams{User: "user", Pass: "pass"}
	case fixture.MechCURVE:
		if bridgeRole == fixture.RoleListener {
			// Bridge is CURVE server.
			spec.CURVE = fixture.CurveParams{
				IsServer:  true,
				PublicKey: z85(serverPub),
				SecretKey: z85([32]byte(serverSec)),
			}
		} else {
			// Bridge is CURVE client; it authenticates against our server pub key.
			spec.CURVE = fixture.CurveParams{
				IsServer:  false,
				ServerKey: z85(serverPub),
				PublicKey: z85(clientPub),
				SecretKey: z85([32]byte(clientSec)),
			}
		}
	}

	// Endpoint allocation.
	var goEP string
	if row.dir == fixture.RoleDialer {
		// Bridge listens; we dial peer.ResolvedEndpoint after Start.
		bridgeEP, sharedDir := allocBridgeListenEndpoint(t, row.scheme)
		spec.Endpoint = bridgeEP
		spec.IPCBindMountHost = sharedDir
		peer := fixture.Start(t, spec)
		goEP = peer.ResolvedEndpoint

		goOpts := buildGoOpts(t, row, false /* we are dialer */, serverPub, serverSec, clientPub, clientSec)
		runGoSocket(t, ctx, row, goEP, goOpts, true /* dial */, peer)
		peer.Wait(t, 10*time.Second)
	} else {
		// Go listens; bridge dials us.
		goEP, sharedDir := allocGoListenEndpoint(t, row.scheme)
		spec.Endpoint = goEP
		spec.IPCBindMountHost = sharedDir

		goOpts := buildGoOpts(t, row, true /* we are listener */, serverPub, serverSec, clientPub, clientSec)
		peer := fixture.Start(t, spec)

		runGoSocket(t, ctx, row, goEP, goOpts, false /* bind */, peer)
		peer.Wait(t, 10*time.Second)
	}
	_ = goEP
}

// ----------------------------------------------------------------------------
// Go socket operations
// ----------------------------------------------------------------------------

// runGoSocket creates the appropriate Go socket, binds or connects, runs the
// scenario, and verifies the result.
func runGoSocket(t *testing.T, ctx context.Context, row interopRow, ep string, opts goOpts, dial bool, peer *fixture.Peer) {
	t.Helper()

	goType, _ := socketTypeNames(row)

	switch goType {
	case "REQ":
		runGoREQ(t, ctx, ep, opts, row.scenario, dial)
	case "REP":
		runGoREP(t, ctx, ep, opts, row.scenario, dial)
	case "DEALER":
		runGoDEALER(t, ctx, ep, opts, row.scenario, dial)
	case "ROUTER":
		runGoROUTER(t, ctx, ep, opts, row.scenario, dial)
	}
	_ = peer
}

func runGoREQ(t *testing.T, ctx context.Context, ep string, opts goOpts, sc fixture.Scenario, dial bool) {
	t.Helper()
	req := zmq4.NewREQ(opts.clientOpts...)
	defer req.Close()

	if dial {
		if err := req.Connect(ctx, ep); err != nil {
			t.Fatalf("REQ.Connect: %v", err)
		}
	} else {
		if err := req.Bind(ctx, ep); err != nil {
			t.Fatalf("REQ.Bind: %v", err)
		}
	}

	payload := testPayload(sc)
	if err := req.Send(ctx, payload); err != nil {
		t.Fatalf("REQ.Send: %v", err)
	}
	got, err := req.Recv(ctx)
	if err != nil {
		t.Fatalf("REQ.Recv: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("REQ.Recv: got empty message")
	}
}

func runGoREP(t *testing.T, ctx context.Context, ep string, opts goOpts, sc fixture.Scenario, dial bool) {
	t.Helper()
	rep := zmq4.NewREP(opts.serverOpts...)
	defer rep.Close()

	if dial {
		if err := rep.Connect(ctx, ep); err != nil {
			t.Fatalf("REP.Connect: %v", err)
		}
	} else {
		if err := rep.Bind(ctx, ep); err != nil {
			t.Fatalf("REP.Bind: %v", err)
		}
	}

	// REP echoes: Recv then Send back.
	got, err := rep.Recv(ctx)
	if err != nil {
		t.Fatalf("REP.Recv: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("REP.Recv: got empty message")
	}
	if err := rep.Send(ctx, got); err != nil {
		t.Fatalf("REP.Send: %v", err)
	}
}

func runGoDEALER(t *testing.T, ctx context.Context, ep string, opts goOpts, sc fixture.Scenario, dial bool) {
	t.Helper()
	dealer := zmq4.NewDEALER(opts.clientOpts...)
	defer dealer.Close()

	if dial {
		if err := dealer.Connect(ctx, ep); err != nil {
			t.Fatalf("DEALER.Connect: %v", err)
		}
	} else {
		if err := dealer.Bind(ctx, ep); err != nil {
			t.Fatalf("DEALER.Bind: %v", err)
		}
	}

	payload := testPayload(sc)
	if err := dealer.Send(ctx, payload); err != nil {
		t.Fatalf("DEALER.Send: %v", err)
	}
	got, err := dealer.Recv(ctx)
	if err != nil {
		t.Fatalf("DEALER.Recv: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("DEALER.Recv: got empty message")
	}
}

func runGoROUTER(t *testing.T, ctx context.Context, ep string, opts goOpts, sc fixture.Scenario, dial bool) {
	t.Helper()
	router := zmq4.NewROUTER(opts.serverOpts...)
	defer router.Close()

	if dial {
		if err := router.Connect(ctx, ep); err != nil {
			t.Fatalf("ROUTER.Connect: %v", err)
		}
	} else {
		if err := router.Bind(ctx, ep); err != nil {
			t.Fatalf("ROUTER.Bind: %v", err)
		}
	}

	// ROUTER echoes: Recv [identity, ...frames], Send [identity, ...frames].
	rmsg, err := router.Recv(ctx)
	if err != nil {
		t.Fatalf("ROUTER.Recv: %v", err)
	}
	if len(rmsg) < 2 {
		t.Fatalf("ROUTER.Recv: want ≥2 frames (identity + payload), got %d", len(rmsg))
	}
	if err := router.Send(ctx, rmsg); err != nil {
		t.Fatalf("ROUTER.Send: %v", err)
	}
}

// ----------------------------------------------------------------------------
// Security options helpers
// ----------------------------------------------------------------------------

type goOpts struct {
	serverOpts []zmq4.Option // options for Bind side (REP, ROUTER)
	clientOpts []zmq4.Option // options for Connect side (REQ, DEALER)
}

// buildGoOpts returns options for our Go socket. weAreListener is true when
// our Go socket will Bind (listener role). The server keypair belongs to the
// CURVE server (= whoever listens).
func buildGoOpts(t *testing.T, row interopRow, weAreListener bool,
	serverPub curve.PublicKey, serverSec curve.SecretKey,
	clientPub curve.PublicKey, clientSec curve.SecretKey,
) goOpts {
	t.Helper()
	switch row.mech {
	case fixture.MechNULL:
		return goOpts{}
	case fixture.MechPLAIN:
		if weAreListener {
			auth := plain.Authenticator(func(user, pass []byte) error {
				if string(user) == "user" && string(pass) == "pass" {
					return nil
				}
				return errors.New("bad credentials")
			})
			return goOpts{
				serverOpts: []zmq4.Option{zmq4.WithPLAINServer(auth)},
				clientOpts: []zmq4.Option{zmq4.WithPLAINServer(auth)},
			}
		}
		return goOpts{
			serverOpts: []zmq4.Option{zmq4.WithPLAIN("user", "pass")},
			clientOpts: []zmq4.Option{zmq4.WithPLAIN("user", "pass")},
		}
	case fixture.MechCURVE:
		if weAreListener {
			// We are CURVE server.
			authorizer := curve.Authorizer(func(_ curve.PublicKey, _ wire.Metadata) error { return nil })
			so := []zmq4.Option{zmq4.WithCURVEServer(curve.ServerOptions{
				OurPublicKey: serverPub,
				OurSecretKey: &serverSec,
				Authorizer:   authorizer,
			})}
			return goOpts{serverOpts: so, clientOpts: so}
		}
		// We are CURVE client.
		co := []zmq4.Option{zmq4.WithCURVE(curve.ClientOptions{
			ServerKey:    serverPub,
			OurPublicKey: clientPub,
			OurSecretKey: &clientSec,
		})}
		return goOpts{serverOpts: co, clientOpts: co}
	}
	t.Fatalf("unknown mechanism %q", row.mech)
	return goOpts{}
}

// ----------------------------------------------------------------------------
// Endpoint allocation
// ----------------------------------------------------------------------------

// allocBridgeListenEndpoint returns the endpoint to give the bridge when it
// is the listener. For TCP, bridge binds to :0 and resolves the port via
// peer.ResolvedEndpoint. For IPC, a unique temp-dir path is used.
func allocBridgeListenEndpoint(t *testing.T, scheme string) (endpoint, sharedDir string) {
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

// allocGoListenEndpoint returns the endpoint for our Go socket to bind to when
// we are the listener. For TCP, a free port is grabbed via a brief listen. For
// IPC, a unique temp-dir path is used.
func allocGoListenEndpoint(t *testing.T, scheme string) (endpoint, sharedDir string) {
	t.Helper()
	switch scheme {
	case "tcp":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("allocGoListenEndpoint: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		return fmt.Sprintf("tcp://127.0.0.1:%d", port), ""
	case "ipc":
		dir := t.TempDir()
		path := filepath.Join(dir, "zmq.sock")
		return "ipc://" + path, dir
	}
	t.Fatalf("unknown scheme %q", scheme)
	return "", ""
}

// ----------------------------------------------------------------------------
// Scenario payload helpers
// ----------------------------------------------------------------------------

func testPayload(sc fixture.Scenario) zmq4.Message {
	switch sc {
	case fixture.ScenarioSingle:
		return zmq4.Message{[]byte("INTEROP_HELLO")}
	case fixture.ScenarioMultipart:
		return zmq4.Message{[]byte("INTEROP_P1"), []byte("INTEROP_P2"), []byte("INTEROP_P3")}
	}
	panic("unknown scenario: " + string(sc))
}

// ----------------------------------------------------------------------------
// Z85 encoder (copied from internal/conn/interop — not exported from there)
// ----------------------------------------------------------------------------

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
