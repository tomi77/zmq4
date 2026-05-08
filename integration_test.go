//go:build integration

package zmq4_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
	"github.com/tomi77/zmq4/internal/security/curve"
	"github.com/tomi77/zmq4/internal/security/plain"
	"github.com/tomi77/zmq4/internal/wire"
)

// tcpPort returns a deterministic fixed port for each (transport, security,
// pair) combination. Only TCP tests use ports; inproc and ipc use name-based
// addressing so they don't need numeric ports.
//
// Layout (6 TCP subtests × 1 port each, base 25550):
//
//	tcp/null/reqrep        → 25550
//	tcp/null/dealerrouter  → 25551
//	tcp/plain/reqrep       → 25552
//	tcp/plain/dealerrouter → 25553
//	tcp/curve/reqrep       → 25554
//	tcp/curve/dealerrouter → 25555
var tcpPortMap = map[string]int{
	"null/reqrep":        25550,
	"null/dealerrouter":  25551,
	"plain/reqrep":       25552,
	"plain/dealerrouter": 25553,
	"curve/reqrep":       25554,
	"curve/dealerrouter": 25555,
}

type integRow struct {
	transport string // "tcp", "ipc", "inproc"
	security  string // "null", "plain", "curve"
	pair      string // "reqrep", "dealerrouter"
}

func TestIntegration(t *testing.T) {
	var rows []integRow
	for _, tr := range []string{"tcp", "ipc", "inproc"} {
		for _, sec := range []string{"null", "plain", "curve"} {
			for _, pair := range []string{"reqrep", "dealerrouter"} {
				rows = append(rows, integRow{tr, sec, pair})
			}
		}
	}
	for _, row := range rows {
		row := row
		t.Run(row.transport+"/"+row.security+"/"+row.pair, func(t *testing.T) {
			t.Parallel()
			runIntegRow(t, row)
		})
	}
}

func runIntegRow(t *testing.T, row integRow) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var ep string
	switch row.transport {
	case "tcp":
		port, ok := tcpPortMap[row.security+"/"+row.pair]
		if !ok {
			t.Fatalf("no port mapping for tcp/%s/%s", row.security, row.pair)
		}
		ep = fmt.Sprintf("tcp://127.0.0.1:%d", port)
	case "ipc":
		ep = "ipc:///tmp/zmq4-integ-" + row.security + "-" + row.pair + ".sock"
	case "inproc":
		ep = "inproc://integ-" + row.transport + "-" + row.security + "-" + row.pair
	}

	serverOpts, clientOpts := securityOpts(t, row.security)

	switch row.pair {
	case "reqrep":
		runREQREP(t, ctx, ep, serverOpts, clientOpts)
	case "dealerrouter":
		runDEALERROUTER(t, ctx, ep, serverOpts, clientOpts)
	default:
		t.Fatalf("unknown pair %q", row.pair)
	}
}

func securityOpts(t *testing.T, security string) (serverOpts, clientOpts []zmq4.Option) {
	t.Helper()
	switch security {
	case "null":
		return nil, nil

	case "plain":
		auth := plain.Authenticator(func(user, pass []byte) error {
			if string(user) == "u" && string(pass) == "p" {
				return nil
			}
			return errors.New("bad credentials")
		})
		return []zmq4.Option{zmq4.WithPLAINServer(auth)},
			[]zmq4.Option{zmq4.WithPLAIN("u", "p")}

	case "curve":
		// Generate server long-term keypair.
		serverPub, serverSec, err := curve.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("curve.GenerateKeyPair (server): %v", err)
		}

		// Generate client long-term keypair.
		clientPub, clientSec, err := curve.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("curve.GenerateKeyPair (client): %v", err)
		}

		// Authorizer: accept any client (key-pinning is out of scope here).
		authorizer := curve.Authorizer(func(_ curve.PublicKey, _ wire.Metadata) error {
			return nil
		})

		serverOptions := curve.ServerOptions{
			OurPublicKey: serverPub,
			OurSecretKey: &serverSec,
			Authorizer:   authorizer,
		}
		clientOptions := curve.ClientOptions{
			ServerKey:    serverPub,
			OurPublicKey: clientPub,
			OurSecretKey: &clientSec,
		}
		return []zmq4.Option{zmq4.WithCURVEServer(serverOptions)},
			[]zmq4.Option{zmq4.WithCURVE(clientOptions)}
	}

	t.Fatalf("unknown security %q", security)
	return nil, nil
}

func runREQREP(t *testing.T, ctx context.Context, ep string, serverOpts, clientOpts []zmq4.Option) {
	t.Helper()

	rep := zmq4.NewREP(serverOpts...)
	if err := rep.Bind(ctx, ep); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	defer rep.Close()

	req := zmq4.NewREQ(clientOpts...)
	if err := req.Connect(ctx, ep); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer req.Close()

	if err := req.Send(ctx, zmq4.Message{[]byte("ping")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := rep.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if len(got) == 0 || string(got[0]) != "ping" {
		t.Fatalf("want ping, got %q", got)
	}
	if err := rep.Send(ctx, zmq4.Message{[]byte("pong")}); err != nil {
		t.Fatalf("Send reply: %v", err)
	}
	reply, err := req.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv reply: %v", err)
	}
	if len(reply) == 0 || string(reply[0]) != "pong" {
		t.Fatalf("want pong, got %q", reply)
	}
}

func runDEALERROUTER(t *testing.T, ctx context.Context, ep string, serverOpts, clientOpts []zmq4.Option) {
	t.Helper()

	router := zmq4.NewROUTER(serverOpts...)
	if err := router.Bind(ctx, ep); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	defer router.Close()

	dealer := zmq4.NewDEALER(clientOpts...)
	if err := dealer.Connect(ctx, ep); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer dealer.Close()

	if err := dealer.Send(ctx, zmq4.Message{[]byte("hi")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	rmsg, err := router.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	// rmsg[0] = identity frame (prepended by ROUTER), rmsg[1:] = payload
	if len(rmsg) < 2 || string(rmsg[1]) != "hi" {
		t.Fatalf("want [identity hi], got %v", rmsg)
	}
	if err := router.Send(ctx, zmq4.Message{rmsg[0], []byte("there")}); err != nil {
		t.Fatalf("Send reply: %v", err)
	}
	dreply, err := dealer.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv reply: %v", err)
	}
	if len(dreply) == 0 || string(dreply[0]) != "there" {
		t.Fatalf("want there, got %q", dreply)
	}
}
