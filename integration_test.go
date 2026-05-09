//go:build integration

package zmq4_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
	"github.com/tomi77/zmq4/internal/security/curve"
	"github.com/tomi77/zmq4/internal/security/plain"
	"github.com/tomi77/zmq4/internal/wire"
	"github.com/tomi77/zmq4/zap"
)

// freePort returns an ephemeral TCP port that was free at time of call.
// There is an inherent TOCTOU gap between this call and Bind, but it is far
// less collision-prone than fixed ports across parallel CI runs.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

type integRow struct {
	transport string // "tcp", "ipc", "inproc"
	security  string // "null", "plain", "curve"
	pair      string // "reqrep", "dealerrouter", "pubsub", "xpubxsub"
}

func TestIntegration(t *testing.T) {
	var rows []integRow
	for _, tr := range []string{"tcp", "ipc", "inproc"} {
		for _, sec := range []string{"null", "plain", "curve"} {
			for _, pair := range []string{"reqrep", "dealerrouter", "pubsub", "xpubxsub", "pushpull", "pair"} {
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
		ep = fmt.Sprintf("tcp://127.0.0.1:%d", freePort(t))
	case "ipc":
		// Use /tmp directly: t.TempDir() produces paths >104 chars on macOS,
		// exceeding the Unix socket path limit.
		dir, err := os.MkdirTemp("/tmp", "zmq4i")
		if err != nil {
			t.Fatalf("MkdirTemp: %v", err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		ep = "ipc://" + filepath.Join(dir, "s.sock")
	case "inproc":
		ep = "inproc://integ-" + row.transport + "-" + row.security + "-" + row.pair
	default:
		t.Fatalf("unknown transport %q", row.transport)
	}

	serverOpts, clientOpts := securityOpts(t, row.security)

	switch row.pair {
	case "reqrep":
		runREQREP(t, ctx, ep, serverOpts, clientOpts)
	case "dealerrouter":
		runDEALERROUTER(t, ctx, ep, serverOpts, clientOpts)
	case "pubsub":
		runPUBSUB(t, ctx, ep, serverOpts, clientOpts)
	case "xpubxsub":
		runXPUBXSUB(t, ctx, ep, serverOpts, clientOpts)
	case "pushpull":
		runPUSHPULL(t, ctx, ep, serverOpts, clientOpts)
	case "pair":
		runPAIR(t, ctx, ep, serverOpts, clientOpts)
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
		// Cleanup at test end, not at securityOpts return: the secret key
		// is kept alive via pointer in curve.ServerOptions until the test
		// completes; defer would zero it before the connection uses it.
		t.Cleanup(serverSec.Zero)

		// Generate client long-term keypair.
		clientPub, clientSec, err := curve.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("curve.GenerateKeyPair (client): %v", err)
		}
		t.Cleanup(clientSec.Zero)

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

func runPUBSUB(t *testing.T, ctx context.Context, ep string, serverOpts, clientOpts []zmq4.Option) {
	t.Helper()
	pub := zmq4.NewPUB(serverOpts...)
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	defer pub.Close()

	sub := zmq4.NewSUB(clientOpts...)
	if err := sub.Connect(ctx, ep); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer sub.Close()

	if err := sub.Subscribe([]byte("ping")); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	if err := pub.Send(ctx, zmq4.Message{[]byte("ping-payload")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := sub.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(got[0]) != "ping-payload" {
		t.Fatalf("want ping-payload, got %q", got[0])
	}
}

func runXPUBXSUB(t *testing.T, ctx context.Context, ep string, serverOpts, clientOpts []zmq4.Option) {
	t.Helper()
	xpub := zmq4.NewXPUB(serverOpts...)
	if err := xpub.Bind(ctx, ep); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	defer xpub.Close()

	xsub := zmq4.NewXSUB(clientOpts...)
	if err := xsub.Connect(ctx, ep); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer xsub.Close()

	if err := xsub.Subscribe([]byte("news")); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// XPUB sees the subscription frame.
	subMsg, err := xpub.Recv(ctx)
	if err != nil {
		t.Fatalf("XPUB Recv sub: %v", err)
	}
	if len(subMsg) == 0 || subMsg[0][0] != 0x01 {
		t.Fatalf("XPUB: expected subscribe frame, got %v", subMsg)
	}

	time.Sleep(10 * time.Millisecond)

	if err := xpub.Send(ctx, zmq4.Message{[]byte("news-item")}); err != nil {
		t.Fatalf("XPUB Send: %v", err)
	}
	got, err := xsub.Recv(ctx)
	if err != nil {
		t.Fatalf("XSUB Recv: %v", err)
	}
	if string(got[0]) != "news-item" {
		t.Fatalf("want news-item, got %q", got[0])
	}
}

func runPUSHPULL(t *testing.T, ctx context.Context, ep string, serverOpts, clientOpts []zmq4.Option) {
	t.Helper()

	pull := zmq4.NewPULL(serverOpts...)
	if err := pull.Bind(ctx, ep); err != nil {
		t.Fatalf("PULL.Bind: %v", err)
	}
	defer pull.Close()

	push := zmq4.NewPUSH(clientOpts...)
	if err := push.Connect(ctx, ep); err != nil {
		t.Fatalf("PUSH.Connect: %v", err)
	}
	defer push.Close()

	if err := push.Send(ctx, zmq4.Message{[]byte("hello")}); err != nil {
		t.Fatalf("PUSH.Send: %v", err)
	}
	got, err := pull.Recv(ctx)
	if err != nil {
		t.Fatalf("PULL.Recv: %v", err)
	}
	if len(got) == 0 || string(got[0]) != "hello" {
		t.Fatalf("want hello, got %q", got)
	}
}

func runPAIR(t *testing.T, ctx context.Context, ep string, serverOpts, clientOpts []zmq4.Option) {
	t.Helper()

	a := zmq4.NewPAIR(serverOpts...)
	if err := a.Bind(ctx, ep); err != nil {
		t.Fatalf("PAIR.Bind: %v", err)
	}
	defer a.Close()

	b := zmq4.NewPAIR(clientOpts...)
	if err := b.Connect(ctx, ep); err != nil {
		t.Fatalf("PAIR.Connect: %v", err)
	}
	defer b.Close()

	if err := b.Send(ctx, zmq4.Message{[]byte("ping")}); err != nil {
		t.Fatalf("PAIR b.Send: %v", err)
	}
	got, err := a.Recv(ctx)
	if err != nil {
		t.Fatalf("PAIR a.Recv: %v", err)
	}
	if len(got) == 0 || string(got[0]) != "ping" {
		t.Fatalf("want ping, got %q", got)
	}

	if err := a.Send(ctx, zmq4.Message{[]byte("pong")}); err != nil {
		t.Fatalf("PAIR a.Send: %v", err)
	}
	reply, err := b.Recv(ctx)
	if err != nil {
		t.Fatalf("PAIR b.Recv: %v", err)
	}
	if len(reply) == 0 || string(reply[0]) != "pong" {
		t.Fatalf("want pong, got %q", reply)
	}
}

func TestPUSHSndHWMBlock(t *testing.T) {
	// PUSH with sndHWM=1 (outCh cap=1) and PULL with rcvHWM=1 (inCh cap=1).
	//
	// The observable pipeline capacity is 4 messages before sends block:
	//   PULL inCh (1) + net.Pipe internal slot (1) + writeLoop in-flight (1) + PUSH outCh (1).
	// After 4 messages are queued without any pull.Recv(), the writeLoop blocks
	// at the network layer (PULL readLoop blocked on full inCh), outCh is full,
	// so the 5th send blocks.  pull.Recv() drains one from inCh, unblocking the
	// pipeline and allowing the blocked send to complete.
	endpoint := "inproc://TestPUSHSndHWMBlock"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	push := zmq4.NewPUSH(zmq4.WithSndHWM(1))
	pull := zmq4.NewPULL(zmq4.WithRcvHWM(1))
	defer push.Close()
	defer pull.Close()

	if err := push.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := pull.Connect(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // allow handshake

	// Fill the pipeline: 4 sends succeed immediately, saturating all buffers.
	for i := range 4 {
		if err := push.Send(ctx, zmq4.Message{[]byte(fmt.Sprintf("fill%d", i))}); err != nil {
			t.Fatalf("fill send %d: %v", i, err)
		}
	}
	// Allow the writeLoop to advance and reach the network-blocked state.
	time.Sleep(20 * time.Millisecond)

	// 5th send should block because outCh is full and writeLoop is network-blocked.
	done := make(chan error, 1)
	go func() {
		done <- push.Send(ctx, zmq4.Message{[]byte("blocked")})
	}()

	select {
	case err := <-done:
		t.Fatalf("5th send completed immediately (want block): err=%v", err)
	case <-time.After(30 * time.Millisecond):
		// correct: still blocking
	}

	// Drain one message from PULL — opens space in inCh, unblocking the pipeline.
	if _, err := pull.Recv(ctx); err != nil {
		t.Fatalf("recv: %v", err)
	}

	// Blocked send should now complete.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("blocked send after drain: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked send did not complete after drain")
	}
}

func TestPUBSndHWMDrop(t *testing.T) {
	// PUB with sndHWM=1 drops messages silently when queue is full.
	endpoint := "inproc://TestPUBSndHWMDrop"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pub := zmq4.NewPUB(zmq4.WithSndHWM(1))
	sub := zmq4.NewSUB()
	defer pub.Close()
	defer sub.Close()

	if err := pub.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := sub.Connect(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := sub.Subscribe([]byte("")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // allow handshake + subscription

	// Send more messages than sndHWM=1 can hold; all sends must return nil
	// (PUB.Send never returns an error for drops).
	for i := range 5 {
		msg := zmq4.Message{[]byte(fmt.Sprintf("msg%d", i))}
		if err := pub.Send(ctx, msg); err != nil {
			t.Fatalf("send %d: unexpected error: %v", i, err)
		}
	}
	// Test passes if no hang and no unexpected error. Drop is silent.
}

func TestNULLZAPAllow(t *testing.T) {
	// NULL mechanism + ZAP allow-all: connection succeeds, message delivered.
	endpoint := "inproc://TestNULLZAPAllow"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	router := zap.NewRouter(zap.HandlerFunc(func(r zap.Request) (zap.Reply, error) {
		if r.Mechanism != "NULL" {
			return zap.Reply{StatusCode: zap.StatusDenied, StatusText: "wrong mechanism"}, nil
		}
		return zap.Reply{StatusCode: zap.StatusOK, UserID: "anonymous"}, nil
	}))
	defer router.Close()

	push := zmq4.NewPUSH()
	pull := zmq4.NewPULL(zmq4.WithZAPDomain(router, ""))
	defer push.Close()
	defer pull.Close()

	if err := pull.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := push.Connect(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)

	if err := push.Send(ctx, zmq4.Message{[]byte("hello")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msg, err := pull.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if len(msg) == 0 || string(msg[0]) != "hello" {
		t.Fatalf("msg = %q, want hello", msg)
	}
}

func TestNULLZAPDenyBlocksConnection(t *testing.T) {
	// NULL mechanism + ZAP deny-all: connection is rejected at handshake.
	endpoint := "inproc://TestNULLZAPDenyBlocksConnection"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	router := zap.NewRouter(zap.HandlerFunc(func(r zap.Request) (zap.Reply, error) {
		return zap.Reply{StatusCode: zap.StatusDenied, StatusText: "denied"}, nil
	}))
	defer router.Close()

	push := zmq4.NewPUSH()
	pull := zmq4.NewPULL(zmq4.WithZAPDomain(router, "secure"))
	defer push.Close()
	defer pull.Close()

	if err := pull.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	// Connect may itself return an error when ZAP denial is synchronous (inproc).
	if err := push.Connect(ctx, endpoint); err != nil {
		return // denial surfaced at connect time — test passes
	}
	time.Sleep(50 * time.Millisecond)

	// Send should time out because no pipe was established.
	sendCtx, sendCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer sendCancel()
	err := push.Send(sendCtx, zmq4.Message{[]byte("blocked")})
	if err == nil {
		t.Fatal("Send succeeded, want error (no pipe established after ZAP denial)")
	}
}

func TestPLAINZAPAllow(t *testing.T) {
	// PLAIN mechanism + ZAP allow: connection succeeds.
	endpoint := "inproc://TestPLAINZAPAllow"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	router := zap.NewRouter(zap.HandlerFunc(func(r zap.Request) (zap.Reply, error) {
		if r.Mechanism != "PLAIN" || len(r.Credentials) < 2 {
			return zap.Reply{StatusCode: zap.StatusDenied}, nil
		}
		if string(r.Credentials[0]) == "alice" && string(r.Credentials[1]) == "secret" {
			return zap.Reply{StatusCode: zap.StatusOK, UserID: "alice"}, nil
		}
		return zap.Reply{StatusCode: zap.StatusDenied}, nil
	}))
	defer router.Close()

	// Local auth callback always denies — ZAP takes precedence.
	localDeny := plain.Authenticator(func(u, p []byte) error { return fmt.Errorf("local deny") })

	rep := zmq4.NewREP(zmq4.WithPLAINServer(localDeny), zmq4.WithZAPDomain(router, ""))
	req := zmq4.NewREQ(zmq4.WithPLAIN("alice", "secret"))
	defer rep.Close()
	defer req.Close()

	if err := rep.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := req.Connect(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)

	if err := req.Send(ctx, zmq4.Message{[]byte("ping")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msg, err := rep.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if len(msg) == 0 || string(msg[0]) != "ping" {
		t.Fatalf("msg = %q, want ping", msg)
	}
}

func TestPLAINZAPDenyRejectsConnection(t *testing.T) {
	// PLAIN mechanism + ZAP deny: wrong password is rejected.
	endpoint := "inproc://TestPLAINZAPDenyRejectsConnection"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	router := zap.NewRouter(zap.HandlerFunc(func(r zap.Request) (zap.Reply, error) {
		return zap.Reply{StatusCode: zap.StatusDenied, StatusText: "bad credentials"}, nil
	}))
	defer router.Close()

	localAllow := plain.Authenticator(func(u, p []byte) error { return nil })

	rep := zmq4.NewREP(zmq4.WithPLAINServer(localAllow), zmq4.WithZAPDomain(router, ""))
	req := zmq4.NewREQ(zmq4.WithPLAIN("alice", "wrong"))
	defer rep.Close()
	defer req.Close()

	if err := rep.Bind(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	// Connect may itself return an error when ZAP denial is synchronous (inproc),
	// or it may succeed at transport level with rejection happening asynchronously.
	// Either way, no usable pipe is established.
	connectErr := req.Connect(ctx, endpoint)
	if connectErr != nil {
		// Denial surfaced at connect time — test passes.
		return
	}
	time.Sleep(50 * time.Millisecond)

	sendCtx, sendCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer sendCancel()
	err := req.Send(sendCtx, zmq4.Message{[]byte("blocked")})
	if err == nil {
		t.Fatal("Send succeeded, want timeout (no pipe after ZAP denial)")
	}
}
