// curve-security demonstrates CURVE encryption and authentication (RFC 25/26).
// Keys are generated ephemerally at startup — no pre-shared key files needed.
// Run: go run ./examples/curve-security/
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"

	"github.com/tomi77/zmq4"
	"github.com/tomi77/zmq4/internal/security/curve"
	"github.com/tomi77/zmq4/internal/wire"
)

func main() {
	ctx := context.Background()
	ep := freePort()

	// Generate long-term key pairs for server and client.
	serverPub, serverSec, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}
	defer serverSec.Zero()

	clientPub, clientSec, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}
	defer clientSec.Zero()

	// Server: REP with CURVE, accepts any client (no authorizer).
	serverOpts := curve.ServerOptions{
		OurPublicKey: serverPub,
		OurSecretKey: &serverSec,
		Authorizer:   func(_ curve.PublicKey, _ wire.Metadata) error { return nil },
	}

	rep := zmq4.NewREP(zmq4.WithCURVEServer(serverOpts))
	if err := rep.Bind(ctx, ep); err != nil {
		panic(err)
	}
	defer rep.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Client: REQ with CURVE, using the server's public key for verification.
		clientOpts := curve.ClientOptions{
			ServerKey:    serverPub,
			OurPublicKey: clientPub,
			OurSecretKey: &clientSec,
		}
		req := zmq4.NewREQ(zmq4.WithCURVE(clientOpts))
		if err := req.Connect(ctx, ep); err != nil {
			fmt.Println("Connect error:", err)
			return
		}
		defer req.Close()

		if err := req.Send(ctx, zmq4.NewStringMsg("secret")); err != nil {
			fmt.Println("Send error:", err)
			return
		}
		msg, err := req.Recv(ctx)
		if err != nil {
			fmt.Println("Recv error:", err)
			return
		}
		fmt.Println("Client received:", msg.String())
	}()

	msg, err := rep.Recv(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Server received:", msg.String())
	if err := rep.Send(ctx, zmq4.NewStringMsg("acknowledged")); err != nil {
		panic(err)
	}
	<-done
}

func freePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}
