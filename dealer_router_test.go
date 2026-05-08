package zmq4_test

import (
	"context"
	"errors"
	"testing"

	"github.com/tomi77/zmq4"
)

func TestDEALERROUTERRoundTrip(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)
	router := zmq4.NewROUTER()
	if err := router.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { router.Close() })

	dealer := zmq4.NewDEALER()
	if err := dealer.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dealer.Close() })

	if err := dealer.Send(ctx, zmq4.Message{[]byte("hi")}); err != nil {
		t.Fatal(err)
	}
	rmsg, err := router.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// rmsg[0] = identity, rmsg[1:] = payload
	if len(rmsg) < 2 {
		t.Fatalf("ROUTER recv: want ≥2 frames, got %d", len(rmsg))
	}
	identity := rmsg[0]
	if string(rmsg[1]) != "hi" {
		t.Fatalf("payload: want hi, got %q", rmsg[1])
	}
	// ROUTER replies using the received identity.
	reply := zmq4.Message{identity, []byte("there")}
	if err := router.Send(ctx, reply); err != nil {
		t.Fatal(err)
	}
	got, err := dealer.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[0]) != "there" {
		t.Fatalf("dealer reply: want there, got %q", got[0])
	}
}

func TestROUTERIdentityOwned(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)
	router := zmq4.NewROUTER()
	if err := router.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { router.Close() })

	dealer := zmq4.NewDEALER(zmq4.WithIdentity([]byte("client1")))
	if err := dealer.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dealer.Close() })

	if err := dealer.Send(ctx, zmq4.Message{[]byte("x")}); err != nil {
		t.Fatal(err)
	}
	msg, err := router.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg[0]) != "client1" {
		t.Fatalf("identity: want client1, got %q", msg[0])
	}

	// Mutate msg[0] — should NOT affect subsequent Recv identity.
	for i := range msg[0] {
		msg[0][i] = 'X'
	}
	// Second send + recv: identity in Recv result must still be "client1".
	if err := dealer.Send(ctx, zmq4.Message{[]byte("y")}); err != nil {
		t.Fatal(err)
	}
	msg2, err := router.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg2[0]) != "client1" {
		t.Fatalf("after mutation: identity: want client1, got %q", msg2[0])
	}
}

func TestROUTERAutoIdentity(t *testing.T) {
	ep := inprocEP(t)
	ctx := newCtx(t)
	router := zmq4.NewROUTER()
	if err := router.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { router.Close() })

	dealer := zmq4.NewDEALER() // no identity set → ROUTER generates random 5-byte identity
	if err := dealer.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dealer.Close() })

	if err := dealer.Send(ctx, zmq4.Message{[]byte("1")}); err != nil {
		t.Fatal(err)
	}
	m1, err := router.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id1 := string(m1[0])

	if err := dealer.Send(ctx, zmq4.Message{[]byte("2")}); err != nil {
		t.Fatal(err)
	}
	m2, err := router.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id2 := string(m2[0])

	if id1 != id2 {
		t.Fatalf("auto-identity must be stable: %q != %q", id1, id2)
	}
	if len(id1) != 5 {
		t.Fatalf("auto-identity must be 5 bytes, got %d", len(id1))
	}
}

func TestROUTERNoRoute(t *testing.T) {
	router := zmq4.NewROUTER()
	t.Cleanup(func() { router.Close() })
	ctx := newCtx(t)
	err := router.Send(ctx, zmq4.Message{[]byte("no-such-peer"), []byte("x")})
	if !errors.Is(err, zmq4.ErrNoRoute) {
		t.Fatalf("want ErrNoRoute, got %v", err)
	}
}

func TestROUTERNoIdentityFrame(t *testing.T) {
	router := zmq4.NewROUTER()
	t.Cleanup(func() { router.Close() })
	ctx := newCtx(t)
	err := router.Send(ctx, zmq4.Message{})
	if !errors.Is(err, zmq4.ErrNoIdentity) {
		t.Fatalf("want ErrNoIdentity, got %v", err)
	}
}

func TestDEALERCtxCancelSend(t *testing.T) {
	dealer := zmq4.NewDEALER()
	t.Cleanup(func() { dealer.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := dealer.Send(ctx, zmq4.Message{[]byte("x")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
