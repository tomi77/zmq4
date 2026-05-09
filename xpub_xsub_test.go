package zmq4_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
)

func xpubEP(t *testing.T) string {
	t.Helper()
	return "inproc://" + strings.ReplaceAll(t.Name(), "/", "_")
}

func xCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestXPUBRecvSubscription(t *testing.T) {
	ep := xpubEP(t)
	ctx := xCtx(t)

	xpub := zmq4.NewXPUB()
	if err := xpub.Bind(ctx, ep); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { xpub.Close() })

	xsub := zmq4.NewXSUB()
	if err := xsub.Connect(ctx, ep); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { xsub.Close() })

	if err := xsub.Subscribe([]byte("foo")); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	got, err := xpub.Recv(ctx)
	if err != nil {
		t.Fatalf("XPUB Recv: %v", err)
	}
	if len(got) == 0 || len(got[0]) == 0 {
		t.Fatalf("want subscription frame, got empty message")
	}
	if got[0][0] != 0x01 {
		t.Fatalf("want subscribe op 0x01, got 0x%02x", got[0][0])
	}
	if string(got[0][1:]) != "foo" {
		t.Fatalf("want topic foo, got %q", got[0][1:])
	}
}

func TestXPUBRecvUnsubscription(t *testing.T) {
	ep := xpubEP(t)
	ctx := xCtx(t)

	xpub := zmq4.NewXPUB()
	if err := xpub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xpub.Close() })

	xsub := zmq4.NewXSUB()
	if err := xsub.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xsub.Close() })

	xsub.Subscribe([]byte("bar"))
	// Consume subscribe frame.
	sub, _ := xpub.Recv(ctx)
	if len(sub) == 0 || sub[0][0] != 0x01 {
		t.Fatalf("expected subscribe frame first, got %v", sub)
	}

	xsub.Unsubscribe([]byte("bar"))
	got, err := xpub.Recv(ctx)
	if err != nil {
		t.Fatalf("XPUB Recv unsub: %v", err)
	}
	if got[0][0] != 0x00 {
		t.Fatalf("want unsubscribe op 0x00, got 0x%02x", got[0][0])
	}
	if string(got[0][1:]) != "bar" {
		t.Fatalf("want topic bar, got %q", got[0][1:])
	}
}

func TestXPUBSendFiltered(t *testing.T) {
	ep := xpubEP(t)
	ctx := xCtx(t)

	xpub := zmq4.NewXPUB()
	if err := xpub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xpub.Close() })

	xsub := zmq4.NewXSUB()
	if err := xsub.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { xsub.Close() })

	xsub.Subscribe([]byte("news"))
	// Drain subscription frame from XPUB.
	xpub.Recv(ctx)
	time.Sleep(10 * time.Millisecond)

	if err := xpub.Send(ctx, zmq4.Message{[]byte("news-flash")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := xsub.Recv(ctx)
	if err != nil {
		t.Fatalf("XSUB Recv: %v", err)
	}
	if string(got[0]) != "news-flash" {
		t.Fatalf("want news-flash, got %q", got[0])
	}
}

func TestXPUBCtxCancelRecv(t *testing.T) {
	xpub := zmq4.NewXPUB()
	t.Cleanup(func() { xpub.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := xpub.Recv(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
