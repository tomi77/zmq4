package zmq4_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomi77/zmq4"
)

func pubSubEP(t *testing.T) string {
	t.Helper()
	return "inproc://" + strings.ReplaceAll(t.Name(), "/", "_")
}

func psCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestPUBSendNoTopic(t *testing.T) {
	pub := zmq4.NewPUB()
	t.Cleanup(func() { pub.Close() })
	ctx := psCtx(t)
	err := pub.Send(ctx, zmq4.Message{})
	if !errors.Is(err, zmq4.ErrNoTopic) {
		t.Fatalf("want ErrNoTopic, got %v", err)
	}
}

func TestPUBCloseIdempotent(t *testing.T) {
	pub := zmq4.NewPUB()
	if err := pub.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := pub.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestPUBSUBRoundTrip(t *testing.T) {
	ep := pubSubEP(t)
	ctx := psCtx(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { pub.Close() })

	sub := zmq4.NewSUB()
	if err := sub.Connect(ctx, ep); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { sub.Close() })

	if err := sub.Subscribe("hello"); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	msg := zmq4.Message{[]byte("hello world")}
	if err := pub.Send(ctx, msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := sub.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(got[0]) != "hello world" {
		t.Fatalf("want %q, got %q", "hello world", got[0])
	}
}

func TestSUBNoSubscriptionsGetsNothing(t *testing.T) {
	ep := pubSubEP(t)
	ctx := psCtx(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pub.Close() })

	sub := zmq4.NewSUB()
	if err := sub.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Close() })

	time.Sleep(10 * time.Millisecond)

	if err := pub.Send(ctx, zmq4.Message{[]byte("anything")}); err != nil {
		t.Fatal(err)
	}

	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, err := sub.Recv(tctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
}

func TestSUBSubscribeAll(t *testing.T) {
	ep := pubSubEP(t)
	ctx := psCtx(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pub.Close() })

	sub := zmq4.NewSUB()
	if err := sub.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Close() })

	if err := sub.Subscribe(""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)

	for _, topic := range []string{"foo", "bar", "baz"} {
		if err := pub.Send(ctx, zmq4.Message{[]byte(topic)}); err != nil {
			t.Fatalf("Send %q: %v", topic, err)
		}
	}
	seen := map[string]bool{}
	for range 3 {
		got, err := sub.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		seen[string(got[0])] = true
	}
	for _, topic := range []string{"foo", "bar", "baz"} {
		if !seen[topic] {
			t.Fatalf("subscribe-all: did not receive %q", topic)
		}
	}
}

func TestPUBSUBTopicFilter(t *testing.T) {
	ep := pubSubEP(t)
	ctx := psCtx(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pub.Close() })

	subA := zmq4.NewSUB()
	if err := subA.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { subA.Close() })
	subA.Subscribe("a")

	subB := zmq4.NewSUB()
	if err := subB.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { subB.Close() })
	subB.Subscribe("b")

	time.Sleep(20 * time.Millisecond)

	pub.Send(ctx, zmq4.Message{[]byte("a-data")})
	pub.Send(ctx, zmq4.Message{[]byte("b-data")})

	gotA, err := subA.Recv(ctx)
	if err != nil {
		t.Fatalf("subA Recv: %v", err)
	}
	if string(gotA[0]) != "a-data" {
		t.Fatalf("subA: want a-data, got %q", gotA[0])
	}
	gotB, err := subB.Recv(ctx)
	if err != nil {
		t.Fatalf("subB Recv: %v", err)
	}
	if string(gotB[0]) != "b-data" {
		t.Fatalf("subB: want b-data, got %q", gotB[0])
	}

	tctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	_, err = subA.Recv(tctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("subA should not receive b-data; got err=%v", err)
	}
}

func TestSUBRefCounting(t *testing.T) {
	ep := pubSubEP(t)
	ctx := psCtx(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pub.Close() })

	sub := zmq4.NewSUB()
	if err := sub.Connect(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Close() })

	sub.Subscribe("x")
	sub.Subscribe("x")
	sub.Unsubscribe("x")
	time.Sleep(10 * time.Millisecond)

	pub.Send(ctx, zmq4.Message{[]byte("x-msg")})
	got, err := sub.Recv(ctx)
	if err != nil {
		t.Fatalf("after 1 unsub: Recv: %v", err)
	}
	if string(got[0]) != "x-msg" {
		t.Fatalf("want x-msg, got %q", got[0])
	}

	sub.Unsubscribe("x")
	time.Sleep(10 * time.Millisecond)

	pub.Send(ctx, zmq4.Message{[]byte("x-msg2")})
	tctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	_, err = sub.Recv(tctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("after full unsub: expected DeadlineExceeded, got %v", err)
	}
}

func TestSUBCloseUnblocksRecv(t *testing.T) {
	sub := zmq4.NewSUB()
	ctx := context.Background()

	var wg sync.WaitGroup
	var recvErr error
	wg.Go(func() {
		_, recvErr = sub.Recv(ctx)
	})

	time.Sleep(10 * time.Millisecond)
	sub.Close()
	wg.Wait()
	if !errors.Is(recvErr, zmq4.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", recvErr)
	}
}

// TestPUBSendFanoutAllMatchingSubscribersReceive verifies that every subscriber
// sharing the same topic prefix receives the broadcast message.
func TestPUBSendFanoutAllMatchingSubscribersReceive(t *testing.T) {
	ep := pubSubEP(t)
	ctx := psCtx(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(ctx, ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pub.Close() })

	const n = 3
	subs := make([]*zmq4.SUB, n)
	for i := range n {
		sub := zmq4.NewSUB()
		if err := sub.Connect(ctx, ep); err != nil {
			t.Fatalf("Connect sub[%d]: %v", i, err)
		}
		if err := sub.Subscribe("news"); err != nil {
			t.Fatalf("Subscribe sub[%d]: %v", i, err)
		}
		t.Cleanup(func() { sub.Close() })
		subs[i] = sub
	}
	time.Sleep(30 * time.Millisecond)

	want := "news-broadcast"
	if err := pub.Send(ctx, zmq4.NewStringMsg(want)); err != nil {
		t.Fatal(err)
	}
	for i, sub := range subs {
		msg, err := sub.Recv(ctx)
		if err != nil {
			t.Fatalf("sub[%d] Recv: %v", i, err)
		}
		if msg.String() != want {
			t.Fatalf("sub[%d]: want %q, got %q", i, want, msg.String())
		}
	}
}

// TestPUBSendFanoutAllocsConstantWithSubscriberCount verifies that PUB.Send
// allocates only one deep copy of the message regardless of how many
// subscribers match — not one copy per subscriber.
func TestPUBSendFanoutAllocsConstantWithSubscriberCount(t *testing.T) {
	ep := pubSubEP(t)

	pub := zmq4.NewPUB()
	if err := pub.Bind(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pub.Close() })

	const n = 3
	for i := range n {
		sub := zmq4.NewSUB(zmq4.WithRcvHWM(10000))
		if err := sub.Connect(context.Background(), ep); err != nil {
			t.Fatalf("Connect sub[%d]: %v", i, err)
		}
		if err := sub.Subscribe("t"); err != nil {
			t.Fatalf("Subscribe sub[%d]: %v", i, err)
		}
		t.Cleanup(func() { sub.Close() })
	}
	time.Sleep(30 * time.Millisecond)

	msg := zmq4.NewStringMsg("t", "payload")

	// With copy-once fanout:
	//   1 (pubPipes snapshot) + 1 (Message header) + 2 (body frames) = 4 allocs
	// With the old per-subscriber copy (n=3, 2 frames):
	//   1 (snapshot) + 3×(1+2) = 10 allocs
	const wantMaxAllocs = 5.0
	got := testing.AllocsPerRun(20, func() {
		if err := pub.Send(context.Background(), msg); err != nil {
			t.Fatalf("Send: %v", err)
		}
	})
	if got > wantMaxAllocs {
		t.Fatalf("PUB.Send with %d subscribers: %.0f allocs/op, want ≤%.0f (copy-once not applied)", n, got, wantMaxAllocs)
	}
}
