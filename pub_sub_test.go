package zmq4_test

import (
	"context"
	"errors"
	"strings"
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
