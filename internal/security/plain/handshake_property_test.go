package plain

import (
	"bytes"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"testing/quick"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestPlainHappyPathProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 1000}
	prop := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		user, pass := randCreds(rng)
		mdC := randMetadata(rng)
		mdS := randMetadata(rng)

		client, err := NewClient(user, pass, mdC)
		if err != nil {
			t.Logf("NewClient: %v", err)
			return false
		}
		server := NewServer(func(_, _ []byte) error { return nil }, mdS)

		hello, err := client.Start()
		if err != nil {
			t.Logf("Start: %v", err)
			return false
		}
		welcome, done, err := server.Receive(hello)
		if err != nil || done || welcome == nil {
			t.Logf("server.Receive(HELLO): out=%v done=%v err=%v", welcome, done, err)
			return false
		}
		initiate, done, err := client.Receive(*welcome)
		if err != nil || done || initiate == nil {
			t.Logf("client.Receive(WELCOME): out=%v done=%v err=%v", initiate, done, err)
			return false
		}
		ready, done, err := server.Receive(*initiate)
		if err != nil || !done || ready == nil {
			t.Logf("server.Receive(INITIATE): out=%v done=%v err=%v", ready, done, err)
			return false
		}
		out, done, err := client.Receive(*ready)
		if err != nil || !done || out != nil {
			t.Logf("client.Receive(READY): out=%v done=%v err=%v", out, done, err)
			return false
		}
		return metadataEqual(client.PeerMetadata(), mdS) &&
			metadataEqual(server.PeerMetadata(), mdC)
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestPlainAuthRejectProperty(t *testing.T) {
	cfg := &quick.Config{MaxCount: 1000}
	prop := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		user, pass := randCreds(rng)

		client, err := NewClient(user, pass, nil)
		if err != nil {
			return false
		}
		rejecter := func(_, _ []byte) error { return errors.New("denied") }
		server := NewServer(rejecter, nil)

		hello, err := client.Start()
		if err != nil {
			return false
		}
		out, done, err := server.Receive(hello)
		if !errors.Is(err, ErrAuthRejected) || done || out == nil {
			t.Logf("server.Receive(HELLO): out=%v done=%v err=%v", out, done, err)
			return false
		}
		ec, perr := wire.ParseError(*out)
		if perr != nil || ec.Reason != "denied" {
			t.Logf("ERROR reason = %q (parse err=%v)", ec.Reason, perr)
			return false
		}
		// Client receives the ERROR.
		_, _, err = client.Receive(*out)
		if !errors.Is(err, ErrPeerError) || !strings.Contains(err.Error(), "denied") {
			t.Logf("client.Receive(ERROR) = %v", err)
			return false
		}
		// Both states are now FAILED.
		if _, _, err := client.Receive(*out); !errors.Is(err, ErrAlreadyFailed) {
			t.Logf("client.Receive after ERROR = %v, want ErrAlreadyFailed", err)
			return false
		}
		if _, _, err := server.Receive(hello); !errors.Is(err, ErrAlreadyFailed) {
			t.Logf("server.Receive after reject = %v, want ErrAlreadyFailed", err)
			return false
		}
		return true
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func randCreds(rng *rand.Rand) ([]byte, []byte) {
	user := make([]byte, rng.Intn(32))
	pass := make([]byte, rng.Intn(32))
	rng.Read(user)
	rng.Read(pass)
	return user, pass
}

func randMetadata(rng *rand.Rand) wire.Metadata {
	names := []string{
		"Socket-Type", "Identity", "Resource",
		"X-Foo", "X-Bar", "X-Baz",
	}
	n := rng.Intn(len(names) + 1)
	used := map[string]bool{}
	var md wire.Metadata
	for range n {
		name := names[rng.Intn(len(names))]
		if used[name] {
			continue
		}
		used[name] = true
		valLen := rng.Intn(33)
		val := make([]byte, valLen)
		rng.Read(val)
		md = append(md, wire.MetadataProperty{
			Name:  []byte(name),
			Value: val,
		})
	}
	return md
}

func metadataEqual(a, b wire.Metadata) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].Name, b[i].Name) ||
			!bytes.Equal(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}
