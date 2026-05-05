package curve

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func makePair(t *testing.T) (PublicKey, SecretKey) {
	t.Helper()
	pub, sec, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return pub, sec
}

func TestEncodeHelloRoundTrip(t *testing.T) {
	clientPub, clientSec := makePair(t)
	serverPub, serverSec := makePair(t)

	helloShared := precompute(serverPub, &clientSec)   // c' × S
	openShared := precompute(clientPub, &serverSec)    // s × C'

	cmd, err := encodeHello(clientPub, helloShared, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	if cmd.Name != helloCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, helloCommandName)
	}
	got, err := parseHello(cmd, openShared)
	if err != nil {
		t.Fatalf("parseHello: %v", err)
	}
	if got != clientPub {
		t.Fatalf("client transient pub = %x, want %x", got, clientPub)
	}
}

func TestParseHelloRejectsWrongName(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: "READY", Data: make([]byte, 194)}
	if _, err := parseHello(bad, shared); !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestParseHelloRejectsWrongSize(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: helloCommandName, Data: []byte{0x01}}
	if _, err := parseHello(bad, shared); !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestParseHelloRejectsBadVersion(t *testing.T) {
	clientPub, clientSec := makePair(t)
	serverPub, serverSec := makePair(t)
	helloShared := precompute(serverPub, &clientSec)
	openShared := precompute(clientPub, &serverSec)

	cmd, err := encodeHello(clientPub, helloShared, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	cmd.Data[0] = 0x02 // major=2 instead of 1
	if _, err := parseHello(cmd, openShared); !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestParseHelloRejectsNonZeroPadding(t *testing.T) {
	clientPub, clientSec := makePair(t)
	serverPub, serverSec := makePair(t)
	helloShared := precompute(serverPub, &clientSec)
	openShared := precompute(clientPub, &serverSec)

	cmd, err := encodeHello(clientPub, helloShared, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	// padding starts at byte 2 (after version[2]).
	cmd.Data[2] = 0xFF
	if _, err := parseHello(cmd, openShared); !errors.Is(err, ErrMalformedHello) {
		t.Fatalf("err = %v, want ErrMalformedHello", err)
	}
}

func TestParseHelloRejectsTamperedBox(t *testing.T) {
	clientPub, clientSec := makePair(t)
	serverPub, serverSec := makePair(t)
	helloShared := precompute(serverPub, &clientSec)
	openShared := precompute(clientPub, &serverSec)

	cmd, err := encodeHello(clientPub, helloShared, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	// Flip a bit in the trailing 80-byte hello-box ciphertext.
	cmd.Data[len(cmd.Data)-1] ^= 0x01
	if _, err := parseHello(cmd, openShared); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestEncodeHelloDoesNotConsumeRand(t *testing.T) {
	// HELLO uses a counter short-nonce, not a random nonce — so encodeHello
	// must not read from its rand reader at all. (It accepts an io.Reader
	// for symmetry with the long-nonce encoders.) A regression that switches
	// to random nonces would silently weaken determinism for vector tests.
	_, clientSec := makePair(t)
	serverPub, _ := makePair(t)
	shared := precompute(serverPub, &clientSec)

	r := bytes.NewReader(make([]byte, 1<<20))
	if _, err := encodeHello(PublicKey{1, 2, 3}, shared, 1, r); err != nil {
		t.Fatalf("encodeHello: %v", err)
	}
	if used := 1<<20 - r.Len(); used != 0 {
		t.Fatalf("encodeHello consumed %d bytes of rand, want 0 (counter short-nonce only)", used)
	}
}
