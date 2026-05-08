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

func TestEncodeWelcomeRoundTrip(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)

	// In the real handshake the server has just generated s'/S' for this
	// connection. We mimic that with a fresh pair.
	serverTransPub, serverTransSec := makePair(t)

	// Cookie key — fresh per ServerState.
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}

	cookie, err := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	if err != nil {
		t.Fatalf("sealCookie: %v", err)
	}

	welcomeShared := precompute(clientTransPub, &serverLongSec) // s × C'
	openShared := precompute(serverLongPub, &clientTransSec)    // c' × S

	cmd, err := encodeWelcome(serverTransPub, cookie, welcomeShared, rand.Reader)
	if err != nil {
		t.Fatalf("encodeWelcome: %v", err)
	}
	if cmd.Name != welcomeCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, welcomeCommandName)
	}
	gotS1, gotCookie, err := parseWelcome(cmd, openShared)
	if err != nil {
		t.Fatalf("parseWelcome: %v", err)
	}
	if gotS1 != serverTransPub {
		t.Fatalf("S' = %x, want %x", gotS1, serverTransPub)
	}
	if gotCookie != cookie {
		t.Fatalf("cookie differs after round-trip")
	}

	// Cookie opens to the original (C', s').
	gotC1, gotSPrimeSec, err := openCookie(gotCookie, &cookieKey)
	if err != nil {
		t.Fatalf("openCookie: %v", err)
	}
	if gotC1 != clientTransPub {
		t.Fatalf("cookie C' = %x, want %x", gotC1, clientTransPub)
	}
	if gotSPrimeSec != serverTransSec {
		t.Fatalf("cookie s' differs from sealed value")
	}
}

func TestParseWelcomeRejectsWrongName(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: "READY", Data: make([]byte, 160)}
	if _, _, err := parseWelcome(bad, shared); !errors.Is(err, ErrMalformedWelcome) {
		t.Fatalf("err = %v, want ErrMalformedWelcome", err)
	}
}

func TestParseWelcomeRejectsWrongSize(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: welcomeCommandName, Data: []byte{0x01}}
	if _, _, err := parseWelcome(bad, shared); !errors.Is(err, ErrMalformedWelcome) {
		t.Fatalf("err = %v, want ErrMalformedWelcome", err)
	}
}

func TestParseWelcomeRejectsTamperedBox(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}

	cookie, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	openShared := precompute(serverLongPub, &clientTransSec)
	cmd, _ := encodeWelcome(serverTransPub, cookie, welcomeShared, rand.Reader)

	cmd.Data[len(cmd.Data)-1] ^= 0x01
	if _, _, err := parseWelcome(cmd, openShared); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestOpenCookieRejectsTampered(t *testing.T) {
	clientTransPub, _ := makePair(t)
	_, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}

	cookie, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	cookie[len(cookie)-1] ^= 0x01
	if _, _, err := openCookie(cookie, &cookieKey); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestOpenCookieRejectsWrongKey(t *testing.T) {
	clientTransPub, _ := makePair(t)
	_, serverTransSec := makePair(t)
	var goodKey, badKey SecretKey
	if _, err := rand.Read(goodKey[:]); err != nil {
		t.Fatalf("rand goodKey: %v", err)
	}
	if _, err := rand.Read(badKey[:]); err != nil {
		t.Fatalf("rand badKey: %v", err)
	}

	cookie, _ := sealCookie(clientTransPub, serverTransSec, &goodKey, rand.Reader)
	if _, _, err := openCookie(cookie, &badKey); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestEncodeVouchRoundTrip(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	clientTransPub, _ := makePair(t)

	vouchShared := precompute(serverLongPub, &clientLongSec) // c × S
	v, err := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	if err != nil {
		t.Fatalf("encodeVouch: %v", err)
	}
	gotC1, gotS, err := openVouch(v, clientLongPub, &serverLongSec)
	if err != nil {
		t.Fatalf("openVouch: %v", err)
	}
	if gotC1 != clientTransPub {
		t.Fatalf("C' = %x, want %x", gotC1, clientTransPub)
	}
	if gotS != serverLongPub {
		t.Fatalf("S = %x, want %x", gotS, serverLongPub)
	}
}

func TestOpenVouchRejectsTampered(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	clientTransPub, _ := makePair(t)

	vouchShared := precompute(serverLongPub, &clientLongSec)
	v, _ := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	v[len(v)-1] ^= 0x01
	if _, _, err := openVouch(v, clientLongPub, &serverLongSec); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestOpenVouchRejectsWrongClientLongPub(t *testing.T) {
	_, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	clientTransPub, _ := makePair(t)

	vouchShared := precompute(serverLongPub, &clientLongSec)
	v, _ := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	otherPub, _ := makePair(t)
	if _, _, err := openVouch(v, otherPub, &serverLongSec); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestEncodeInitiateRoundTrip(t *testing.T) {
	// Set up the post-WELCOME state: client has S' from welcome,
	// server has c' from HELLO.
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)

	afterReadyClient := precompute(serverTransPub, &clientTransSec) // c' × S'
	afterReadyServer := precompute(clientTransPub, &serverTransSec) // s' × C'

	// Sanity: NaCl box DH symmetry.
	if !bytes.Equal(afterReadyClient[:], afterReadyServer[:]) {
		t.Fatalf("afterReady asymmetry: %x vs %x", afterReadyClient[:], afterReadyServer[:])
	}

	vouchShared := precompute(serverLongPub, &clientLongSec)
	v, err := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	if err != nil {
		t.Fatalf("encodeVouch: %v", err)
	}
	cookieValue := cookie{1, 2, 3, 4} // opaque; not opened by INITIATE codec.

	md := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
		{Name: []byte("Identity"), Value: []byte{0xAA, 0xBB}},
	}

	cmd, err := encodeInitiate(cookieValue, v, clientLongPub, md, afterReadyClient, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeInitiate: %v", err)
	}
	if cmd.Name != initiateCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, initiateCommandName)
	}
	gotCookie, gotVouch, gotLongPub, gotMeta, err := parseInitiate(cmd, afterReadyServer)
	if err != nil {
		t.Fatalf("parseInitiate: %v", err)
	}
	if gotCookie != cookieValue {
		t.Fatalf("cookie not echoed verbatim")
	}
	if gotVouch != v {
		t.Fatalf("vouch differs after round-trip")
	}
	if gotLongPub != clientLongPub {
		t.Fatalf("client long-term pub = %x, want %x", gotLongPub, clientLongPub)
	}
	if len(gotMeta) != len(md) ||
		!bytes.Equal(gotMeta[0].Name, md[0].Name) ||
		!bytes.Equal(gotMeta[0].Value, md[0].Value) ||
		!bytes.Equal(gotMeta[1].Name, md[1].Name) ||
		!bytes.Equal(gotMeta[1].Value, md[1].Value) {
		t.Fatalf("metadata differs after round-trip: got=%+v want=%+v", gotMeta, md)
	}
}

func TestEncodeInitiateEmptyMetadataRoundTrip(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	vouchShared := precompute(serverLongPub, &clientLongSec)
	v, err := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	if err != nil {
		t.Fatalf("encodeVouch: %v", err)
	}

	cmd, err := encodeInitiate(cookie{}, v, clientLongPub, nil, afterReadyClient, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeInitiate(nil): %v", err)
	}
	_, _, gotLongPub, gotMeta, err := parseInitiate(cmd, afterReadyServer)
	if err != nil {
		t.Fatalf("parseInitiate: %v", err)
	}
	if gotLongPub != clientLongPub {
		t.Fatalf("clientLongPub = %x, want %x", gotLongPub, clientLongPub)
	}
	if len(gotMeta) != 0 {
		t.Fatalf("metadata = %+v, want empty", gotMeta)
	}
}

func TestParseInitiateRejectsWrongName(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: "READY", Data: make([]byte, 200)}
	if _, _, _, _, err := parseInitiate(bad, shared); !errors.Is(err, ErrMalformedInitiate) {
		t.Fatalf("err = %v, want ErrMalformedInitiate", err)
	}
}

func TestParseInitiateRejectsTooSmall(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: initiateCommandName, Data: []byte{0x01, 0x02}}
	if _, _, _, _, err := parseInitiate(bad, shared); !errors.Is(err, ErrMalformedInitiate) {
		t.Fatalf("err = %v, want ErrMalformedInitiate", err)
	}
}

func TestParseInitiateRejectsTamperedOuterBox(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	vouchShared := precompute(serverLongPub, &clientLongSec)
	v, _ := encodeVouch(clientTransPub, serverLongPub, vouchShared, rand.Reader)
	cmd, _ := encodeInitiate(cookie{}, v, clientLongPub, nil, afterReadyClient, 1, rand.Reader)
	cmd.Data[len(cmd.Data)-1] ^= 0x01
	if _, _, _, _, err := parseInitiate(cmd, afterReadyServer); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestEncodeReadyRoundTrip(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)

	md := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
		{Name: []byte("Identity"), Value: bytes.Repeat([]byte{0x77}, 8)},
	}
	cmd, err := encodeReady(md, afterReadyServer, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeReady: %v", err)
	}
	if cmd.Name != readyCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, readyCommandName)
	}
	got, err := parseReady(cmd, afterReadyClient)
	if err != nil {
		t.Fatalf("parseReady: %v", err)
	}
	if len(got) != len(md) ||
		!bytes.Equal(got[0].Name, md[0].Name) ||
		!bytes.Equal(got[1].Value, md[1].Value) {
		t.Fatalf("metadata differs after round-trip: got=%+v want=%+v", got, md)
	}
}

func TestEncodeReadyEmptyMetadata(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)

	cmd, err := encodeReady(nil, afterReadyServer, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeReady(nil): %v", err)
	}
	got, err := parseReady(cmd, afterReadyClient)
	if err != nil {
		t.Fatalf("parseReady: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("metadata = %+v, want empty", got)
	}
}

func TestParseReadyRejectsWrongName(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: "WELCOME", Data: make([]byte, 24)}
	if _, err := parseReady(bad, shared); !errors.Is(err, ErrMalformedReady) {
		t.Fatalf("err = %v, want ErrMalformedReady", err)
	}
}

func TestParseReadyRejectsTooSmall(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: readyCommandName, Data: []byte{0x01}}
	if _, err := parseReady(bad, shared); !errors.Is(err, ErrMalformedReady) {
		t.Fatalf("err = %v, want ErrMalformedReady", err)
	}
}

func TestParseReadyRejectsTamperedBox(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)

	cmd, _ := encodeReady(nil, afterReadyServer, 1, rand.Reader)
	cmd.Data[len(cmd.Data)-1] ^= 0x01
	if _, err := parseReady(cmd, afterReadyClient); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestEncodeMessageRoundTrip(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	for _, tc := range []struct {
		name    string
		flags   byte
		payload []byte
	}{
		{"empty", 0x00, []byte{}},
		{"more", 0x01, []byte("hi")},
		{"large", 0x00, bytes.Repeat([]byte{0xAB}, 4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := encodeMessage(tc.flags, tc.payload, afterReadyClient, messageClientPrefix, 7)
			if err != nil {
				t.Fatalf("encodeMessage: %v", err)
			}
			if cmd.Name != wire.MessageCommandName {
				t.Fatalf("cmd.Name = %q, want %q", cmd.Name, wire.MessageCommandName)
			}
			gotFlags, gotPayload, gotNonce, err := parseMessage(cmd, afterReadyServer, messageClientPrefix)
			if err != nil {
				t.Fatalf("parseMessage: %v", err)
			}
			if gotNonce != 7 {
				t.Fatalf("nonce = %d, want 7", gotNonce)
			}
			if gotFlags != tc.flags {
				t.Fatalf("flags = %#x, want %#x", gotFlags, tc.flags)
			}
			if !bytes.Equal(gotPayload, tc.payload) {
				t.Fatalf("payload differs: got %x want %x", gotPayload, tc.payload)
			}
		})
	}
}

func TestParseMessageRejectsWrongName(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: "READY", Data: make([]byte, 25)}
	if _, _, _, err := parseMessage(bad, shared, messageClientPrefix); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("err = %v, want ErrMalformedMessage", err)
	}
}

func TestParseMessageRejectsTooSmall(t *testing.T) {
	_, sk := makePair(t)
	shared := precompute(PublicKey{1}, &sk)
	bad := wire.Command{Name: wire.MessageCommandName, Data: []byte{0x01}}
	if _, _, _, err := parseMessage(bad, shared, messageClientPrefix); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("err = %v, want ErrMalformedMessage", err)
	}
}

func TestParseMessageRejectsTamperedBox(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	cmd, _ := encodeMessage(0x00, []byte("payload"), afterReadyClient, messageClientPrefix, 1)
	cmd.Data[len(cmd.Data)-1] ^= 0x01
	if _, _, _, err := parseMessage(cmd, afterReadyServer, messageClientPrefix); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestParseMessageRejectsWrongPrefix(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	// Encode with client→server prefix; try to parse with server→client.
	cmd, _ := encodeMessage(0x00, []byte("payload"), afterReadyClient, messageClientPrefix, 1)
	if _, _, _, err := parseMessage(cmd, afterReadyServer, messageServerPrefix); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestEncodeMessageEmptyPayload(t *testing.T) {
	clientTransPub, clientTransSec := makePair(t)
	serverTransPub, serverTransSec := makePair(t)
	afterReadyClient := precompute(serverTransPub, &clientTransSec)
	afterReadyServer := precompute(clientTransPub, &serverTransSec)

	cmd, err := encodeMessage(0x00, nil, afterReadyClient, messageClientPrefix, 1)
	if err != nil {
		t.Fatalf("encodeMessage(nil): %v", err)
	}
	// Body = 8 (nonce) + 1 (flags) + 0 (payload) + 16 (overhead) = 25.
	if got := len(cmd.Data); got != 25 {
		t.Fatalf("body len = %d, want 25", got)
	}
	gotFlags, gotPayload, _, err := parseMessage(cmd, afterReadyServer, messageClientPrefix)
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	if gotFlags != 0x00 || len(gotPayload) != 0 {
		t.Fatalf("flags=%#x payload=%x, want 0x00 + empty", gotFlags, gotPayload)
	}
}
