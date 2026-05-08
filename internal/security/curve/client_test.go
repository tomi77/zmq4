package curve

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/tomi77/zmq4/internal/security"
	"github.com/tomi77/zmq4/internal/wire"
)

func TestNewClientRejectsZeroServerKey(t *testing.T) {
	_, sec := makePair(t)
	_, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{},
		OurPublicKey: PublicKey{1},
		OurSecretKey: &sec,
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewClientRejectsZeroOurPublicKey(t *testing.T) {
	_, sec := makePair(t)
	_, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{1},
		OurPublicKey: PublicKey{},
		OurSecretKey: &sec,
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewClientRejectsNilOurSecretKey(t *testing.T) {
	_, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{1},
		OurPublicKey: PublicKey{1},
	})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
}

func TestNewClientNotDone(t *testing.T) {
	_, sec := makePair(t)
	c, err := NewClient(ClientOptions{
		ServerKey:    PublicKey{1},
		OurPublicKey: PublicKey{1},
		OurSecretKey: &sec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Done() {
		t.Fatalf("new client is Done()")
	}
}

func TestClientStartEmitsValidHello(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)

	c, err := NewClient(ClientOptions{
		ServerKey:    serverLongPub,
		OurPublicKey: clientLongPub,
		OurSecretKey: &clientLongSec,
		Rand:         rand.Reader,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if hello.Name != helloCommandName {
		t.Fatalf("Name = %q, want %q", hello.Name, helloCommandName)
	}

	// Server-side parseHello should accept the produced HELLO.
	// Read C' from the cleartext part first.
	if len(hello.Data) != helloBodyLen {
		t.Fatalf("body len = %d, want %d", len(hello.Data), helloBodyLen)
	}
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	openShared := precompute(clientTransPub, &serverLongSec)
	if _, err := parseHello(hello, openShared); err != nil {
		t.Fatalf("parseHello: %v", err)
	}
}

func TestClientStartTwiceReturnsAlreadyStarted(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, err := NewClient(ClientOptions{
		ServerKey:    serverLongPub,
		OurPublicKey: clientLongPub,
		OurSecretKey: &clientLongSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if _, err := c.Start(); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start = %v, want ErrAlreadyStarted", err)
	}
}

// failingReadOnNthCall returns wantErr on the n-th Read; succeeds before
// that.
type failingReadOnNthCall struct {
	n     int
	calls int
	src   io.Reader
}

func (f *failingReadOnNthCall) Read(p []byte) (int, error) {
	f.calls++
	if f.calls == f.n {
		return 0, errors.New("synthetic")
	}
	return f.src.Read(p)
}

func TestClientStartFailsWhenRandFails(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	rng := &failingReadOnNthCall{n: 1, src: rand.Reader}
	c, err := NewClient(ClientOptions{
		ServerKey:    serverLongPub,
		OurPublicKey: clientLongPub,
		OurSecretKey: &clientLongSec,
		Rand:         rng,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Start(); !errors.Is(err, ErrCryptoRand) {
		t.Fatalf("Start = %v, want ErrCryptoRand", err)
	}
}

func TestClientReceiveWelcomeEmitsValidInitiate(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	mdC := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("DEALER")},
	}
	c, err := NewClient(ClientOptions{
		ServerKey:     serverLongPub,
		OurPublicKey:  clientLongPub,
		OurSecretKey:  &clientLongSec,
		LocalMetadata: mdC,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, err := c.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Drive the server side manually with codec primitives so we can
	// build a valid WELCOME without depending on ServerState yet.
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	helloOpenShared := precompute(clientTransPub, &serverLongSec) // s × C'
	if _, err := parseHello(hello, helloOpenShared); err != nil {
		t.Fatalf("server-side parseHello: %v", err)
	}

	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, err := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	if err != nil {
		t.Fatalf("sealCookie: %v", err)
	}
	welcomeShared := precompute(clientTransPub, &serverLongSec) // s × C'
	welcome, err := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)
	if err != nil {
		t.Fatalf("encodeWelcome: %v", err)
	}

	out, done, err := c.Receive(welcome)
	if err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	if done {
		t.Fatalf("done=true after WELCOME, want false")
	}
	if out == nil || out.Name != initiateCommandName {
		t.Fatalf("out = %+v, want INITIATE", out)
	}

	// Open INITIATE with the server's afterReady = s' × C'.
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	gotCookie, gotVouch, gotLongPub, gotMeta, err := parseInitiate(*out, afterReadyServer)
	if err != nil {
		t.Fatalf("parseInitiate: %v", err)
	}
	if gotCookie != ck {
		t.Fatalf("cookie not echoed verbatim")
	}
	if gotLongPub != clientLongPub {
		t.Fatalf("client long pub = %x, want %x", gotLongPub, clientLongPub)
	}
	// Vouch authenticates (C' || S) under c × S; we open it via box.Open.
	gotC1, gotS, err := openVouch(gotVouch, clientLongPub, &serverLongSec)
	if err != nil {
		t.Fatalf("openVouch: %v", err)
	}
	if gotC1 != clientTransPub {
		t.Fatalf("vouch C' = %x, want %x", gotC1, clientTransPub)
	}
	if gotS != serverLongPub {
		t.Fatalf("vouch S = %x, want %x", gotS, serverLongPub)
	}
	if v, ok := gotMeta.Get("Socket-Type"); !ok || string(v) != "DEALER" {
		t.Fatalf("INITIATE Socket-Type = %q, want DEALER", v)
	}
}

func TestClientReceiveBeforeStart(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if _, _, err := c.Receive(wire.Command{Name: welcomeCommandName}); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Receive before Start = %v, want ErrNotStarted", err)
	}
}

func TestClientReceiveMalformedWelcome(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	bad := wire.Command{Name: welcomeCommandName, Data: []byte{0x01}}
	if _, _, err := c.Receive(bad); !errors.Is(err, ErrMalformedWelcome) {
		t.Fatalf("err = %v, want ErrMalformedWelcome", err)
	}
}

func TestClientReceiveTamperedWelcome(t *testing.T) {
	// Build a real WELCOME, flip a bit, expect ErrBoxOpen.
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	welcome, _ := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)

	welcome.Data[len(welcome.Data)-1] ^= 0x01
	if _, _, err := c.Receive(welcome); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

func TestClientReceiveReadyCompletesHandshake(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	mdS := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
		{Name: []byte("Identity"), Value: []byte("server-1")},
	}

	c, err := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, _ := c.Start()
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	welcome, _ := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)
	if _, _, err := c.Receive(welcome); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}

	// Server seals a READY under afterReady = s' × C'.
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	ready, err := encodeReady(mdS, afterReadyServer, 1, rand.Reader)
	if err != nil {
		t.Fatalf("encodeReady: %v", err)
	}

	out, done, err := c.Receive(ready)
	if err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}
	if !done || out != nil {
		t.Fatalf("Receive(READY): out=%+v done=%v, want nil/true", out, done)
	}
	if !c.Done() {
		t.Fatalf("Done() == false after READY")
	}
	pm := c.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "ROUTER" {
		t.Fatalf("PeerMetadata Socket-Type = %q, want ROUTER", v)
	}
	if c.PeerPublicKey() != serverLongPub {
		t.Fatalf("PeerPublicKey = %x, want %x", c.PeerPublicKey(), serverLongPub)
	}
}

func TestClientPeerMetadataIndependentOfInputBuffer(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)
	mdS := wire.Metadata{
		{Name: []byte("Socket-Type"), Value: []byte("ROUTER")},
	}

	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])
	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	welcome, _ := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)
	c.Receive(welcome)

	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	ready, _ := encodeReady(mdS, afterReadyServer, 1, rand.Reader)

	// Wrap ready.Data in a fresh buffer we can later clobber.
	buf := make([]byte, len(ready.Data))
	copy(buf, ready.Data)
	ready = wire.Command{Name: ready.Name, Data: buf}

	if _, _, err := c.Receive(ready); err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}
	for i := range buf {
		buf[i] = 0xFF
	}
	pm := c.PeerMetadata()
	if v, ok := pm.Get("Socket-Type"); !ok || string(v) != "ROUTER" {
		t.Fatalf("PeerMetadata after clobber = %q, want ROUTER", v)
	}
}

func TestClientReceiveTamperedReady(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)

	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	hello, _ := c.Start()
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])
	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	welcome, _ := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)
	c.Receive(welcome)

	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	ready, _ := encodeReady(nil, afterReadyServer, 1, rand.Reader)
	ready.Data[len(ready.Data)-1] ^= 0x01

	if _, _, err := c.Receive(ready); !errors.Is(err, ErrBoxOpen) {
		t.Fatalf("err = %v, want ErrBoxOpen", err)
	}
}

// newClientDoneAndPeerKey drives a fresh ClientState to DONE through
// the codec primitives and returns it together with the shared
// afterReady key the peer-server would have, plus the two direction
// prefixes. Used by Wrap/Unwrap tests in this task; Chunk 7's tests
// use the real ServerState pair.
func newClientDoneAndPeerKey(t *testing.T) (c *ClientState, peerKey *SharedKey, sendPrefix, recvPrefix [16]byte) {
	t.Helper()
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, serverLongSec := makePair(t)

	c, err := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hello, _ := c.Start()
	var clientTransPub PublicKey
	copy(clientTransPub[:], hello.Data[2+72:2+72+32])

	serverTransPub, serverTransSec := makePair(t)
	var cookieKey SecretKey
	if _, err := rand.Read(cookieKey[:]); err != nil {
		t.Fatalf("rand cookieKey: %v", err)
	}
	ck, _ := sealCookie(clientTransPub, serverTransSec, &cookieKey, rand.Reader)
	welcomeShared := precompute(clientTransPub, &serverLongSec)
	welcome, _ := encodeWelcome(serverTransPub, ck, welcomeShared, rand.Reader)
	if _, _, err := c.Receive(welcome); err != nil {
		t.Fatalf("Receive(WELCOME): %v", err)
	}
	afterReadyServer := precompute(clientTransPub, &serverTransSec)
	ready, _ := encodeReady(nil, afterReadyServer, 1, rand.Reader)
	if _, _, err := c.Receive(ready); err != nil {
		t.Fatalf("Receive(READY): %v", err)
	}
	if !c.Done() {
		t.Fatalf("client not done")
	}
	return c, afterReadyServer, messageClientPrefix, messageServerPrefix
}

func TestClientWrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	_, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: []byte("x")})
	if !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("err = %v, want security.ErrNotDone", err)
	}
}

func TestClientUnwrapBeforeDoneReturnsErrNotDone(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	_, err := c.Unwrap(wire.Frame{Kind: wire.FrameCommand, Body: make([]byte, 25)})
	if !errors.Is(err, security.ErrNotDone) {
		t.Fatalf("err = %v, want security.ErrNotDone", err)
	}
}

func TestClientWrapUnwrapRoundTrip(t *testing.T) {
	c, peerKey, sendPrefix, recvPrefix := newClientDoneAndPeerKey(t)

	for _, tc := range []struct {
		name string
		more bool
		body []byte
	}{
		{"empty", false, []byte{}},
		{"more-true", true, []byte("hello")},
		{"large", false, bytes.Repeat([]byte{0x42}, 4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := wire.Frame{Kind: wire.FrameMessage, More: tc.more, Body: tc.body}
			wrapped, err := c.Wrap(in)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if wrapped.Kind != wire.FrameCommand || wrapped.More {
				t.Fatalf("wrapped = %+v, want FrameCommand non-MORE", wrapped)
			}
			cmd, perr := wire.ParseCommand(wrapped.Body)
			if perr != nil {
				t.Fatalf("ParseCommand: %v", perr)
			}
			gotFlags, gotPayload, _, derr := parseMessage(cmd, peerKey, sendPrefix)
			if derr != nil {
				t.Fatalf("parseMessage: %v", derr)
			}
			wantFlags := byte(0)
			if tc.more {
				wantFlags = 0x01
			}
			if gotFlags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", gotFlags, wantFlags)
			}
			if !bytes.Equal(gotPayload, tc.body) {
				t.Fatalf("payload differs")
			}

			// Reverse: synthesise a server→client MESSAGE under
			// recvPrefix and feed it to c.Unwrap.
			outer, err := encodeMessage(wantFlags, tc.body, peerKey, recvPrefix, uint64(1+ /*nonce slot per subtest*/ 0))
			if err != nil {
				t.Fatalf("encodeMessage: %v", err)
			}
			outerBody, err := wire.EncodeCommand(outer)
			if err != nil {
				t.Fatalf("EncodeCommand: %v", err)
			}
			gotFrame, err := c.Unwrap(wire.Frame{Kind: wire.FrameCommand, Body: outerBody})
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if gotFrame.Kind != wire.FrameMessage || gotFrame.More != tc.more || !bytes.Equal(gotFrame.Body, tc.body) {
				t.Fatalf("Unwrap = %+v, want %+v", gotFrame, in)
			}

			// New ClientState per subtest so recvNonce starts at 0
			// every iteration. (Re-running on the same c with nonce=1
			// each time would trigger ErrNonceReused on the second
			// subtest.) Replace c for the next iteration:
			c, peerKey, sendPrefix, recvPrefix = newClientDoneAndPeerKey(t)
			_ = sendPrefix
			_ = recvPrefix
		})
	}
}

func TestClientUnwrapReplayReturnsErrNonceReused(t *testing.T) {
	c, peerKey, _, recvPrefix := newClientDoneAndPeerKey(t)

	outer, _ := encodeMessage(0x00, []byte("once"), peerKey, recvPrefix, 1)
	outerBody, _ := wire.EncodeCommand(outer)
	frame := wire.Frame{Kind: wire.FrameCommand, Body: outerBody}

	if _, err := c.Unwrap(frame); err != nil {
		t.Fatalf("first Unwrap: %v", err)
	}
	if _, err := c.Unwrap(frame); !errors.Is(err, ErrNonceReused) {
		t.Fatalf("replay Unwrap = %v, want ErrNonceReused", err)
	}
}

func TestClientWrapNonceExhausted(t *testing.T) {
	c, _, _, _ := newClientDoneAndPeerKey(t)
	c.sendNonce = ^uint64(0) // all-ones
	if _, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage}); !errors.Is(err, ErrNonceExhausted) {
		t.Fatalf("err = %v, want ErrNonceExhausted", err)
	}
}

func TestClientCloseIdempotentAndPreservesLongTermSecret(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	c.Close()
	c.Close() // idempotent

	if _, err := c.Start(); !errors.Is(err, security.ErrClosed) {
		t.Fatalf("Start after Close = %v, want security.ErrClosed", err)
	}
	if _, _, err := c.Receive(wire.Command{Name: welcomeCommandName}); !errors.Is(err, security.ErrClosed) {
		t.Fatalf("Receive after Close = %v, want security.ErrClosed", err)
	}
	if _, err := c.Wrap(wire.Frame{}); !errors.Is(err, security.ErrClosed) {
		t.Fatalf("Wrap after Close = %v, want security.ErrClosed", err)
	}
	if _, err := c.Unwrap(wire.Frame{Kind: wire.FrameCommand, Body: make([]byte, 25)}); !errors.Is(err, security.ErrClosed) {
		t.Fatalf("Unwrap after Close = %v, want security.ErrClosed", err)
	}
	if c.Done() {
		t.Fatalf("Done() == true after Close")
	}
	// Long-term secret must be intact (caller-owned). All-zeros would
	// be the post-Zero state; we assert it has at least one non-zero
	// byte — `makePair` returns non-zero with overwhelming probability.
	if clientLongSec == (SecretKey{}) {
		t.Fatalf("long-term secret was zeroed by Close")
	}
}

// --- Lifecycle / spec §6 coverage ---

func TestClientReceiveAfterDoneReturnsAlreadyDone(t *testing.T) {
	c, _, _, _ := newClientDoneAndPeerKey(t)
	if _, _, err := c.Receive(wire.Command{Name: readyCommandName}); !errors.Is(err, ErrAlreadyDone) {
		t.Fatalf("err = %v, want ErrAlreadyDone", err)
	}
}

func TestClientReceiveHelloAtAwaitWelcomeReturnsUnexpectedCommand(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	bogus := wire.Command{Name: helloCommandName, Data: make([]byte, helloBodyLen)}
	if _, _, err := c.Receive(bogus); !errors.Is(err, ErrUnexpectedCommand) {
		t.Fatalf("err = %v, want ErrUnexpectedCommand", err)
	}
}

func TestClientPeerPublicKeyReturnsServerKeyFromOptions(t *testing.T) {
	clientLongPub, clientLongSec := makePair(t)
	serverLongPub, _ := makePair(t)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverLongPub, OurPublicKey: clientLongPub, OurSecretKey: &clientLongSec,
	})
	if got := c.PeerPublicKey(); got != serverLongPub {
		t.Fatalf("PeerPublicKey = %x, want %x", got, serverLongPub)
	}
}

func TestClientStateName(t *testing.T) {
	clientPub, clientSec, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	serverPub, _, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	c, err := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got := c.Name(); got != "CURVE" {
		t.Fatalf("Name() = %q, want %q", got, "CURVE")
	}
}
