package curve

import (
	"crypto/rand"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestClientHandshakeAllocBudget(t *testing.T) {
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)

	// Pre-canned server outputs (driven once, reused).
	cBoot, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	sBoot, _ := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
	})
	helloBoot, _ := cBoot.Start()
	welcomeBoot, _, _ := sBoot.Receive(helloBoot)
	initiateBoot, _, _ := cBoot.Receive(*welcomeBoot)
	readyBoot, _, _ := sBoot.Receive(*initiateBoot)

	allocs := testing.AllocsPerRun(50, func() {
		c, _ := NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		})
		_, _ = c.Start()
		_, _, _ = c.Receive(*welcomeBoot)
		_, _, _ = c.Receive(*readyBoot)
	})
	// Empirical: 27 allocs/op (testing.AllocsPerRun, Go 1.26.2, darwin/arm64).
	// Budget = empirical + 1.
	const budget = 28
	if allocs > budget {
		t.Fatalf("client handshake allocs/op = %.0f, budget = %d", allocs, budget)
	}
}

func TestServerHandshakeAllocBudget(t *testing.T) {
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)

	cBoot, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	helloBoot, _ := cBoot.Start()

	// Mirror BenchmarkServerHandshake: reuse cBoot to generate a valid
	// INITIATE for each fresh server (the server's WELCOME is encrypted
	// to cBoot's transient pubkey, so a fresh client can't decrypt it),
	// then reset cBoot for the next iteration. AllocsPerRun runs the
	// closure once for warmup plus N times for measurement; cBoot must
	// be at AWAIT_WELCOME entering each call.
	allocs := testing.AllocsPerRun(50, func() {
		s, _ := NewServer(ServerOptions{
			OurPublicKey: serverPub, OurSecretKey: &serverSec,
			Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
		})
		welcome, _, _ := s.Receive(helloBoot)
		initiate, _, _ := cBoot.Receive(*welcome)
		_, _, _ = s.Receive(*initiate)
		// Reset cBoot for the next iteration.
		cBoot, _ = NewClient(ClientOptions{
			ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
		})
		helloBoot, _ = cBoot.Start()
	})
	// Server-side: NewServer (~3: transPub keypair + cookieKey + struct),
	//              handleHello (~3),
	//              handleInitiate (~3).
	// In-loop client work re-derives cBoot per iteration so the harness
	// also pays for NewClient + Start + Receive(welcome). Budget covers
	// both sides — this is a HARNESS-INCLUSIVE budget, not a pure
	// server-side count.
	// Empirical: 83 allocs/op (testing.AllocsPerRun, Go 1.26.2, darwin/arm64).
	// Budget = empirical + 1.
	const budget = 84
	if allocs > budget {
		t.Fatalf("server handshake allocs/op = %.0f, budget = %d (harness-inclusive)", allocs, budget)
	}
}

func TestWrapAllocBudget(t *testing.T) {
	c, _ := donePairForTest(t)
	allocs := testing.AllocsPerRun(100, func() {
		_, _ = c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: []byte("payload")})
	})
	// Empirical: 3 allocs/op for a 7-byte payload (testing.AllocsPerRun,
	// Go 1.26.2, darwin/arm64). Lower than the bench harness in Task 25
	// because b.Loop's lifecycle differs from AllocsPerRun.
	// Budget = empirical + 1.
	const budget = 4
	if allocs > budget {
		t.Fatalf("Wrap allocs/op = %.0f, budget = %d", allocs, budget)
	}
}

func TestUnwrapAllocBudget(t *testing.T) {
	c, s := donePairForTest(t)

	// Pre-build N wrapped frames so each Unwrap iteration gets a
	// fresh nonce (Unwrap rejects replays).
	const n = 200
	wraps := make([]wire.Frame, n)
	for i := range wraps {
		w, err := c.Wrap(wire.Frame{Kind: wire.FrameMessage, Body: []byte("payload")})
		if err != nil {
			t.Fatalf("Wrap[%d]: %v", i, err)
		}
		wraps[i] = w
	}

	idx := 0
	allocs := testing.AllocsPerRun(50, func() {
		_, _ = s.Unwrap(wraps[idx])
		idx++
	})
	// Empirical: 2 allocs/op for a 7-byte payload (testing.AllocsPerRun,
	// Go 1.26.2, darwin/arm64). Lower than the bench harness in Task 25
	// (5–6) because AllocsPerRun amortizes setup that b.Loop counts.
	// Budget = empirical + 1.
	const budget = 3
	if allocs > budget {
		t.Fatalf("Unwrap allocs/op = %.0f, budget = %d", allocs, budget)
	}
}

// donePairForTest mirrors donePair but takes *testing.T (alloc-budget
// tests, not benches).
func donePairForTest(t *testing.T) (*ClientState, *ServerState) {
	t.Helper()
	clientPub, clientSec, _ := GenerateKeyPair(rand.Reader)
	serverPub, serverSec, _ := GenerateKeyPair(rand.Reader)
	c, _ := NewClient(ClientOptions{
		ServerKey: serverPub, OurPublicKey: clientPub, OurSecretKey: &clientSec,
	})
	s, _ := NewServer(ServerOptions{
		OurPublicKey: serverPub, OurSecretKey: &serverSec,
		Authorizer: func(_ PublicKey, _ wire.Metadata) error { return nil },
	})
	hello, _ := c.Start()
	welcome, _, _ := s.Receive(hello)
	initiate, _, _ := c.Receive(*welcome)
	ready, _, _ := s.Receive(*initiate)
	c.Receive(*ready)
	return c, s
}
