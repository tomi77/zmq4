package curve

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestGenerateKeyPairWithCryptoRand(t *testing.T) {
	pub, sec, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if pub == (PublicKey{}) {
		t.Fatalf("public key is all zero")
	}
	if sec == (SecretKey{}) {
		t.Fatalf("secret key is all zero")
	}
}

// failingReader returns wantErr on the first Read.
type failingReader struct{ wantErr error }

func (f failingReader) Read(_ []byte) (int, error) { return 0, f.wantErr }

func TestGenerateKeyPairWrapsRandError(t *testing.T) {
	want := errors.New("synthetic")
	_, _, err := GenerateKeyPair(failingReader{want})
	if !errors.Is(err, ErrCryptoRand) {
		t.Fatalf("err = %v, want ErrCryptoRand", err)
	}
}

func TestSecretKeyStringIsRedacted(t *testing.T) {
	var sk SecretKey
	for i := range sk {
		sk[i] = 0xAB
	}
	got := fmt.Sprintf("%v", &sk)
	if got != "[REDACTED]" {
		t.Fatalf("%%v = %q, want \"[REDACTED]\"", got)
	}
	gs := fmt.Sprintf("%#v", &sk)
	if !strings.Contains(gs, "[REDACTED]") {
		t.Fatalf("%%#v = %q, want to contain [REDACTED]", gs)
	}
}

func TestSecretKeyZero(t *testing.T) {
	var sk SecretKey
	for i := range sk {
		sk[i] = 0xAB
	}
	sk.Zero()
	if !bytes.Equal(sk[:], make([]byte, 32)) {
		t.Fatalf("after Zero, key = %x, want all zero", sk[:])
	}
	// Idempotent.
	sk.Zero()
	if !bytes.Equal(sk[:], make([]byte, 32)) {
		t.Fatalf("after second Zero, key changed")
	}
}

func TestSharedKeyStringIsRedacted(t *testing.T) {
	var sk SharedKey
	for i := range sk {
		sk[i] = 0xCD
	}
	got := fmt.Sprintf("%v", &sk)
	if got != "[REDACTED]" {
		t.Fatalf("%%v = %q, want \"[REDACTED]\"", got)
	}
}

func TestSharedKeyZero(t *testing.T) {
	var sk SharedKey
	for i := range sk {
		sk[i] = 0xCD
	}
	sk.Zero()
	if !bytes.Equal(sk[:], make([]byte, 32)) {
		t.Fatalf("after Zero, shared = %x, want all zero", sk[:])
	}
}

func TestPrecomputeIsSymmetric(t *testing.T) {
	// box DH is symmetric: precompute(B, a) == precompute(A, b).
	pubA, secA, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	pubB, secB, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}
	skAB := precompute(pubB, &secA)
	skBA := precompute(pubA, &secB)
	if !bytes.Equal(skAB[:], skBA[:]) {
		t.Fatalf("precompute asymmetry: %x vs %x", skAB[:], skBA[:])
	}
}

// silence unused-import warnings if a refactor removes references.
var _ io.Reader = failingReader{}
