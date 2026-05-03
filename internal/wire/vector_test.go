package wire

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func vectorPath(file string) string {
	return filepath.Join("testdata", "interop", file)
}

// readVector loads a vector file. If missing, it skips (when ZMQ4_VECTORS_PENDING=1)
// or fails the test otherwise.
func readVector(t *testing.T, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(vectorPath(file))
	if err != nil {
		if os.Getenv("ZMQ4_VECTORS_PENDING") == "1" {
			t.Skipf("vector not yet captured: %v", err)
		}
		t.Fatalf("required vector missing (set ZMQ4_VECTORS_PENDING=1 during dev only): %v", err)
	}
	return raw
}

func TestGreetingVectors(t *testing.T) {
	cases := []struct {
		file      string
		wantMech  string
		wantAsSrv bool
	}{
		{"greeting-null.bin", "NULL", false},
		{"greeting-plain.bin", "PLAIN", false},
		{"greeting-curve.bin", "CURVE", true},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			raw := readVector(t, c.file)
			g, err := DecodeGreeting(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if g.Mechanism != c.wantMech || g.AsServer != c.wantAsSrv {
				t.Fatalf("got %+v, want mech=%s asServer=%v", g, c.wantMech, c.wantAsSrv)
			}
			// Re-encode and compare. Padding bytes 1..8 are "any" per spec; mask before compare.
			var enc [GreetingSize]byte
			if err := EncodeGreeting(enc[:], g); err != nil {
				t.Fatalf("encode: %v", err)
			}
			rawNorm := append([]byte{}, raw...)
			for i := 1; i < 9; i++ {
				rawNorm[i] = 0
			}
			if !bytes.Equal(enc[:], rawNorm) {
				t.Fatalf("round-trip mismatch:\ngot:  %x\nwant: %x", enc[:], rawNorm)
			}
		})
	}
}

func TestFrameVectors(t *testing.T) {
	cases := []struct {
		file     string
		wantKind FrameKind
		wantMore bool
		wantBody []byte
	}{
		{"frame-empty.bin", FrameMessage, false, nil},
		{"frame-short.bin", FrameMessage, false, []byte("hello")},
		{"frame-long.bin", FrameMessage, false, bytes.Repeat([]byte{0xAB}, 300)},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			raw := readVector(t, c.file)
			f, n, err := DecodeFrame(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if n != len(raw) {
				t.Fatalf("consumed %d, want %d", n, len(raw))
			}
			if f.Kind != c.wantKind || f.More != c.wantMore {
				t.Fatalf("got kind=%v more=%v, want %v %v", f.Kind, f.More, c.wantKind, c.wantMore)
			}
			if !bytes.Equal(f.Body, c.wantBody) && !(len(f.Body) == 0 && len(c.wantBody) == 0) {
				t.Fatalf("body mismatch")
			}
			// Re-encode and compare bytes.
			out := make([]byte, f.WireSize())
			if _, err := EncodeFrame(out, f); err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			if !bytes.Equal(out, raw) {
				t.Fatalf("round-trip mismatch:\ngot:  %x\nwant: %x", out, raw)
			}
		})
	}
}

func TestFrameMultipartVector(t *testing.T) {
	raw := readVector(t, "frame-multipart.bin")
	wantBodies := [][]byte{[]byte("part-1"), []byte("part-2"), []byte("part-3-lst")}
	wantMore := []bool{true, true, false}
	in := raw
	for i := range wantBodies {
		f, n, err := DecodeFrame(in)
		if err != nil {
			t.Fatalf("frame %d decode: %v", i, err)
		}
		if f.Kind != FrameMessage || f.More != wantMore[i] {
			t.Fatalf("frame %d: got kind=%v more=%v, want msg %v", i, f.Kind, f.More, wantMore[i])
		}
		if !bytes.Equal(f.Body, wantBodies[i]) {
			t.Fatalf("frame %d body: got %q, want %q", i, f.Body, wantBodies[i])
		}
		in = in[n:]
	}
	if len(in) != 0 {
		t.Fatalf("trailing bytes: %x", in)
	}
}

func TestCommandReadyVectors(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		raw := readVector(t, "cmd-ready-empty.bin")
		cmd, err := ParseCommand(raw)
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Name != "READY" {
			t.Fatalf("got name=%q, want READY", cmd.Name)
		}
		rc, err := ParseReady(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if len(rc.Metadata) != 0 {
			t.Fatalf("got %d properties, want 0", len(rc.Metadata))
		}
	})
	t.Run("typical", func(t *testing.T) {
		raw := readVector(t, "cmd-ready-typical.bin")
		cmd, err := ParseCommand(raw)
		if err != nil {
			t.Fatal(err)
		}
		rc, err := ParseReady(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := rc.Metadata.Get("Socket-Type"); !ok || string(v) != "REQ" {
			t.Fatalf("Socket-Type: got (%q,%v), want (REQ,true)", v, ok)
		}
		if v, ok := rc.Metadata.Get("Identity"); !ok || string(v) != "client-1" {
			t.Fatalf("Identity: got (%q,%v), want (client-1,true)", v, ok)
		}
	})
}

func TestCommandErrorVector(t *testing.T) {
	raw := readVector(t, "cmd-error.bin")
	cmd, err := ParseCommand(raw)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ParseError(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if ec.Reason != "Authentication failure" {
		t.Fatalf("reason: got %q", ec.Reason)
	}
}

func TestCommandPingPongVectors(t *testing.T) {
	t.Run("ping", func(t *testing.T) {
		raw := readVector(t, "cmd-ping.bin")
		cmd, err := ParseCommand(raw)
		if err != nil {
			t.Fatal(err)
		}
		pc, err := ParsePing(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if pc.TTL != 100 || string(pc.Context) != "ctx" {
			t.Fatalf("got TTL=%d ctx=%q, want 100 ctx", pc.TTL, pc.Context)
		}
	})
	t.Run("pong", func(t *testing.T) {
		raw := readVector(t, "cmd-pong.bin")
		cmd, err := ParseCommand(raw)
		if err != nil {
			t.Fatal(err)
		}
		pc, err := ParsePong(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if string(pc.Context) != "ctx" {
			t.Fatalf("got %q, want ctx", pc.Context)
		}
	})
}

func TestCommandSubscribeCancelVectors(t *testing.T) {
	t.Run("subscribe", func(t *testing.T) {
		raw := readVector(t, "cmd-subscribe.bin")
		cmd, err := ParseCommand(raw)
		if err != nil {
			t.Fatal(err)
		}
		sc, err := ParseSubscribe(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if string(sc.Topic) != "news" {
			t.Fatalf("got %q, want news", sc.Topic)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		raw := readVector(t, "cmd-cancel.bin")
		cmd, err := ParseCommand(raw)
		if err != nil {
			t.Fatal(err)
		}
		cc, err := ParseCancel(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if string(cc.Topic) != "news" {
			t.Fatalf("got %q, want news", cc.Topic)
		}
	})
}

// Reference errors import to avoid "imported and not used" if all reads succeed.
var _ = errors.Is
