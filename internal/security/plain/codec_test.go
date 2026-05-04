package plain

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tomi77/zmq4/internal/wire"
)

func TestEncodeHelloRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name     string
		username []byte
		password []byte
	}{
		{"empty", []byte{}, []byte{}},
		{"creds", []byte("admin"), []byte("secret")},
		{"max-len", bytes.Repeat([]byte("u"), 255), bytes.Repeat([]byte("p"), 255)},
		{"binary-password", []byte("user"), []byte{0x00, 0x01, 0xFF, 0x7F}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := encodeHello(helloBody{Username: tc.username, Password: tc.password})
			if err != nil {
				t.Fatalf("encodeHello: %v", err)
			}
			if cmd.Name != helloCommandName {
				t.Fatalf("cmd.Name = %q, want %q", cmd.Name, helloCommandName)
			}
			got, err := parseHello(cmd)
			if err != nil {
				t.Fatalf("parseHello: %v", err)
			}
			if !bytes.Equal(got.Username, tc.username) {
				t.Fatalf("Username = %x, want %x", got.Username, tc.username)
			}
			if !bytes.Equal(got.Password, tc.password) {
				t.Fatalf("Password = %x, want %x", got.Password, tc.password)
			}
		})
	}
}

func TestParseHelloRejectsTruncatedUsername(t *testing.T) {
	// usernameLen=5 but only 2 bytes follow.
	bad := wire.Command{Name: helloCommandName, Data: []byte{0x05, 'a', 'b'}}
	if _, err := parseHello(bad); err == nil {
		t.Fatalf("parseHello(truncated username): err=nil, want non-nil")
	}
}

func TestParseHelloRejectsTruncatedPassword(t *testing.T) {
	// usernameLen=2, "ab", passwordLen=5, but only 1 byte follows.
	bad := wire.Command{Name: helloCommandName, Data: []byte{0x02, 'a', 'b', 0x05, 'x'}}
	if _, err := parseHello(bad); err == nil {
		t.Fatalf("parseHello(truncated password): err=nil, want non-nil")
	}
}

func TestParseHelloRejectsTrailingBytes(t *testing.T) {
	// Two zero-length fields (legal) followed by an extra byte.
	bad := wire.Command{Name: helloCommandName, Data: []byte{0x00, 0x00, 0xAA}}
	if _, err := parseHello(bad); err == nil {
		t.Fatalf("parseHello(trailing): err=nil, want non-nil")
	}
}

func TestParseHelloRejectsWrongName(t *testing.T) {
	cmd := wire.Command{Name: "READY", Data: []byte{0x00, 0x00}}
	if _, err := parseHello(cmd); err == nil {
		t.Fatalf("parseHello(name=READY): err=nil, want non-nil")
	}
}

func TestEncodeWelcomeIsEmpty(t *testing.T) {
	cmd := encodeWelcome()
	if cmd.Name != welcomeCommandName {
		t.Fatalf("cmd.Name = %q, want %q", cmd.Name, welcomeCommandName)
	}
	if len(cmd.Data) != 0 {
		t.Fatalf("cmd.Data = %x, want empty", cmd.Data)
	}
	if err := parseWelcome(cmd); err != nil {
		t.Fatalf("parseWelcome(empty): %v", err)
	}
}

func TestParseWelcomeRejectsNonEmptyBody(t *testing.T) {
	cmd := wire.Command{Name: welcomeCommandName, Data: []byte{0xAA}}
	if err := parseWelcome(cmd); err == nil {
		t.Fatalf("parseWelcome(non-empty): err=nil, want non-nil")
	}
}

func TestParseWelcomeRejectsWrongName(t *testing.T) {
	cmd := wire.Command{Name: "READY"}
	if err := parseWelcome(cmd); err == nil {
		t.Fatalf("parseWelcome(name=READY): err=nil, want non-nil")
	}
}

func TestSanitizeReasonReplacesNonVCHAR(t *testing.T) {
	// VCHAR = 0x21..0x7E. Inputs include space (0x20), tab, newline,
	// nul, DEL, and a high-bit byte — all non-VCHAR.
	in := "ok\nhuh\x00\tend\x7F\xFF "
	out := sanitizeReason(in)
	for i, c := range []byte(out) {
		if c < 0x21 || c > 0x7E {
			t.Fatalf("sanitizeReason left non-VCHAR byte %#x at index %d in %q", c, i, out)
		}
	}
	if len(out) != len(in) {
		t.Fatalf("sanitizeReason length = %d, want %d", len(out), len(in))
	}
}

func TestSanitizeReasonTruncatesTo255(t *testing.T) {
	in := strings.Repeat("a", 300)
	out := sanitizeReason(in)
	if len(out) != 255 {
		t.Fatalf("len = %d, want 255", len(out))
	}
}

func TestSanitizeReasonEmpty(t *testing.T) {
	if out := sanitizeReason(""); out != "" {
		t.Fatalf("sanitizeReason(\"\") = %q, want \"\"", out)
	}
}
