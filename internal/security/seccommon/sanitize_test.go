package seccommon

import (
	"strings"
	"testing"
)

func TestSanitizeReasonReplacesNonVCHAR(t *testing.T) {
	in := "ok\nhuh\x00\tend\x7F\xFF "
	out := SanitizeReason(in)
	for i, c := range []byte(out) {
		if c < 0x21 || c > 0x7E {
			t.Fatalf("SanitizeReason left non-VCHAR byte %#x at index %d in %q", c, i, out)
		}
	}
	if len(out) != len(in) {
		t.Fatalf("SanitizeReason length = %d, want %d", len(out), len(in))
	}
}

func TestSanitizeReasonTruncatesTo255(t *testing.T) {
	in := strings.Repeat("a", 300)
	out := SanitizeReason(in)
	if len(out) != 255 {
		t.Fatalf("len = %d, want 255", len(out))
	}
}

func TestSanitizeReasonEmpty(t *testing.T) {
	if out := SanitizeReason(""); out != "" {
		t.Fatalf("SanitizeReason(\"\") = %q, want \"\"", out)
	}
}

func TestSanitizeReasonAllVCHARPassthrough(t *testing.T) {
	in := "ALL_PRINT-Able_!#$%&*+,-./0123456789:;<=>?@ABCDEFG"
	out := SanitizeReason(in)
	if out != in {
		t.Fatalf("SanitizeReason(%q) = %q, want unchanged", in, out)
	}
}

func TestSanitizeReasonBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"vchar-low-boundary-0x21", "!", "!"},
		{"vchar-high-boundary-0x7E", "~", "~"},
		{"just-below-boundary-0x20-space", " ", "?"},
		{"just-above-boundary-0x7F-DEL", "\x7f", "?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeReason(tc.in); got != tc.want {
				t.Fatalf("SanitizeReason(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeReasonTruncatesAt256ButNot255(t *testing.T) {
	in255 := strings.Repeat("a", 255)
	if out := SanitizeReason(in255); len(out) != 255 {
		t.Fatalf("len(in=255) = %d, want 255 (no truncation)", len(out))
	}
	in256 := strings.Repeat("a", 256)
	if out := SanitizeReason(in256); len(out) != 255 {
		t.Fatalf("len(in=256) = %d, want 255 (truncated)", len(out))
	}
}
