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
