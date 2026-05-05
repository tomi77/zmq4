package seccommon

// SanitizeReason makes s safe to embed in the body of a ZMTP ERROR
// command (RFC 37 §3 ABNF: error-reason = OCTET 0*255VCHAR). Replaces
// any non-VCHAR byte with '?', then truncates to 255 bytes. VCHAR is
// %x21..%x7E (printable ASCII excluding space).
//
// The empty string is returned unchanged.
func SanitizeReason(s string) string {
	if s == "" {
		return ""
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x21 || c > 0x7E {
			b[i] = '?'
		}
	}
	if len(b) > 255 {
		b = b[:255]
	}
	return string(b)
}
