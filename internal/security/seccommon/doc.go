// Package seccommon hosts pure helpers shared by the L2 security
// mechanisms (null, plain, curve):
//
//   - CloneMetadata makes a defensive deep copy of wire.Metadata so
//     PeerMetadata is independent of the input frame buffer.
//   - SanitizeReason makes an arbitrary string safe to embed in a ZMTP
//     ERROR command body (RFC 37 §3 ABNF: 0*255 VCHAR).
//
// Replaces the former internal/security/metaclone package; the rename
// happened in F2c so all three mechanisms could converge on a single
// helper package.
package seccommon
