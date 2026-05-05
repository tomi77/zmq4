// Package security defines cross-mechanism types for the ZMTP 3.1
// security layer (L2). Concrete mechanisms live in subpackages:
//
//   - internal/security/null    — NULL mechanism (RFC 37 §3.1).
//   - internal/security/plain   — PLAIN mechanism (RFC 37 §3.2).
//   - internal/security/curve   — CURVE mechanism (RFC 37 §3.3 / RFC 26).
//
// All three implement Mechanism (and the active side of each
// implements ClientMechanism). The interfaces are consumed by F4
// (connection layer) and tested cross-mechanism in
// interfaces_conformance_test.go.
//
// See docs/specs/02c-security-curve.md §4.1 for the full contract.
package security
