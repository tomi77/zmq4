// Package ipc implements the ipc:// transport for F3 — Unix domain
// sockets on Unix platforms.
//
// On Windows the package compiles to stubs returning
// transport.ErrSchemeUnknown; a real Windows implementation (Named
// Pipes) is deferred — see docs/specs/03-transports.md §9 Open
// Question 7.
//
// Listen creates the socket file with mode 0600 and SetUnlinkOnClose(true).
// A small chmod-window between bind and chmod is documented in the spec.
package ipc
