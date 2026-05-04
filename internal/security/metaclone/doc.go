// Package metaclone provides a defensive deep-copy helper for
// wire.Metadata, shared by the L2 security mechanisms.
//
// The mechanisms (null, plain, curve) parse peer metadata out of frame
// buffers that the connection layer (F4) is free to reuse. PeerMetadata
// must therefore alias an independent buffer, decoupled from the input.
// Clone provides exactly that — a fresh slice, fresh Name/Value backing
// arrays, no shared bytes with the source.
package metaclone
