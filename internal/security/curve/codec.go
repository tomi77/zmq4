package curve

import (
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"

	"github.com/tomi77/zmq4/internal/wire"
)

const (
	helloCommandName    = "HELLO"
	welcomeCommandName  = "WELCOME"
	initiateCommandName = "INITIATE"
	readyCommandName    = "READY"
	messageCommandName  = "MESSAGE"
	// errorCommandName is shared with NULL/PLAIN; we reference
	// wire.ErrorCommandName directly rather than redeclare it.
)

// Nonce prefixes (RFC 26 §3). Two shapes:
//
//   - Short-nonce prefixes are 16 B; on the wire the full 24-byte NaCl
//     nonce is prefix||short-nonce(8 B big-endian counter).
//   - Long-nonce prefixes are 8 B; on the wire the full 24-byte NaCl
//     nonce is prefix||long-nonce(16 B random).
//
// Trailing letter on MESSAGE prefixes encodes the SENDER role: "C" for
// client-sent, "S" for server-sent (per RFC 26 §6).
var (
	helloNoncePrefix    = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'H', 'E', 'L', 'L', 'O', '-', '-', '-'}
	welcomeNoncePrefix  = [8]byte{'W', 'E', 'L', 'C', 'O', 'M', 'E', '-'}
	cookieNoncePrefix   = [8]byte{'C', 'O', 'O', 'K', 'I', 'E', '-', '-'}
	vouchNoncePrefix    = [8]byte{'V', 'O', 'U', 'C', 'H', '-', '-', '-'}
	initiateNoncePrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'I', 'N', 'I', 'T', 'I', 'A', 'T', 'E'}
	readyNoncePrefix    = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'R', 'E', 'A', 'D', 'Y', '-', '-', '-'}
	messageClientPrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'M', 'E', 'S', 'S', 'A', 'G', 'E', 'C'}
	messageServerPrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'M', 'E', 'S', 'S', 'A', 'G', 'E', 'S'}
)

// HELLO wire layout (RFC 26 §5.2):
//
//	%x01 %x00 (version major=1 minor=0)         2 B
//	72 zero bytes (padding)                     72 B
//	C' (client transient public)                32 B
//	hello-nonce                                  8 B
//	hello-box (NaCl box of 64 zero bytes)       80 B  (= 64+16 overhead)
//
// Total body: 194 B.
const helloBodyLen = 2 + 72 + 32 + 8 + 80

// encodeHello builds a HELLO command. clientTransPub is the client's
// fresh transient public key (C'). sharedKey is precompute(serverLongPub,
// clientTransSec) = c' × S. nonce is the per-handshake short-nonce
// counter (starts at 1, monotonically increasing). rand is currently
// unused by encodeHello (the wire format only requires a counter
// short-nonce here) but accepted for symmetry with other encoders that
// emit long-nonces — pass nil if you do not have one. Returns the
// fully-formed wire.Command ready for the caller to send.
func encodeHello(clientTransPub PublicKey, sharedKey *SharedKey, nonce uint64, rand io.Reader) (wire.Command, error) {
	_ = rand // unused; reserved for symmetry with long-nonce encoders.

	data := make([]byte, helloBodyLen)
	data[0] = 0x01 // version major
	data[1] = 0x00 // version minor
	// 72-byte padding stays zero by virtue of make().
	copy(data[2+72:2+72+32], clientTransPub[:])

	binary.BigEndian.PutUint64(data[2+72+32:2+72+32+8], nonce)

	var nacl [24]byte
	copy(nacl[:16], helloNoncePrefix[:])
	binary.BigEndian.PutUint64(nacl[16:], nonce)

	// hello-box content is 64 zero bytes (the "signature" payload).
	var zeros [64]byte
	out := box.SealAfterPrecomputation(nil, zeros[:], &nacl, (*[32]byte)(sharedKey))
	if len(out) != 80 {
		return wire.Command{}, fmt.Errorf("curve: internal: hello-box len=%d want 80", len(out))
	}
	copy(data[2+72+32+8:], out)

	return wire.Command{Name: helloCommandName, Data: data}, nil
}

// parseHello opens a peer HELLO and returns the client's transient
// public key. sharedKey must be precompute(clientTransPub, serverLongSec)
// = s × C' for the server side (note: NaCl box DH is symmetric in the
// pair, so c'×S and s×C' yield the same bytes — but the server, which
// does not yet know C', cannot use this until after parsing C' from
// the cleartext part of HELLO; sharedKey should therefore be computed
// AFTER C' is read out of the body).
func parseHello(cmd wire.Command, sharedKey *SharedKey) (PublicKey, error) {
	if cmd.Name != helloCommandName {
		return PublicKey{}, fmt.Errorf("%w: command name %q", ErrMalformedHello, cmd.Name)
	}
	if len(cmd.Data) != helloBodyLen {
		return PublicKey{}, fmt.Errorf("%w: body size %d, want %d", ErrMalformedHello, len(cmd.Data), helloBodyLen)
	}
	if cmd.Data[0] != 0x01 || cmd.Data[1] != 0x00 {
		return PublicKey{}, fmt.Errorf("%w: bad version %x %x", ErrMalformedHello, cmd.Data[0], cmd.Data[1])
	}
	for i := 0; i < 72; i++ {
		if cmd.Data[2+i] != 0 {
			return PublicKey{}, fmt.Errorf("%w: non-zero padding at byte %d", ErrMalformedHello, 2+i)
		}
	}
	var clientTransPub PublicKey
	copy(clientTransPub[:], cmd.Data[2+72:2+72+32])

	var nacl [24]byte
	copy(nacl[:16], helloNoncePrefix[:])
	copy(nacl[16:], cmd.Data[2+72+32:2+72+32+8])

	box64 := cmd.Data[2+72+32+8:]
	if _, ok := box.OpenAfterPrecomputation(nil, box64, &nacl, (*[32]byte)(sharedKey)); !ok {
		return PublicKey{}, fmt.Errorf("%w: hello-box", ErrBoxOpen)
	}
	return clientTransPub, nil
}
