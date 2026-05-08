package conn

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/tomi77/zmq4/internal/security/null"
	"github.com/tomi77/zmq4/internal/wire"
)

// newPipeConn builds an unhandshaken *Conn around one end of a net.Pipe
// for testing the non-handshake surface. The mech is a fresh null state
// (it is never driven; the conn is post-construction synthetic).
func newPipeConn(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	ours, peer := net.Pipe()
	cfg := newConfig(nil)
	c := &Conn{
		raw:      ours,
		fr:       wire.NewFrameReader(ours, wire.WithMaxBodySize(cfg.maxFrameBodySize)),
		fw:       wire.NewFrameWriter(ours),
		mech:     null.New(nil),
		peerMeta: nil,
	}
	t.Cleanup(func() {
		_ = c.Close()
		_ = peer.Close()
	})
	return c, peer
}

func TestConnCloseIdempotent(t *testing.T) {
	c, _ := newPipeConn(t)
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestConnCloseClosesRaw(t *testing.T) {
	c, peer := newPipeConn(t)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Reading the peer side should now see EOF (or ErrClosedPipe — net.Pipe
	// closes both directions on one Close).
	buf := make([]byte, 1)
	_, err := peer.Read(buf)
	if err == nil {
		t.Fatalf("peer.Read after Close: nil error, want EOF/ErrClosedPipe")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("peer.Read after Close: %v, want io.EOF or io.ErrClosedPipe", err)
	}
}

func TestConnRemoteLocalAddrDelegate(t *testing.T) {
	c, peer := newPipeConn(t)
	if c.RemoteAddr() == nil {
		t.Errorf("RemoteAddr() = nil")
	}
	if c.LocalAddr() == nil {
		t.Errorf("LocalAddr() = nil")
	}
	// Both should equal the underlying conn's addrs.
	if c.RemoteAddr().String() != c.raw.RemoteAddr().String() {
		t.Errorf("RemoteAddr delegation mismatch")
	}
	if c.LocalAddr().String() != c.raw.LocalAddr().String() {
		t.Errorf("LocalAddr delegation mismatch")
	}
	_ = peer
}

func TestConnPeerMetadataReturnsStoredSlice(t *testing.T) {
	c, _ := newPipeConn(t)
	c.peerMeta = wire.Metadata{{Name: []byte("Socket-Type"), Value: []byte("PAIR")}}
	got := c.PeerMetadata()
	if len(got) != 1 || string(got[0].Name) != "Socket-Type" || string(got[0].Value) != "PAIR" {
		t.Fatalf("PeerMetadata() = %+v, want one Socket-Type=PAIR property", got)
	}
}
