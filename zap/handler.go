package zap

// Status codes defined by RFC 27 §7.
const (
	StatusOK          = "200"
	StatusTemporary   = "300"
	StatusDenied      = "400"
	StatusInternalErr = "500"
)

// Handler decides whether to accept an incoming connection.
// Authenticate is called synchronously during the ZMTP handshake;
// it must not block indefinitely.
type Handler interface {
	Authenticate(r Request) (Reply, error)
}

// Request is the ZAP authentication request (RFC 27 §7).
type Request struct {
	Version     string   // always "1.0"
	RequestID   []byte   // 8 random bytes; opaque to the handler
	Domain      string   // security domain configured on the socket
	Address     string   // peer network address, e.g. "192.0.2.1:40000"
	Identity    []byte   // always empty in this implementation
	Mechanism   string   // "NULL", "PLAIN", or "CURVE"
	Credentials [][]byte // NULL: nil; PLAIN: [username, password]; CURVE: [clientPublicKey]
}

// Reply is the ZAP handler's response (RFC 27 §7).
type Reply struct {
	StatusCode string            // "200", "300", "400", or "500"
	StatusText string            // human-readable status description
	UserID     string            // application-level user identifier (may be empty)
	Metadata   map[string]string // additional properties merged into PeerMetadata()
}
