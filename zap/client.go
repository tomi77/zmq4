package zap

import (
	"crypto/rand"
	"fmt"

	"github.com/tomi77/zmq4/internal/wire"
)

// Client sends ZAP authentication requests to a Router. Obtain via NewClient.
// Client is safe for concurrent use by multiple goroutines (each handshake
// goroutine calls Authenticate independently).
type Client struct {
	router *Router
}

// NewClient creates a Client backed by r. r must not be nil.
func NewClient(r *Router) *Client {
	return &Client{router: r}
}

// Authenticate sends a ZAP REQUEST to the Router and waits for a REPLY.
// Returns (statusCode, userID, zapMetadata, error).
// statusCode is one of the Status* constants ("200", "300", "400", "500").
// Returns ErrRouterClosed if the Router has been shut down.
func (c *Client) Authenticate(domain, address, identity, mechanism string, credentials [][]byte) (statusCode, userID string, metadata wire.Metadata, err error) {
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", "", nil, fmt.Errorf("zap: generate request ID: %w", err)
	}
	replyCh := make(chan zapResult, 1)
	env := zapEnvelope{
		req: Request{
			Version:     "1.0",
			RequestID:   id[:],
			Domain:      domain,
			Address:     address,
			Identity:    []byte(identity),
			Mechanism:   mechanism,
			Credentials: credentials,
		},
		replyCh: replyCh,
	}
	if dispErr := c.router.dispatch(env); dispErr != nil {
		return "", "", nil, dispErr
	}
	var result zapResult
	select {
	case result = <-replyCh:
	case <-c.router.closeCh:
		return "", "", nil, ErrRouterClosed
	}
	if result.err != nil {
		return "", "", nil, result.err
	}
	return result.reply.StatusCode, result.reply.UserID, convertMetadata(result.reply.Metadata), nil
}

func convertMetadata(m map[string]string) wire.Metadata {
	if len(m) == 0 {
		return nil
	}
	md := make(wire.Metadata, 0, len(m))
	for k, v := range m {
		md = append(md, wire.MetadataProperty{Name: []byte(k), Value: []byte(v)})
	}
	return md
}
