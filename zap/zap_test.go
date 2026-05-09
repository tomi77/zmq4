package zap_test

import (
	"errors"
	"testing"

	zmqzap "github.com/tomi77/zmq4/zap"
)

func TestRouterCallsHandler(t *testing.T) {
	called := make(chan zmqzap.Request, 1)
	h := zmqzap.HandlerFunc(func(r zmqzap.Request) (zmqzap.Reply, error) {
		called <- r
		return zmqzap.Reply{StatusCode: zmqzap.StatusOK}, nil
	})
	r := zmqzap.NewRouter(h)
	defer r.Close()

	c := zmqzap.NewClient(r)
	code, _, _, err := c.Authenticate("dom", "1.2.3.4:5000", "", "NULL", nil)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if code != zmqzap.StatusOK {
		t.Fatalf("status = %q, want %q", code, zmqzap.StatusOK)
	}
	req := <-called
	if req.Domain != "dom" {
		t.Fatalf("Domain = %q, want %q", req.Domain, "dom")
	}
	if req.Address != "1.2.3.4:5000" {
		t.Fatalf("Address = %q, want %q", req.Address, "1.2.3.4:5000")
	}
	if req.Mechanism != "NULL" {
		t.Fatalf("Mechanism = %q, want %q", req.Mechanism, "NULL")
	}
}

func TestRouterReturnsReplyFields(t *testing.T) {
	h := zmqzap.HandlerFunc(func(r zmqzap.Request) (zmqzap.Reply, error) {
		return zmqzap.Reply{
			StatusCode: zmqzap.StatusOK,
			StatusText: "OK",
			UserID:     "alice",
			Metadata:   map[string]string{"X-Role": "admin"},
		}, nil
	})
	r := zmqzap.NewRouter(h)
	defer r.Close()

	c := zmqzap.NewClient(r)
	code, userID, meta, err := c.Authenticate("", "", "", "NULL", nil)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if code != zmqzap.StatusOK {
		t.Fatalf("code = %q, want %q", code, zmqzap.StatusOK)
	}
	if userID != "alice" {
		t.Fatalf("userID = %q, want %q", userID, "alice")
	}
	if meta == nil {
		t.Fatal("metadata nil, want non-nil")
	}
}

func TestRouterDenyReturns400(t *testing.T) {
	h := zmqzap.HandlerFunc(func(r zmqzap.Request) (zmqzap.Reply, error) {
		return zmqzap.Reply{StatusCode: zmqzap.StatusDenied, StatusText: "no"}, nil
	})
	r := zmqzap.NewRouter(h)
	defer r.Close()

	c := zmqzap.NewClient(r)
	code, _, _, err := c.Authenticate("", "", "", "NULL", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != zmqzap.StatusDenied {
		t.Fatalf("code = %q, want %q", code, zmqzap.StatusDenied)
	}
}

func TestClientOnClosedRouterReturnsErr(t *testing.T) {
	h := zmqzap.HandlerFunc(func(r zmqzap.Request) (zmqzap.Reply, error) {
		return zmqzap.Reply{StatusCode: zmqzap.StatusOK}, nil
	})
	r := zmqzap.NewRouter(h)
	r.Close()

	c := zmqzap.NewClient(r)
	_, _, _, err := c.Authenticate("", "", "", "NULL", nil)
	if !errors.Is(err, zmqzap.ErrRouterClosed) {
		t.Fatalf("err = %v, want ErrRouterClosed", err)
	}
}

func TestRouterPLAINCredentials(t *testing.T) {
	var gotCreds [][]byte
	h := zmqzap.HandlerFunc(func(r zmqzap.Request) (zmqzap.Reply, error) {
		gotCreds = r.Credentials
		return zmqzap.Reply{StatusCode: zmqzap.StatusOK}, nil
	})
	r := zmqzap.NewRouter(h)
	defer r.Close()

	c := zmqzap.NewClient(r)
	_, _, _, err := c.Authenticate("", "", "", "PLAIN", [][]byte{[]byte("user"), []byte("pass")})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(gotCreds) != 2 || string(gotCreds[0]) != "user" || string(gotCreds[1]) != "pass" {
		t.Fatalf("credentials = %v, want [user pass]", gotCreds)
	}
}
