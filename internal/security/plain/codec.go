package plain

import (
	"fmt"

	"github.com/tomi77/zmq4/internal/wire"
)

const (
	helloCommandName    = "HELLO"
	welcomeCommandName  = "WELCOME"
	initiateCommandName = "INITIATE"
)

// helloBody is the parsed body of a HELLO command:
//
//	hello = "HELLO" username password
//	username = OCTET 0*255OCTET    ; 1-byte length prefix
//	password = OCTET 0*255OCTET    ; 1-byte length prefix
type helloBody struct {
	Username []byte
	Password []byte
}

func encodeHello(b helloBody) (wire.Command, error) {
	if len(b.Username) > 255 {
		return wire.Command{}, fmt.Errorf("%w: username", ErrCredentialsTooLong)
	}
	if len(b.Password) > 255 {
		return wire.Command{}, fmt.Errorf("%w: password", ErrCredentialsTooLong)
	}
	data := make([]byte, 0, 2+len(b.Username)+len(b.Password))
	data = append(data, byte(len(b.Username)))
	data = append(data, b.Username...)
	data = append(data, byte(len(b.Password)))
	data = append(data, b.Password...)
	return wire.Command{Name: helloCommandName, Data: data}, nil
}

func parseHello(cmd wire.Command) (helloBody, error) {
	if cmd.Name != helloCommandName {
		return helloBody{}, fmt.Errorf("%w: command name %q", ErrMalformedHello, cmd.Name)
	}
	d := cmd.Data
	if len(d) < 1 {
		return helloBody{}, fmt.Errorf("%w: missing username length", ErrMalformedHello)
	}
	uLen := int(d[0])
	d = d[1:]
	if len(d) < uLen {
		return helloBody{}, fmt.Errorf("%w: username truncated", ErrMalformedHello)
	}
	user := d[:uLen]
	d = d[uLen:]
	if len(d) < 1 {
		return helloBody{}, fmt.Errorf("%w: missing password length", ErrMalformedHello)
	}
	pLen := int(d[0])
	d = d[1:]
	if len(d) < pLen {
		return helloBody{}, fmt.Errorf("%w: password truncated", ErrMalformedHello)
	}
	pass := d[:pLen]
	d = d[pLen:]
	if len(d) != 0 {
		return helloBody{}, fmt.Errorf("%w: %d trailing bytes", ErrMalformedHello, len(d))
	}
	return helloBody{Username: user, Password: pass}, nil
}

func encodeWelcome() wire.Command {
	return wire.Command{Name: welcomeCommandName, Data: nil}
}

func parseWelcome(cmd wire.Command) error {
	if cmd.Name != welcomeCommandName {
		return fmt.Errorf("%w: command name %q", ErrMalformedWelcome, cmd.Name)
	}
	if len(cmd.Data) != 0 {
		return fmt.Errorf("%w: %d unexpected body bytes", ErrMalformedWelcome, len(cmd.Data))
	}
	return nil
}

// sanitizeReason makes s safe to put inside an ERROR command body
// (RFC 37 §3 ABNF: error-reason = OCTET 0*255VCHAR). Replaces any
// non-VCHAR byte with '?', then truncates to 255 bytes.
//
// VCHAR is %x21..%x7E (printable ASCII excluding space).
func sanitizeReason(s string) string {
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
