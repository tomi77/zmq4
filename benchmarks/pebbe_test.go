//go:build libzmq

package bench_test

import (
	"fmt"
	"strings"

	pebbe "github.com/pebbe/zmq4"
)

func init() { registerAdapter(pebbeAdapter{}) }

type pebbeAdapter struct{}

func (pebbeAdapter) Name() string { return "pebbe" }

type pebbeSocket struct {
	send  func([]byte) error
	recv  func() ([]byte, error)
	close func() error
}

func (s *pebbeSocket) Send(msg []byte) error { return s.send(msg) }
func (s *pebbeSocket) Recv() ([]byte, error) { return s.recv() }
func (s *pebbeSocket) Close() error          { return s.close() }

func isInprocAddr(addr string) bool {
	return strings.HasPrefix(addr, "inproc://")
}

func (pebbeAdapter) PushPull(addr string) (Socket, Socket, func(), error) {
	if isInprocAddr(addr) {
		return nil, nil, nil, ErrNotSupported
	}
	push, err := pebbe.NewSocket(pebbe.PUSH)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new PUSH: %w", err)
	}
	pull, err := pebbe.NewSocket(pebbe.PULL)
	if err != nil {
		push.Close()
		return nil, nil, nil, fmt.Errorf("new PULL: %w", err)
	}
	if err := push.Bind(addr); err != nil {
		push.Close(); pull.Close()
		return nil, nil, nil, fmt.Errorf("push bind: %w", err)
	}
	if err := pull.Connect(addr); err != nil {
		push.Close(); pull.Close()
		return nil, nil, nil, fmt.Errorf("pull connect: %w", err)
	}
	sender := &pebbeSocket{
		send:  func(b []byte) error { _, err := push.SendBytes(b, 0); return err },
		recv:  func() ([]byte, error) { panic("push cannot recv") },
		close: func() error { push.Close(); return nil },
	}
	receiver := &pebbeSocket{
		send:  func(b []byte) error { panic("pull cannot send") },
		recv:  func() ([]byte, error) { return pull.RecvBytes(0) },
		close: func() error { pull.Close(); return nil },
	}
	cleanup := func() { push.Close(); pull.Close() }
	return sender, receiver, cleanup, nil
}

func (pebbeAdapter) ReqRep(addr string) (Socket, Socket, func(), error) {
	if isInprocAddr(addr) {
		return nil, nil, nil, ErrNotSupported
	}
	req, err := pebbe.NewSocket(pebbe.REQ)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new REQ: %w", err)
	}
	rep, err := pebbe.NewSocket(pebbe.REP)
	if err != nil {
		req.Close()
		return nil, nil, nil, fmt.Errorf("new REP: %w", err)
	}
	if err := rep.Bind(addr); err != nil {
		req.Close(); rep.Close()
		return nil, nil, nil, fmt.Errorf("rep bind: %w", err)
	}
	if err := req.Connect(addr); err != nil {
		req.Close(); rep.Close()
		return nil, nil, nil, fmt.Errorf("req connect: %w", err)
	}
	reqSock := &pebbeSocket{
		send:  func(b []byte) error { _, err := req.SendBytes(b, 0); return err },
		recv:  func() ([]byte, error) { return req.RecvBytes(0) },
		close: func() error { req.Close(); return nil },
	}
	repSock := &pebbeSocket{
		send:  func(b []byte) error { _, err := rep.SendBytes(b, 0); return err },
		recv:  func() ([]byte, error) { return rep.RecvBytes(0) },
		close: func() error { rep.Close(); return nil },
	}
	cleanup := func() { req.Close(); rep.Close() }
	return reqSock, repSock, cleanup, nil
}

func (pebbeAdapter) PubSub(addr string, topic []byte) (Socket, Socket, func(), error) {
	if isInprocAddr(addr) {
		return nil, nil, nil, ErrNotSupported
	}
	pub, err := pebbe.NewSocket(pebbe.PUB)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new PUB: %w", err)
	}
	sub, err := pebbe.NewSocket(pebbe.SUB)
	if err != nil {
		pub.Close()
		return nil, nil, nil, fmt.Errorf("new SUB: %w", err)
	}
	if err := pub.Bind(addr); err != nil {
		pub.Close(); sub.Close()
		return nil, nil, nil, fmt.Errorf("pub bind: %w", err)
	}
	if err := sub.Connect(addr); err != nil {
		pub.Close(); sub.Close()
		return nil, nil, nil, fmt.Errorf("sub connect: %w", err)
	}
	if err := sub.SetSubscribe(string(topic)); err != nil {
		pub.Close(); sub.Close()
		return nil, nil, nil, fmt.Errorf("subscribe: %w", err)
	}
	pubSock := &pebbeSocket{
		send: func(b []byte) error {
			frame := append(append([]byte(nil), topic...), b...)
			_, err := pub.SendBytes(frame, 0)
			return err
		},
		recv:  func() ([]byte, error) { panic("pub cannot recv") },
		close: func() error { pub.Close(); return nil },
	}
	subSock := &pebbeSocket{
		send:  func(b []byte) error { panic("sub cannot send") },
		recv:  func() ([]byte, error) { return sub.RecvBytes(0) },
		close: func() error { sub.Close(); return nil },
	}
	cleanup := func() { pub.Close(); sub.Close() }
	return pubSock, subSock, cleanup, nil
}

func (pebbeAdapter) Pair(addr string) (Socket, Socket, func(), error) {
	if isInprocAddr(addr) {
		return nil, nil, nil, ErrNotSupported
	}
	a, err := pebbe.NewSocket(pebbe.PAIR)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new PAIR a: %w", err)
	}
	c, err := pebbe.NewSocket(pebbe.PAIR)
	if err != nil {
		a.Close()
		return nil, nil, nil, fmt.Errorf("new PAIR c: %w", err)
	}
	if err := a.Bind(addr); err != nil {
		a.Close(); c.Close()
		return nil, nil, nil, fmt.Errorf("pair bind: %w", err)
	}
	if err := c.Connect(addr); err != nil {
		a.Close(); c.Close()
		return nil, nil, nil, fmt.Errorf("pair connect: %w", err)
	}
	wrap := func(s *pebbe.Socket) *pebbeSocket {
		return &pebbeSocket{
			send:  func(b []byte) error { _, err := s.SendBytes(b, 0); return err },
			recv:  func() ([]byte, error) { return s.RecvBytes(0) },
			close: func() error { s.Close(); return nil },
		}
	}
	cleanup := func() { a.Close(); c.Close() }
	return wrap(a), wrap(c), cleanup, nil
}
