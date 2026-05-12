package bench_test

import (
	"context"
	"fmt"
	"strings"

	gozmq "github.com/go-zeromq/zmq4"
)

func init() { registerAdapter(gozeromqAdapter{}) }

type gozeromqAdapter struct{}

func (gozeromqAdapter) Name() string { return "gozeromq" }

type gozeromqSocket struct {
	send  func([]byte) error
	recv  func() ([]byte, error)
	close func() error
}

func (s *gozeromqSocket) Send(msg []byte) error { return s.send(msg) }
func (s *gozeromqSocket) Recv() ([]byte, error) { return s.recv() }
func (s *gozeromqSocket) Close() error          { return s.close() }

// gozeromqSupportsAddr returns ErrNotSupported for inproc addresses.
// go-zeromq/zmq4 v0.17.0 has a race in its internal qreader goroutine:
// on inproc, the goroutine may outlive Close() and panic with
// "makeslice: len out of range" on the next benchmark iteration.
func gozeromqSupportsAddr(addr string) error {
	if strings.HasPrefix(addr, "inproc://") {
		return ErrNotSupported
	}
	return nil
}

func (gozeromqAdapter) PushPull(addr string) (Socket, Socket, func(), error) {
	if err := gozeromqSupportsAddr(addr); err != nil {
		return nil, nil, nil, err
	}
	ctx := context.Background()
	push := gozmq.NewPush(ctx)
	pull := gozmq.NewPull(ctx)
	if err := push.Listen(addr); err != nil {
		return nil, nil, nil, fmt.Errorf("push listen: %w", err)
	}
	if err := pull.Dial(addr); err != nil {
		push.Close()
		return nil, nil, nil, fmt.Errorf("pull dial: %w", err)
	}
	sender := &gozeromqSocket{
		send:  func(b []byte) error { return push.Send(gozmq.NewMsg(b)) },
		recv:  func() ([]byte, error) { panic("push cannot recv") },
		close: push.Close,
	}
	receiver := &gozeromqSocket{
		send: func(b []byte) error { panic("pull cannot send") },
		recv: func() ([]byte, error) {
			m, err := pull.Recv()
			if err != nil {
				return nil, err
			}
			return m.Frames[0], nil
		},
		close: pull.Close,
	}
	cleanup := func() { push.Close(); pull.Close() }
	return sender, receiver, cleanup, nil
}

func (gozeromqAdapter) ReqRep(addr string) (Socket, Socket, func(), error) {
	if err := gozeromqSupportsAddr(addr); err != nil {
		return nil, nil, nil, err
	}
	ctx := context.Background()
	rep := gozmq.NewRep(ctx)
	req := gozmq.NewReq(ctx)
	if err := rep.Listen(addr); err != nil {
		return nil, nil, nil, fmt.Errorf("rep listen: %w", err)
	}
	if err := req.Dial(addr); err != nil {
		rep.Close()
		return nil, nil, nil, fmt.Errorf("req dial: %w", err)
	}
	reqSock := &gozeromqSocket{
		send: func(b []byte) error { return req.Send(gozmq.NewMsg(b)) },
		recv: func() ([]byte, error) {
			m, err := req.Recv()
			if err != nil {
				return nil, err
			}
			return m.Frames[0], nil
		},
		close: req.Close,
	}
	repSock := &gozeromqSocket{
		send: func(b []byte) error { return rep.Send(gozmq.NewMsg(b)) },
		recv: func() ([]byte, error) {
			m, err := rep.Recv()
			if err != nil {
				return nil, err
			}
			return m.Frames[0], nil
		},
		close: rep.Close,
	}
	cleanup := func() { req.Close(); rep.Close() }
	return reqSock, repSock, cleanup, nil
}

func (gozeromqAdapter) PubSub(addr string, topic []byte) (Socket, Socket, func(), error) {
	if err := gozeromqSupportsAddr(addr); err != nil {
		return nil, nil, nil, err
	}
	ctx := context.Background()
	pub := gozmq.NewPub(ctx)
	sub := gozmq.NewSub(ctx)
	if err := pub.Listen(addr); err != nil {
		return nil, nil, nil, fmt.Errorf("pub listen: %w", err)
	}
	if err := sub.Dial(addr); err != nil {
		pub.Close()
		return nil, nil, nil, fmt.Errorf("sub dial: %w", err)
	}
	if err := sub.SetOption(gozmq.OptionSubscribe, string(topic)); err != nil {
		pub.Close()
		sub.Close()
		return nil, nil, nil, fmt.Errorf("subscribe: %w", err)
	}
	pubSock := &gozeromqSocket{
		send: func(b []byte) error {
			frame := append(append([]byte(nil), topic...), b...)
			return pub.Send(gozmq.NewMsg(frame))
		},
		recv:  func() ([]byte, error) { panic("pub cannot recv") },
		close: pub.Close,
	}
	subSock := &gozeromqSocket{
		send: func(b []byte) error { panic("sub cannot send") },
		recv: func() ([]byte, error) {
			m, err := sub.Recv()
			if err != nil {
				return nil, err
			}
			return m.Frames[0], nil
		},
		close: sub.Close,
	}
	cleanup := func() { pub.Close(); sub.Close() }
	return pubSock, subSock, cleanup, nil
}

func (gozeromqAdapter) Pair(addr string) (Socket, Socket, func(), error) {
	if err := gozeromqSupportsAddr(addr); err != nil {
		return nil, nil, nil, err
	}
	ctx := context.Background()
	a := gozmq.NewPair(ctx)
	c := gozmq.NewPair(ctx)
	if err := a.Listen(addr); err != nil {
		return nil, nil, nil, fmt.Errorf("pair listen: %w", err)
	}
	if err := c.Dial(addr); err != nil {
		a.Close()
		return nil, nil, nil, fmt.Errorf("pair dial: %w", err)
	}
	wrap := func(s gozmq.Socket) *gozeromqSocket {
		return &gozeromqSocket{
			send: func(b []byte) error { return s.Send(gozmq.NewMsg(b)) },
			recv: func() ([]byte, error) {
				m, err := s.Recv()
				if err != nil {
					return nil, err
				}
				return m.Frames[0], nil
			},
			close: s.Close,
		}
	}
	cleanup := func() { a.Close(); c.Close() }
	return wrap(a), wrap(c), cleanup, nil
}
