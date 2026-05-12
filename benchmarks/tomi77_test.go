package bench_test

import (
	"context"
	"fmt"

	zmq4 "github.com/tomi77/zmq4"
)

func init() { registerAdapter(tomi77Adapter{}) }

type tomi77Adapter struct{}

func (tomi77Adapter) Name() string { return "tomi77" }

// tomi77Socket opakowuje dowolny socket tomi77 w interfejs Socket.
type tomi77Socket struct {
	send  func([]byte) error
	recv  func() ([]byte, error)
	close func() error
}

func (s *tomi77Socket) Send(msg []byte) error { return s.send(msg) }
func (s *tomi77Socket) Recv() ([]byte, error) { return s.recv() }
func (s *tomi77Socket) Close() error          { return s.close() }

func (tomi77Adapter) PushPull(addr string) (Socket, Socket, func(), error) {
	ctx := context.Background()
	push := zmq4.NewPUSH()
	pull := zmq4.NewPULL()
	if err := push.Bind(ctx, addr); err != nil {
		return nil, nil, nil, fmt.Errorf("push bind: %w", err)
	}
	if err := pull.Connect(ctx, addr); err != nil {
		push.Close()
		return nil, nil, nil, fmt.Errorf("pull connect: %w", err)
	}
	sender := &tomi77Socket{
		send:  func(b []byte) error { return push.Send(ctx, zmq4.NewMsg(b)) },
		recv:  func() ([]byte, error) { panic("push cannot recv") },
		close: push.Close,
	}
	receiver := &tomi77Socket{
		send: func(b []byte) error { panic("pull cannot send") },
		recv: func() ([]byte, error) {
			m, err := pull.Recv(ctx)
			if err != nil {
				return nil, err
			}
			return m.Frame(0), nil
		},
		close: pull.Close,
	}
	cleanup := func() { push.Close(); pull.Close() }
	return sender, receiver, cleanup, nil
}

func (tomi77Adapter) ReqRep(addr string) (Socket, Socket, func(), error) {
	ctx := context.Background()
	req := zmq4.NewREQ()
	rep := zmq4.NewREP()
	if err := rep.Bind(ctx, addr); err != nil {
		return nil, nil, nil, fmt.Errorf("rep bind: %w", err)
	}
	if err := req.Connect(ctx, addr); err != nil {
		rep.Close()
		return nil, nil, nil, fmt.Errorf("req connect: %w", err)
	}
	reqSock := &tomi77Socket{
		send: func(b []byte) error { return req.Send(ctx, zmq4.NewMsg(b)) },
		recv: func() ([]byte, error) {
			m, err := req.Recv(ctx)
			if err != nil {
				return nil, err
			}
			return m.Frame(0), nil
		},
		close: req.Close,
	}
	repSock := &tomi77Socket{
		send: func(b []byte) error { return rep.Send(ctx, zmq4.NewMsg(b)) },
		recv: func() ([]byte, error) {
			m, err := rep.Recv(ctx)
			if err != nil {
				return nil, err
			}
			return m.Frame(0), nil
		},
		close: rep.Close,
	}
	cleanup := func() { req.Close(); rep.Close() }
	return reqSock, repSock, cleanup, nil
}

func (tomi77Adapter) PubSub(addr string, topic []byte) (Socket, Socket, func(), error) {
	ctx := context.Background()
	pub := zmq4.NewPUB()
	sub := zmq4.NewSUB()
	if err := pub.Bind(ctx, addr); err != nil {
		return nil, nil, nil, fmt.Errorf("pub bind: %w", err)
	}
	if err := sub.Connect(ctx, addr); err != nil {
		pub.Close()
		return nil, nil, nil, fmt.Errorf("sub connect: %w", err)
	}
	if err := sub.Subscribe(string(topic)); err != nil {
		pub.Close()
		sub.Close()
		return nil, nil, nil, fmt.Errorf("subscribe: %w", err)
	}
	// PubSub: wiadomość zawiera prefix tematu + payload
	pubSock := &tomi77Socket{
		send: func(b []byte) error {
			frame := append(append([]byte(nil), topic...), b...)
			return pub.Send(ctx, zmq4.NewMsg(frame))
		},
		recv:  func() ([]byte, error) { panic("pub cannot recv") },
		close: pub.Close,
	}
	subSock := &tomi77Socket{
		send: func(b []byte) error { panic("sub cannot send") },
		recv: func() ([]byte, error) {
			m, err := sub.Recv(ctx)
			if err != nil {
				return nil, err
			}
			return m.Frame(0), nil
		},
		close: sub.Close,
	}
	cleanup := func() { pub.Close(); sub.Close() }
	return pubSock, subSock, cleanup, nil
}

func (tomi77Adapter) Pair(addr string) (Socket, Socket, func(), error) {
	ctx := context.Background()
	a := zmq4.NewPAIR()
	c := zmq4.NewPAIR()
	if err := a.Bind(ctx, addr); err != nil {
		return nil, nil, nil, fmt.Errorf("pair bind: %w", err)
	}
	if err := c.Connect(ctx, addr); err != nil {
		a.Close()
		return nil, nil, nil, fmt.Errorf("pair connect: %w", err)
	}
	wrap := func(s interface {
		Send(context.Context, zmq4.Message) error
		Recv(context.Context) (zmq4.Message, error)
		Close() error
	}) *tomi77Socket {
		return &tomi77Socket{
			send: func(b []byte) error { return s.Send(ctx, zmq4.NewMsg(b)) },
			recv: func() ([]byte, error) {
				m, err := s.Recv(ctx)
				if err != nil {
					return nil, err
				}
				return m.Frame(0), nil
			},
			close: s.Close,
		}
	}
	cleanup := func() { a.Close(); c.Close() }
	return wrap(a), wrap(c), cleanup, nil
}
