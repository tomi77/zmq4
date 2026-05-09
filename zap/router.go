package zap

import "sync"

// zapEnvelope carries a request and its reply channel through the Router loop.
type zapEnvelope struct {
	req     Request
	replyCh chan zapResult
}

type zapResult struct {
	reply Reply
	err   error
}

// Router serialises authentication requests to a Handler in a dedicated
// goroutine. Create with NewRouter; close with Close.
type Router struct {
	handler   Handler
	reqCh     chan zapEnvelope
	closeCh   chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewRouter starts a Router goroutine backed by h. h must not be nil.
func NewRouter(h Handler) *Router {
	r := &Router{
		handler: h,
		reqCh:   make(chan zapEnvelope, 16),
		closeCh: make(chan struct{}),
	}
	r.wg.Add(1)
	go r.loop()
	return r
}

// Close stops the Router goroutine and waits for it to exit.
// Idempotent — safe to call multiple times.
// Subsequent Client.Authenticate calls return ErrRouterClosed.
func (r *Router) Close() error {
	r.closeOnce.Do(func() { close(r.closeCh) })
	r.wg.Wait()
	return nil
}

func (r *Router) loop() {
	defer r.wg.Done()
	for {
		select {
		case env := <-r.reqCh:
			reply, err := r.handler.Authenticate(env.req)
			env.replyCh <- zapResult{reply: reply, err: err}
		case <-r.closeCh:
			return
		}
	}
}

// dispatch enqueues env for the handler goroutine.
func (r *Router) dispatch(env zapEnvelope) error {
	select {
	case r.reqCh <- env:
		return nil
	case <-r.closeCh:
		return ErrRouterClosed
	}
}
