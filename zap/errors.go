package zap

import "errors"

// ErrRouterClosed is returned by Client.Authenticate when the Router
// has been closed before or during the request.
var ErrRouterClosed = errors.New("zap: router closed")
