package zmq4

// EventType identifies the kind of lifecycle event a socket emitted.
type EventType int

const (
	// EventListening is emitted when Bind() establishes a listener.
	EventListening EventType = iota + 1
	// EventBindFailed is emitted when Bind() fails.
	EventBindFailed
	// EventAccepted is emitted when a raw incoming connection is accepted,
	// before the ZMTP handshake starts.
	EventAccepted
	// EventAcceptFailed is emitted when the accept loop encounters an error.
	EventAcceptFailed
	// EventConnected is emitted after transport.Dial succeeds, before the
	// ZMTP handshake starts.
	EventConnected
	// EventConnectFailed is emitted when transport.Dial fails.
	EventConnectFailed
	// EventHandshakeSucceeded is emitted when a ZMTP handshake completes
	// successfully, on both client and server sides.
	EventHandshakeSucceeded
	// EventHandshakeFailed is emitted when a ZMTP handshake fails.
	EventHandshakeFailed
	// EventDisconnected is emitted when a pipe is removed due to an unexpected
	// peer-initiated connection drop while the socket is still open.
	EventDisconnected
	// EventClosed is emitted once per pipe during socket.Close().
	EventClosed
	// EventMonitorStopped is the final event. The socket closes the monitor
	// channel immediately after emitting it.
	EventMonitorStopped
)

// SocketEvent is a lifecycle event emitted by a socket to its monitor channel.
type SocketEvent struct {
	Type     EventType
	Endpoint string // transport address; format varies by context (see WithMonitor)
	Err      error  // non-nil for *Failed and EventHandshakeFailed events
}
