package zmq4

// Message is an ordered sequence of message parts.
// Each part is an owned byte slice; callers may retain and mutate freely.
type Message [][]byte
