package zmq4

// Message is an ordered sequence of message parts.
// Each part is an owned byte slice; callers may retain and mutate freely.
type Message [][]byte

// NewMsg returns a Message composed of the given frames.
// Called with no arguments it returns an empty Message.
func NewMsg(frames ...[]byte) Message { return Message(frames) }

// NewStringMsg returns a Message whose frames are the UTF-8 encodings of
// the given strings.
func NewStringMsg(frames ...string) Message {
	msg := make(Message, len(frames))
	for i, s := range frames {
		msg[i] = []byte(s)
	}
	return msg
}
