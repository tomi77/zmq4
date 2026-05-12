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

// Frames returns the number of frames in the message.
func (m Message) Frames() int { return len(m) }

// Frame returns the i-th frame. Panics if i is out of range, matching the
// behaviour of a plain slice index expression.
func (m Message) Frame(i int) []byte { return m[i] }

// String returns the first frame decoded as a UTF-8 string.
// Returns "" for an empty message. For multi-frame messages only frame 0
// is returned.
func (m Message) String() string {
	if len(m) == 0 {
		return ""
	}
	return string(m[0])
}

// Clone returns a deep copy of m. Each frame body is a new allocation
// independent of the original, so caller and clone may be used concurrently
// without data races.
func (m Message) Clone() Message {
	c := make(Message, len(m))
	for i, part := range m {
		c[i] = append([]byte(nil), part...)
	}
	return c
}
