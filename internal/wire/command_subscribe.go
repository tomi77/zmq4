package wire

import "fmt"

const (
	SubscribeCommandName = "SUBSCRIBE"
	CancelCommandName    = "CANCEL"
)

// SubscribeCommand asks the peer to deliver messages matching Topic.
type SubscribeCommand struct{ Topic []byte }

// CancelCommand undoes a prior SUBSCRIBE for Topic.
type CancelCommand struct{ Topic []byte }

func ParseSubscribe(cmd Command) (SubscribeCommand, error) {
	if cmd.Name != SubscribeCommandName {
		return SubscribeCommand{}, fmt.Errorf("%w: expected SUBSCRIBE, got %q", ErrInvalidCommand, cmd.Name)
	}
	return SubscribeCommand{Topic: cmd.Data}, nil
}

func (sc SubscribeCommand) Encode() Command {
	return Command{Name: SubscribeCommandName, Data: append([]byte(nil), sc.Topic...)}
}

func ParseCancel(cmd Command) (CancelCommand, error) {
	if cmd.Name != CancelCommandName {
		return CancelCommand{}, fmt.Errorf("%w: expected CANCEL, got %q", ErrInvalidCommand, cmd.Name)
	}
	return CancelCommand{Topic: cmd.Data}, nil
}

func (cc CancelCommand) Encode() Command {
	return Command{Name: CancelCommandName, Data: append([]byte(nil), cc.Topic...)}
}
