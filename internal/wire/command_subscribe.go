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

// Encode produces the Command form. Data aliases sc.Topic; mutating
// Topic after Encode also mutates the returned Command.
func (sc SubscribeCommand) Encode() (Command, error) {
	return Command{Name: SubscribeCommandName, Data: sc.Topic}, nil
}

func ParseCancel(cmd Command) (CancelCommand, error) {
	if cmd.Name != CancelCommandName {
		return CancelCommand{}, fmt.Errorf("%w: expected CANCEL, got %q", ErrInvalidCommand, cmd.Name)
	}
	return CancelCommand{Topic: cmd.Data}, nil
}

// Encode produces the Command form. Data aliases cc.Topic; mutating
// Topic after Encode also mutates the returned Command.
func (cc CancelCommand) Encode() (Command, error) {
	return Command{Name: CancelCommandName, Data: cc.Topic}, nil
}
