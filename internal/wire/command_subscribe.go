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

// Encode produces the Command form. The error return is reserved for
// future validation and is currently always nil; the signature matches
// the other Encode methods for API symmetry.
func (sc SubscribeCommand) Encode() (Command, error) {
	return Command{Name: SubscribeCommandName, Data: append([]byte(nil), sc.Topic...)}, nil
}

func ParseCancel(cmd Command) (CancelCommand, error) {
	if cmd.Name != CancelCommandName {
		return CancelCommand{}, fmt.Errorf("%w: expected CANCEL, got %q", ErrInvalidCommand, cmd.Name)
	}
	return CancelCommand{Topic: cmd.Data}, nil
}

// Encode produces the Command form. The error return is reserved for
// future validation and is currently always nil.
func (cc CancelCommand) Encode() (Command, error) {
	return Command{Name: CancelCommandName, Data: append([]byte(nil), cc.Topic...)}, nil
}
