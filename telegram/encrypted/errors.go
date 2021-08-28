package encrypted

import (
	"fmt"

	"github.com/gotd/td/tg"
)

type ChatDiscardedError struct {
	Chat *tg.EncryptedChatDiscarded
}

func (c *ChatDiscardedError) Error() string {
	return fmt.Sprintf("chat %d discarded", c.Chat.ID)
}
