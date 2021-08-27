package encrypted

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tg/e2e"
)

func (m *Manager) sendResult(id int, c tg.EncryptedChatClass) {
	m.requestsMux.Lock()
	req, ok := m.requests[id]
	delete(m.requests, id)
	m.requestsMux.Unlock()
	if !ok {
		return
	}

	select {
	case req.result <- c:
	default:
	}
}

func (m *Manager) Register(d tg.UpdateDispatcher) {
	d.OnEncryption(m.OnEncryption)
	d.OnNewEncryptedMessage(m.OnNewEncryptedMessage)
}

func (m *Manager) OnNewEncryptedMessage(ctx context.Context, e tg.Entities, u *tg.UpdateNewEncryptedMessage) error {
	chatID := u.Message.GetChatID()

	chat, err := m.storage.FindByID(ctx, ChatID(chatID))
	if err != nil {
		m.logger.Info("Received encrypted message from unknown chat", zap.Int("chat_id", chatID))
		return xerrors.Errorf("find chat %d: %w", chatID, err)
	}

	data, err := chat.Decrypt(u.Message.GetBytes())
	if err != nil {
		return xerrors.Errorf("encrypt: %w", err)
	}

	layer := e2e.DecryptedMessageLayer{}
	if err := layer.Decode(&bin.Buffer{Buf: data}); err != nil {
		return xerrors.Errorf("decode layer: %w", err)
	}

	return m.handleMessage(ctx, chat, layer)
}

func (m *Manager) handleMessage(ctx context.Context, chat Chat, layer e2e.DecryptedMessageLayer) error {
	chatID := int(chat.ID)
	logger := m.logger.With(zap.Int("chat_id", chatID))

	logger.Debug("Received encrypted message",
		zap.Int("in_seq", layer.InSeqNo),
		zap.Int("out_seq", layer.OutSeqNo),
		zap.String("type", fmt.Sprintf("%T", layer.Message)),
	)

	// See https://core.telegram.org/api/end-to-end/seq_no#checking-out-seq-no.
	//
	// If the received out_seq_no<=C, the local client must drop the message (repeated message).
	// The client should not check the contents of the message because the original message could have
	// been deleted (see Deleting unacknowledged messages).
	inSeq, _ := chat.seqNo()
	if out := layer.OutSeqNo; out > 0 && inSeq > 0 && out <= inSeq {
		return nil
	}

	chat.InSeq++
	inSeq, _ = chat.seqNo()
	// If the received out_seq_no>C+1, it most likely means that the server left out some messages due
	// to a technical failure or due to the messages becoming obsolete. A temporary solution to this is
	// to simply abort the secret chat. But since this may cause some existing older secret chats to be aborted,
	// it is strongly recommended for the client to properly handle such seq_no gaps. Note that in_seq_no is not
	// increased upon receipt of such a message; it is advanced only after all preceding gaps are filled.
	if layer.OutSeqNo > inSeq {
		// TODO(tdakkota): request resend.
		logger.Warn("E2E chat gap", zap.Int("local", inSeq))
	}

	if err := m.storage.Save(ctx, chat); err != nil {
		return xerrors.Errorf("save chat %d: %w", chatID, err)
	}

	return m.message(ctx, chat, layer.Message)
}

func (m *Manager) OnEncryption(ctx context.Context, e tg.Entities, update *tg.UpdateEncryption) error {
	switch c := update.Chat.(type) {
	case *tg.EncryptedChat:
		m.logger.Debug("Chat accepted", zap.Int("chat_id", c.ID))
		m.sendResult(c.ID, c)
		return nil
	case *tg.EncryptedChatDiscarded:
		m.logger.Debug("Chat discarded", zap.Int("chat_id", c.ID))
		m.sendResult(c.ID, c)
		return nil
	case *tg.EncryptedChatRequested:
		accepted, err := m.accept(ctx, e, c)
		if err != nil {
			return xerrors.Errorf("accept handler: %w", err)
		}

		if accepted {
			chat, err := m.acceptChat(ctx, c)
			if err != nil {
				return xerrors.Errorf("accept: %w", err)
			}

			if err := m.storage.Save(ctx, chat); err != nil {
				return xerrors.Errorf("save chat: %w", err)
			}

			if err := m.created(ctx, chat); err != nil {
				return xerrors.Errorf("created handler: %w", err)
			}

			return nil
		}

		return m.rejectChat(ctx, c)
	default:
		m.logger.Warn("Unexpected type", zap.String("type", fmt.Sprintf("%T", c)))
		return nil
	}
}
