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

func (m *Manager) notifyNewChat(id int, c tg.EncryptedChatClass) {
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

func (m *Manager) OnNewEncryptedMessage(ctx context.Context, _ tg.Entities, u *tg.UpdateNewEncryptedMessage) error {
	chatID := u.Message.GetChatID()

	chat, err := m.storage.FindByID(ctx, chatID)
	if err != nil {
		m.logger.Info("Received encrypted message from unknown chat", zap.Int("chat_id", chatID))
		return xerrors.Errorf("find chat %d: %w", chatID, err)
	}

	data, err := chat.decrypt(u.Message.GetBytes())
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
	myIn, myOut := chat.seqNo()
	logger := m.logger.With(
		zap.Int("chat_id", chat.ID),
		zap.Int("his_in_seq", layer.InSeqNo),
		zap.Int("his_out_seq", layer.OutSeqNo),
		zap.Int("my_in_seq", myIn),
		zap.Int("my_out_seq", myOut),
	)

	logger.Debug("Received encrypted message",
		zap.String("type", fmt.Sprintf("%T", layer.Message)),
	)

	switch chat.consumeMessage(layer.InSeqNo, layer.OutSeqNo) {
	case skipMessage:
		logger.Debug("Skip duplicate message")
		return nil
	case fillGap:
		logger.Debug("Fill gap")
	// TODO(tdakkota): request resend.
	case abortChat:
		logger.Debug("Abort chat due to invalid in_seq")
	default:
	}

	if err := m.storage.Save(ctx, chat); err != nil {
		return xerrors.Errorf("save chat %d: %w", chat.ID, err)
	}

	return m.message(ctx, chat, layer.Message)
}

func (m *Manager) OnEncryption(ctx context.Context, e tg.Entities, update *tg.UpdateEncryption) error {
	switch c := update.Chat.(type) {
	case *tg.EncryptedChat:
		m.logger.Debug("Chat accepted", zap.Int("chat_id", c.ID))
		m.notifyNewChat(c.ID, c)
		return nil
	case *tg.EncryptedChatDiscarded:
		m.logger.Debug("Chat discarded", zap.Int("chat_id", c.ID))
		m.notifyNewChat(c.ID, c)
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

		return m.discardChat(ctx, c.ID)
	default:
		m.logger.Warn("Unexpected type", zap.String("type", fmt.Sprintf("%T", c)))
		return nil
	}
}
