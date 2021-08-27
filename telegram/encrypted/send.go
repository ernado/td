package encrypted

import (
	"context"
	"io"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/internal/crypto"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tg/e2e"
)

const latestLayer = 101

func (m *Manager) Send(ctx context.Context, chatID int, msg e2e.DecryptedMessageClass) error {
	chat, err := m.storage.FindByID(ctx, chatID)
	if err != nil {
		return xerrors.Errorf("find chat %d: %w", chatID, err)
	}

	return m.send(ctx, chat, msg)
}

func (m *Manager) sendLayer(ctx context.Context, e Chat) error {
	randomID, err := crypto.RandInt64(m.rand)
	if err != nil {
		return xerrors.Errorf("generate random_id: %w", err)
	}

	return m.send(ctx, e, &e2e.DecryptedMessageService{
		RandomID: randomID,
		Action: &e2e.DecryptedMessageActionNotifyLayer{
			Layer: latestLayer,
		},
	})
}

func (m *Manager) send(ctx context.Context, chat Chat, msg e2e.DecryptedMessageClass) error {
	logger := m.logger.With(zap.Int("chat_id", chat.ID))

	randomBytes := make([]byte, 32)
	if _, err := io.ReadFull(m.rand, randomBytes); err != nil {
		return xerrors.Errorf("read random bytes: %w", err)
	}

	layer := chat.Layer
	if layer == 0 {
		layer = latestLayer
	}

	inSeq, outSeq := chat.nextMessage()
	data := e2e.DecryptedMessageLayer{
		RandomBytes: randomBytes,
		Layer:       layer,
		InSeqNo:     inSeq,
		OutSeqNo:    outSeq,
		Message:     msg,
	}

	logger.Debug("Send encrypted message",
		zap.Int("in_seq", data.InSeqNo),
		zap.Int("out_seq", data.OutSeqNo),
	)
	if _, err := m.sendRaw(ctx, chat, false, &data); err != nil {
		return err
	}

	if err := m.storage.Save(ctx, chat); err != nil {
		return xerrors.Errorf("save chat: %w", err)
	}

	return nil
}

func (m *Manager) sendRaw(
	ctx context.Context,
	e Chat,
	silent bool,
	msg bin.Encoder,
) (tg.MessagesSentEncryptedMessageClass, error) {
	b := bin.Buffer{}

	if err := msg.Encode(&b); err != nil {
		return nil, xerrors.Errorf("encode: %w", err)
	}

	encrypted, err := e.encrypt(m.rand, b.Buf)
	if err != nil {
		return nil, xerrors.Errorf("encrypt: %w", err)
	}

	randomID, err := crypto.RandInt64(m.rand)
	if err != nil {
		return nil, xerrors.Errorf("generate random_id: %w", err)
	}

	r, err := m.raw.MessagesSendEncrypted(ctx, &tg.MessagesSendEncryptedRequest{
		Silent: silent,
		Peer: tg.InputEncryptedChat{
			ChatID:     e.ID,
			AccessHash: e.AccessHash,
		},
		RandomID: randomID,
		Data:     encrypted,
	})
	if err != nil {
		return nil, xerrors.Errorf("send encrypted: %w", err)
	}

	return r, nil
}
