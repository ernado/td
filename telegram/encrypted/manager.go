package encrypted

import (
	"context"
	"fmt"
	"io"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/gotd/td/internal/crypto"
	"github.com/gotd/td/tg"
)

type Manager struct {
	raw     *tg.Client
	storage ChatStorage

	accept  AcceptHandler
	created CreatedHandler
	message MessageHandler

	requests    map[int]request
	requestsMux sync.Mutex

	cfg    dhConfig
	cfgMux sync.Mutex

	rand   io.Reader
	logger *zap.Logger
}

func NewManager(raw *tg.Client, d tg.UpdateDispatcher, opts Options) *Manager {
	opts.setDefaults()

	m := &Manager{
		raw:      raw,
		storage:  opts.Storage,
		accept:   opts.Accept,
		created:  opts.Created,
		message:  opts.Message,
		requests: map[int]request{},
		cfg:      dhConfig{},
		rand:     opts.Random,
		logger:   opts.Logger,
	}
	m.Register(d)
	return m
}

type request struct {
	result chan tg.EncryptedChatClass
}

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
	m.logger.Debug("Received encrypted message", zap.Int("chat_id", chatID))

	chat, err := m.storage.FindByID(ctx, chatID)
	if err != nil {
		return xerrors.Errorf("find chat %d: %w", chatID, err)
	}

	data, err := chat.Decrypt(u.Message.GetBytes())
	if err != nil {
		return xerrors.Errorf("encrypt: %w", err)
	}

	return m.message(ctx, chat, data)
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
				return xerrors.Errorf("save chat: %w")
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

func (m *Manager) Send(ctx context.Context, e Chat, plaintext []byte) error {
	data, err := e.Encrypt(m.rand, plaintext)
	if err != nil {
		return xerrors.Errorf("encrypt: %w", err)
	}

	randomID, err := crypto.RandInt64(m.rand)
	if err != nil {
		return xerrors.Errorf("generate random_id: %w", err)
	}

	_, err = m.raw.MessagesSendEncrypted(ctx, &tg.MessagesSendEncryptedRequest{
		Silent: false,
		Peer: tg.InputEncryptedChat{
			ChatID:     e.ID,
			AccessHash: e.AccessHash,
		},
		RandomID: randomID,
		Data:     data,
	})
	return err
}
