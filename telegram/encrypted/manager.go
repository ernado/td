package encrypted

import (
	"context"
	"io"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

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

func (m *Manager) discardChat(ctx context.Context, id int) error {
	m.logger.Debug("Discard chat", zap.Int("id", id))

	if err := m.storage.Discard(ctx, id); err != nil {
		return xerrors.Errorf("discard chat in storage: %w", err)
	}

	if _, err := m.raw.MessagesDiscardEncryption(ctx, &tg.MessagesDiscardEncryptionRequest{
		ChatID: id,
	}); err != nil {
		return xerrors.Errorf("send discard request: %w", err)
	}

	return nil
}
