package encrypted

import (
	"context"
	"io"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/internal/crypto"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tg/e2e"
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

func (m *Manager) Send(ctx context.Context, e Chat, data *e2e.DecryptedMessageLayer) error {
	b := bin.Buffer{}
	if err := data.Encode(&b); err != nil {
		return xerrors.Errorf("encode layer: %w", err)
	}

	encrypted, err := e.Encrypt(m.rand, b.Buf)
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
		Data:     encrypted,
	})
	return err
}
