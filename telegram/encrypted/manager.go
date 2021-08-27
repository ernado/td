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

const latestLayer = 101

func (m *Manager) Send(ctx context.Context, chatID ChatID, msg e2e.DecryptedMessageClass) error {
	logger := m.logger.With(zap.Int("chat_id", int(chatID)))

	chat, err := m.storage.FindByID(ctx, chatID)
	if err != nil {
		return xerrors.Errorf("find chat %d: %w", chatID, err)
	}

	randomBytes := make([]byte, 32)
	if _, err := io.ReadFull(m.rand, randomBytes); err != nil {
		return xerrors.Errorf("read random bytes: %w", err)
	}

	layer := chat.Layer
	if layer == 0 {
		layer = latestLayer
	}

	inSeq, outSeq := chat.seqNo()
	data := e2e.DecryptedMessageLayer{
		RandomBytes: randomBytes,
		Layer:       layer,
		InSeqNo:     inSeq,
		OutSeqNo:    outSeq,
		Message:     msg,
	}
	chat.OutSeq++

	b := bin.Buffer{}
	if err := data.Encode(&b); err != nil {
		return xerrors.Errorf("encode layer: %w", err)
	}

	logger.Debug("Send encrypted message",
		zap.Int("in_seq", data.InSeqNo),
		zap.Int("out_seq", data.OutSeqNo),
	)
	if _, err := m.sendEncrypted(ctx, chat, false, &b); err != nil {
		return err
	}

	if err := m.storage.Save(ctx, chat); err != nil {
		return xerrors.Errorf("save chat: %w", err)
	}

	return nil
}

func (m *Manager) sendEncrypted(
	ctx context.Context,
	e Chat,
	silent bool,
	b *bin.Buffer,
) (tg.MessagesSentEncryptedMessageClass, error) {
	encrypted, err := e.Encrypt(m.rand, b.Buf)
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
			ChatID:     int(e.ID),
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
