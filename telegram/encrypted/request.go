package encrypted

import (
	"context"
	"math/big"

	"go.uber.org/multierr"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/gotd/td/internal/crypto"
	"github.com/gotd/td/tg"
)

// requestChat requests new encrypted chat.
//
// See https://core.telegram.org/api/end-to-end#sending-a-request.
func (m *Manager) requestChat(ctx context.Context, user tg.InputUserClass) (Chat, error) {
	a, dhCfg, err := m.initDH(ctx)
	if err != nil {
		return Chat{}, xerrors.Errorf("init DH: %w", err)
	}

	g := dhCfg.GBig
	dhPrime := dhCfg.P
	gA := big.NewInt(0).Exp(g, a, dhPrime)

	randomID, err := crypto.RandInt64(m.rand)
	if err != nil {
		return Chat{}, xerrors.Errorf("generate random ID: %w", err)
	}

	m.requestsMux.Lock()
	requested, err := m.raw.MessagesRequestEncryption(ctx, &tg.MessagesRequestEncryptionRequest{
		UserID:   user,
		RandomID: int(randomID),
		GA:       gA.Bytes(),
	})
	if err != nil {
		m.requestsMux.Unlock()
		return Chat{}, xerrors.Errorf("request chat: %w", err)
	}

	result := make(chan tg.EncryptedChatClass, 1)
	m.requests[requested.GetID()] = request{
		result: result,
	}
	m.requestsMux.Unlock()

	select {
	case <-ctx.Done():
		return Chat{}, ctx.Err()
	case r := <-result:
		switch c := r.(type) {
		case *tg.EncryptedChat:
			gB := big.NewInt(0).SetBytes(c.GAOrB)

			// key := pow(g_b, a) mod dh_prime
			k := crypto.Key{}
			big.NewInt(0).Exp(gB, a, dhPrime).FillBytes(k[:])
			key := k.WithID()

			if getKeyFingerprint(key) != c.KeyFingerprint {
				err := xerrors.New("key fingerprint mismatch")
				return Chat{}, multierr.Append(err, m.discardChat(ctx, c.ID))
			}

			chat := Chat{
				ID:            c.ID,
				AccessHash:    c.AccessHash,
				Date:          c.Date,
				AdminID:       c.AdminID,
				ParticipantID: c.ParticipantID,
				Originator:    true,
				Key:           key,
			}
			return chat, m.storage.Save(ctx, chat)
		case *tg.EncryptedChatDiscarded:
			return Chat{}, &ChatDiscardedError{Chat: c}
		default:
			return Chat{}, xerrors.Errorf("unexpected type %T", c)
		}
	}
}

func (m *Manager) discardChat(ctx context.Context, id int) error {
	m.logger.Debug("Discard chat", zap.Int("id", id))
	_, err := m.raw.MessagesDiscardEncryption(ctx, &tg.MessagesDiscardEncryptionRequest{
		ChatID: id,
	})
	return err
}
