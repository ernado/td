package encrypted

import (
	"context"
	"math/big"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/gotd/td/internal/crypto"
	"github.com/gotd/td/tg"
)

// acceptChat generates key and accepts chat request.
//
// See https://core.telegram.org/api/end-to-end#accepting-a-request.
func (m *Manager) acceptChat(ctx context.Context, req *tg.EncryptedChatRequested) (Chat, error) {
	m.logger.Debug("Accept chat", zap.Int("id", req.ID))

	b, dhCfg, err := m.initDH(ctx)
	if err != nil {
		return Chat{}, xerrors.Errorf("init DH: %w", err)
	}

	g := dhCfg.GBig
	dhPrime := dhCfg.P
	// g_b := pow(g, b) mod dh_prime
	gB := big.NewInt(0).Exp(g, b, dhPrime)

	gA := big.NewInt(0).SetBytes(req.GA)
	// key := pow(g_a, b) mod dh_prime
	k := crypto.Key{}
	big.NewInt(0).Exp(gA, b, dhPrime).FillBytes(k[:])
	key := k.WithID()

	c, err := m.raw.MessagesAcceptEncryption(ctx, &tg.MessagesAcceptEncryptionRequest{
		Peer: tg.InputEncryptedChat{
			ChatID:     req.ID,
			AccessHash: req.AccessHash,
		},
		GB:             gB.Bytes(),
		KeyFingerprint: getKeyFingerprint(key),
	})
	if err != nil {
		return Chat{}, err
	}

	switch chat := c.(type) {
	case *tg.EncryptedChat:
		accepted := Chat{
			ID:            chat.ID,
			AccessHash:    chat.AccessHash,
			Layer:         0,
			Date:          chat.Date,
			AdminID:       chat.AdminID,
			ParticipantID: chat.ParticipantID,
			Originator:    false,
			OutSeq:        0,
			Key:           key,
		}
		return accepted, nil
	case *tg.EncryptedChatDiscarded:
		return Chat{}, &ChatDiscardedError{Chat: chat}
	default:
		return Chat{}, xerrors.Errorf("unexpected type %T", chat)
	}
}
