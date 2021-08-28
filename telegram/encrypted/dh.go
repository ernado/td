package encrypted

import (
	"context"
	"crypto/rand"
	"io"
	"math/big"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/gotd/td/internal/crypto"
	"github.com/gotd/td/tg"
)

var randMax = big.NewInt(0).SetBit(big.NewInt(0), crypto.RSAKeyBits, 1)

func generateBig(r io.Reader) (*big.Int, error) {
	a, err := rand.Int(r, randMax)
	if err != nil {
		return nil, err
	}
	return a, nil
}

type dhConfig struct {
	G       int
	GBig    *big.Int
	P       *big.Int
	Version int
	set     bool
}

func (m *Manager) getDHConfig(ctx context.Context) (dhConfig, error) {
	m.cfgMux.Lock()
	defer m.cfgMux.Unlock()

	version := 0
	if m.cfg.set {
		version = m.cfg.Version
	}

	d, err := m.raw.MessagesGetDhConfig(ctx, &tg.MessagesGetDhConfigRequest{
		RandomLength: crypto.RSAKeyBits,
		Version:      version,
	})
	if err != nil {
		return dhConfig{}, xerrors.Errorf("get DH config: %w", err)
	}

	switch cfg := d.(type) {
	case *tg.MessagesDhConfig:
		p := big.NewInt(0).SetBytes(cfg.P)

		if err := crypto.CheckDH(cfg.G, p); err != nil {
			return dhConfig{}, xerrors.Errorf("check DH: %w", err)
		}

		m.cfg = dhConfig{
			G:       cfg.G,
			GBig:    big.NewInt(int64(cfg.G)),
			P:       p,
			Version: cfg.Version,
		}
		m.logger.Debug("DH Config updated", zap.Int("version", cfg.Version))
	case *tg.MessagesDhConfigNotModified:
		if !m.cfg.set {
			return dhConfig{}, xerrors.Errorf("unexpected type %T", d)
		}
	default:
		return dhConfig{}, xerrors.Errorf("unexpected type %T", d)
	}

	return m.cfg, nil
}

func (m *Manager) initDH(ctx context.Context) (*big.Int, dhConfig, error) {
	dhCfg, err := m.getDHConfig(ctx)
	if err != nil {
		return nil, dhConfig{}, err
	}

	a, err := generateBig(m.rand)
	if err != nil {
		return nil, dhConfig{}, xerrors.Errorf("generate random: %w", err)
	}

	return a, dhCfg, nil
}
