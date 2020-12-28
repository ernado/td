package exchange

import (
	"crypto/rsa"
	"io"

	"go.uber.org/zap"

	"github.com/gotd/td/internal/crypto"
)

// ClientExchange is a client-side key exchange flow.
type ClientExchange struct {
	unencryptedWriter
	rand io.Reader
	log  *zap.Logger

	keys []*rsa.PublicKey
}

// ClientExchangeResult contains client part of key exchange result.
type ClientExchangeResult struct {
	AuthKey    crypto.AuthKeyWithID
	SessionID  int64
	ServerSalt int64
}
