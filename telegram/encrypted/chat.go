package encrypted

import (
	"crypto/aes"
	"encoding/binary"
	"io"

	"github.com/gotd/ige"
	"github.com/gotd/td/bin"
	"github.com/gotd/td/internal/crypto"
)

// getKeyFingerprint computes key fingerprint.
func getKeyFingerprint(key crypto.AuthKey) int64 {
	return int64(binary.LittleEndian.Uint64(key.ID[:]))
}

// Chat is an encrypted chat metadata structure.
type Chat struct {
	// Chat ID.
	ID int
	// AccessHash is a chat access hash.
	AccessHash int64
	// Date chat was created.
	Date int
	// AdminID is a chat creator ID.
	AdminID int
	// ParticipantID is an id of the second chat participant.
	ParticipantID int
	// Originator denotes current user is creator.
	Originator bool
	// Key is message encryption key.
	Key crypto.AuthKey
}

func (c Chat) encryptSide() crypto.Side {
	s := crypto.Server
	if c.Originator {
		s = crypto.Client
	}
	return s
}

func (c Chat) decryptSide() crypto.Side {
	s := crypto.Client
	if c.Originator {
		s = crypto.Server
	}
	return s
}

func (c Chat) Decrypt(data []byte) ([]byte, error) {
	var (
		msg  crypto.EncryptedMessage
		side = c.decryptSide()
	)

	if err := msg.DecodeWithoutCopy(&bin.Buffer{Buf: data}); err != nil {
		return nil, err
	}

	key, iv := crypto.Keys(c.Key.Value, msg.MsgKey, side)
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(msg.EncryptedData))
	ige.DecryptBlocks(cipher, iv[:], plaintext, msg.EncryptedData)

	return plaintext, nil
}

func countPadding(l int) int { return 16 + (16 - (l % 16)) }

func (c Chat) padBuffer(rand io.Reader, data []byte) ([]byte, error) {
	length := len(data)
	padding := countPadding(length)

	padded := make([]byte, length+padding)
	copy(padded, data)
	if _, err := io.ReadFull(rand, padded[length:]); err != nil {
		return nil, err
	}

	return padded, nil
}

func (c Chat) Encrypt(rand io.Reader, data []byte) ([]byte, error) {
	padded, err := c.padBuffer(rand, data)
	if err != nil {
		return nil, err
	}
	side := c.encryptSide()

	messageKey := crypto.MessageKey(c.Key.Value, padded, side)
	key, iv := crypto.Keys(c.Key.Value, messageKey, side)
	aesBlock, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	msg := crypto.EncryptedMessage{
		AuthKeyID:     c.Key.ID,
		MsgKey:        messageKey,
		EncryptedData: make([]byte, len(padded)),
	}
	ige.EncryptBlocks(aesBlock, iv[:], msg.EncryptedData, padded)

	buf := bin.Buffer{}
	if err := msg.Encode(&buf); err != nil {
		return nil, err
	}
	return buf.Buf, nil

}
