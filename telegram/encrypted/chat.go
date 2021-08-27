package encrypted

import (
	"crypto/aes"
	"encoding/binary"
	"io"

	"golang.org/x/xerrors"

	"github.com/gotd/ige"
	"github.com/gotd/td/bin"
	"github.com/gotd/td/internal/crypto"
)

// getKeyFingerprint computes key fingerprint.
func getKeyFingerprint(key crypto.AuthKey) int64 {
	return int64(binary.LittleEndian.Uint64(key.ID[:]))
}

// ChatID is a type which represents chat ID.
type ChatID int

// Chat is an encrypted chat metadata structure.
type Chat struct {
	// Chat ID.
	ID ChatID
	// AccessHash is a chat access hash.
	AccessHash int64
	// Layer is a TL encrypted schema layer version.
	Layer int
	// Date chat was created.
	Date int
	// AdminID is a chat creator ID.
	AdminID int
	// ParticipantID is an id of the second chat participant.
	ParticipantID int
	// Originator denotes current user is creator.
	Originator bool

	// InSeq is an incoming message sequence.
	InSeq int
	// OutSeq is a outgoing message sequence.
	OutSeq int

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

func (c Chat) seqNo() (seqIn, seqOut int) {
	if c.Originator {
		seqIn = 2 * c.InSeq
		seqOut = 2*c.OutSeq + 1
	} else {
		seqIn = 2*c.InSeq + 1
		seqOut = 2 * c.OutSeq
	}
	return seqIn, seqOut
}

func (c Chat) Decrypt(data []byte) ([]byte, error) {
	// TODO(tdakkota): optimize, maybe do better buffer API.
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

	buf := bin.Buffer{Buf: plaintext}
	messageDataLen, err := buf.Int()
	if err != nil {
		return nil, xerrors.Errorf("get messageDataLen: %w", err)
	}
	if l := buf.Len(); l < messageDataLen {
		return nil, xerrors.Errorf("buffer too small (%d < %d)", l, messageDataLen)
	}

	return buf.Buf[:messageDataLen], nil
}

func countPadding(l int) int { return 16 + (16 - (l % 16)) }

func (c Chat) padBuffer(rand io.Reader, data []byte) (*bin.Buffer, error) {
	length := len(data) + 4
	padding := countPadding(length)

	padded := &bin.Buffer{Buf: make([]byte, 0, length+padding)}
	padded.PutInt(length)
	padded.Put(data)

	if _, err := io.ReadFull(rand, padded.Buf[length:]); err != nil {
		return nil, err
	}
	padded.Buf = padded.Buf[:length+padding]

	return padded, nil
}

func (c Chat) Encrypt(rand io.Reader, data []byte) ([]byte, error) {
	// TODO(tdakkota): optimize, maybe do better buffer API.
	padded, err := c.padBuffer(rand, data)
	if err != nil {
		return nil, err
	}
	side := c.encryptSide()

	messageKey := crypto.MessageKey(c.Key.Value, padded.Buf, side)
	key, iv := crypto.Keys(c.Key.Value, messageKey, side)
	aesBlock, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	msg := crypto.EncryptedMessage{
		AuthKeyID:     c.Key.ID,
		MsgKey:        messageKey,
		EncryptedData: make([]byte, len(padded.Buf)),
	}
	ige.EncryptBlocks(aesBlock, iv[:], msg.EncryptedData, padded.Buf)

	buf := bin.Buffer{}
	if err := msg.Encode(&buf); err != nil {
		return nil, err
	}
	return buf.Buf, nil

}
