package encrypted

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gotd/td/internal/crypto"
)

func TestEncryptDecrypt(t *testing.T) {
	a := require.New(t)
	randSource := rand.Reader

	test := func(x, y Chat) {
		text := []byte("aboba")
		encrypted, err := x.Encrypt(randSource, text)
		a.NoError(err)

		decrypted, err := y.Decrypt(encrypted)
		a.NoError(err)
		a.Equal(text, decrypted[:len(text)])
	}

	k := crypto.Key{}
	if _, err := io.ReadFull(randSource, k[:]); err != nil {
		t.Fatal(err)
	}
	key := k.WithID()

	x, y := Chat{
		Originator: false,
		Key:        key,
	}, Chat{
		Originator: true,
		Key:        key,
	}
	test(x, y)
	test(y, x)
}
