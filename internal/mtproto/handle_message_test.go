package mtproto

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/internal/mt"
	"github.com/gotd/td/internal/rpc"
	"github.com/gotd/td/internal/testutil"
	"github.com/gotd/td/internal/tmap"
	"github.com/gotd/td/tg"
)

func newTestMessageHandler() func(b *bin.Buffer) error {
	types := tmap.NewConstructor(
		tg.TypesConstructorMap(),
		mt.TypesConstructorMap(),
	)

	return func(b *bin.Buffer) error {
		id, err := b.PeekID()
		if err != nil {
			return err
		}
		v := types.New(id)
		if v == nil {
			return xerrors.New("not found")
		}
		if err := v.Decode(b); err != nil {
			return xerrors.Errorf("decode: %w", err)
		}
		return nil
	}
}

func TestConnHandleMessage(t *testing.T) {
	c := &Conn{
		rand:      Zero{},
		log:       zap.NewNop(),
		onMessage: newTestMessageHandler(),
		onSession: func(Session) error { return nil },
	}

	for i, input := range []string{
		"\xdc\xf8\xf1stewa\x00O\x03expired c" +
			"ertificate\x02\x00\x00\x00\xef",

		"\x01m\\\xf300000000\x19\xcaD!0000" +
			"\x1100000000000000000",

		"\x01m\\\xf300000000\x19\xcaD!0000" +
			"\xfe0",

		"@B\xaet\x15ĵ\x1c0000,\x8f\xf8B0000" +
			"00000000\x15ĵ\x1c0000\xff000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"000000000000",
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			if err := c.handleMessage(&bin.Buffer{Buf: []byte(input)}); err == nil {
				t.Fatal("error expected")
			}
		})
	}
}

func TestConnHandleMessageCorpus(t *testing.T) {
	c := &Conn{
		rand:      Zero{},
		log:       zap.NewNop(),
		rpc:       rpc.New(rpc.NopSend, rpc.Options{}),
		onMessage: newTestMessageHandler(),
		onSession: func(Session) error { return nil },
	}

	corpusDir := filepath.Join("..", "_fuzz", "handle_message", "corpus")
	corpus, err := os.ReadDir(corpusDir)
	if os.IsNotExist(err) || testutil.Race {
		t.Skip("Skipped")
	}
	b := &bin.Buffer{}
	types := tmap.New(
		tg.TypesMap(),
		mt.TypesMap(),
	)

	for _, f := range corpus {
		t.Run(f.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(corpusDir, f.Name()))
			require.NoError(t, err)

			// Default to 128 bytes per invocation.
			allocThreshold := 128

			// Adjusting threshold for specific types.
			//
			// Probably there should be better way to do this, but
			// manually ensuring allocation distribution by type is
			// pretty ok.
			b.ResetTo(data)
			if id, err := b.PeekID(); err == nil {
				t.Logf("Type: 0x%x %s", id, types.Get(id))
				switch id {
				case tg.UpdatesTypeID,
					tg.TextFixedTypeID,
					tg.InputPeerChannelFromMessageTypeID,
					tg.PageBlockRelatedArticlesTypeID:
					allocThreshold = 512
				case tg.TextBoldTypeID,
					tg.TextItalicTypeID,
					tg.TextMarkedTypeID,
					tg.MessageTypeID,
					tg.PageBlockCoverTypeID,
					tg.InputMediaUploadedDocumentTypeID:
					allocThreshold = 256
				}
			}

			testutil.MaxAlloc(t, allocThreshold, func() {
				b.ResetTo(data)
				_ = c.handleMessage(b)
			})
		})
	}
}
