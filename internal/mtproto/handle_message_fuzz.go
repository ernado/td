// +build fuzz

package mtproto

import (
	"time"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/internal/mt"
	"github.com/gotd/td/internal/proto"
	"github.com/gotd/td/internal/rpc"
	"github.com/gotd/td/internal/tmap"
	"github.com/gotd/td/tg"
)

type Zero struct{}

func (Zero) Read(p []byte) (n int, err error) { return len(p), nil }

func newFuzzMessageHandler() func(b *bin.Buffer) error {
	types := tmap.NewConstructor(
		tg.TypesConstructorMap(),
		mt.TypesConstructorMap(),
	)

	return func(b *bin.Buffer) error {
		id, err := b.PeekID()
		if err != nil {
			return err
		}
		v := h.types.New(id)
		if v == nil {
			return xerrors.New("not found")
		}
		if err := v.Decode(b); err != nil {
			return xerrors.Errorf("decode: %w", err)
		}

		// Performing decode cycle.
		var newBuff bin.Buffer
		newV := h.types.New(id)
		if err := v.Encode(&newBuff); err != nil {
			panic(err)
		}
		if err := newV.Decode(&newBuff); err != nil {
			panic(err)
		}

		return nil
	}
}

var (
	conn *Conn
	buf  *bin.Buffer
)

func init() {
	c := &Conn{
		rand:      Zero{},
		rpc:       rpc.New(rpc.NopSend, rpc.Options{}),
		log:       zap.NewNop(),
		messageID: proto.NewMessageIDGen(time.Now, 1),

		// Handler will try to dynamically decode any incoming message.
		msgHandler:  newFuzzMessageHandler(),
		sessHandler: func(Session) error { return nil },
	}

	conn = c
	buf = &bin.Buffer{}
}

func FuzzHandleMessage(data []byte) int {
	buf.ResetTo(data)
	if err := conn.handleMessage(buf); err != nil {
		return 0
	}
	return 1
}
