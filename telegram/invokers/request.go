package invokers

import (
	"context"

	"github.com/gotd/td/bin"
)

// Object is a abstraction for Telegram API object with TypeID.
type Object interface {
	TypeID() uint32
}

type key uint64

func (k *key) fromEncoder(encoder bin.Encoder) {
	obj, ok := encoder.(Object)
	if !ok {
		return
	}
	*k = key(obj.TypeID())
}

type request struct {
	ctx    context.Context
	input  bin.Encoder
	output bin.Decoder
	key    key

	retry  int
	result chan error
}
