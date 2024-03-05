// Code generated by gotdgen, DO NOT EDIT.

package td

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"go.uber.org/multierr"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/tdjson"
	"github.com/gotd/td/tdp"
	"github.com/gotd/td/tgerr"
)

// No-op definition for keeping imports.
var (
	_ = bin.Buffer{}
	_ = context.Background()
	_ = fmt.Stringer(nil)
	_ = strings.Builder{}
	_ = errors.Is
	_ = multierr.AppendInto
	_ = sort.Ints
	_ = tdp.Format
	_ = tgerr.Error{}
	_ = tdjson.Encoder{}
)

// GetUpdatesResp represents TL type `getUpdatesResp#300bb5e1`.
//
// See https://localhost:80/doc/constructor/getUpdatesResp for reference.
type GetUpdatesResp struct {
	// Updates field of GetUpdatesResp.
	Updates []AbstractMessageClass
}

// GetUpdatesRespTypeID is TL type id of GetUpdatesResp.
const GetUpdatesRespTypeID = 0x300bb5e1

// Ensuring interfaces in compile-time for GetUpdatesResp.
var (
	_ bin.Encoder     = &GetUpdatesResp{}
	_ bin.Decoder     = &GetUpdatesResp{}
	_ bin.BareEncoder = &GetUpdatesResp{}
	_ bin.BareDecoder = &GetUpdatesResp{}
)

func (g *GetUpdatesResp) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Updates == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *GetUpdatesResp) String() string {
	if g == nil {
		return "GetUpdatesResp(nil)"
	}
	type Alias GetUpdatesResp
	return fmt.Sprintf("GetUpdatesResp%+v", Alias(*g))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*GetUpdatesResp) TypeID() uint32 {
	return GetUpdatesRespTypeID
}

// TypeName returns name of type in TL schema.
func (*GetUpdatesResp) TypeName() string {
	return "getUpdatesResp"
}

// TypeInfo returns info about TL type.
func (g *GetUpdatesResp) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "getUpdatesResp",
		ID:   GetUpdatesRespTypeID,
	}
	if g == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Updates",
			SchemaName: "updates",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (g *GetUpdatesResp) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode getUpdatesResp#300bb5e1 as nil")
	}
	b.PutID(GetUpdatesRespTypeID)
	return g.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (g *GetUpdatesResp) EncodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode getUpdatesResp#300bb5e1 as nil")
	}
	b.PutVectorHeader(len(g.Updates))
	for idx, v := range g.Updates {
		if v == nil {
			return fmt.Errorf("unable to encode getUpdatesResp#300bb5e1: field updates element with index %d is nil", idx)
		}
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode getUpdatesResp#300bb5e1: field updates element with index %d: %w", idx, err)
		}
	}
	return nil
}

// Decode implements bin.Decoder.
func (g *GetUpdatesResp) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode getUpdatesResp#300bb5e1 to nil")
	}
	if err := b.ConsumeID(GetUpdatesRespTypeID); err != nil {
		return fmt.Errorf("unable to decode getUpdatesResp#300bb5e1: %w", err)
	}
	return g.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (g *GetUpdatesResp) DecodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode getUpdatesResp#300bb5e1 to nil")
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode getUpdatesResp#300bb5e1: field updates: %w", err)
		}

		if headerLen > 0 {
			g.Updates = make([]AbstractMessageClass, 0, headerLen%bin.PreallocateLimit)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeAbstractMessage(b)
			if err != nil {
				return fmt.Errorf("unable to decode getUpdatesResp#300bb5e1: field updates: %w", err)
			}
			g.Updates = append(g.Updates, value)
		}
	}
	return nil
}

// GetUpdates returns value of Updates field.
func (g *GetUpdatesResp) GetUpdates() (value []AbstractMessageClass) {
	if g == nil {
		return
	}
	return g.Updates
}