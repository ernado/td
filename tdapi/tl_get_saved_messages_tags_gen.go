// Code generated by gotdgen, DO NOT EDIT.

package tdapi

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

// GetSavedMessagesTagsRequest represents TL type `getSavedMessagesTags#611591cb`.
type GetSavedMessagesTagsRequest struct {
}

// GetSavedMessagesTagsRequestTypeID is TL type id of GetSavedMessagesTagsRequest.
const GetSavedMessagesTagsRequestTypeID = 0x611591cb

// Ensuring interfaces in compile-time for GetSavedMessagesTagsRequest.
var (
	_ bin.Encoder     = &GetSavedMessagesTagsRequest{}
	_ bin.Decoder     = &GetSavedMessagesTagsRequest{}
	_ bin.BareEncoder = &GetSavedMessagesTagsRequest{}
	_ bin.BareDecoder = &GetSavedMessagesTagsRequest{}
)

func (g *GetSavedMessagesTagsRequest) Zero() bool {
	if g == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (g *GetSavedMessagesTagsRequest) String() string {
	if g == nil {
		return "GetSavedMessagesTagsRequest(nil)"
	}
	type Alias GetSavedMessagesTagsRequest
	return fmt.Sprintf("GetSavedMessagesTagsRequest%+v", Alias(*g))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*GetSavedMessagesTagsRequest) TypeID() uint32 {
	return GetSavedMessagesTagsRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*GetSavedMessagesTagsRequest) TypeName() string {
	return "getSavedMessagesTags"
}

// TypeInfo returns info about TL type.
func (g *GetSavedMessagesTagsRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "getSavedMessagesTags",
		ID:   GetSavedMessagesTagsRequestTypeID,
	}
	if g == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{}
	return typ
}

// Encode implements bin.Encoder.
func (g *GetSavedMessagesTagsRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode getSavedMessagesTags#611591cb as nil")
	}
	b.PutID(GetSavedMessagesTagsRequestTypeID)
	return g.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (g *GetSavedMessagesTagsRequest) EncodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode getSavedMessagesTags#611591cb as nil")
	}
	return nil
}

// Decode implements bin.Decoder.
func (g *GetSavedMessagesTagsRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode getSavedMessagesTags#611591cb to nil")
	}
	if err := b.ConsumeID(GetSavedMessagesTagsRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode getSavedMessagesTags#611591cb: %w", err)
	}
	return g.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (g *GetSavedMessagesTagsRequest) DecodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode getSavedMessagesTags#611591cb to nil")
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (g *GetSavedMessagesTagsRequest) EncodeTDLibJSON(b tdjson.Encoder) error {
	if g == nil {
		return fmt.Errorf("can't encode getSavedMessagesTags#611591cb as nil")
	}
	b.ObjStart()
	b.PutID("getSavedMessagesTags")
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (g *GetSavedMessagesTagsRequest) DecodeTDLibJSON(b tdjson.Decoder) error {
	if g == nil {
		return fmt.Errorf("can't decode getSavedMessagesTags#611591cb to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("getSavedMessagesTags"); err != nil {
				return fmt.Errorf("unable to decode getSavedMessagesTags#611591cb: %w", err)
			}
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetSavedMessagesTags invokes method getSavedMessagesTags#611591cb returning error if any.
func (c *Client) GetSavedMessagesTags(ctx context.Context) (*SavedMessagesTags, error) {
	var result SavedMessagesTags

	request := &GetSavedMessagesTagsRequest{}
	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
