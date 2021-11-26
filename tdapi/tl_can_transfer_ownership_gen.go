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

// CanTransferOwnershipRequest represents TL type `canTransferOwnership#25d3440c`.
type CanTransferOwnershipRequest struct {
}

// CanTransferOwnershipRequestTypeID is TL type id of CanTransferOwnershipRequest.
const CanTransferOwnershipRequestTypeID = 0x25d3440c

// Ensuring interfaces in compile-time for CanTransferOwnershipRequest.
var (
	_ bin.Encoder     = &CanTransferOwnershipRequest{}
	_ bin.Decoder     = &CanTransferOwnershipRequest{}
	_ bin.BareEncoder = &CanTransferOwnershipRequest{}
	_ bin.BareDecoder = &CanTransferOwnershipRequest{}
)

func (c *CanTransferOwnershipRequest) Zero() bool {
	if c == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (c *CanTransferOwnershipRequest) String() string {
	if c == nil {
		return "CanTransferOwnershipRequest(nil)"
	}
	type Alias CanTransferOwnershipRequest
	return fmt.Sprintf("CanTransferOwnershipRequest%+v", Alias(*c))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*CanTransferOwnershipRequest) TypeID() uint32 {
	return CanTransferOwnershipRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*CanTransferOwnershipRequest) TypeName() string {
	return "canTransferOwnership"
}

// TypeInfo returns info about TL type.
func (c *CanTransferOwnershipRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "canTransferOwnership",
		ID:   CanTransferOwnershipRequestTypeID,
	}
	if c == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{}
	return typ
}

// Encode implements bin.Encoder.
func (c *CanTransferOwnershipRequest) Encode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode canTransferOwnership#25d3440c as nil")
	}
	b.PutID(CanTransferOwnershipRequestTypeID)
	return c.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (c *CanTransferOwnershipRequest) EncodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode canTransferOwnership#25d3440c as nil")
	}
	return nil
}

// Decode implements bin.Decoder.
func (c *CanTransferOwnershipRequest) Decode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode canTransferOwnership#25d3440c to nil")
	}
	if err := b.ConsumeID(CanTransferOwnershipRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode canTransferOwnership#25d3440c: %w", err)
	}
	return c.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (c *CanTransferOwnershipRequest) DecodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode canTransferOwnership#25d3440c to nil")
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (c *CanTransferOwnershipRequest) EncodeTDLibJSON(b tdjson.Encoder) error {
	if c == nil {
		return fmt.Errorf("can't encode canTransferOwnership#25d3440c as nil")
	}
	b.ObjStart()
	b.PutID("canTransferOwnership")
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (c *CanTransferOwnershipRequest) DecodeTDLibJSON(b tdjson.Decoder) error {
	if c == nil {
		return fmt.Errorf("can't decode canTransferOwnership#25d3440c to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("canTransferOwnership"); err != nil {
				return fmt.Errorf("unable to decode canTransferOwnership#25d3440c: %w", err)
			}
		default:
			return b.Skip()
		}
		return nil
	})
}

// CanTransferOwnership invokes method canTransferOwnership#25d3440c returning error if any.
func (c *Client) CanTransferOwnership(ctx context.Context) (CanTransferOwnershipResultClass, error) {
	var result CanTransferOwnershipResultBox

	request := &CanTransferOwnershipRequest{}
	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return result.CanTransferOwnershipResult, nil
}