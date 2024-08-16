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

// EditStarSubscriptionRequest represents TL type `editStarSubscription#7a1a3918`.
type EditStarSubscriptionRequest struct {
	// Identifier of the subscription to change
	SubscriptionID string
	// New value of is_canceled
	IsCanceled bool
}

// EditStarSubscriptionRequestTypeID is TL type id of EditStarSubscriptionRequest.
const EditStarSubscriptionRequestTypeID = 0x7a1a3918

// Ensuring interfaces in compile-time for EditStarSubscriptionRequest.
var (
	_ bin.Encoder     = &EditStarSubscriptionRequest{}
	_ bin.Decoder     = &EditStarSubscriptionRequest{}
	_ bin.BareEncoder = &EditStarSubscriptionRequest{}
	_ bin.BareDecoder = &EditStarSubscriptionRequest{}
)

func (e *EditStarSubscriptionRequest) Zero() bool {
	if e == nil {
		return true
	}
	if !(e.SubscriptionID == "") {
		return false
	}
	if !(e.IsCanceled == false) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (e *EditStarSubscriptionRequest) String() string {
	if e == nil {
		return "EditStarSubscriptionRequest(nil)"
	}
	type Alias EditStarSubscriptionRequest
	return fmt.Sprintf("EditStarSubscriptionRequest%+v", Alias(*e))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*EditStarSubscriptionRequest) TypeID() uint32 {
	return EditStarSubscriptionRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*EditStarSubscriptionRequest) TypeName() string {
	return "editStarSubscription"
}

// TypeInfo returns info about TL type.
func (e *EditStarSubscriptionRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "editStarSubscription",
		ID:   EditStarSubscriptionRequestTypeID,
	}
	if e == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "SubscriptionID",
			SchemaName: "subscription_id",
		},
		{
			Name:       "IsCanceled",
			SchemaName: "is_canceled",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (e *EditStarSubscriptionRequest) Encode(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't encode editStarSubscription#7a1a3918 as nil")
	}
	b.PutID(EditStarSubscriptionRequestTypeID)
	return e.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (e *EditStarSubscriptionRequest) EncodeBare(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't encode editStarSubscription#7a1a3918 as nil")
	}
	b.PutString(e.SubscriptionID)
	b.PutBool(e.IsCanceled)
	return nil
}

// Decode implements bin.Decoder.
func (e *EditStarSubscriptionRequest) Decode(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't decode editStarSubscription#7a1a3918 to nil")
	}
	if err := b.ConsumeID(EditStarSubscriptionRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode editStarSubscription#7a1a3918: %w", err)
	}
	return e.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (e *EditStarSubscriptionRequest) DecodeBare(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't decode editStarSubscription#7a1a3918 to nil")
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode editStarSubscription#7a1a3918: field subscription_id: %w", err)
		}
		e.SubscriptionID = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode editStarSubscription#7a1a3918: field is_canceled: %w", err)
		}
		e.IsCanceled = value
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (e *EditStarSubscriptionRequest) EncodeTDLibJSON(b tdjson.Encoder) error {
	if e == nil {
		return fmt.Errorf("can't encode editStarSubscription#7a1a3918 as nil")
	}
	b.ObjStart()
	b.PutID("editStarSubscription")
	b.Comma()
	b.FieldStart("subscription_id")
	b.PutString(e.SubscriptionID)
	b.Comma()
	b.FieldStart("is_canceled")
	b.PutBool(e.IsCanceled)
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (e *EditStarSubscriptionRequest) DecodeTDLibJSON(b tdjson.Decoder) error {
	if e == nil {
		return fmt.Errorf("can't decode editStarSubscription#7a1a3918 to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("editStarSubscription"); err != nil {
				return fmt.Errorf("unable to decode editStarSubscription#7a1a3918: %w", err)
			}
		case "subscription_id":
			value, err := b.String()
			if err != nil {
				return fmt.Errorf("unable to decode editStarSubscription#7a1a3918: field subscription_id: %w", err)
			}
			e.SubscriptionID = value
		case "is_canceled":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode editStarSubscription#7a1a3918: field is_canceled: %w", err)
			}
			e.IsCanceled = value
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetSubscriptionID returns value of SubscriptionID field.
func (e *EditStarSubscriptionRequest) GetSubscriptionID() (value string) {
	if e == nil {
		return
	}
	return e.SubscriptionID
}

// GetIsCanceled returns value of IsCanceled field.
func (e *EditStarSubscriptionRequest) GetIsCanceled() (value bool) {
	if e == nil {
		return
	}
	return e.IsCanceled
}

// EditStarSubscription invokes method editStarSubscription#7a1a3918 returning error if any.
func (c *Client) EditStarSubscription(ctx context.Context, request *EditStarSubscriptionRequest) error {
	var ok Ok

	if err := c.rpc.Invoke(ctx, request, &ok); err != nil {
		return err
	}
	return nil
}
