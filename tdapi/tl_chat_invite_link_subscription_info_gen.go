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

// ChatInviteLinkSubscriptionInfo represents TL type `chatInviteLinkSubscriptionInfo#38cf7368`.
type ChatInviteLinkSubscriptionInfo struct {
	// Information about subscription plan that must be paid by the user to use the link
	Pricing StarSubscriptionPricing
	// True, if the user has already paid for the subscription and can use
	// joinChatByInviteLink to join the subscribed chat again
	CanReuse bool
	// Identifier of the payment form to use for subscription payment; 0 if the subscription
	// can't be paid
	FormID int64
}

// ChatInviteLinkSubscriptionInfoTypeID is TL type id of ChatInviteLinkSubscriptionInfo.
const ChatInviteLinkSubscriptionInfoTypeID = 0x38cf7368

// Ensuring interfaces in compile-time for ChatInviteLinkSubscriptionInfo.
var (
	_ bin.Encoder     = &ChatInviteLinkSubscriptionInfo{}
	_ bin.Decoder     = &ChatInviteLinkSubscriptionInfo{}
	_ bin.BareEncoder = &ChatInviteLinkSubscriptionInfo{}
	_ bin.BareDecoder = &ChatInviteLinkSubscriptionInfo{}
)

func (c *ChatInviteLinkSubscriptionInfo) Zero() bool {
	if c == nil {
		return true
	}
	if !(c.Pricing.Zero()) {
		return false
	}
	if !(c.CanReuse == false) {
		return false
	}
	if !(c.FormID == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (c *ChatInviteLinkSubscriptionInfo) String() string {
	if c == nil {
		return "ChatInviteLinkSubscriptionInfo(nil)"
	}
	type Alias ChatInviteLinkSubscriptionInfo
	return fmt.Sprintf("ChatInviteLinkSubscriptionInfo%+v", Alias(*c))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*ChatInviteLinkSubscriptionInfo) TypeID() uint32 {
	return ChatInviteLinkSubscriptionInfoTypeID
}

// TypeName returns name of type in TL schema.
func (*ChatInviteLinkSubscriptionInfo) TypeName() string {
	return "chatInviteLinkSubscriptionInfo"
}

// TypeInfo returns info about TL type.
func (c *ChatInviteLinkSubscriptionInfo) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "chatInviteLinkSubscriptionInfo",
		ID:   ChatInviteLinkSubscriptionInfoTypeID,
	}
	if c == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Pricing",
			SchemaName: "pricing",
		},
		{
			Name:       "CanReuse",
			SchemaName: "can_reuse",
		},
		{
			Name:       "FormID",
			SchemaName: "form_id",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (c *ChatInviteLinkSubscriptionInfo) Encode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode chatInviteLinkSubscriptionInfo#38cf7368 as nil")
	}
	b.PutID(ChatInviteLinkSubscriptionInfoTypeID)
	return c.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (c *ChatInviteLinkSubscriptionInfo) EncodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode chatInviteLinkSubscriptionInfo#38cf7368 as nil")
	}
	if err := c.Pricing.Encode(b); err != nil {
		return fmt.Errorf("unable to encode chatInviteLinkSubscriptionInfo#38cf7368: field pricing: %w", err)
	}
	b.PutBool(c.CanReuse)
	b.PutLong(c.FormID)
	return nil
}

// Decode implements bin.Decoder.
func (c *ChatInviteLinkSubscriptionInfo) Decode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode chatInviteLinkSubscriptionInfo#38cf7368 to nil")
	}
	if err := b.ConsumeID(ChatInviteLinkSubscriptionInfoTypeID); err != nil {
		return fmt.Errorf("unable to decode chatInviteLinkSubscriptionInfo#38cf7368: %w", err)
	}
	return c.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (c *ChatInviteLinkSubscriptionInfo) DecodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode chatInviteLinkSubscriptionInfo#38cf7368 to nil")
	}
	{
		if err := c.Pricing.Decode(b); err != nil {
			return fmt.Errorf("unable to decode chatInviteLinkSubscriptionInfo#38cf7368: field pricing: %w", err)
		}
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode chatInviteLinkSubscriptionInfo#38cf7368: field can_reuse: %w", err)
		}
		c.CanReuse = value
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode chatInviteLinkSubscriptionInfo#38cf7368: field form_id: %w", err)
		}
		c.FormID = value
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (c *ChatInviteLinkSubscriptionInfo) EncodeTDLibJSON(b tdjson.Encoder) error {
	if c == nil {
		return fmt.Errorf("can't encode chatInviteLinkSubscriptionInfo#38cf7368 as nil")
	}
	b.ObjStart()
	b.PutID("chatInviteLinkSubscriptionInfo")
	b.Comma()
	b.FieldStart("pricing")
	if err := c.Pricing.EncodeTDLibJSON(b); err != nil {
		return fmt.Errorf("unable to encode chatInviteLinkSubscriptionInfo#38cf7368: field pricing: %w", err)
	}
	b.Comma()
	b.FieldStart("can_reuse")
	b.PutBool(c.CanReuse)
	b.Comma()
	b.FieldStart("form_id")
	b.PutLong(c.FormID)
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (c *ChatInviteLinkSubscriptionInfo) DecodeTDLibJSON(b tdjson.Decoder) error {
	if c == nil {
		return fmt.Errorf("can't decode chatInviteLinkSubscriptionInfo#38cf7368 to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("chatInviteLinkSubscriptionInfo"); err != nil {
				return fmt.Errorf("unable to decode chatInviteLinkSubscriptionInfo#38cf7368: %w", err)
			}
		case "pricing":
			if err := c.Pricing.DecodeTDLibJSON(b); err != nil {
				return fmt.Errorf("unable to decode chatInviteLinkSubscriptionInfo#38cf7368: field pricing: %w", err)
			}
		case "can_reuse":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode chatInviteLinkSubscriptionInfo#38cf7368: field can_reuse: %w", err)
			}
			c.CanReuse = value
		case "form_id":
			value, err := b.Long()
			if err != nil {
				return fmt.Errorf("unable to decode chatInviteLinkSubscriptionInfo#38cf7368: field form_id: %w", err)
			}
			c.FormID = value
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetPricing returns value of Pricing field.
func (c *ChatInviteLinkSubscriptionInfo) GetPricing() (value StarSubscriptionPricing) {
	if c == nil {
		return
	}
	return c.Pricing
}

// GetCanReuse returns value of CanReuse field.
func (c *ChatInviteLinkSubscriptionInfo) GetCanReuse() (value bool) {
	if c == nil {
		return
	}
	return c.CanReuse
}

// GetFormID returns value of FormID field.
func (c *ChatInviteLinkSubscriptionInfo) GetFormID() (value int64) {
	if c == nil {
		return
	}
	return c.FormID
}
