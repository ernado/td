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

// EditChatSubscriptionInviteLinkRequest represents TL type `editChatSubscriptionInviteLink#c74445d3`.
type EditChatSubscriptionInviteLinkRequest struct {
	// Chat identifier
	ChatID int64
	// Invite link to be edited
	InviteLink string
	// Invite link name; 0-32 characters
	Name string
}

// EditChatSubscriptionInviteLinkRequestTypeID is TL type id of EditChatSubscriptionInviteLinkRequest.
const EditChatSubscriptionInviteLinkRequestTypeID = 0xc74445d3

// Ensuring interfaces in compile-time for EditChatSubscriptionInviteLinkRequest.
var (
	_ bin.Encoder     = &EditChatSubscriptionInviteLinkRequest{}
	_ bin.Decoder     = &EditChatSubscriptionInviteLinkRequest{}
	_ bin.BareEncoder = &EditChatSubscriptionInviteLinkRequest{}
	_ bin.BareDecoder = &EditChatSubscriptionInviteLinkRequest{}
)

func (e *EditChatSubscriptionInviteLinkRequest) Zero() bool {
	if e == nil {
		return true
	}
	if !(e.ChatID == 0) {
		return false
	}
	if !(e.InviteLink == "") {
		return false
	}
	if !(e.Name == "") {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (e *EditChatSubscriptionInviteLinkRequest) String() string {
	if e == nil {
		return "EditChatSubscriptionInviteLinkRequest(nil)"
	}
	type Alias EditChatSubscriptionInviteLinkRequest
	return fmt.Sprintf("EditChatSubscriptionInviteLinkRequest%+v", Alias(*e))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*EditChatSubscriptionInviteLinkRequest) TypeID() uint32 {
	return EditChatSubscriptionInviteLinkRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*EditChatSubscriptionInviteLinkRequest) TypeName() string {
	return "editChatSubscriptionInviteLink"
}

// TypeInfo returns info about TL type.
func (e *EditChatSubscriptionInviteLinkRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "editChatSubscriptionInviteLink",
		ID:   EditChatSubscriptionInviteLinkRequestTypeID,
	}
	if e == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "ChatID",
			SchemaName: "chat_id",
		},
		{
			Name:       "InviteLink",
			SchemaName: "invite_link",
		},
		{
			Name:       "Name",
			SchemaName: "name",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (e *EditChatSubscriptionInviteLinkRequest) Encode(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't encode editChatSubscriptionInviteLink#c74445d3 as nil")
	}
	b.PutID(EditChatSubscriptionInviteLinkRequestTypeID)
	return e.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (e *EditChatSubscriptionInviteLinkRequest) EncodeBare(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't encode editChatSubscriptionInviteLink#c74445d3 as nil")
	}
	b.PutInt53(e.ChatID)
	b.PutString(e.InviteLink)
	b.PutString(e.Name)
	return nil
}

// Decode implements bin.Decoder.
func (e *EditChatSubscriptionInviteLinkRequest) Decode(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't decode editChatSubscriptionInviteLink#c74445d3 to nil")
	}
	if err := b.ConsumeID(EditChatSubscriptionInviteLinkRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode editChatSubscriptionInviteLink#c74445d3: %w", err)
	}
	return e.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (e *EditChatSubscriptionInviteLinkRequest) DecodeBare(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't decode editChatSubscriptionInviteLink#c74445d3 to nil")
	}
	{
		value, err := b.Int53()
		if err != nil {
			return fmt.Errorf("unable to decode editChatSubscriptionInviteLink#c74445d3: field chat_id: %w", err)
		}
		e.ChatID = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode editChatSubscriptionInviteLink#c74445d3: field invite_link: %w", err)
		}
		e.InviteLink = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode editChatSubscriptionInviteLink#c74445d3: field name: %w", err)
		}
		e.Name = value
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (e *EditChatSubscriptionInviteLinkRequest) EncodeTDLibJSON(b tdjson.Encoder) error {
	if e == nil {
		return fmt.Errorf("can't encode editChatSubscriptionInviteLink#c74445d3 as nil")
	}
	b.ObjStart()
	b.PutID("editChatSubscriptionInviteLink")
	b.Comma()
	b.FieldStart("chat_id")
	b.PutInt53(e.ChatID)
	b.Comma()
	b.FieldStart("invite_link")
	b.PutString(e.InviteLink)
	b.Comma()
	b.FieldStart("name")
	b.PutString(e.Name)
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (e *EditChatSubscriptionInviteLinkRequest) DecodeTDLibJSON(b tdjson.Decoder) error {
	if e == nil {
		return fmt.Errorf("can't decode editChatSubscriptionInviteLink#c74445d3 to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("editChatSubscriptionInviteLink"); err != nil {
				return fmt.Errorf("unable to decode editChatSubscriptionInviteLink#c74445d3: %w", err)
			}
		case "chat_id":
			value, err := b.Int53()
			if err != nil {
				return fmt.Errorf("unable to decode editChatSubscriptionInviteLink#c74445d3: field chat_id: %w", err)
			}
			e.ChatID = value
		case "invite_link":
			value, err := b.String()
			if err != nil {
				return fmt.Errorf("unable to decode editChatSubscriptionInviteLink#c74445d3: field invite_link: %w", err)
			}
			e.InviteLink = value
		case "name":
			value, err := b.String()
			if err != nil {
				return fmt.Errorf("unable to decode editChatSubscriptionInviteLink#c74445d3: field name: %w", err)
			}
			e.Name = value
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetChatID returns value of ChatID field.
func (e *EditChatSubscriptionInviteLinkRequest) GetChatID() (value int64) {
	if e == nil {
		return
	}
	return e.ChatID
}

// GetInviteLink returns value of InviteLink field.
func (e *EditChatSubscriptionInviteLinkRequest) GetInviteLink() (value string) {
	if e == nil {
		return
	}
	return e.InviteLink
}

// GetName returns value of Name field.
func (e *EditChatSubscriptionInviteLinkRequest) GetName() (value string) {
	if e == nil {
		return
	}
	return e.Name
}

// EditChatSubscriptionInviteLink invokes method editChatSubscriptionInviteLink#c74445d3 returning error if any.
func (c *Client) EditChatSubscriptionInviteLink(ctx context.Context, request *EditChatSubscriptionInviteLinkRequest) (*ChatInviteLink, error) {
	var result ChatInviteLink

	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
