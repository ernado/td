// Code generated by gotdgen, DO NOT EDIT.

package tg

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"go.uber.org/multierr"

	"github.com/gotd/td/bin"
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
)

// MessagesGetFullChatRequest represents TL type `messages.getFullChat#aeb00b34`.
// Returns full chat info according to its ID.
//
// See https://core.telegram.org/method/messages.getFullChat for reference.
type MessagesGetFullChatRequest struct {
	// Chat ID
	ChatID int64
}

// MessagesGetFullChatRequestTypeID is TL type id of MessagesGetFullChatRequest.
const MessagesGetFullChatRequestTypeID = 0xaeb00b34

// Ensuring interfaces in compile-time for MessagesGetFullChatRequest.
var (
	_ bin.Encoder     = &MessagesGetFullChatRequest{}
	_ bin.Decoder     = &MessagesGetFullChatRequest{}
	_ bin.BareEncoder = &MessagesGetFullChatRequest{}
	_ bin.BareDecoder = &MessagesGetFullChatRequest{}
)

func (g *MessagesGetFullChatRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.ChatID == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *MessagesGetFullChatRequest) String() string {
	if g == nil {
		return "MessagesGetFullChatRequest(nil)"
	}
	type Alias MessagesGetFullChatRequest
	return fmt.Sprintf("MessagesGetFullChatRequest%+v", Alias(*g))
}

// FillFrom fills MessagesGetFullChatRequest from given interface.
func (g *MessagesGetFullChatRequest) FillFrom(from interface {
	GetChatID() (value int64)
}) {
	g.ChatID = from.GetChatID()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*MessagesGetFullChatRequest) TypeID() uint32 {
	return MessagesGetFullChatRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*MessagesGetFullChatRequest) TypeName() string {
	return "messages.getFullChat"
}

// TypeInfo returns info about TL type.
func (g *MessagesGetFullChatRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "messages.getFullChat",
		ID:   MessagesGetFullChatRequestTypeID,
	}
	if g == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "ChatID",
			SchemaName: "chat_id",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (g *MessagesGetFullChatRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode messages.getFullChat#aeb00b34 as nil")
	}
	b.PutID(MessagesGetFullChatRequestTypeID)
	return g.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (g *MessagesGetFullChatRequest) EncodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode messages.getFullChat#aeb00b34 as nil")
	}
	b.PutLong(g.ChatID)
	return nil
}

// Decode implements bin.Decoder.
func (g *MessagesGetFullChatRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode messages.getFullChat#aeb00b34 to nil")
	}
	if err := b.ConsumeID(MessagesGetFullChatRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.getFullChat#aeb00b34: %w", err)
	}
	return g.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (g *MessagesGetFullChatRequest) DecodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode messages.getFullChat#aeb00b34 to nil")
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getFullChat#aeb00b34: field chat_id: %w", err)
		}
		g.ChatID = value
	}
	return nil
}

// GetChatID returns value of ChatID field.
func (g *MessagesGetFullChatRequest) GetChatID() (value int64) {
	return g.ChatID
}

// MessagesGetFullChat invokes method messages.getFullChat#aeb00b34 returning error if any.
// Returns full chat info according to its ID.
//
// Possible errors:
//  400 CHAT_ID_INVALID: The provided chat id is invalid
//  400 PEER_ID_INVALID: The provided peer id is invalid
//
// See https://core.telegram.org/method/messages.getFullChat for reference.
// Can be used by bots.
func (c *Client) MessagesGetFullChat(ctx context.Context, chatid int64) (*MessagesChatFull, error) {
	var result MessagesChatFull

	request := &MessagesGetFullChatRequest{
		ChatID: chatid,
	}
	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
