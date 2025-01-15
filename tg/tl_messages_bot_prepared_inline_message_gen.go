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

// MessagesBotPreparedInlineMessage represents TL type `messages.botPreparedInlineMessage#8ecf0511`.
// Represents a prepared inline message saved by a bot, to be sent to the user via a web
// app »¹
//
// Links:
//  1. https://core.telegram.org/api/bots/inline#21-using-a-prepared-inline-message
//
// See https://core.telegram.org/constructor/messages.botPreparedInlineMessage for reference.
type MessagesBotPreparedInlineMessage struct {
	// The ID of the saved message, to be passed to the id field of the
	// web_app_send_prepared_message event »¹
	//
	// Links:
	//  1) https://core.telegram.org/api/web-events#web-app-send-prepared-message
	ID string
	// Expiration date of the message
	ExpireDate int
}

// MessagesBotPreparedInlineMessageTypeID is TL type id of MessagesBotPreparedInlineMessage.
const MessagesBotPreparedInlineMessageTypeID = 0x8ecf0511

// Ensuring interfaces in compile-time for MessagesBotPreparedInlineMessage.
var (
	_ bin.Encoder     = &MessagesBotPreparedInlineMessage{}
	_ bin.Decoder     = &MessagesBotPreparedInlineMessage{}
	_ bin.BareEncoder = &MessagesBotPreparedInlineMessage{}
	_ bin.BareDecoder = &MessagesBotPreparedInlineMessage{}
)

func (b *MessagesBotPreparedInlineMessage) Zero() bool {
	if b == nil {
		return true
	}
	if !(b.ID == "") {
		return false
	}
	if !(b.ExpireDate == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (b *MessagesBotPreparedInlineMessage) String() string {
	if b == nil {
		return "MessagesBotPreparedInlineMessage(nil)"
	}
	type Alias MessagesBotPreparedInlineMessage
	return fmt.Sprintf("MessagesBotPreparedInlineMessage%+v", Alias(*b))
}

// FillFrom fills MessagesBotPreparedInlineMessage from given interface.
func (b *MessagesBotPreparedInlineMessage) FillFrom(from interface {
	GetID() (value string)
	GetExpireDate() (value int)
}) {
	b.ID = from.GetID()
	b.ExpireDate = from.GetExpireDate()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*MessagesBotPreparedInlineMessage) TypeID() uint32 {
	return MessagesBotPreparedInlineMessageTypeID
}

// TypeName returns name of type in TL schema.
func (*MessagesBotPreparedInlineMessage) TypeName() string {
	return "messages.botPreparedInlineMessage"
}

// TypeInfo returns info about TL type.
func (b *MessagesBotPreparedInlineMessage) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "messages.botPreparedInlineMessage",
		ID:   MessagesBotPreparedInlineMessageTypeID,
	}
	if b == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "ID",
			SchemaName: "id",
		},
		{
			Name:       "ExpireDate",
			SchemaName: "expire_date",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (b *MessagesBotPreparedInlineMessage) Encode(buf *bin.Buffer) error {
	if b == nil {
		return fmt.Errorf("can't encode messages.botPreparedInlineMessage#8ecf0511 as nil")
	}
	buf.PutID(MessagesBotPreparedInlineMessageTypeID)
	return b.EncodeBare(buf)
}

// EncodeBare implements bin.BareEncoder.
func (b *MessagesBotPreparedInlineMessage) EncodeBare(buf *bin.Buffer) error {
	if b == nil {
		return fmt.Errorf("can't encode messages.botPreparedInlineMessage#8ecf0511 as nil")
	}
	buf.PutString(b.ID)
	buf.PutInt(b.ExpireDate)
	return nil
}

// Decode implements bin.Decoder.
func (b *MessagesBotPreparedInlineMessage) Decode(buf *bin.Buffer) error {
	if b == nil {
		return fmt.Errorf("can't decode messages.botPreparedInlineMessage#8ecf0511 to nil")
	}
	if err := buf.ConsumeID(MessagesBotPreparedInlineMessageTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.botPreparedInlineMessage#8ecf0511: %w", err)
	}
	return b.DecodeBare(buf)
}

// DecodeBare implements bin.BareDecoder.
func (b *MessagesBotPreparedInlineMessage) DecodeBare(buf *bin.Buffer) error {
	if b == nil {
		return fmt.Errorf("can't decode messages.botPreparedInlineMessage#8ecf0511 to nil")
	}
	{
		value, err := buf.String()
		if err != nil {
			return fmt.Errorf("unable to decode messages.botPreparedInlineMessage#8ecf0511: field id: %w", err)
		}
		b.ID = value
	}
	{
		value, err := buf.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.botPreparedInlineMessage#8ecf0511: field expire_date: %w", err)
		}
		b.ExpireDate = value
	}
	return nil
}

// GetID returns value of ID field.
func (b *MessagesBotPreparedInlineMessage) GetID() (value string) {
	if b == nil {
		return
	}
	return b.ID
}

// GetExpireDate returns value of ExpireDate field.
func (b *MessagesBotPreparedInlineMessage) GetExpireDate() (value int) {
	if b == nil {
		return
	}
	return b.ExpireDate
}