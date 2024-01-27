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

// DeleteSavedMessagesTopicMessagesByDateRequest represents TL type `deleteSavedMessagesTopicMessagesByDate#a18f779d`.
type DeleteSavedMessagesTopicMessagesByDateRequest struct {
	// Saved Messages topic which messages will be deleted
	SavedMessagesTopic SavedMessagesTopicClass
	// The minimum date of the messages to delete
	MinDate int32
	// The maximum date of the messages to delete
	MaxDate int32
}

// DeleteSavedMessagesTopicMessagesByDateRequestTypeID is TL type id of DeleteSavedMessagesTopicMessagesByDateRequest.
const DeleteSavedMessagesTopicMessagesByDateRequestTypeID = 0xa18f779d

// Ensuring interfaces in compile-time for DeleteSavedMessagesTopicMessagesByDateRequest.
var (
	_ bin.Encoder     = &DeleteSavedMessagesTopicMessagesByDateRequest{}
	_ bin.Decoder     = &DeleteSavedMessagesTopicMessagesByDateRequest{}
	_ bin.BareEncoder = &DeleteSavedMessagesTopicMessagesByDateRequest{}
	_ bin.BareDecoder = &DeleteSavedMessagesTopicMessagesByDateRequest{}
)

func (d *DeleteSavedMessagesTopicMessagesByDateRequest) Zero() bool {
	if d == nil {
		return true
	}
	if !(d.SavedMessagesTopic == nil) {
		return false
	}
	if !(d.MinDate == 0) {
		return false
	}
	if !(d.MaxDate == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (d *DeleteSavedMessagesTopicMessagesByDateRequest) String() string {
	if d == nil {
		return "DeleteSavedMessagesTopicMessagesByDateRequest(nil)"
	}
	type Alias DeleteSavedMessagesTopicMessagesByDateRequest
	return fmt.Sprintf("DeleteSavedMessagesTopicMessagesByDateRequest%+v", Alias(*d))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*DeleteSavedMessagesTopicMessagesByDateRequest) TypeID() uint32 {
	return DeleteSavedMessagesTopicMessagesByDateRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*DeleteSavedMessagesTopicMessagesByDateRequest) TypeName() string {
	return "deleteSavedMessagesTopicMessagesByDate"
}

// TypeInfo returns info about TL type.
func (d *DeleteSavedMessagesTopicMessagesByDateRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "deleteSavedMessagesTopicMessagesByDate",
		ID:   DeleteSavedMessagesTopicMessagesByDateRequestTypeID,
	}
	if d == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "SavedMessagesTopic",
			SchemaName: "saved_messages_topic",
		},
		{
			Name:       "MinDate",
			SchemaName: "min_date",
		},
		{
			Name:       "MaxDate",
			SchemaName: "max_date",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (d *DeleteSavedMessagesTopicMessagesByDateRequest) Encode(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't encode deleteSavedMessagesTopicMessagesByDate#a18f779d as nil")
	}
	b.PutID(DeleteSavedMessagesTopicMessagesByDateRequestTypeID)
	return d.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (d *DeleteSavedMessagesTopicMessagesByDateRequest) EncodeBare(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't encode deleteSavedMessagesTopicMessagesByDate#a18f779d as nil")
	}
	if d.SavedMessagesTopic == nil {
		return fmt.Errorf("unable to encode deleteSavedMessagesTopicMessagesByDate#a18f779d: field saved_messages_topic is nil")
	}
	if err := d.SavedMessagesTopic.Encode(b); err != nil {
		return fmt.Errorf("unable to encode deleteSavedMessagesTopicMessagesByDate#a18f779d: field saved_messages_topic: %w", err)
	}
	b.PutInt32(d.MinDate)
	b.PutInt32(d.MaxDate)
	return nil
}

// Decode implements bin.Decoder.
func (d *DeleteSavedMessagesTopicMessagesByDateRequest) Decode(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't decode deleteSavedMessagesTopicMessagesByDate#a18f779d to nil")
	}
	if err := b.ConsumeID(DeleteSavedMessagesTopicMessagesByDateRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode deleteSavedMessagesTopicMessagesByDate#a18f779d: %w", err)
	}
	return d.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (d *DeleteSavedMessagesTopicMessagesByDateRequest) DecodeBare(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't decode deleteSavedMessagesTopicMessagesByDate#a18f779d to nil")
	}
	{
		value, err := DecodeSavedMessagesTopic(b)
		if err != nil {
			return fmt.Errorf("unable to decode deleteSavedMessagesTopicMessagesByDate#a18f779d: field saved_messages_topic: %w", err)
		}
		d.SavedMessagesTopic = value
	}
	{
		value, err := b.Int32()
		if err != nil {
			return fmt.Errorf("unable to decode deleteSavedMessagesTopicMessagesByDate#a18f779d: field min_date: %w", err)
		}
		d.MinDate = value
	}
	{
		value, err := b.Int32()
		if err != nil {
			return fmt.Errorf("unable to decode deleteSavedMessagesTopicMessagesByDate#a18f779d: field max_date: %w", err)
		}
		d.MaxDate = value
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (d *DeleteSavedMessagesTopicMessagesByDateRequest) EncodeTDLibJSON(b tdjson.Encoder) error {
	if d == nil {
		return fmt.Errorf("can't encode deleteSavedMessagesTopicMessagesByDate#a18f779d as nil")
	}
	b.ObjStart()
	b.PutID("deleteSavedMessagesTopicMessagesByDate")
	b.Comma()
	b.FieldStart("saved_messages_topic")
	if d.SavedMessagesTopic == nil {
		return fmt.Errorf("unable to encode deleteSavedMessagesTopicMessagesByDate#a18f779d: field saved_messages_topic is nil")
	}
	if err := d.SavedMessagesTopic.EncodeTDLibJSON(b); err != nil {
		return fmt.Errorf("unable to encode deleteSavedMessagesTopicMessagesByDate#a18f779d: field saved_messages_topic: %w", err)
	}
	b.Comma()
	b.FieldStart("min_date")
	b.PutInt32(d.MinDate)
	b.Comma()
	b.FieldStart("max_date")
	b.PutInt32(d.MaxDate)
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (d *DeleteSavedMessagesTopicMessagesByDateRequest) DecodeTDLibJSON(b tdjson.Decoder) error {
	if d == nil {
		return fmt.Errorf("can't decode deleteSavedMessagesTopicMessagesByDate#a18f779d to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("deleteSavedMessagesTopicMessagesByDate"); err != nil {
				return fmt.Errorf("unable to decode deleteSavedMessagesTopicMessagesByDate#a18f779d: %w", err)
			}
		case "saved_messages_topic":
			value, err := DecodeTDLibJSONSavedMessagesTopic(b)
			if err != nil {
				return fmt.Errorf("unable to decode deleteSavedMessagesTopicMessagesByDate#a18f779d: field saved_messages_topic: %w", err)
			}
			d.SavedMessagesTopic = value
		case "min_date":
			value, err := b.Int32()
			if err != nil {
				return fmt.Errorf("unable to decode deleteSavedMessagesTopicMessagesByDate#a18f779d: field min_date: %w", err)
			}
			d.MinDate = value
		case "max_date":
			value, err := b.Int32()
			if err != nil {
				return fmt.Errorf("unable to decode deleteSavedMessagesTopicMessagesByDate#a18f779d: field max_date: %w", err)
			}
			d.MaxDate = value
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetSavedMessagesTopic returns value of SavedMessagesTopic field.
func (d *DeleteSavedMessagesTopicMessagesByDateRequest) GetSavedMessagesTopic() (value SavedMessagesTopicClass) {
	if d == nil {
		return
	}
	return d.SavedMessagesTopic
}

// GetMinDate returns value of MinDate field.
func (d *DeleteSavedMessagesTopicMessagesByDateRequest) GetMinDate() (value int32) {
	if d == nil {
		return
	}
	return d.MinDate
}

// GetMaxDate returns value of MaxDate field.
func (d *DeleteSavedMessagesTopicMessagesByDateRequest) GetMaxDate() (value int32) {
	if d == nil {
		return
	}
	return d.MaxDate
}

// DeleteSavedMessagesTopicMessagesByDate invokes method deleteSavedMessagesTopicMessagesByDate#a18f779d returning error if any.
func (c *Client) DeleteSavedMessagesTopicMessagesByDate(ctx context.Context, request *DeleteSavedMessagesTopicMessagesByDateRequest) error {
	var ok Ok

	if err := c.rpc.Invoke(ctx, request, &ok); err != nil {
		return err
	}
	return nil
}
