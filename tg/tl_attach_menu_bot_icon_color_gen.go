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

// AttachMenuBotIconColor represents TL type `attachMenuBotIconColor#4576f3f0`.
//
// See https://core.telegram.org/constructor/attachMenuBotIconColor for reference.
type AttachMenuBotIconColor struct {
	//
	Name string
	//
	Color int
}

// AttachMenuBotIconColorTypeID is TL type id of AttachMenuBotIconColor.
const AttachMenuBotIconColorTypeID = 0x4576f3f0

// Ensuring interfaces in compile-time for AttachMenuBotIconColor.
var (
	_ bin.Encoder     = &AttachMenuBotIconColor{}
	_ bin.Decoder     = &AttachMenuBotIconColor{}
	_ bin.BareEncoder = &AttachMenuBotIconColor{}
	_ bin.BareDecoder = &AttachMenuBotIconColor{}
)

func (a *AttachMenuBotIconColor) Zero() bool {
	if a == nil {
		return true
	}
	if !(a.Name == "") {
		return false
	}
	if !(a.Color == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (a *AttachMenuBotIconColor) String() string {
	if a == nil {
		return "AttachMenuBotIconColor(nil)"
	}
	type Alias AttachMenuBotIconColor
	return fmt.Sprintf("AttachMenuBotIconColor%+v", Alias(*a))
}

// FillFrom fills AttachMenuBotIconColor from given interface.
func (a *AttachMenuBotIconColor) FillFrom(from interface {
	GetName() (value string)
	GetColor() (value int)
}) {
	a.Name = from.GetName()
	a.Color = from.GetColor()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*AttachMenuBotIconColor) TypeID() uint32 {
	return AttachMenuBotIconColorTypeID
}

// TypeName returns name of type in TL schema.
func (*AttachMenuBotIconColor) TypeName() string {
	return "attachMenuBotIconColor"
}

// TypeInfo returns info about TL type.
func (a *AttachMenuBotIconColor) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "attachMenuBotIconColor",
		ID:   AttachMenuBotIconColorTypeID,
	}
	if a == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Name",
			SchemaName: "name",
		},
		{
			Name:       "Color",
			SchemaName: "color",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (a *AttachMenuBotIconColor) Encode(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't encode attachMenuBotIconColor#4576f3f0 as nil")
	}
	b.PutID(AttachMenuBotIconColorTypeID)
	return a.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (a *AttachMenuBotIconColor) EncodeBare(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't encode attachMenuBotIconColor#4576f3f0 as nil")
	}
	b.PutString(a.Name)
	b.PutInt(a.Color)
	return nil
}

// Decode implements bin.Decoder.
func (a *AttachMenuBotIconColor) Decode(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't decode attachMenuBotIconColor#4576f3f0 to nil")
	}
	if err := b.ConsumeID(AttachMenuBotIconColorTypeID); err != nil {
		return fmt.Errorf("unable to decode attachMenuBotIconColor#4576f3f0: %w", err)
	}
	return a.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (a *AttachMenuBotIconColor) DecodeBare(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't decode attachMenuBotIconColor#4576f3f0 to nil")
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode attachMenuBotIconColor#4576f3f0: field name: %w", err)
		}
		a.Name = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode attachMenuBotIconColor#4576f3f0: field color: %w", err)
		}
		a.Color = value
	}
	return nil
}

// GetName returns value of Name field.
func (a *AttachMenuBotIconColor) GetName() (value string) {
	if a == nil {
		return
	}
	return a.Name
}

// GetColor returns value of Color field.
func (a *AttachMenuBotIconColor) GetColor() (value int) {
	if a == nil {
		return
	}
	return a.Color
}
