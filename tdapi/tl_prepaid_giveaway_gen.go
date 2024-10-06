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

// PrepaidGiveaway represents TL type `prepaidGiveaway#ef70338f`.
type PrepaidGiveaway struct {
	// Unique identifier of the prepaid giveaway
	ID int64
	// Number of users which will receive giveaway prize
	WinnerCount int32
	// Prize of the giveaway
	Prize GiveawayPrizeClass
	// The number of boosts received by the chat from the giveaway; for Telegram Star
	// giveaways only
	BoostCount int32
	// Point in time (Unix timestamp) when the giveaway was paid
	PaymentDate int32
}

// PrepaidGiveawayTypeID is TL type id of PrepaidGiveaway.
const PrepaidGiveawayTypeID = 0xef70338f

// Ensuring interfaces in compile-time for PrepaidGiveaway.
var (
	_ bin.Encoder     = &PrepaidGiveaway{}
	_ bin.Decoder     = &PrepaidGiveaway{}
	_ bin.BareEncoder = &PrepaidGiveaway{}
	_ bin.BareDecoder = &PrepaidGiveaway{}
)

func (p *PrepaidGiveaway) Zero() bool {
	if p == nil {
		return true
	}
	if !(p.ID == 0) {
		return false
	}
	if !(p.WinnerCount == 0) {
		return false
	}
	if !(p.Prize == nil) {
		return false
	}
	if !(p.BoostCount == 0) {
		return false
	}
	if !(p.PaymentDate == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (p *PrepaidGiveaway) String() string {
	if p == nil {
		return "PrepaidGiveaway(nil)"
	}
	type Alias PrepaidGiveaway
	return fmt.Sprintf("PrepaidGiveaway%+v", Alias(*p))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*PrepaidGiveaway) TypeID() uint32 {
	return PrepaidGiveawayTypeID
}

// TypeName returns name of type in TL schema.
func (*PrepaidGiveaway) TypeName() string {
	return "prepaidGiveaway"
}

// TypeInfo returns info about TL type.
func (p *PrepaidGiveaway) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "prepaidGiveaway",
		ID:   PrepaidGiveawayTypeID,
	}
	if p == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "ID",
			SchemaName: "id",
		},
		{
			Name:       "WinnerCount",
			SchemaName: "winner_count",
		},
		{
			Name:       "Prize",
			SchemaName: "prize",
		},
		{
			Name:       "BoostCount",
			SchemaName: "boost_count",
		},
		{
			Name:       "PaymentDate",
			SchemaName: "payment_date",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (p *PrepaidGiveaway) Encode(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't encode prepaidGiveaway#ef70338f as nil")
	}
	b.PutID(PrepaidGiveawayTypeID)
	return p.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (p *PrepaidGiveaway) EncodeBare(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't encode prepaidGiveaway#ef70338f as nil")
	}
	b.PutLong(p.ID)
	b.PutInt32(p.WinnerCount)
	if p.Prize == nil {
		return fmt.Errorf("unable to encode prepaidGiveaway#ef70338f: field prize is nil")
	}
	if err := p.Prize.Encode(b); err != nil {
		return fmt.Errorf("unable to encode prepaidGiveaway#ef70338f: field prize: %w", err)
	}
	b.PutInt32(p.BoostCount)
	b.PutInt32(p.PaymentDate)
	return nil
}

// Decode implements bin.Decoder.
func (p *PrepaidGiveaway) Decode(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't decode prepaidGiveaway#ef70338f to nil")
	}
	if err := b.ConsumeID(PrepaidGiveawayTypeID); err != nil {
		return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: %w", err)
	}
	return p.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (p *PrepaidGiveaway) DecodeBare(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't decode prepaidGiveaway#ef70338f to nil")
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: field id: %w", err)
		}
		p.ID = value
	}
	{
		value, err := b.Int32()
		if err != nil {
			return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: field winner_count: %w", err)
		}
		p.WinnerCount = value
	}
	{
		value, err := DecodeGiveawayPrize(b)
		if err != nil {
			return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: field prize: %w", err)
		}
		p.Prize = value
	}
	{
		value, err := b.Int32()
		if err != nil {
			return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: field boost_count: %w", err)
		}
		p.BoostCount = value
	}
	{
		value, err := b.Int32()
		if err != nil {
			return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: field payment_date: %w", err)
		}
		p.PaymentDate = value
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (p *PrepaidGiveaway) EncodeTDLibJSON(b tdjson.Encoder) error {
	if p == nil {
		return fmt.Errorf("can't encode prepaidGiveaway#ef70338f as nil")
	}
	b.ObjStart()
	b.PutID("prepaidGiveaway")
	b.Comma()
	b.FieldStart("id")
	b.PutLong(p.ID)
	b.Comma()
	b.FieldStart("winner_count")
	b.PutInt32(p.WinnerCount)
	b.Comma()
	b.FieldStart("prize")
	if p.Prize == nil {
		return fmt.Errorf("unable to encode prepaidGiveaway#ef70338f: field prize is nil")
	}
	if err := p.Prize.EncodeTDLibJSON(b); err != nil {
		return fmt.Errorf("unable to encode prepaidGiveaway#ef70338f: field prize: %w", err)
	}
	b.Comma()
	b.FieldStart("boost_count")
	b.PutInt32(p.BoostCount)
	b.Comma()
	b.FieldStart("payment_date")
	b.PutInt32(p.PaymentDate)
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (p *PrepaidGiveaway) DecodeTDLibJSON(b tdjson.Decoder) error {
	if p == nil {
		return fmt.Errorf("can't decode prepaidGiveaway#ef70338f to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("prepaidGiveaway"); err != nil {
				return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: %w", err)
			}
		case "id":
			value, err := b.Long()
			if err != nil {
				return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: field id: %w", err)
			}
			p.ID = value
		case "winner_count":
			value, err := b.Int32()
			if err != nil {
				return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: field winner_count: %w", err)
			}
			p.WinnerCount = value
		case "prize":
			value, err := DecodeTDLibJSONGiveawayPrize(b)
			if err != nil {
				return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: field prize: %w", err)
			}
			p.Prize = value
		case "boost_count":
			value, err := b.Int32()
			if err != nil {
				return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: field boost_count: %w", err)
			}
			p.BoostCount = value
		case "payment_date":
			value, err := b.Int32()
			if err != nil {
				return fmt.Errorf("unable to decode prepaidGiveaway#ef70338f: field payment_date: %w", err)
			}
			p.PaymentDate = value
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetID returns value of ID field.
func (p *PrepaidGiveaway) GetID() (value int64) {
	if p == nil {
		return
	}
	return p.ID
}

// GetWinnerCount returns value of WinnerCount field.
func (p *PrepaidGiveaway) GetWinnerCount() (value int32) {
	if p == nil {
		return
	}
	return p.WinnerCount
}

// GetPrize returns value of Prize field.
func (p *PrepaidGiveaway) GetPrize() (value GiveawayPrizeClass) {
	if p == nil {
		return
	}
	return p.Prize
}

// GetBoostCount returns value of BoostCount field.
func (p *PrepaidGiveaway) GetBoostCount() (value int32) {
	if p == nil {
		return
	}
	return p.BoostCount
}

// GetPaymentDate returns value of PaymentDate field.
func (p *PrepaidGiveaway) GetPaymentDate() (value int32) {
	if p == nil {
		return
	}
	return p.PaymentDate
}