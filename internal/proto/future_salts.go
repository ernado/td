package proto

import (
	"fmt"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/tdp"
)

// FutureSalts represents TL type `future_salts#ae500895`.
type FutureSalts struct {
	// ReqMsgID field of FutureSalts.
	ReqMsgID int64
	// Now field of FutureSalts.
	Now int
	// Salts field of FutureSalts.
	Salts []FutureSalt
}

// FutureSaltsTypeID is TL type id of FutureSalts.
const FutureSaltsTypeID = 0xae500895

// String implements fmt.Stringer.
func (f *FutureSalts) String() string {
	if f == nil {
		return "FutureSalts(nil)"
	}
	type Alias FutureSalts
	return fmt.Sprintf("FutureSalts%+v", Alias(*f))
}

// FillFrom fills FutureSalts from given interface.
func (f *FutureSalts) FillFrom(from interface {
	GetReqMsgID() (value int64)
	GetNow() (value int)
	GetSalts() (value []FutureSalt)
}) {
	f.ReqMsgID = from.GetReqMsgID()
	f.Now = from.GetNow()
	f.Salts = from.GetSalts()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*FutureSalts) TypeID() uint32 {
	return FutureSaltsTypeID
}

// TypeName returns name of type in TL schema.
func (*FutureSalts) TypeName() string {
	return "future_salts"
}

// TypeInfo returns info about TL type.
func (f *FutureSalts) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "future_salts",
		ID:   FutureSaltsTypeID,
	}
	if f == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "ReqMsgID",
			SchemaName: "req_msg_id",
		},
		{
			Name:       "Now",
			SchemaName: "now",
		},
		{
			Name:       "Salts",
			SchemaName: "salts",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (f *FutureSalts) Encode(b *bin.Buffer) error {
	if f == nil {
		return fmt.Errorf("can't encode future_salts#ae500895 as nil")
	}
	b.PutID(FutureSaltsTypeID)
	b.PutLong(f.ReqMsgID)
	b.PutInt(f.Now)
	b.PutInt(len(f.Salts))
	for idx, v := range f.Salts {
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode future_salts#ae500895: field salts element with index %d: %w", idx, err)
		}
	}
	return nil
}

// GetReqMsgID returns value of ReqMsgID field.
func (f *FutureSalts) GetReqMsgID() (value int64) {
	return f.ReqMsgID
}

// GetNow returns value of Now field.
func (f *FutureSalts) GetNow() (value int) {
	return f.Now
}

// GetSalts returns value of Salts field.
func (f *FutureSalts) GetSalts() (value []FutureSalt) {
	return f.Salts
}

// Decode implements bin.Decoder.
func (f *FutureSalts) Decode(b *bin.Buffer) error {
	if f == nil {
		return fmt.Errorf("can't decode future_salts#ae500895 to nil")
	}
	if err := b.ConsumeID(FutureSaltsTypeID); err != nil {
		return fmt.Errorf("unable to decode future_salts#ae500895: %w", err)
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode future_salts#ae500895: field req_msg_id: %w", err)
		}
		f.ReqMsgID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode future_salts#ae500895: field now: %w", err)
		}
		f.Now = value
	}
	{
		headerLen, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode future_salts#ae500895: field salts: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			var value FutureSalt
			if err := value.Decode(b); err != nil {
				return fmt.Errorf("unable to decode future_salts#ae500895: field salts: %w", err)
			}
			f.Salts = append(f.Salts, value)
		}
	}
	return nil
}

// Ensuring interfaces in compile-time for FutureSalts.
var (
	_ bin.Encoder = &FutureSalts{}
	_ bin.Decoder = &FutureSalts{}
)
