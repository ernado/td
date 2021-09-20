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

// PaymentsPaymentReceipt represents TL type `payments.paymentReceipt#70c4fe03`.
// Receipt
//
// See https://core.telegram.org/constructor/payments.paymentReceipt for reference.
type PaymentsPaymentReceipt struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields
	// Date of generation
	Date int
	// Bot ID
	BotID int64
	// Provider ID
	ProviderID int64
	// Title field of PaymentsPaymentReceipt.
	Title string
	// Description field of PaymentsPaymentReceipt.
	Description string
	// Photo field of PaymentsPaymentReceipt.
	//
	// Use SetPhoto and GetPhoto helpers.
	Photo WebDocumentClass
	// Invoice
	Invoice Invoice
	// Info
	//
	// Use SetInfo and GetInfo helpers.
	Info PaymentRequestedInfo
	// Selected shipping option
	//
	// Use SetShipping and GetShipping helpers.
	Shipping ShippingOption
	// TipAmount field of PaymentsPaymentReceipt.
	//
	// Use SetTipAmount and GetTipAmount helpers.
	TipAmount int64
	// Three-letter ISO 4217 currency¹ code
	//
	// Links:
	//  1) https://core.telegram.org/bots/payments#supported-currencies
	Currency string
	// Total amount in the smallest units of the currency (integer, not float/double). For
	// example, for a price of US$ 1.45 pass amount = 145. See the exp parameter in
	// currencies.json¹, it shows the number of digits past the decimal point for each
	// currency (2 for the majority of currencies).
	//
	// Links:
	//  1) https://core.telegram.org/bots/payments/currencies.json
	TotalAmount int64
	// Payment credential name
	CredentialsTitle string
	// Users
	Users []UserClass
}

// PaymentsPaymentReceiptTypeID is TL type id of PaymentsPaymentReceipt.
const PaymentsPaymentReceiptTypeID = 0x70c4fe03

// Ensuring interfaces in compile-time for PaymentsPaymentReceipt.
var (
	_ bin.Encoder     = &PaymentsPaymentReceipt{}
	_ bin.Decoder     = &PaymentsPaymentReceipt{}
	_ bin.BareEncoder = &PaymentsPaymentReceipt{}
	_ bin.BareDecoder = &PaymentsPaymentReceipt{}
)

func (p *PaymentsPaymentReceipt) Zero() bool {
	if p == nil {
		return true
	}
	if !(p.Flags.Zero()) {
		return false
	}
	if !(p.Date == 0) {
		return false
	}
	if !(p.BotID == 0) {
		return false
	}
	if !(p.ProviderID == 0) {
		return false
	}
	if !(p.Title == "") {
		return false
	}
	if !(p.Description == "") {
		return false
	}
	if !(p.Photo == nil) {
		return false
	}
	if !(p.Invoice.Zero()) {
		return false
	}
	if !(p.Info.Zero()) {
		return false
	}
	if !(p.Shipping.Zero()) {
		return false
	}
	if !(p.TipAmount == 0) {
		return false
	}
	if !(p.Currency == "") {
		return false
	}
	if !(p.TotalAmount == 0) {
		return false
	}
	if !(p.CredentialsTitle == "") {
		return false
	}
	if !(p.Users == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (p *PaymentsPaymentReceipt) String() string {
	if p == nil {
		return "PaymentsPaymentReceipt(nil)"
	}
	type Alias PaymentsPaymentReceipt
	return fmt.Sprintf("PaymentsPaymentReceipt%+v", Alias(*p))
}

// FillFrom fills PaymentsPaymentReceipt from given interface.
func (p *PaymentsPaymentReceipt) FillFrom(from interface {
	GetDate() (value int)
	GetBotID() (value int64)
	GetProviderID() (value int64)
	GetTitle() (value string)
	GetDescription() (value string)
	GetPhoto() (value WebDocumentClass, ok bool)
	GetInvoice() (value Invoice)
	GetInfo() (value PaymentRequestedInfo, ok bool)
	GetShipping() (value ShippingOption, ok bool)
	GetTipAmount() (value int64, ok bool)
	GetCurrency() (value string)
	GetTotalAmount() (value int64)
	GetCredentialsTitle() (value string)
	GetUsers() (value []UserClass)
}) {
	p.Date = from.GetDate()
	p.BotID = from.GetBotID()
	p.ProviderID = from.GetProviderID()
	p.Title = from.GetTitle()
	p.Description = from.GetDescription()
	if val, ok := from.GetPhoto(); ok {
		p.Photo = val
	}

	p.Invoice = from.GetInvoice()
	if val, ok := from.GetInfo(); ok {
		p.Info = val
	}

	if val, ok := from.GetShipping(); ok {
		p.Shipping = val
	}

	if val, ok := from.GetTipAmount(); ok {
		p.TipAmount = val
	}

	p.Currency = from.GetCurrency()
	p.TotalAmount = from.GetTotalAmount()
	p.CredentialsTitle = from.GetCredentialsTitle()
	p.Users = from.GetUsers()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*PaymentsPaymentReceipt) TypeID() uint32 {
	return PaymentsPaymentReceiptTypeID
}

// TypeName returns name of type in TL schema.
func (*PaymentsPaymentReceipt) TypeName() string {
	return "payments.paymentReceipt"
}

// TypeInfo returns info about TL type.
func (p *PaymentsPaymentReceipt) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "payments.paymentReceipt",
		ID:   PaymentsPaymentReceiptTypeID,
	}
	if p == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Date",
			SchemaName: "date",
		},
		{
			Name:       "BotID",
			SchemaName: "bot_id",
		},
		{
			Name:       "ProviderID",
			SchemaName: "provider_id",
		},
		{
			Name:       "Title",
			SchemaName: "title",
		},
		{
			Name:       "Description",
			SchemaName: "description",
		},
		{
			Name:       "Photo",
			SchemaName: "photo",
			Null:       !p.Flags.Has(2),
		},
		{
			Name:       "Invoice",
			SchemaName: "invoice",
		},
		{
			Name:       "Info",
			SchemaName: "info",
			Null:       !p.Flags.Has(0),
		},
		{
			Name:       "Shipping",
			SchemaName: "shipping",
			Null:       !p.Flags.Has(1),
		},
		{
			Name:       "TipAmount",
			SchemaName: "tip_amount",
			Null:       !p.Flags.Has(3),
		},
		{
			Name:       "Currency",
			SchemaName: "currency",
		},
		{
			Name:       "TotalAmount",
			SchemaName: "total_amount",
		},
		{
			Name:       "CredentialsTitle",
			SchemaName: "credentials_title",
		},
		{
			Name:       "Users",
			SchemaName: "users",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (p *PaymentsPaymentReceipt) Encode(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't encode payments.paymentReceipt#70c4fe03 as nil")
	}
	b.PutID(PaymentsPaymentReceiptTypeID)
	return p.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (p *PaymentsPaymentReceipt) EncodeBare(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't encode payments.paymentReceipt#70c4fe03 as nil")
	}
	if !(p.Photo == nil) {
		p.Flags.Set(2)
	}
	if !(p.Info.Zero()) {
		p.Flags.Set(0)
	}
	if !(p.Shipping.Zero()) {
		p.Flags.Set(1)
	}
	if !(p.TipAmount == 0) {
		p.Flags.Set(3)
	}
	if err := p.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode payments.paymentReceipt#70c4fe03: field flags: %w", err)
	}
	b.PutInt(p.Date)
	b.PutLong(p.BotID)
	b.PutLong(p.ProviderID)
	b.PutString(p.Title)
	b.PutString(p.Description)
	if p.Flags.Has(2) {
		if p.Photo == nil {
			return fmt.Errorf("unable to encode payments.paymentReceipt#70c4fe03: field photo is nil")
		}
		if err := p.Photo.Encode(b); err != nil {
			return fmt.Errorf("unable to encode payments.paymentReceipt#70c4fe03: field photo: %w", err)
		}
	}
	if err := p.Invoice.Encode(b); err != nil {
		return fmt.Errorf("unable to encode payments.paymentReceipt#70c4fe03: field invoice: %w", err)
	}
	if p.Flags.Has(0) {
		if err := p.Info.Encode(b); err != nil {
			return fmt.Errorf("unable to encode payments.paymentReceipt#70c4fe03: field info: %w", err)
		}
	}
	if p.Flags.Has(1) {
		if err := p.Shipping.Encode(b); err != nil {
			return fmt.Errorf("unable to encode payments.paymentReceipt#70c4fe03: field shipping: %w", err)
		}
	}
	if p.Flags.Has(3) {
		b.PutLong(p.TipAmount)
	}
	b.PutString(p.Currency)
	b.PutLong(p.TotalAmount)
	b.PutString(p.CredentialsTitle)
	b.PutVectorHeader(len(p.Users))
	for idx, v := range p.Users {
		if v == nil {
			return fmt.Errorf("unable to encode payments.paymentReceipt#70c4fe03: field users element with index %d is nil", idx)
		}
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode payments.paymentReceipt#70c4fe03: field users element with index %d: %w", idx, err)
		}
	}
	return nil
}

// Decode implements bin.Decoder.
func (p *PaymentsPaymentReceipt) Decode(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't decode payments.paymentReceipt#70c4fe03 to nil")
	}
	if err := b.ConsumeID(PaymentsPaymentReceiptTypeID); err != nil {
		return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: %w", err)
	}
	return p.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (p *PaymentsPaymentReceipt) DecodeBare(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't decode payments.paymentReceipt#70c4fe03 to nil")
	}
	{
		if err := p.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field flags: %w", err)
		}
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field date: %w", err)
		}
		p.Date = value
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field bot_id: %w", err)
		}
		p.BotID = value
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field provider_id: %w", err)
		}
		p.ProviderID = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field title: %w", err)
		}
		p.Title = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field description: %w", err)
		}
		p.Description = value
	}
	if p.Flags.Has(2) {
		value, err := DecodeWebDocument(b)
		if err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field photo: %w", err)
		}
		p.Photo = value
	}
	{
		if err := p.Invoice.Decode(b); err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field invoice: %w", err)
		}
	}
	if p.Flags.Has(0) {
		if err := p.Info.Decode(b); err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field info: %w", err)
		}
	}
	if p.Flags.Has(1) {
		if err := p.Shipping.Decode(b); err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field shipping: %w", err)
		}
	}
	if p.Flags.Has(3) {
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field tip_amount: %w", err)
		}
		p.TipAmount = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field currency: %w", err)
		}
		p.Currency = value
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field total_amount: %w", err)
		}
		p.TotalAmount = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field credentials_title: %w", err)
		}
		p.CredentialsTitle = value
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field users: %w", err)
		}

		if headerLen > 0 {
			p.Users = make([]UserClass, 0, headerLen%bin.PreallocateLimit)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeUser(b)
			if err != nil {
				return fmt.Errorf("unable to decode payments.paymentReceipt#70c4fe03: field users: %w", err)
			}
			p.Users = append(p.Users, value)
		}
	}
	return nil
}

// GetDate returns value of Date field.
func (p *PaymentsPaymentReceipt) GetDate() (value int) {
	return p.Date
}

// GetBotID returns value of BotID field.
func (p *PaymentsPaymentReceipt) GetBotID() (value int64) {
	return p.BotID
}

// GetProviderID returns value of ProviderID field.
func (p *PaymentsPaymentReceipt) GetProviderID() (value int64) {
	return p.ProviderID
}

// GetTitle returns value of Title field.
func (p *PaymentsPaymentReceipt) GetTitle() (value string) {
	return p.Title
}

// GetDescription returns value of Description field.
func (p *PaymentsPaymentReceipt) GetDescription() (value string) {
	return p.Description
}

// SetPhoto sets value of Photo conditional field.
func (p *PaymentsPaymentReceipt) SetPhoto(value WebDocumentClass) {
	p.Flags.Set(2)
	p.Photo = value
}

// GetPhoto returns value of Photo conditional field and
// boolean which is true if field was set.
func (p *PaymentsPaymentReceipt) GetPhoto() (value WebDocumentClass, ok bool) {
	if !p.Flags.Has(2) {
		return value, false
	}
	return p.Photo, true
}

// GetInvoice returns value of Invoice field.
func (p *PaymentsPaymentReceipt) GetInvoice() (value Invoice) {
	return p.Invoice
}

// SetInfo sets value of Info conditional field.
func (p *PaymentsPaymentReceipt) SetInfo(value PaymentRequestedInfo) {
	p.Flags.Set(0)
	p.Info = value
}

// GetInfo returns value of Info conditional field and
// boolean which is true if field was set.
func (p *PaymentsPaymentReceipt) GetInfo() (value PaymentRequestedInfo, ok bool) {
	if !p.Flags.Has(0) {
		return value, false
	}
	return p.Info, true
}

// SetShipping sets value of Shipping conditional field.
func (p *PaymentsPaymentReceipt) SetShipping(value ShippingOption) {
	p.Flags.Set(1)
	p.Shipping = value
}

// GetShipping returns value of Shipping conditional field and
// boolean which is true if field was set.
func (p *PaymentsPaymentReceipt) GetShipping() (value ShippingOption, ok bool) {
	if !p.Flags.Has(1) {
		return value, false
	}
	return p.Shipping, true
}

// SetTipAmount sets value of TipAmount conditional field.
func (p *PaymentsPaymentReceipt) SetTipAmount(value int64) {
	p.Flags.Set(3)
	p.TipAmount = value
}

// GetTipAmount returns value of TipAmount conditional field and
// boolean which is true if field was set.
func (p *PaymentsPaymentReceipt) GetTipAmount() (value int64, ok bool) {
	if !p.Flags.Has(3) {
		return value, false
	}
	return p.TipAmount, true
}

// GetCurrency returns value of Currency field.
func (p *PaymentsPaymentReceipt) GetCurrency() (value string) {
	return p.Currency
}

// GetTotalAmount returns value of TotalAmount field.
func (p *PaymentsPaymentReceipt) GetTotalAmount() (value int64) {
	return p.TotalAmount
}

// GetCredentialsTitle returns value of CredentialsTitle field.
func (p *PaymentsPaymentReceipt) GetCredentialsTitle() (value string) {
	return p.CredentialsTitle
}

// GetUsers returns value of Users field.
func (p *PaymentsPaymentReceipt) GetUsers() (value []UserClass) {
	return p.Users
}

// MapUsers returns field Users wrapped in UserClassArray helper.
func (p *PaymentsPaymentReceipt) MapUsers() (value UserClassArray) {
	return UserClassArray(p.Users)
}
