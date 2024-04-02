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

// AccountResolveBusinessChatLinkRequest represents TL type `account.resolveBusinessChatLink#5492e5ee`.
//
// See https://core.telegram.org/method/account.resolveBusinessChatLink for reference.
type AccountResolveBusinessChatLinkRequest struct {
	// Slug field of AccountResolveBusinessChatLinkRequest.
	Slug string
}

// AccountResolveBusinessChatLinkRequestTypeID is TL type id of AccountResolveBusinessChatLinkRequest.
const AccountResolveBusinessChatLinkRequestTypeID = 0x5492e5ee

// Ensuring interfaces in compile-time for AccountResolveBusinessChatLinkRequest.
var (
	_ bin.Encoder     = &AccountResolveBusinessChatLinkRequest{}
	_ bin.Decoder     = &AccountResolveBusinessChatLinkRequest{}
	_ bin.BareEncoder = &AccountResolveBusinessChatLinkRequest{}
	_ bin.BareDecoder = &AccountResolveBusinessChatLinkRequest{}
)

func (r *AccountResolveBusinessChatLinkRequest) Zero() bool {
	if r == nil {
		return true
	}
	if !(r.Slug == "") {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (r *AccountResolveBusinessChatLinkRequest) String() string {
	if r == nil {
		return "AccountResolveBusinessChatLinkRequest(nil)"
	}
	type Alias AccountResolveBusinessChatLinkRequest
	return fmt.Sprintf("AccountResolveBusinessChatLinkRequest%+v", Alias(*r))
}

// FillFrom fills AccountResolveBusinessChatLinkRequest from given interface.
func (r *AccountResolveBusinessChatLinkRequest) FillFrom(from interface {
	GetSlug() (value string)
}) {
	r.Slug = from.GetSlug()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*AccountResolveBusinessChatLinkRequest) TypeID() uint32 {
	return AccountResolveBusinessChatLinkRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*AccountResolveBusinessChatLinkRequest) TypeName() string {
	return "account.resolveBusinessChatLink"
}

// TypeInfo returns info about TL type.
func (r *AccountResolveBusinessChatLinkRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "account.resolveBusinessChatLink",
		ID:   AccountResolveBusinessChatLinkRequestTypeID,
	}
	if r == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Slug",
			SchemaName: "slug",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (r *AccountResolveBusinessChatLinkRequest) Encode(b *bin.Buffer) error {
	if r == nil {
		return fmt.Errorf("can't encode account.resolveBusinessChatLink#5492e5ee as nil")
	}
	b.PutID(AccountResolveBusinessChatLinkRequestTypeID)
	return r.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (r *AccountResolveBusinessChatLinkRequest) EncodeBare(b *bin.Buffer) error {
	if r == nil {
		return fmt.Errorf("can't encode account.resolveBusinessChatLink#5492e5ee as nil")
	}
	b.PutString(r.Slug)
	return nil
}

// Decode implements bin.Decoder.
func (r *AccountResolveBusinessChatLinkRequest) Decode(b *bin.Buffer) error {
	if r == nil {
		return fmt.Errorf("can't decode account.resolveBusinessChatLink#5492e5ee to nil")
	}
	if err := b.ConsumeID(AccountResolveBusinessChatLinkRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode account.resolveBusinessChatLink#5492e5ee: %w", err)
	}
	return r.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (r *AccountResolveBusinessChatLinkRequest) DecodeBare(b *bin.Buffer) error {
	if r == nil {
		return fmt.Errorf("can't decode account.resolveBusinessChatLink#5492e5ee to nil")
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode account.resolveBusinessChatLink#5492e5ee: field slug: %w", err)
		}
		r.Slug = value
	}
	return nil
}

// GetSlug returns value of Slug field.
func (r *AccountResolveBusinessChatLinkRequest) GetSlug() (value string) {
	if r == nil {
		return
	}
	return r.Slug
}

// AccountResolveBusinessChatLink invokes method account.resolveBusinessChatLink#5492e5ee returning error if any.
//
// See https://core.telegram.org/method/account.resolveBusinessChatLink for reference.
func (c *Client) AccountResolveBusinessChatLink(ctx context.Context, slug string) (*AccountResolvedBusinessChatLinks, error) {
	var result AccountResolvedBusinessChatLinks

	request := &AccountResolveBusinessChatLinkRequest{
		Slug: slug,
	}
	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
