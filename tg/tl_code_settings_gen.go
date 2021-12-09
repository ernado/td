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

// CodeSettings represents TL type `codeSettings#8a6469c2`.
// Settings used by telegram servers for sending the confirm code.
// Example implementations: telegram for android¹, tdlib².
//
// Links:
//  1) https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/ui/LoginActivity.java
//  2) https://github.com/tdlib/td/tree/master/td/telegram/SendCodeHelper.cpp
//
// See https://core.telegram.org/constructor/codeSettings for reference.
type CodeSettings struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields
	// Whether to allow phone verification via phone calls¹.
	//
	// Links:
	//  1) https://core.telegram.org/api/auth
	AllowFlashcall bool
	// Pass true if the phone number is used on the current device. Ignored if
	// allow_flashcall is not set.
	CurrentNumber bool
	// If a token that will be included in eventually sent SMSs is required: required in
	// newer versions of android, to use the android SMS receiver APIs¹
	//
	// Links:
	//  1) https://developers.google.com/identity/sms-retriever/overview
	AllowAppHash bool
	// AllowMissedCall field of CodeSettings.
	AllowMissedCall bool
	// LogoutTokens field of CodeSettings.
	//
	// Use SetLogoutTokens and GetLogoutTokens helpers.
	LogoutTokens [][]byte
}

// CodeSettingsTypeID is TL type id of CodeSettings.
const CodeSettingsTypeID = 0x8a6469c2

// Ensuring interfaces in compile-time for CodeSettings.
var (
	_ bin.Encoder     = &CodeSettings{}
	_ bin.Decoder     = &CodeSettings{}
	_ bin.BareEncoder = &CodeSettings{}
	_ bin.BareDecoder = &CodeSettings{}
)

func (c *CodeSettings) Zero() bool {
	if c == nil {
		return true
	}
	if !(c.Flags.Zero()) {
		return false
	}
	if !(c.AllowFlashcall == false) {
		return false
	}
	if !(c.CurrentNumber == false) {
		return false
	}
	if !(c.AllowAppHash == false) {
		return false
	}
	if !(c.AllowMissedCall == false) {
		return false
	}
	if !(c.LogoutTokens == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (c *CodeSettings) String() string {
	if c == nil {
		return "CodeSettings(nil)"
	}
	type Alias CodeSettings
	return fmt.Sprintf("CodeSettings%+v", Alias(*c))
}

// FillFrom fills CodeSettings from given interface.
func (c *CodeSettings) FillFrom(from interface {
	GetAllowFlashcall() (value bool)
	GetCurrentNumber() (value bool)
	GetAllowAppHash() (value bool)
	GetAllowMissedCall() (value bool)
	GetLogoutTokens() (value [][]byte, ok bool)
}) {
	c.AllowFlashcall = from.GetAllowFlashcall()
	c.CurrentNumber = from.GetCurrentNumber()
	c.AllowAppHash = from.GetAllowAppHash()
	c.AllowMissedCall = from.GetAllowMissedCall()
	if val, ok := from.GetLogoutTokens(); ok {
		c.LogoutTokens = val
	}

}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*CodeSettings) TypeID() uint32 {
	return CodeSettingsTypeID
}

// TypeName returns name of type in TL schema.
func (*CodeSettings) TypeName() string {
	return "codeSettings"
}

// TypeInfo returns info about TL type.
func (c *CodeSettings) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "codeSettings",
		ID:   CodeSettingsTypeID,
	}
	if c == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "AllowFlashcall",
			SchemaName: "allow_flashcall",
			Null:       !c.Flags.Has(0),
		},
		{
			Name:       "CurrentNumber",
			SchemaName: "current_number",
			Null:       !c.Flags.Has(1),
		},
		{
			Name:       "AllowAppHash",
			SchemaName: "allow_app_hash",
			Null:       !c.Flags.Has(4),
		},
		{
			Name:       "AllowMissedCall",
			SchemaName: "allow_missed_call",
			Null:       !c.Flags.Has(5),
		},
		{
			Name:       "LogoutTokens",
			SchemaName: "logout_tokens",
			Null:       !c.Flags.Has(6),
		},
	}
	return typ
}

// SetFlags sets flags for non-zero fields.
func (c *CodeSettings) SetFlags() {
	if !(c.AllowFlashcall == false) {
		c.Flags.Set(0)
	}
	if !(c.CurrentNumber == false) {
		c.Flags.Set(1)
	}
	if !(c.AllowAppHash == false) {
		c.Flags.Set(4)
	}
	if !(c.AllowMissedCall == false) {
		c.Flags.Set(5)
	}
	if !(c.LogoutTokens == nil) {
		c.Flags.Set(6)
	}
}

// Encode implements bin.Encoder.
func (c *CodeSettings) Encode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode codeSettings#8a6469c2 as nil")
	}
	b.PutID(CodeSettingsTypeID)
	return c.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (c *CodeSettings) EncodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode codeSettings#8a6469c2 as nil")
	}
	c.SetFlags()
	if err := c.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode codeSettings#8a6469c2: field flags: %w", err)
	}
	if c.Flags.Has(6) {
		b.PutVectorHeader(len(c.LogoutTokens))
		for _, v := range c.LogoutTokens {
			b.PutBytes(v)
		}
	}
	return nil
}

// Decode implements bin.Decoder.
func (c *CodeSettings) Decode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode codeSettings#8a6469c2 to nil")
	}
	if err := b.ConsumeID(CodeSettingsTypeID); err != nil {
		return fmt.Errorf("unable to decode codeSettings#8a6469c2: %w", err)
	}
	return c.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (c *CodeSettings) DecodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode codeSettings#8a6469c2 to nil")
	}
	{
		if err := c.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode codeSettings#8a6469c2: field flags: %w", err)
		}
	}
	c.AllowFlashcall = c.Flags.Has(0)
	c.CurrentNumber = c.Flags.Has(1)
	c.AllowAppHash = c.Flags.Has(4)
	c.AllowMissedCall = c.Flags.Has(5)
	if c.Flags.Has(6) {
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode codeSettings#8a6469c2: field logout_tokens: %w", err)
		}

		if headerLen > 0 {
			c.LogoutTokens = make([][]byte, 0, headerLen%bin.PreallocateLimit)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := b.Bytes()
			if err != nil {
				return fmt.Errorf("unable to decode codeSettings#8a6469c2: field logout_tokens: %w", err)
			}
			c.LogoutTokens = append(c.LogoutTokens, value)
		}
	}
	return nil
}

// SetAllowFlashcall sets value of AllowFlashcall conditional field.
func (c *CodeSettings) SetAllowFlashcall(value bool) {
	if value {
		c.Flags.Set(0)
		c.AllowFlashcall = true
	} else {
		c.Flags.Unset(0)
		c.AllowFlashcall = false
	}
}

// GetAllowFlashcall returns value of AllowFlashcall conditional field.
func (c *CodeSettings) GetAllowFlashcall() (value bool) {
	return c.Flags.Has(0)
}

// SetCurrentNumber sets value of CurrentNumber conditional field.
func (c *CodeSettings) SetCurrentNumber(value bool) {
	if value {
		c.Flags.Set(1)
		c.CurrentNumber = true
	} else {
		c.Flags.Unset(1)
		c.CurrentNumber = false
	}
}

// GetCurrentNumber returns value of CurrentNumber conditional field.
func (c *CodeSettings) GetCurrentNumber() (value bool) {
	return c.Flags.Has(1)
}

// SetAllowAppHash sets value of AllowAppHash conditional field.
func (c *CodeSettings) SetAllowAppHash(value bool) {
	if value {
		c.Flags.Set(4)
		c.AllowAppHash = true
	} else {
		c.Flags.Unset(4)
		c.AllowAppHash = false
	}
}

// GetAllowAppHash returns value of AllowAppHash conditional field.
func (c *CodeSettings) GetAllowAppHash() (value bool) {
	return c.Flags.Has(4)
}

// SetAllowMissedCall sets value of AllowMissedCall conditional field.
func (c *CodeSettings) SetAllowMissedCall(value bool) {
	if value {
		c.Flags.Set(5)
		c.AllowMissedCall = true
	} else {
		c.Flags.Unset(5)
		c.AllowMissedCall = false
	}
}

// GetAllowMissedCall returns value of AllowMissedCall conditional field.
func (c *CodeSettings) GetAllowMissedCall() (value bool) {
	return c.Flags.Has(5)
}

// SetLogoutTokens sets value of LogoutTokens conditional field.
func (c *CodeSettings) SetLogoutTokens(value [][]byte) {
	c.Flags.Set(6)
	c.LogoutTokens = value
}

// GetLogoutTokens returns value of LogoutTokens conditional field and
// boolean which is true if field was set.
func (c *CodeSettings) GetLogoutTokens() (value [][]byte, ok bool) {
	if !c.Flags.Has(6) {
		return value, false
	}
	return c.LogoutTokens, true
}
