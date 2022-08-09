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

// PeerNotifySettings represents TL type `peerNotifySettings#a83b0426`.
// Notification settings.
//
// See https://core.telegram.org/constructor/peerNotifySettings for reference.
type PeerNotifySettings struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields
	// Display text in notifications
	//
	// Use SetShowPreviews and GetShowPreviews helpers.
	ShowPreviews bool
	// Mute peer?
	//
	// Use SetSilent and GetSilent helpers.
	Silent bool
	// Mute all notifications until this date
	//
	// Use SetMuteUntil and GetMuteUntil helpers.
	MuteUntil int
	//
	//
	// Use SetIosSound and GetIosSound helpers.
	IosSound NotificationSoundClass
	//
	//
	// Use SetAndroidSound and GetAndroidSound helpers.
	AndroidSound NotificationSoundClass
	//
	//
	// Use SetOtherSound and GetOtherSound helpers.
	OtherSound NotificationSoundClass
}

// PeerNotifySettingsTypeID is TL type id of PeerNotifySettings.
const PeerNotifySettingsTypeID = 0xa83b0426

// Ensuring interfaces in compile-time for PeerNotifySettings.
var (
	_ bin.Encoder     = &PeerNotifySettings{}
	_ bin.Decoder     = &PeerNotifySettings{}
	_ bin.BareEncoder = &PeerNotifySettings{}
	_ bin.BareDecoder = &PeerNotifySettings{}
)

func (p *PeerNotifySettings) Zero() bool {
	if p == nil {
		return true
	}
	if !(p.Flags.Zero()) {
		return false
	}
	if !(p.ShowPreviews == false) {
		return false
	}
	if !(p.Silent == false) {
		return false
	}
	if !(p.MuteUntil == 0) {
		return false
	}
	if !(p.IosSound == nil) {
		return false
	}
	if !(p.AndroidSound == nil) {
		return false
	}
	if !(p.OtherSound == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (p *PeerNotifySettings) String() string {
	if p == nil {
		return "PeerNotifySettings(nil)"
	}
	type Alias PeerNotifySettings
	return fmt.Sprintf("PeerNotifySettings%+v", Alias(*p))
}

// FillFrom fills PeerNotifySettings from given interface.
func (p *PeerNotifySettings) FillFrom(from interface {
	GetShowPreviews() (value bool, ok bool)
	GetSilent() (value bool, ok bool)
	GetMuteUntil() (value int, ok bool)
	GetIosSound() (value NotificationSoundClass, ok bool)
	GetAndroidSound() (value NotificationSoundClass, ok bool)
	GetOtherSound() (value NotificationSoundClass, ok bool)
}) {
	if val, ok := from.GetShowPreviews(); ok {
		p.ShowPreviews = val
	}

	if val, ok := from.GetSilent(); ok {
		p.Silent = val
	}

	if val, ok := from.GetMuteUntil(); ok {
		p.MuteUntil = val
	}

	if val, ok := from.GetIosSound(); ok {
		p.IosSound = val
	}

	if val, ok := from.GetAndroidSound(); ok {
		p.AndroidSound = val
	}

	if val, ok := from.GetOtherSound(); ok {
		p.OtherSound = val
	}

}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*PeerNotifySettings) TypeID() uint32 {
	return PeerNotifySettingsTypeID
}

// TypeName returns name of type in TL schema.
func (*PeerNotifySettings) TypeName() string {
	return "peerNotifySettings"
}

// TypeInfo returns info about TL type.
func (p *PeerNotifySettings) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "peerNotifySettings",
		ID:   PeerNotifySettingsTypeID,
	}
	if p == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "ShowPreviews",
			SchemaName: "show_previews",
			Null:       !p.Flags.Has(0),
		},
		{
			Name:       "Silent",
			SchemaName: "silent",
			Null:       !p.Flags.Has(1),
		},
		{
			Name:       "MuteUntil",
			SchemaName: "mute_until",
			Null:       !p.Flags.Has(2),
		},
		{
			Name:       "IosSound",
			SchemaName: "ios_sound",
			Null:       !p.Flags.Has(3),
		},
		{
			Name:       "AndroidSound",
			SchemaName: "android_sound",
			Null:       !p.Flags.Has(4),
		},
		{
			Name:       "OtherSound",
			SchemaName: "other_sound",
			Null:       !p.Flags.Has(5),
		},
	}
	return typ
}

// SetFlags sets flags for non-zero fields.
func (p *PeerNotifySettings) SetFlags() {
	if !(p.ShowPreviews == false) {
		p.Flags.Set(0)
	}
	if !(p.Silent == false) {
		p.Flags.Set(1)
	}
	if !(p.MuteUntil == 0) {
		p.Flags.Set(2)
	}
	if !(p.IosSound == nil) {
		p.Flags.Set(3)
	}
	if !(p.AndroidSound == nil) {
		p.Flags.Set(4)
	}
	if !(p.OtherSound == nil) {
		p.Flags.Set(5)
	}
}

// Encode implements bin.Encoder.
func (p *PeerNotifySettings) Encode(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't encode peerNotifySettings#a83b0426 as nil")
	}
	b.PutID(PeerNotifySettingsTypeID)
	return p.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (p *PeerNotifySettings) EncodeBare(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't encode peerNotifySettings#a83b0426 as nil")
	}
	p.SetFlags()
	if err := p.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode peerNotifySettings#a83b0426: field flags: %w", err)
	}
	if p.Flags.Has(0) {
		b.PutBool(p.ShowPreviews)
	}
	if p.Flags.Has(1) {
		b.PutBool(p.Silent)
	}
	if p.Flags.Has(2) {
		b.PutInt(p.MuteUntil)
	}
	if p.Flags.Has(3) {
		if p.IosSound == nil {
			return fmt.Errorf("unable to encode peerNotifySettings#a83b0426: field ios_sound is nil")
		}
		if err := p.IosSound.Encode(b); err != nil {
			return fmt.Errorf("unable to encode peerNotifySettings#a83b0426: field ios_sound: %w", err)
		}
	}
	if p.Flags.Has(4) {
		if p.AndroidSound == nil {
			return fmt.Errorf("unable to encode peerNotifySettings#a83b0426: field android_sound is nil")
		}
		if err := p.AndroidSound.Encode(b); err != nil {
			return fmt.Errorf("unable to encode peerNotifySettings#a83b0426: field android_sound: %w", err)
		}
	}
	if p.Flags.Has(5) {
		if p.OtherSound == nil {
			return fmt.Errorf("unable to encode peerNotifySettings#a83b0426: field other_sound is nil")
		}
		if err := p.OtherSound.Encode(b); err != nil {
			return fmt.Errorf("unable to encode peerNotifySettings#a83b0426: field other_sound: %w", err)
		}
	}
	return nil
}

// Decode implements bin.Decoder.
func (p *PeerNotifySettings) Decode(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't decode peerNotifySettings#a83b0426 to nil")
	}
	if err := b.ConsumeID(PeerNotifySettingsTypeID); err != nil {
		return fmt.Errorf("unable to decode peerNotifySettings#a83b0426: %w", err)
	}
	return p.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (p *PeerNotifySettings) DecodeBare(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't decode peerNotifySettings#a83b0426 to nil")
	}
	{
		if err := p.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode peerNotifySettings#a83b0426: field flags: %w", err)
		}
	}
	if p.Flags.Has(0) {
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode peerNotifySettings#a83b0426: field show_previews: %w", err)
		}
		p.ShowPreviews = value
	}
	if p.Flags.Has(1) {
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode peerNotifySettings#a83b0426: field silent: %w", err)
		}
		p.Silent = value
	}
	if p.Flags.Has(2) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode peerNotifySettings#a83b0426: field mute_until: %w", err)
		}
		p.MuteUntil = value
	}
	if p.Flags.Has(3) {
		value, err := DecodeNotificationSound(b)
		if err != nil {
			return fmt.Errorf("unable to decode peerNotifySettings#a83b0426: field ios_sound: %w", err)
		}
		p.IosSound = value
	}
	if p.Flags.Has(4) {
		value, err := DecodeNotificationSound(b)
		if err != nil {
			return fmt.Errorf("unable to decode peerNotifySettings#a83b0426: field android_sound: %w", err)
		}
		p.AndroidSound = value
	}
	if p.Flags.Has(5) {
		value, err := DecodeNotificationSound(b)
		if err != nil {
			return fmt.Errorf("unable to decode peerNotifySettings#a83b0426: field other_sound: %w", err)
		}
		p.OtherSound = value
	}
	return nil
}

// SetShowPreviews sets value of ShowPreviews conditional field.
func (p *PeerNotifySettings) SetShowPreviews(value bool) {
	p.Flags.Set(0)
	p.ShowPreviews = value
}

// GetShowPreviews returns value of ShowPreviews conditional field and
// boolean which is true if field was set.
func (p *PeerNotifySettings) GetShowPreviews() (value bool, ok bool) {
	if p == nil {
		return
	}
	if !p.Flags.Has(0) {
		return value, false
	}
	return p.ShowPreviews, true
}

// SetSilent sets value of Silent conditional field.
func (p *PeerNotifySettings) SetSilent(value bool) {
	p.Flags.Set(1)
	p.Silent = value
}

// GetSilent returns value of Silent conditional field and
// boolean which is true if field was set.
func (p *PeerNotifySettings) GetSilent() (value bool, ok bool) {
	if p == nil {
		return
	}
	if !p.Flags.Has(1) {
		return value, false
	}
	return p.Silent, true
}

// SetMuteUntil sets value of MuteUntil conditional field.
func (p *PeerNotifySettings) SetMuteUntil(value int) {
	p.Flags.Set(2)
	p.MuteUntil = value
}

// GetMuteUntil returns value of MuteUntil conditional field and
// boolean which is true if field was set.
func (p *PeerNotifySettings) GetMuteUntil() (value int, ok bool) {
	if p == nil {
		return
	}
	if !p.Flags.Has(2) {
		return value, false
	}
	return p.MuteUntil, true
}

// SetIosSound sets value of IosSound conditional field.
func (p *PeerNotifySettings) SetIosSound(value NotificationSoundClass) {
	p.Flags.Set(3)
	p.IosSound = value
}

// GetIosSound returns value of IosSound conditional field and
// boolean which is true if field was set.
func (p *PeerNotifySettings) GetIosSound() (value NotificationSoundClass, ok bool) {
	if p == nil {
		return
	}
	if !p.Flags.Has(3) {
		return value, false
	}
	return p.IosSound, true
}

// SetAndroidSound sets value of AndroidSound conditional field.
func (p *PeerNotifySettings) SetAndroidSound(value NotificationSoundClass) {
	p.Flags.Set(4)
	p.AndroidSound = value
}

// GetAndroidSound returns value of AndroidSound conditional field and
// boolean which is true if field was set.
func (p *PeerNotifySettings) GetAndroidSound() (value NotificationSoundClass, ok bool) {
	if p == nil {
		return
	}
	if !p.Flags.Has(4) {
		return value, false
	}
	return p.AndroidSound, true
}

// SetOtherSound sets value of OtherSound conditional field.
func (p *PeerNotifySettings) SetOtherSound(value NotificationSoundClass) {
	p.Flags.Set(5)
	p.OtherSound = value
}

// GetOtherSound returns value of OtherSound conditional field and
// boolean which is true if field was set.
func (p *PeerNotifySettings) GetOtherSound() (value NotificationSoundClass, ok bool) {
	if p == nil {
		return
	}
	if !p.Flags.Has(5) {
		return value, false
	}
	return p.OtherSound, true
}
