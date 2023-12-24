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

// StoriesSendStoryRequest represents TL type `stories.sendStory#e4e6694b`.
// Uploads a Telegram Story¹.
//
// Links:
//  1. https://core.telegram.org/api/stories
//
// See https://core.telegram.org/method/stories.sendStory for reference.
type StoriesSendStoryRequest struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields
	// Whether to add the story to the profile automatically upon expiration. If not set, the
	// story will only be added to the archive, see here »¹ for more info.
	//
	// Links:
	//  1) https://core.telegram.org/api/stories
	Pinned bool
	// If set, disables forwards, screenshots, and downloads.
	Noforwards bool
	// Set this flag when reposting stories with fwd_from_id+fwd_from_id, if the media was
	// modified before reposting.
	FwdModified bool
	// The peer to send the story as.
	Peer InputPeerClass
	// The story media.
	Media InputMediaClass
	// Media areas¹ associated to the story, see here »² for more info.
	//
	// Links:
	//  1) https://core.telegram.org/api/stories#media-areas
	//  2) https://core.telegram.org/api/stories#media-areas
	//
	// Use SetMediaAreas and GetMediaAreas helpers.
	MediaAreas []MediaAreaClass
	// Story caption.
	//
	// Use SetCaption and GetCaption helpers.
	Caption string
	// Message entities for styled text¹, if allowed by the stories_entities client
	// configuration parameter »².
	//
	// Links:
	//  1) https://core.telegram.org/api/entities
	//  2) https://core.telegram.org/api/config#stories-entities
	//
	// Use SetEntities and GetEntities helpers.
	Entities []MessageEntityClass
	// Privacy rules¹ for the story, indicating who can or can't view the story.
	//
	// Links:
	//  1) https://core.telegram.org/api/privacy
	PrivacyRules []InputPrivacyRuleClass
	// Unique client message ID required to prevent message resending.
	RandomID int64
	// Period after which the story is moved to archive (and to the profile if pinned is set)
	// in seconds; must be one of 6 * 3600, 12 * 3600, 86400, or 2 * 86400 for Telegram
	// Premium users, and 86400 otherwise.
	//
	// Use SetPeriod and GetPeriod helpers.
	Period int
	// If set, indicates that this story is a repost of story with ID fwd_from_story posted
	// by the peer in fwd_from_id.
	//
	// Use SetFwdFromID and GetFwdFromID helpers.
	FwdFromID InputPeerClass
	// If set, indicates that this story is a repost of story with ID fwd_from_story posted
	// by the peer in fwd_from_id.
	//
	// Use SetFwdFromStory and GetFwdFromStory helpers.
	FwdFromStory int
}

// StoriesSendStoryRequestTypeID is TL type id of StoriesSendStoryRequest.
const StoriesSendStoryRequestTypeID = 0xe4e6694b

// Ensuring interfaces in compile-time for StoriesSendStoryRequest.
var (
	_ bin.Encoder     = &StoriesSendStoryRequest{}
	_ bin.Decoder     = &StoriesSendStoryRequest{}
	_ bin.BareEncoder = &StoriesSendStoryRequest{}
	_ bin.BareDecoder = &StoriesSendStoryRequest{}
)

func (s *StoriesSendStoryRequest) Zero() bool {
	if s == nil {
		return true
	}
	if !(s.Flags.Zero()) {
		return false
	}
	if !(s.Pinned == false) {
		return false
	}
	if !(s.Noforwards == false) {
		return false
	}
	if !(s.FwdModified == false) {
		return false
	}
	if !(s.Peer == nil) {
		return false
	}
	if !(s.Media == nil) {
		return false
	}
	if !(s.MediaAreas == nil) {
		return false
	}
	if !(s.Caption == "") {
		return false
	}
	if !(s.Entities == nil) {
		return false
	}
	if !(s.PrivacyRules == nil) {
		return false
	}
	if !(s.RandomID == 0) {
		return false
	}
	if !(s.Period == 0) {
		return false
	}
	if !(s.FwdFromID == nil) {
		return false
	}
	if !(s.FwdFromStory == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (s *StoriesSendStoryRequest) String() string {
	if s == nil {
		return "StoriesSendStoryRequest(nil)"
	}
	type Alias StoriesSendStoryRequest
	return fmt.Sprintf("StoriesSendStoryRequest%+v", Alias(*s))
}

// FillFrom fills StoriesSendStoryRequest from given interface.
func (s *StoriesSendStoryRequest) FillFrom(from interface {
	GetPinned() (value bool)
	GetNoforwards() (value bool)
	GetFwdModified() (value bool)
	GetPeer() (value InputPeerClass)
	GetMedia() (value InputMediaClass)
	GetMediaAreas() (value []MediaAreaClass, ok bool)
	GetCaption() (value string, ok bool)
	GetEntities() (value []MessageEntityClass, ok bool)
	GetPrivacyRules() (value []InputPrivacyRuleClass)
	GetRandomID() (value int64)
	GetPeriod() (value int, ok bool)
	GetFwdFromID() (value InputPeerClass, ok bool)
	GetFwdFromStory() (value int, ok bool)
}) {
	s.Pinned = from.GetPinned()
	s.Noforwards = from.GetNoforwards()
	s.FwdModified = from.GetFwdModified()
	s.Peer = from.GetPeer()
	s.Media = from.GetMedia()
	if val, ok := from.GetMediaAreas(); ok {
		s.MediaAreas = val
	}

	if val, ok := from.GetCaption(); ok {
		s.Caption = val
	}

	if val, ok := from.GetEntities(); ok {
		s.Entities = val
	}

	s.PrivacyRules = from.GetPrivacyRules()
	s.RandomID = from.GetRandomID()
	if val, ok := from.GetPeriod(); ok {
		s.Period = val
	}

	if val, ok := from.GetFwdFromID(); ok {
		s.FwdFromID = val
	}

	if val, ok := from.GetFwdFromStory(); ok {
		s.FwdFromStory = val
	}

}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*StoriesSendStoryRequest) TypeID() uint32 {
	return StoriesSendStoryRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*StoriesSendStoryRequest) TypeName() string {
	return "stories.sendStory"
}

// TypeInfo returns info about TL type.
func (s *StoriesSendStoryRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "stories.sendStory",
		ID:   StoriesSendStoryRequestTypeID,
	}
	if s == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Pinned",
			SchemaName: "pinned",
			Null:       !s.Flags.Has(2),
		},
		{
			Name:       "Noforwards",
			SchemaName: "noforwards",
			Null:       !s.Flags.Has(4),
		},
		{
			Name:       "FwdModified",
			SchemaName: "fwd_modified",
			Null:       !s.Flags.Has(7),
		},
		{
			Name:       "Peer",
			SchemaName: "peer",
		},
		{
			Name:       "Media",
			SchemaName: "media",
		},
		{
			Name:       "MediaAreas",
			SchemaName: "media_areas",
			Null:       !s.Flags.Has(5),
		},
		{
			Name:       "Caption",
			SchemaName: "caption",
			Null:       !s.Flags.Has(0),
		},
		{
			Name:       "Entities",
			SchemaName: "entities",
			Null:       !s.Flags.Has(1),
		},
		{
			Name:       "PrivacyRules",
			SchemaName: "privacy_rules",
		},
		{
			Name:       "RandomID",
			SchemaName: "random_id",
		},
		{
			Name:       "Period",
			SchemaName: "period",
			Null:       !s.Flags.Has(3),
		},
		{
			Name:       "FwdFromID",
			SchemaName: "fwd_from_id",
			Null:       !s.Flags.Has(6),
		},
		{
			Name:       "FwdFromStory",
			SchemaName: "fwd_from_story",
			Null:       !s.Flags.Has(6),
		},
	}
	return typ
}

// SetFlags sets flags for non-zero fields.
func (s *StoriesSendStoryRequest) SetFlags() {
	if !(s.Pinned == false) {
		s.Flags.Set(2)
	}
	if !(s.Noforwards == false) {
		s.Flags.Set(4)
	}
	if !(s.FwdModified == false) {
		s.Flags.Set(7)
	}
	if !(s.MediaAreas == nil) {
		s.Flags.Set(5)
	}
	if !(s.Caption == "") {
		s.Flags.Set(0)
	}
	if !(s.Entities == nil) {
		s.Flags.Set(1)
	}
	if !(s.Period == 0) {
		s.Flags.Set(3)
	}
	if !(s.FwdFromID == nil) {
		s.Flags.Set(6)
	}
	if !(s.FwdFromStory == 0) {
		s.Flags.Set(6)
	}
}

// Encode implements bin.Encoder.
func (s *StoriesSendStoryRequest) Encode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode stories.sendStory#e4e6694b as nil")
	}
	b.PutID(StoriesSendStoryRequestTypeID)
	return s.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (s *StoriesSendStoryRequest) EncodeBare(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode stories.sendStory#e4e6694b as nil")
	}
	s.SetFlags()
	if err := s.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field flags: %w", err)
	}
	if s.Peer == nil {
		return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field peer is nil")
	}
	if err := s.Peer.Encode(b); err != nil {
		return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field peer: %w", err)
	}
	if s.Media == nil {
		return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field media is nil")
	}
	if err := s.Media.Encode(b); err != nil {
		return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field media: %w", err)
	}
	if s.Flags.Has(5) {
		b.PutVectorHeader(len(s.MediaAreas))
		for idx, v := range s.MediaAreas {
			if v == nil {
				return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field media_areas element with index %d is nil", idx)
			}
			if err := v.Encode(b); err != nil {
				return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field media_areas element with index %d: %w", idx, err)
			}
		}
	}
	if s.Flags.Has(0) {
		b.PutString(s.Caption)
	}
	if s.Flags.Has(1) {
		b.PutVectorHeader(len(s.Entities))
		for idx, v := range s.Entities {
			if v == nil {
				return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field entities element with index %d is nil", idx)
			}
			if err := v.Encode(b); err != nil {
				return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field entities element with index %d: %w", idx, err)
			}
		}
	}
	b.PutVectorHeader(len(s.PrivacyRules))
	for idx, v := range s.PrivacyRules {
		if v == nil {
			return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field privacy_rules element with index %d is nil", idx)
		}
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field privacy_rules element with index %d: %w", idx, err)
		}
	}
	b.PutLong(s.RandomID)
	if s.Flags.Has(3) {
		b.PutInt(s.Period)
	}
	if s.Flags.Has(6) {
		if s.FwdFromID == nil {
			return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field fwd_from_id is nil")
		}
		if err := s.FwdFromID.Encode(b); err != nil {
			return fmt.Errorf("unable to encode stories.sendStory#e4e6694b: field fwd_from_id: %w", err)
		}
	}
	if s.Flags.Has(6) {
		b.PutInt(s.FwdFromStory)
	}
	return nil
}

// Decode implements bin.Decoder.
func (s *StoriesSendStoryRequest) Decode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode stories.sendStory#e4e6694b to nil")
	}
	if err := b.ConsumeID(StoriesSendStoryRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: %w", err)
	}
	return s.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (s *StoriesSendStoryRequest) DecodeBare(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode stories.sendStory#e4e6694b to nil")
	}
	{
		if err := s.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field flags: %w", err)
		}
	}
	s.Pinned = s.Flags.Has(2)
	s.Noforwards = s.Flags.Has(4)
	s.FwdModified = s.Flags.Has(7)
	{
		value, err := DecodeInputPeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field peer: %w", err)
		}
		s.Peer = value
	}
	{
		value, err := DecodeInputMedia(b)
		if err != nil {
			return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field media: %w", err)
		}
		s.Media = value
	}
	if s.Flags.Has(5) {
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field media_areas: %w", err)
		}

		if headerLen > 0 {
			s.MediaAreas = make([]MediaAreaClass, 0, headerLen%bin.PreallocateLimit)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeMediaArea(b)
			if err != nil {
				return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field media_areas: %w", err)
			}
			s.MediaAreas = append(s.MediaAreas, value)
		}
	}
	if s.Flags.Has(0) {
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field caption: %w", err)
		}
		s.Caption = value
	}
	if s.Flags.Has(1) {
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field entities: %w", err)
		}

		if headerLen > 0 {
			s.Entities = make([]MessageEntityClass, 0, headerLen%bin.PreallocateLimit)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeMessageEntity(b)
			if err != nil {
				return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field entities: %w", err)
			}
			s.Entities = append(s.Entities, value)
		}
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field privacy_rules: %w", err)
		}

		if headerLen > 0 {
			s.PrivacyRules = make([]InputPrivacyRuleClass, 0, headerLen%bin.PreallocateLimit)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeInputPrivacyRule(b)
			if err != nil {
				return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field privacy_rules: %w", err)
			}
			s.PrivacyRules = append(s.PrivacyRules, value)
		}
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field random_id: %w", err)
		}
		s.RandomID = value
	}
	if s.Flags.Has(3) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field period: %w", err)
		}
		s.Period = value
	}
	if s.Flags.Has(6) {
		value, err := DecodeInputPeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field fwd_from_id: %w", err)
		}
		s.FwdFromID = value
	}
	if s.Flags.Has(6) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode stories.sendStory#e4e6694b: field fwd_from_story: %w", err)
		}
		s.FwdFromStory = value
	}
	return nil
}

// SetPinned sets value of Pinned conditional field.
func (s *StoriesSendStoryRequest) SetPinned(value bool) {
	if value {
		s.Flags.Set(2)
		s.Pinned = true
	} else {
		s.Flags.Unset(2)
		s.Pinned = false
	}
}

// GetPinned returns value of Pinned conditional field.
func (s *StoriesSendStoryRequest) GetPinned() (value bool) {
	if s == nil {
		return
	}
	return s.Flags.Has(2)
}

// SetNoforwards sets value of Noforwards conditional field.
func (s *StoriesSendStoryRequest) SetNoforwards(value bool) {
	if value {
		s.Flags.Set(4)
		s.Noforwards = true
	} else {
		s.Flags.Unset(4)
		s.Noforwards = false
	}
}

// GetNoforwards returns value of Noforwards conditional field.
func (s *StoriesSendStoryRequest) GetNoforwards() (value bool) {
	if s == nil {
		return
	}
	return s.Flags.Has(4)
}

// SetFwdModified sets value of FwdModified conditional field.
func (s *StoriesSendStoryRequest) SetFwdModified(value bool) {
	if value {
		s.Flags.Set(7)
		s.FwdModified = true
	} else {
		s.Flags.Unset(7)
		s.FwdModified = false
	}
}

// GetFwdModified returns value of FwdModified conditional field.
func (s *StoriesSendStoryRequest) GetFwdModified() (value bool) {
	if s == nil {
		return
	}
	return s.Flags.Has(7)
}

// GetPeer returns value of Peer field.
func (s *StoriesSendStoryRequest) GetPeer() (value InputPeerClass) {
	if s == nil {
		return
	}
	return s.Peer
}

// GetMedia returns value of Media field.
func (s *StoriesSendStoryRequest) GetMedia() (value InputMediaClass) {
	if s == nil {
		return
	}
	return s.Media
}

// SetMediaAreas sets value of MediaAreas conditional field.
func (s *StoriesSendStoryRequest) SetMediaAreas(value []MediaAreaClass) {
	s.Flags.Set(5)
	s.MediaAreas = value
}

// GetMediaAreas returns value of MediaAreas conditional field and
// boolean which is true if field was set.
func (s *StoriesSendStoryRequest) GetMediaAreas() (value []MediaAreaClass, ok bool) {
	if s == nil {
		return
	}
	if !s.Flags.Has(5) {
		return value, false
	}
	return s.MediaAreas, true
}

// SetCaption sets value of Caption conditional field.
func (s *StoriesSendStoryRequest) SetCaption(value string) {
	s.Flags.Set(0)
	s.Caption = value
}

// GetCaption returns value of Caption conditional field and
// boolean which is true if field was set.
func (s *StoriesSendStoryRequest) GetCaption() (value string, ok bool) {
	if s == nil {
		return
	}
	if !s.Flags.Has(0) {
		return value, false
	}
	return s.Caption, true
}

// SetEntities sets value of Entities conditional field.
func (s *StoriesSendStoryRequest) SetEntities(value []MessageEntityClass) {
	s.Flags.Set(1)
	s.Entities = value
}

// GetEntities returns value of Entities conditional field and
// boolean which is true if field was set.
func (s *StoriesSendStoryRequest) GetEntities() (value []MessageEntityClass, ok bool) {
	if s == nil {
		return
	}
	if !s.Flags.Has(1) {
		return value, false
	}
	return s.Entities, true
}

// GetPrivacyRules returns value of PrivacyRules field.
func (s *StoriesSendStoryRequest) GetPrivacyRules() (value []InputPrivacyRuleClass) {
	if s == nil {
		return
	}
	return s.PrivacyRules
}

// GetRandomID returns value of RandomID field.
func (s *StoriesSendStoryRequest) GetRandomID() (value int64) {
	if s == nil {
		return
	}
	return s.RandomID
}

// SetPeriod sets value of Period conditional field.
func (s *StoriesSendStoryRequest) SetPeriod(value int) {
	s.Flags.Set(3)
	s.Period = value
}

// GetPeriod returns value of Period conditional field and
// boolean which is true if field was set.
func (s *StoriesSendStoryRequest) GetPeriod() (value int, ok bool) {
	if s == nil {
		return
	}
	if !s.Flags.Has(3) {
		return value, false
	}
	return s.Period, true
}

// SetFwdFromID sets value of FwdFromID conditional field.
func (s *StoriesSendStoryRequest) SetFwdFromID(value InputPeerClass) {
	s.Flags.Set(6)
	s.FwdFromID = value
}

// GetFwdFromID returns value of FwdFromID conditional field and
// boolean which is true if field was set.
func (s *StoriesSendStoryRequest) GetFwdFromID() (value InputPeerClass, ok bool) {
	if s == nil {
		return
	}
	if !s.Flags.Has(6) {
		return value, false
	}
	return s.FwdFromID, true
}

// SetFwdFromStory sets value of FwdFromStory conditional field.
func (s *StoriesSendStoryRequest) SetFwdFromStory(value int) {
	s.Flags.Set(6)
	s.FwdFromStory = value
}

// GetFwdFromStory returns value of FwdFromStory conditional field and
// boolean which is true if field was set.
func (s *StoriesSendStoryRequest) GetFwdFromStory() (value int, ok bool) {
	if s == nil {
		return
	}
	if !s.Flags.Has(6) {
		return value, false
	}
	return s.FwdFromStory, true
}

// MapMediaAreas returns field MediaAreas wrapped in MediaAreaClassArray helper.
func (s *StoriesSendStoryRequest) MapMediaAreas() (value MediaAreaClassArray, ok bool) {
	if !s.Flags.Has(5) {
		return value, false
	}
	return MediaAreaClassArray(s.MediaAreas), true
}

// MapEntities returns field Entities wrapped in MessageEntityClassArray helper.
func (s *StoriesSendStoryRequest) MapEntities() (value MessageEntityClassArray, ok bool) {
	if !s.Flags.Has(1) {
		return value, false
	}
	return MessageEntityClassArray(s.Entities), true
}

// MapPrivacyRules returns field PrivacyRules wrapped in InputPrivacyRuleClassArray helper.
func (s *StoriesSendStoryRequest) MapPrivacyRules() (value InputPrivacyRuleClassArray) {
	return InputPrivacyRuleClassArray(s.PrivacyRules)
}

// StoriesSendStory invokes method stories.sendStory#e4e6694b returning error if any.
// Uploads a Telegram Story¹.
//
// Links:
//  1. https://core.telegram.org/api/stories
//
// Possible errors:
//
//	400 IMAGE_PROCESS_FAILED: Failure while processing image.
//	400 MEDIA_EMPTY: The provided media object is invalid.
//	400 MEDIA_FILE_INVALID: The specified media file is invalid.
//	400 MEDIA_TYPE_INVALID: The specified media type cannot be used in stories.
//	400 MEDIA_VIDEO_STORY_MISSING:
//	400 PEER_ID_INVALID: The provided peer id is invalid.
//	400 PREMIUM_ACCOUNT_REQUIRED: A premium account is required to execute this action.
//	400 STORIES_TOO_MUCH: You have hit the maximum active stories limit as specified by the story_expiring_limit_* client configuration parameters: you should buy a Premium subscription, delete an active story, or wait for the oldest story to expire.
//	400 STORY_PERIOD_INVALID: The specified story period is invalid for this account.
//	400 VENUE_ID_INVALID: The specified venue ID is invalid.
//
// See https://core.telegram.org/method/stories.sendStory for reference.
func (c *Client) StoriesSendStory(ctx context.Context, request *StoriesSendStoryRequest) (UpdatesClass, error) {
	var result UpdatesBox

	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return result.Updates, nil
}
