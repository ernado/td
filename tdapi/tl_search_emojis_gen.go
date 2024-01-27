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

// SearchEmojisRequest represents TL type `searchEmojis#d513cd61`.
type SearchEmojisRequest struct {
	// Text to search for
	Text string
	// List of possible IETF language tags of the user's input language; may be empty if
	// unknown
	InputLanguageCodes []string
}

// SearchEmojisRequestTypeID is TL type id of SearchEmojisRequest.
const SearchEmojisRequestTypeID = 0xd513cd61

// Ensuring interfaces in compile-time for SearchEmojisRequest.
var (
	_ bin.Encoder     = &SearchEmojisRequest{}
	_ bin.Decoder     = &SearchEmojisRequest{}
	_ bin.BareEncoder = &SearchEmojisRequest{}
	_ bin.BareDecoder = &SearchEmojisRequest{}
)

func (s *SearchEmojisRequest) Zero() bool {
	if s == nil {
		return true
	}
	if !(s.Text == "") {
		return false
	}
	if !(s.InputLanguageCodes == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (s *SearchEmojisRequest) String() string {
	if s == nil {
		return "SearchEmojisRequest(nil)"
	}
	type Alias SearchEmojisRequest
	return fmt.Sprintf("SearchEmojisRequest%+v", Alias(*s))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*SearchEmojisRequest) TypeID() uint32 {
	return SearchEmojisRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*SearchEmojisRequest) TypeName() string {
	return "searchEmojis"
}

// TypeInfo returns info about TL type.
func (s *SearchEmojisRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "searchEmojis",
		ID:   SearchEmojisRequestTypeID,
	}
	if s == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Text",
			SchemaName: "text",
		},
		{
			Name:       "InputLanguageCodes",
			SchemaName: "input_language_codes",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (s *SearchEmojisRequest) Encode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode searchEmojis#d513cd61 as nil")
	}
	b.PutID(SearchEmojisRequestTypeID)
	return s.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (s *SearchEmojisRequest) EncodeBare(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode searchEmojis#d513cd61 as nil")
	}
	b.PutString(s.Text)
	b.PutInt(len(s.InputLanguageCodes))
	for _, v := range s.InputLanguageCodes {
		b.PutString(v)
	}
	return nil
}

// Decode implements bin.Decoder.
func (s *SearchEmojisRequest) Decode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode searchEmojis#d513cd61 to nil")
	}
	if err := b.ConsumeID(SearchEmojisRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode searchEmojis#d513cd61: %w", err)
	}
	return s.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (s *SearchEmojisRequest) DecodeBare(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode searchEmojis#d513cd61 to nil")
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode searchEmojis#d513cd61: field text: %w", err)
		}
		s.Text = value
	}
	{
		headerLen, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode searchEmojis#d513cd61: field input_language_codes: %w", err)
		}

		if headerLen > 0 {
			s.InputLanguageCodes = make([]string, 0, headerLen%bin.PreallocateLimit)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := b.String()
			if err != nil {
				return fmt.Errorf("unable to decode searchEmojis#d513cd61: field input_language_codes: %w", err)
			}
			s.InputLanguageCodes = append(s.InputLanguageCodes, value)
		}
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (s *SearchEmojisRequest) EncodeTDLibJSON(b tdjson.Encoder) error {
	if s == nil {
		return fmt.Errorf("can't encode searchEmojis#d513cd61 as nil")
	}
	b.ObjStart()
	b.PutID("searchEmojis")
	b.Comma()
	b.FieldStart("text")
	b.PutString(s.Text)
	b.Comma()
	b.FieldStart("input_language_codes")
	b.ArrStart()
	for _, v := range s.InputLanguageCodes {
		b.PutString(v)
		b.Comma()
	}
	b.StripComma()
	b.ArrEnd()
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (s *SearchEmojisRequest) DecodeTDLibJSON(b tdjson.Decoder) error {
	if s == nil {
		return fmt.Errorf("can't decode searchEmojis#d513cd61 to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("searchEmojis"); err != nil {
				return fmt.Errorf("unable to decode searchEmojis#d513cd61: %w", err)
			}
		case "text":
			value, err := b.String()
			if err != nil {
				return fmt.Errorf("unable to decode searchEmojis#d513cd61: field text: %w", err)
			}
			s.Text = value
		case "input_language_codes":
			if err := b.Arr(func(b tdjson.Decoder) error {
				value, err := b.String()
				if err != nil {
					return fmt.Errorf("unable to decode searchEmojis#d513cd61: field input_language_codes: %w", err)
				}
				s.InputLanguageCodes = append(s.InputLanguageCodes, value)
				return nil
			}); err != nil {
				return fmt.Errorf("unable to decode searchEmojis#d513cd61: field input_language_codes: %w", err)
			}
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetText returns value of Text field.
func (s *SearchEmojisRequest) GetText() (value string) {
	if s == nil {
		return
	}
	return s.Text
}

// GetInputLanguageCodes returns value of InputLanguageCodes field.
func (s *SearchEmojisRequest) GetInputLanguageCodes() (value []string) {
	if s == nil {
		return
	}
	return s.InputLanguageCodes
}

// SearchEmojis invokes method searchEmojis#d513cd61 returning error if any.
func (c *Client) SearchEmojis(ctx context.Context, request *SearchEmojisRequest) (*EmojiKeywords, error) {
	var result EmojiKeywords

	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
