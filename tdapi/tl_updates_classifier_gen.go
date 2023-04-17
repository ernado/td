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

func IsPtsUpdate(u UpdateClass) (pts, ptsCount int, ok bool) {
	switch u := u.(type) {
	}

	return
}

func IsQtsUpdate(u UpdateClass) (qts int, ok bool) {
	switch u := u.(type) {
	}

	return
}

func IsChannelPtsUpdate(u UpdateClass) (channelID int64, pts, ptsCount int, ok bool, err error) {
	switch u := u.(type) {
	}

	return
}

func extractChannelID(msg MessageClass) (int64, error) {
	switch msg := msg.(type) {
	default:
		return 0, errors.New("unexpected MessageClass type")
	}
}
