package encrypted

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChat_consumeMessage(t *testing.T) {
	t.Run("Originator", func(t *testing.T) {
		a := require.New(t)
		ch := Chat{
			Originator: true,
		}

		a.Equal(consumeMessage, ch.consumeMessage(1, 0))
		a.Equal(skipMessage, ch.consumeMessage(1, 0))
		a.Equal(consumeMessage, ch.consumeMessage(1, 2))
		a.Equal(fillGap, ch.consumeMessage(1, 6))
		ch.InSeq = 4 // fill gap
		a.Equal(abortChat, ch.consumeMessage(3, 8))
	})
	t.Run("NotOriginator", func(t *testing.T) {
		a := require.New(t)
		ch := Chat{
			Originator: false,
		}

		a.Equal(consumeMessage, ch.consumeMessage(0, 1))
		a.Equal(skipMessage, ch.consumeMessage(0, 1))
		a.Equal(consumeMessage, ch.consumeMessage(0, 3))
		a.Equal(fillGap, ch.consumeMessage(0, 7))
		ch.InSeq = 4 // fill gap
		a.Equal(abortChat, ch.consumeMessage(2, 9))
	})
}

func TestChat_nextMessage(t *testing.T) {
	test := func(orig bool, s []int) func(t *testing.T) {
		return func(t *testing.T) {
			ch := Chat{
				Originator: orig,
			}

			for _, seqNo := range s {
				_, out := ch.nextMessage()
				require.Equal(t, seqNo, out)
			}
		}

	}

	t.Run("Originator", test(true, []int{1, 3, 5, 7}))
	t.Run("NotOriginator", test(false, []int{0, 2, 4, 6}))
}

type seqState struct {
	in  int
	out int
}

// Chat structure stores raw(!) seq_no, so we make an alias type seqRawState
// to distinguish raw and computed state.
type seqRawState = seqState

func TestChat_seqNo(t *testing.T) {
	tests := []struct {
		originator bool
		localRaw   seqRawState
		expect     seqState
	}{
		{true, seqRawState{0, 0}, seqState{0, 1}},
		{true, seqRawState{0, 1}, seqState{0, 3}},
		{true, seqRawState{1, 2}, seqState{2, 5}},
		{true, seqRawState{2, 2}, seqState{4, 5}},
		{false, seqRawState{0, 0}, seqState{1, 0}},
		{false, seqRawState{0, 1}, seqState{1, 2}},
		{false, seqRawState{1, 2}, seqState{3, 4}},
		{false, seqRawState{2, 2}, seqState{5, 4}},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("Test%d", i), func(t *testing.T) {
			a := require.New(t)
			ch := Chat{
				Originator: tt.originator,
				InSeq:      tt.localRaw.in,
				OutSeq:     tt.localRaw.out,
			}

			in, out := ch.seqNo()
			a.Equal(tt.expect.in, in)
			a.Equal(tt.expect.out, out)
		})
	}
}
