package encrypted

import (
	"encoding/binary"

	"github.com/gotd/td/internal/crypto"
)

// getKeyFingerprint computes key fingerprint.
func getKeyFingerprint(key crypto.AuthKey) int64 {
	return int64(binary.LittleEndian.Uint64(key.ID[:]))
}

// Chat is an encrypted chat metadata structure.
type Chat struct {
	// Chat ID.
	ID int
	// AccessHash is a chat access hash.
	AccessHash int64
	// Layer is a TL encrypted schema layer version.
	Layer int
	// Date chat was created.
	Date int
	// AdminID is a chat creator ID.
	AdminID int
	// ParticipantID is an id of the second chat participant.
	ParticipantID int
	// Originator denotes current user is creator.
	Originator bool

	// InSeq is an incoming message sequence.
	InSeq int
	// OutSeq is a outgoing message sequence.
	OutSeq int

	// Key is message encryption key.
	Key crypto.AuthKey
}

func (c Chat) seqNo() (in, out int) {
	if c.Originator {
		in = 2 * c.InSeq
		out = 2*c.OutSeq + 1
	} else {
		in = 2*c.InSeq + 1
		out = 2 * c.OutSeq
	}
	return in, out
}

func (c *Chat) nextMessage() (in, out int) {
	in, out = c.seqNo()
	c.OutSeq++
	return in, out
}

type consumeResult int

const (
	skipMessage    consumeResult = -1
	consumeMessage consumeResult = 0
	fillGap        consumeResult = 1
	abortChat      consumeResult = 2
)

func (c *Chat) consumeMessage(hisInSeq, hisOutSeq int) consumeResult {
	// See https://core.telegram.org/api/end-to-end/seq_no#checking-out-seq-no.
	//
	// If the received out_seq_no<=C, the local client must drop the message (repeated message).
	// The client should not check the contents of the message because the original message could have
	// been deleted (see Deleting unacknowledged messages).

	myInSeq, myOutSeq := c.seqNo()
	if hisOutSeq < myInSeq {
		return skipMessage
	}

	// If the received out_seq_no>C+1, it most likely means that the server left out some messages due
	// to a technical failure or due to the messages becoming obsolete. A temporary solution to this is
	// to simply abort the secret chat. But since this may cause some existing older secret chats to be aborted,
	// it is strongly recommended for the client to properly handle such seq_no gaps. Note that in_seq_no is not
	// increased upon receipt of such a message; it is advanced only after all preceding gaps are filled.
	if hisOutSeq > myInSeq {
		return fillGap
	}
	c.InSeq++

	// See https://core.telegram.org/api/end-to-end/seq_no#checking-and-handling-in-seq-no.
	//
	// - in_seq_no must form a non-decreasing sequence of non-negative integer numbers.
	// - in_seq_no must be valid at the moment of receiving the message, that is, if D
	// is the out_seq_no of last message we sent, the received in_seq_no should not
	// be greater than D + 1.
	//
	if hisInSeq < myOutSeq-2 || hisInSeq > myOutSeq {
		// If in_seq_no contradicts these criteria, the local client is required
		// to immediately abort the secret chat.
		return abortChat
	}

	return consumeMessage
}
