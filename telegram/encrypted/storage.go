package encrypted

import (
	"context"
	"errors"
	"sync"
)

// ChatStorage contains encrypted chats.
type ChatStorage interface {
	Save(ctx context.Context, chat Chat) error
	FindByID(ctx context.Context, id int) (Chat, error)
	ForEach(ctx context.Context, cb func(ctx context.Context, chat Chat) error) error
}

var ErrChatNotFound = errors.New("chat not found")

// InmemoryStorage is an in-memory implementation of ChatStorage.
type InmemoryStorage struct {
	chats map[int]Chat
	mux   sync.Mutex
}

// NewInmemoryStorage creates new InmemoryStorage.
func NewInmemoryStorage() *InmemoryStorage {
	return &InmemoryStorage{
		chats: map[int]Chat{},
	}
}

// Save saves chat to storage.
func (i *InmemoryStorage) Save(ctx context.Context, chat Chat) error {
	i.mux.Lock()
	defer i.mux.Unlock()

	i.chats[chat.ID] = chat
	return nil
}

// FindByID finds chat by ID.
func (i *InmemoryStorage) FindByID(ctx context.Context, id int) (Chat, error) {
	i.mux.Lock()
	defer i.mux.Unlock()

	ch, ok := i.chats[id]
	if !ok {
		return Chat{}, ErrChatNotFound
	}
	return ch, nil
}

// ForEach iterates over storage and calls callback with every saved chat.
func (i *InmemoryStorage) ForEach(ctx context.Context, cb func(ctx context.Context, chat Chat) error) error {
	i.mux.Lock()
	defer i.mux.Unlock()

	for _, chat := range i.chats {
		if err := cb(ctx, chat); err != nil {
			return err
		}
	}

	return nil
}
