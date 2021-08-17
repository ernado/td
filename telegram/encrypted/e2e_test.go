package encrypted

import (
	"context"
	"strconv"
	"testing"

	"github.com/cenkalti/backoff/v4"
	"github.com/k0kubun/pp/v3"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"golang.org/x/xerrors"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/internal/tdsync"
	"github.com/gotd/td/telegram/internal/e2etest"
	"github.com/gotd/td/telegram/message"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tg/e2e"
	"github.com/gotd/td/tgerr"
)

func requester(ctx context.Context, suite *e2etest.Suite, usernameCh <-chan string) error {
	log := suite.Logger().Named("requester")
	d := tg.NewUpdateDispatcher()

	msgs := make(chan string, 1)

	client := suite.Client(log, d)
	raw := client.API()
	sender := message.NewSender(raw)
	m := NewManager(raw, d, Options{
		Logger: log.Named("manager"),
		Message: func(ctx context.Context, chat Chat, bytes []byte) error {
			msg := &e2e.DecryptedMessage{}

			if err := msg.Decode(&bin.Buffer{Buf: bytes}); err != nil {
				return xerrors.Errorf("decode: %w", err)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case msgs <- msg.Message:
				return nil
			}
		},
	})

	return client.Run(ctx, func(ctx context.Context) error {
		if err := suite.RetryAuthenticate(ctx, client.Auth()); err != nil {
			return xerrors.Errorf("authenticate: %w", err)
		}

		var username string
		select {
		case <-ctx.Done():
			return ctx.Err()
		case u := <-usernameCh:
			username = u
		}

		user, err := sender.Resolve(username).AsInputUser(ctx)
		if err != nil {
			return xerrors.Errorf("resolve %q: %w", username, err)
		}

		ch, err := m.requestChat(ctx, user)
		if err != nil {
			return xerrors.Errorf("request: %w", err)
		}

		pp.Println("request", ch, ch.Key.ID)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-msgs:
			pp.Println("receive", msg)
		}
		return nil
	})
}

func retryFloodWait(ctx context.Context, cb func() error) error {
	return backoff.Retry(func() error {
		if err := cb(); err != nil {
			if ok, err := tgerr.FloodWait(ctx, err); ok {
				return err
			}

			return backoff.Permanent(err)
		}

		return nil
	}, backoff.WithContext(backoff.NewExponentialBackOff(), ctx))
}

func receiver(ctx context.Context, suite *e2etest.Suite, usernameCh chan<- string) error {
	log := suite.Logger().Named("receiver")
	d := tg.NewUpdateDispatcher()

	accepted := make(chan Chat)

	client := suite.Client(log, d)
	raw := client.API()
	m := NewManager(raw, d, Options{
		Accept: func(ctx context.Context, e tg.Entities, r *tg.EncryptedChatRequested) (bool, error) {
			// Accept all.
			return true, nil
		},
		Created: func(ctx context.Context, chat Chat) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case accepted <- chat:
				return nil
			}
		},
		Logger: log.Named("manager"),
	})

	return client.Run(ctx, func(ctx context.Context) error {
		if err := suite.RetryAuthenticate(ctx, client.Auth()); err != nil {
			return xerrors.Errorf("authenticate: %w", err)
		}

		var me *tg.User
		if err := retryFloodWait(ctx, func() (err error) {
			me, err = client.Self(ctx)
			return err
		}); err != nil {
			return err
		}

		expectedUsername := "echobot" + strconv.Itoa(me.ID)
		user, err := e2etest.EnsureUsername(ctx, client, expectedUsername)
		if err != nil {
			return xerrors.Errorf("ensure username: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case usernameCh <- user.Username:
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case chat := <-accepted:
			pp.Println("accepted", chat, chat.Key.ID)

			var buf bin.Buffer
			if err := buf.Encode(&e2e.DecryptedMessage{
				Message: "десять",
			}); err != nil {
				return xerrors.Errorf("encode decrypted: %w", err)
			}

			return m.Send(ctx, chat, buf.Buf)
		}
	})
}

func TestE2E(t *testing.T) {
	logger := zaptest.NewLogger(t, zaptest.Level(zapcore.InfoLevel))
	suite := e2etest.NewSuite(t, e2etest.TestOptions{
		Logger: logger,
	})

	ctx := context.Background()
	grp := tdsync.NewCancellableGroup(ctx)

	usernameCh := make(chan string)
	grp.Go(func(ctx context.Context) error {
		return requester(ctx, suite, usernameCh)
	})
	grp.Go(func(ctx context.Context) error {
		return receiver(ctx, suite, usernameCh)
	})

	if err := grp.Wait(); err != nil {
		t.Error(err)
	}
}
