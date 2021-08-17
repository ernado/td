package e2etest

import (
	"context"

	"github.com/cenkalti/backoff/v4"
	"golang.org/x/xerrors"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

// EnsureUsername updates username and waits until server applies update.
func EnsureUsername(ctx context.Context, client *telegram.Client, expectedUsername string) (*tg.User, error) {
	raw := tg.NewClient(waitInvoker{prev: client})
	_, err := raw.AccountUpdateUsername(ctx, expectedUsername)
	if err != nil {
		if !tgerr.Is(err, tg.ErrUsernameNotModified) {
			return nil, xerrors.Errorf("update username: %w", err)
		}
	}

	var me *tg.User
	if err := backoff.Retry(func() error {
		me, err = client.Self(ctx)
		if err != nil {
			if ok, err := tgerr.FloodWait(ctx, err); ok {
				return err
			}

			return backoff.Permanent(xerrors.Errorf("get self: %w", err))
		}

		if me.Username != expectedUsername {
			return xerrors.Errorf("expected username %q, got %q", expectedUsername, me.Username)
		}

		return nil
	}, backoff.WithContext(backoff.NewExponentialBackOff(), ctx)); err != nil {
		return nil, err
	}

	return me, nil
}
