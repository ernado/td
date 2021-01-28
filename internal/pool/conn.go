package pool

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/clock"
	"github.com/gotd/td/internal/tdsync"
	"github.com/gotd/td/mtproto"
	"github.com/gotd/td/tg"
)

type protoConn interface {
	InvokeRaw(ctx context.Context, input bin.Encoder, output bin.Decoder) error
	Run(ctx context.Context, f func(ctx context.Context) error) error
}

//go:generate go run golang.org/x/tools/cmd/stringer -type=connMode
type connMode byte

const (
	connModeUpdates connMode = iota
	connModeData
	connModeCDN
)

// ConnHandler handles
type ConnHandler interface {
	OnSession(addr string, cfg tg.Config, s mtproto.Session) error
	OnMessage(b *bin.Buffer) error
}

type conn struct {
	// Connection parameters.
	addr string   // immutable
	mode connMode // immutable
	// MTProto connection.
	proto protoConn // immutable

	// Wrappers for external world, like logs or PRNG.
	// Should be immutable.
	clock clock.Clock // immutable
	log   *zap.Logger // immutable

	// Handler passed by client.
	handler ConnHandler // immutable

	// State fields.
	cfg     tg.Config
	ongoing int
	latest  time.Time
	mux     sync.Mutex

	sessionInit *tdsync.Ready // immutable
	gotConfig   *tdsync.Ready // immutable
}

func (c *conn) OnSession(session mtproto.Session) error {
	c.sessionInit.Signal()

	// Waiting for config, because OnSession can occur before we set config.
	<-c.gotConfig.Ready()

	c.mux.Lock()
	cfg := c.cfg
	c.mux.Unlock()

	return c.handler.OnSession(c.addr, cfg, session)
}

func (c *conn) OnMessage(b *bin.Buffer) error {
	return c.handler.OnMessage(b)
}

func (c *conn) InvokeRaw(ctx context.Context, input bin.Encoder, output bin.Decoder) error {
	// Tracking ongoing invokes.
	defer c.trackInvoke()()
	if err := c.waitSession(ctx); err != nil {
		return xerrors.Errorf("waitSession: %w", err)
	}

	return c.proto.InvokeRaw(ctx, input, output)
}

func (c *conn) trackInvoke() func() {
	start := c.clock.Now()

	c.mux.Lock()
	defer c.mux.Unlock()

	c.ongoing++
	c.latest = start

	return func() {
		c.mux.Lock()
		defer c.mux.Unlock()

		c.ongoing--
		end := c.clock.Now()
		c.latest = end

		c.log.Debug("Invoke",
			zap.Duration("duration", end.Sub(start)),
			zap.Int("ongoing", c.ongoing),
		)
	}
}

func (c *conn) waitSession(ctx context.Context) error {
	select {
	case <-c.sessionInit.Ready():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *conn) Ready() <-chan struct{} {
	return c.gotConfig.Ready()
}

func (c *conn) Init(ctx context.Context, appID int, device DeviceConfig) error {
	return c.proto.Run(ctx, func(ctx context.Context) error {
		return c.init(ctx, appID, device)
	})
}

func (c *conn) init(ctx context.Context, appID int, device DeviceConfig) error {
	defer c.gotConfig.Signal()
	c.log.Debug("Initializing")

	q := &tg.InitConnectionRequest{
		APIID:          appID,
		DeviceModel:    device.DeviceModel,
		SystemVersion:  device.SystemVersion,
		AppVersion:     device.AppVersion,
		SystemLangCode: device.SystemLangCode,
		LangPack:       device.LangPack,
		LangCode:       device.LangCode,
		Query:          &tg.HelpGetConfigRequest{},
	}
	var req bin.Object = &tg.InvokeWithLayerRequest{
		Layer: tg.Layer,
		Query: q,
	}
	if c.mode == connModeData || c.mode == connModeCDN {
		// This connection will not receive updates.
		req = &tg.InvokeWithoutUpdatesRequest{
			Query: req,
		}
	}

	var cfg tg.Config
	if err := c.proto.InvokeRaw(ctx, req, &cfg); err != nil {
		return xerrors.Errorf("invoke: %w", err)
	}

	c.mux.Lock()
	c.latest = c.clock.Now()
	c.cfg = cfg
	c.mux.Unlock()

	return nil
}

func newConn(
	handler ConnHandler,
	addr string,
	mode connMode,
	opt mtproto.Options,
) *conn {
	c := &conn{
		mode:        mode,
		addr:        addr,
		clock:       opt.Clock,
		log:         opt.Logger.Named("mtproto"),
		handler:     handler,
		sessionInit: tdsync.NewReady(),
		gotConfig:   tdsync.NewReady(),
	}
	opt.Handler = c
	c.proto = mtproto.New(addr, opt)
	return c
}
