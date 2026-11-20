package workflow

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/gatework/netops/batch"
	"github.com/gatework/netops/cache"
	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/failure"
	"github.com/gatework/netops/ops"

	"github.com/gatework/wireless"
)

// Mode selects how queries use the cache.
type Mode = cache.Mode

// Cache modes.
const (
	ModeAuto    = cache.ModeAuto
	ModeLive    = cache.ModeLive
	ModeOffline = cache.ModeOffline
)

// Reasons a stale controller was not refreshed.
const (
	SkipNoCredentials = cache.SkipNoCredentials
	SkipBackoff       = cache.SkipBackoff
	SkipOffline       = cache.SkipOffline
	// SkipNotConfigured marks a cached controller that is no longer a
	// target.
	SkipNotConfigured cache.Skip = "not_configured"
)

// Policy is the wireless cache policy.
type Policy struct {
	Mode       Mode
	TTL        map[evidence.Dimension]time.Duration
	DefaultTTL time.Duration
	// Timeout bounds one refresh, so a slow controller cannot stall a query.
	Timeout time.Duration
	// RetryAfter is the back-off after a failed refresh.
	RetryAfter time.Duration
}

// DefaultPolicy refreshes station data every five minutes, APs and BSS
// every half hour, conflicts hourly and configuration daily.
func DefaultPolicy() Policy {
	return Policy{
		Mode: ModeAuto,
		TTL: map[evidence.Dimension]time.Duration{
			wireless.DimensionClients: 5 * time.Minute, wireless.DimensionDot1X: 5 * time.Minute,
			wireless.DimensionMAC: 5 * time.Minute, wireless.DimensionBlocked: 10 * time.Minute,
			wireless.DimensionAccessPoints: 30 * time.Minute, wireless.DimensionBSS: 30 * time.Minute,
			wireless.DimensionConflicts: time.Hour, wireless.DimensionConfiguration: 24 * time.Hour,
		},
		DefaultTTL: 30 * time.Minute,
		Timeout:    45 * time.Second,
		RetryAfter: 2 * time.Minute,
	}
}

// Cache returns the netops cache policy.
func (p Policy) Cache() cache.Policy {
	return cache.Policy{Mode: p.Mode, TTL: maps.Clone(p.TTL), DefaultTTL: p.DefaultTTL, Backoff: p.RetryAfter}
}

// Validate checks the policy.
func (p Policy) Validate() error {
	if p.Timeout <= 0 {
		return fmt.Errorf("workflow: invalid cache timeout")
	}
	if err := p.Cache().Validate(); err != nil {
		return fmt.Errorf("workflow: %w", err)
	}
	return nil
}

// RefreshRequest brings the cache up to the policy for the targets.
type RefreshRequest struct {
	Targets    []device.Device
	Dimensions []evidence.Dimension
	Vendor     Vendor
	// Dialer is nil without credentials; stale data is then reused.
	Dialer    ops.Dialer
	Cache     Store
	Sightings Sightings
	Policy    Policy
	Workers   int
	Events    batch.Events[capture.Capture]
	Now       func() time.Time
}

// Freshness tells how current the data behind a result is.
type Freshness struct {
	Mode        Mode                  `json:"mode"`
	Controllers []ControllerFreshness `json:"controllers"`
}

// ControllerFreshness is the freshness of one controller.
type ControllerFreshness struct {
	Host      string               `json:"host"`
	Oldest    time.Time            `json:"oldest,omitzero"`
	Stale     []evidence.Dimension `json:"stale,omitempty"`
	Refreshed bool                 `json:"refreshed,omitempty"`
	Skipped   cache.Skip           `json:"skipped,omitempty"`
	Failure   failure.Code         `json:"failure,omitempty"`
}

// Refresh refreshes what is stale for the targets and returns every cached
// capture with its freshness. Cached controllers that are no longer targets
// are reported as not configured.
func Refresh(ctx context.Context, r RefreshRequest) ([]capture.Capture, Freshness, error) {
	dims := dimensions(r.Dimensions)
	rctx, cancel := context.WithTimeout(ctx, r.Policy.Timeout)
	defer cancel()
	res, err := ops.Refresh(rctx, ops.RefreshRequest{
		Devices: r.Targets, Dimensions: dims, Probes: r.Vendor, Dialer: r.Dialer, Snapshots: r.Cache,
		Policy: r.Policy.Cache(), Workers: r.Workers, Events: r.Events, Now: r.Now,
		OnCapture: sightings(r.Vendor, r.Sightings),
	})
	if err != nil && ctx.Err() != nil {
		return nil, Freshness{}, err
	}
	cached, err := r.Cache.LoadAll(ctx)
	if err != nil {
		return nil, Freshness{}, fmt.Errorf("workflow: read cache: %w", err)
	}
	f := Freshness{Mode: r.Policy.Mode}
	targeted := map[netip.Addr]bool{}
	for _, fr := range res.Freshness {
		targeted[fr.Device.Mgmt] = true
		f.Controllers = append(f.Controllers, ControllerFreshness{
			Host: fr.Device.Mgmt.String(), Oldest: fr.Oldest, Stale: fr.Stale,
			Refreshed: fr.Refreshed, Skipped: fr.Skipped, Failure: fr.Failure,
		})
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	pol := r.Policy.Cache()
	for _, c := range cached {
		if targeted[c.Host] {
			continue
		}
		d := device.Device{ID: c.Host.String(), Mgmt: c.Host}
		e := cache.Entry{Device: d, Recorded: ops.Recorded(r.Vendor, d, c, dims)}
		fr := pol.Fresh(now(), e, dims, cache.Decision{}, false)
		cf := ControllerFreshness{Host: c.Host.String(), Oldest: fr.Oldest, Stale: fr.Stale}
		if len(cf.Stale) > 0 {
			cf.Skipped = SkipNotConfigured
		}
		f.Controllers = append(f.Controllers, cf)
	}
	slices.SortFunc(f.Controllers, func(a, b ControllerFreshness) int {
		return netip.MustParseAddr(a.Host).Compare(netip.MustParseAddr(b.Host))
	})
	return cached, f, nil
}

// RecordedAt returns when dimension d of capture c was last answered.
func RecordedAt(v Vendor, c capture.Capture, d evidence.Dimension) (time.Time, bool) {
	at, ok := ops.Recorded(v, device.Device{Mgmt: c.Host}, c, []evidence.Dimension{d})[d]
	return at, ok
}
