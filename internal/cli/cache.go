package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/internal/bootstrap"
	"github.com/gatework/wireless/internal/workflow"
)

// index loads the local cache, importing the configured offline snapshot
// and refreshing what the policy considers stale for dims, then keeps the
// controllers selected by --controller.
func (a *app) index(ctx context.Context, dims ...evidence.Dimension) (*wireless.Index, error) {
	cfg, err := a.config(ctx)
	if err != nil {
		return nil, err
	}
	captures, fresh, err := a.refresh(ctx, dims)
	if err != nil {
		return nil, err
	}
	all := captures
	captures = slices.DeleteFunc(slices.Clone(captures), func(c capture.Capture) bool { return !a.selects(c.Host.String(), sysnameOf(c.Prompt)) })
	switch {
	case len(all) == 0:
		fmt.Fprintf(a.env.Stderr, msgNoCache, cfg.CacheDir)
		return nil, errNotFound
	case len(captures) == 0:
		fmt.Fprintf(a.env.Stderr, msgNoMatch, strings.Join(a.controllers, " "), controllerNames(all))
		return nil, errNotFound
	}
	fresh.Controllers = slices.DeleteFunc(fresh.Controllers, func(c workflow.ControllerFreshness) bool {
		return !slices.ContainsFunc(captures, func(x capture.Capture) bool { return x.Host.String() == c.Host })
	})
	a.fresh = &fresh
	if !a.json {
		a.banner(ctx, fresh, captures)
	}
	return workflow.Decode(ctx, cfg.Vendor(), captures, cfg.Parallel)
}

// refresh imports the offline snapshot, then brings the cache up to the
// policy. Without credentials or targets it reads the cache as it is.
func (a *app) refresh(ctx context.Context, dims []evidence.Dimension) ([]capture.Capture, workflow.Freshness, error) {
	cfg, err := a.config(ctx)
	if err != nil {
		return nil, workflow.Freshness{}, err
	}
	st, err := cfg.Store()
	if err != nil {
		return nil, workflow.Freshness{}, err
	}
	if cfg.Snapshot != "" {
		r, err := st.Import(ctx, cfg.Snapshot)
		if err != nil {
			return nil, workflow.Freshness{}, err
		}
		if r.Updated > 0 && !a.json {
			fmt.Fprintf(a.env.Stderr, msgImported, r.Updated, cfg.Snapshot, cfg.CacheDir)
		}
	}
	targets, err := cfg.Targets(ctx, a.controllers)
	if err != nil && !errors.Is(err, bootstrap.ErrNoTargets) {
		fmt.Fprintf(a.env.Stderr, msgTargetsFailed, err)
	}
	req := workflow.RefreshRequest{
		Targets: targets, Dimensions: dims, Vendor: cfg.Vendor(), Cache: st,
		Sightings: cfg.Sightings(), Policy: cfg.Cache, Workers: cfg.Parallel, Now: a.env.Now,
	}
	if cfg.HasCredentials(ctx) && cfg.Cache.Mode != workflow.ModeOffline {
		if dialer, err := cfg.Dialer(ctx); err == nil {
			req.Dialer = dialer
			if !a.json {
				req.Events.Started = func(d device.Device) { fmt.Fprintf(a.env.Stderr, msgRefreshing, d.Label()) }
			}
		}
	}
	return workflow.Refresh(ctx, req)
}

// banner prints one line on how current the data is, and one line per
// controller whose refresh did not happen as it should.
func (a *app) banner(ctx context.Context, f workflow.Freshness, captures []capture.Capture) {
	names := map[string]string{}
	for _, c := range captures {
		names[c.Host.String()] = sysnameOf(c.Prompt)
	}
	var oldest time.Time
	stale := 0
	var notes []string
	for _, c := range f.Controllers {
		if !c.Oldest.IsZero() && (oldest.IsZero() || c.Oldest.Before(oldest)) {
			oldest = c.Oldest
		}
		if len(c.Stale) > 0 {
			stale++
		}
		name := firstNonEmpty(names[c.Host], c.Host)
		switch {
		case c.Failure != "":
			notes = append(notes, fmt.Sprintf(bannerFailed, name, c.Failure, a.age(c.Oldest)))
		case c.Skipped == workflow.SkipNotConfigured && len(c.Stale) > 0 && a.cfg.HasCredentials(ctx):
			notes = append(notes, fmt.Sprintf(bannerNotConfigured, name))
		}
	}
	line := fmt.Sprintf(bannerHead, len(f.Controllers), a.age(oldest))
	if stale > 0 {
		line += fmt.Sprintf(bannerStale, stale)
	}
	if mode := a.modeText(ctx, f); mode != "" {
		line += bannerSep + mode
	}
	fmt.Fprintln(a.env.Stderr, line)
	for _, n := range notes[:min(len(notes), maxBannerNotes)] {
		fmt.Fprintln(a.env.Stderr, "  "+n)
	}
}

// maxBannerNotes keeps the banner short on large fleets.
const maxBannerNotes = 5

func (a *app) modeText(ctx context.Context, f workflow.Freshness) string {
	cfg := a.cfg
	switch {
	case f.Mode == workflow.ModeOffline:
		return bannerOffline
	case cfg != nil && !cfg.HasCredentials(ctx):
		return bannerNoLogin
	case f.Mode == workflow.ModeLive:
		return bannerLive
	}
	return ""
}

// age renders how long ago t was: "刚刚", "5 分钟前", "6 天前".
func (a *app) age(t time.Time) string {
	if t.IsZero() {
		return ageUnknown
	}
	d := a.env.Now().Sub(t)
	switch {
	case d < time.Minute:
		return ageJustNow
	case d < time.Hour:
		return fmt.Sprintf(ageMinutes, int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf(ageHours, int(d/time.Hour))
	}
	return fmt.Sprintf(ageDays, int(d/(24*time.Hour)))
}

func controllerNames(caps []capture.Capture) string {
	names := make([]string, 0, len(caps))
	for _, c := range caps {
		names = append(names, firstNonEmpty(sysnameOf(c.Prompt), c.Host.String())+"("+c.Host.String()+")")
	}
	return strings.Join(names, " ")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
