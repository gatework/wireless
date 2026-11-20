package cli

import (
	"context"
	"net/netip"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/ops"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/roam"
	"github.com/gatework/wireless/vendors/h3c"
)

// defaultSince is how far back roaming history is read by default.
const defaultSince = 24 * time.Hour

// tracks reads the sighting journal since d ago and analyzes it per
// station. keep, when set, limits the stations. It returns nil when the
// journal holds nothing, so rules that need history are skipped rather
// than concluding "no roaming problems".
func (a *app) tracks(ctx context.Context, d time.Duration, keep func(wireless.MAC) bool) ([]roam.Track, error) {
	cfg, err := a.config(ctx)
	if err != nil {
		return nil, err
	}
	var filter func(roam.Observation) bool
	if keep != nil {
		filter = func(o roam.Observation) bool { return keep(o.MAC) }
	}
	obs, err := cfg.Sightings().Read(ctx, a.env.Now().Add(-d), filter)
	if err != nil || len(obs) == 0 {
		return nil, err
	}
	return cfg.Models.Roaming.Tracks(obs), nil
}

// trackOf returns one station's track: the controller's own roam history
// when live and available, otherwise the sighting journal.
func (a *app) trackOf(ctx context.Context, v *wireless.ClientView, d time.Duration) *roam.Track {
	cfg, err := a.config(ctx)
	if err != nil {
		return nil
	}
	params := cfg.Models.Roaming
	if a.live {
		if records, ok := a.roamTrack(ctx, v.Controller.Host, v.Client.MAC); ok && len(records) > 0 {
			t := params.Analyze(roam.FromRoamTrack(v.Controller.Host, v.Client.MAC, records))
			return &t
		}
	}
	tracks, err := a.tracks(ctx, d, func(m wireless.MAC) bool { return m == v.Client.MAC })
	if err != nil || len(tracks) == 0 {
		return nil
	}
	return &tracks[0]
}

// roamTrack asks the controller for a station's roam history. Failures
// are not errors: the history is supplementary evidence.
func (a *app) roamTrack(ctx context.Context, host string, mac wireless.MAC) ([]wireless.RoamRecord, bool) {
	cfg, err := a.config(ctx)
	if err != nil {
		return nil, false
	}
	dialer, err := cfg.Dialer(ctx)
	if err != nil {
		return nil, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, false
	}
	command := h3c.RoamTrackCommand(mac)
	var c capture.Capture
	opErr, closeErr := dialer.Open(ctx, device.Device{ID: addr.String(), Mgmt: addr, Platform: h3c.Platform},
		func(ctx context.Context, s ops.Session) error {
			var err error
			c, err = s.Collect(ctx, []string{command})
			return err
		})
	if opErr != nil || closeErr != nil {
		return nil, false
	}
	o, ok := c.Answer(command)
	if !ok {
		return nil, false
	}
	records, err := cfg.Vendor().RoamTrack(ctx, o)
	return records, err == nil
}
