package workflow

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/gatework/netops/batch"
	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/ops"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/roam"
)

// Store is the capture cache.
type Store interface {
	ops.Snapshots
	LoadAll(ctx context.Context) ([]capture.Capture, error)
}

// Sightings records station sightings for roaming analysis.
type Sightings interface {
	Append(ctx context.Context, obs []roam.Observation) error
}

// CollectRequest collects dimensions from controllers.
type CollectRequest struct {
	Targets    []device.Device
	Dimensions []evidence.Dimension
	Vendor     Vendor
	Dialer     ops.Dialer
	Store      Store
	// Sightings is optional; when set, every fresh client listing is
	// recorded.
	Sightings Sightings
	Workers   int
	Timeout   time.Duration
	Events    batch.Events[capture.Capture]
	// Notify publishes collect.failed for controllers that failed.
	Notify ops.Notify
	Now    func() time.Time
}

// DimensionSummary is how one dimension of one controller decoded.
type DimensionSummary struct {
	Status evidence.Status `json:"status"`
	Facts  int             `json:"facts"`
	Issues []string        `json:"issues,omitempty"`
}

// Collected is the outcome of a collection.
type Collected struct {
	Summary batch.Summary `json:"summary"`
	// Dimensions are keyed by device ID, for the devices that returned a
	// capture.
	Dimensions map[string]map[evidence.Dimension]DimensionSummary `json:"dimensions"`
}

// Collect collects the dimensions into the store and summarizes how each
// requested dimension decoded.
func Collect(ctx context.Context, r CollectRequest) (Collected, error) {
	dims := dimensions(r.Dimensions)
	rep, err := ops.Collect(ctx, ops.CollectRequest{
		Devices: r.Targets, Dimensions: dims, Probes: r.Vendor, Dialer: r.Dialer, Snapshots: r.Store,
		Workers: r.Workers, Timeout: r.Timeout, Events: r.Events, Now: r.Now, Notify: r.Notify,
		OnCapture: sightings(r.Vendor, r.Sightings),
	})
	out := Collected{Summary: rep.Summary(), Dimensions: map[string]map[evidence.Dimension]DimensionSummary{}}
	for _, res := range rep.Results {
		if res.State == batch.StateSkipped || res.Value.Empty() {
			continue
		}
		out.Dimensions[res.Device.ID] = summarize(r.Vendor.Decode(res.Value), dims)
	}
	if err != nil {
		return out, fmt.Errorf("workflow: collect: %w", err)
	}
	return out, nil
}

// sightings returns the hook that records a fresh client listing.
func sightings(v Vendor, s Sightings) func(context.Context, device.Device, capture.Capture) error {
	if s == nil {
		return nil
	}
	return func(ctx context.Context, d device.Device, fresh capture.Capture) error {
		snap := v.Decode(fresh)
		if !snap.Clients.Status.Usable() {
			return nil
		}
		if err := s.Append(ctx, roam.Observe(snap)); err != nil {
			return fmt.Errorf("workflow: sightings %s: %w", d.ID, err)
		}
		return nil
	}
}

func summarize(s *wireless.Snapshot, dims []evidence.Dimension) map[evidence.Dimension]DimensionSummary {
	out := make(map[evidence.Dimension]DimensionSummary, len(dims))
	for _, d := range dims {
		status, facts, issues := s.Observed(d)
		ds := DimensionSummary{Status: status, Facts: facts}
		for _, i := range issues {
			if !slices.Contains(ds.Issues, i.Code) {
				ds.Issues = append(ds.Issues, i.Code)
			}
		}
		out[d] = ds
	}
	return out
}

func dimensions(dims []evidence.Dimension) []evidence.Dimension {
	if len(dims) == 0 {
		return wireless.Dimensions()
	}
	return dims
}
