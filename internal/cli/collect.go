package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/batch"
	nbootstrap "github.com/gatework/netops/bootstrap"
	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/ops"
	"github.com/gatework/netops/term"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/internal/workflow"
)

// errIncomplete marks a run whose evidence is partial; it exits 1.
var errIncomplete = errors.New("cli: incomplete")

func (a *app) collectCommand() *cobra.Command {
	var dims []string
	var parallel int
	cmd := &cobra.Command{
		Use: "collect", Short: shortCollect, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			selected, err := parseDimensions(dims)
			if err != nil {
				return err
			}
			res, err := a.collect(cmd.Context(), selected, parallel, false)
			if err != nil && len(res.Summary.Devices) == 0 {
				return err
			}
			if a.json {
				if err := a.emitJSON(res); err != nil {
					return err
				}
			} else if err := renderCollect(a, res); err != nil {
				return err
			}
			if err != nil || res.Summary.Interrupted || res.Summary.Counts[batch.StateSucceeded] != res.Summary.Requested {
				return errIncomplete
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&dims, "dimension", nil, flagDimension)
	cmd.Flags().IntVar(&parallel, "parallel", 0, flagParallel)
	return cmd
}

// collect refreshes dims on the selected controllers. Progress goes to
// stderr unless quiet.
func (a *app) collect(ctx context.Context, dims []evidence.Dimension, parallel int, quiet bool) (workflow.Collected, error) {
	return a.collectNotify(ctx, dims, parallel, quiet, ops.Notify{})
}

// collectNotify is collect that also publishes collection failures.
func (a *app) collectNotify(ctx context.Context, dims []evidence.Dimension, parallel int, quiet bool, n ops.Notify) (workflow.Collected, error) {
	cfg, err := a.config(ctx)
	if err != nil {
		return workflow.Collected{}, err
	}
	targets, err := cfg.Targets(ctx, a.controllers)
	if err != nil {
		return workflow.Collected{}, err
	}
	dialer, err := cfg.Dialer(ctx)
	if err != nil {
		return workflow.Collected{}, err
	}
	st, err := cfg.Store()
	if err != nil {
		return workflow.Collected{}, err
	}
	if parallel <= 0 {
		parallel = cfg.Parallel
	}
	if err := nbootstrap.PrepareFileLimit(ctx, min(parallel, len(targets))); err != nil {
		return workflow.Collected{}, err
	}
	var events batch.Events[capture.Capture]
	if !quiet && !a.json {
		events.Started = func(d device.Device) { fmt.Fprintf(a.env.Stderr, msgProgressStart, d.Label()) }
		events.Finished = func(r batch.Result[capture.Capture]) {
			fmt.Fprintf(a.env.Stderr, msgProgressDone, r.Device.Label(), statusWords[string(r.State)], durationCell(r.Duration))
		}
	}
	return workflow.Collect(ctx, workflow.CollectRequest{
		Targets: targets, Dimensions: dims, Vendor: cfg.Vendor(), Dialer: dialer,
		Store: st, Sightings: cfg.Sightings(), Workers: parallel, Events: events, Now: a.env.Now, Notify: n,
	})
}

func renderCollect(a *app, res workflow.Collected) error {
	t := newTable(headCollect...)
	for _, d := range res.Summary.Devices {
		dims := res.Dimensions[d.Device.ID]
		var parts []string
		for _, dim := range sortedDims(dims) {
			ds := dims[dim]
			parts = append(parts, fmt.Sprintf("%s=%d/%s", dim, ds.Facts, statusWords[string(ds.Status)]))
		}
		codes := make([]string, len(d.Codes))
		for i, c := range d.Codes {
			codes[i] = term.Chinese().Text(string(c))
		}
		t.add(d.Device.Label(), statusWords[string(d.State)], durationCell(time.Duration(d.DurationMS)*time.Millisecond),
			strings.Join(parts, " "), dash(strings.Join(codes, "，")))
	}
	return t.render(a.env.Stdout)
}

func parseDimensions(names []string) ([]evidence.Dimension, error) {
	known := wireless.Dimensions()
	out := make([]evidence.Dimension, 0, len(names))
	for _, n := range names {
		d := evidence.Dimension(n)
		if !slices.Contains(known, d) {
			return nil, fmt.Errorf("cli: unknown dimension %q", n)
		}
		out = append(out, d)
	}
	return out, nil
}

func sortedDims(m map[evidence.Dimension]workflow.DimensionSummary) []evidence.Dimension {
	var out []evidence.Dimension
	for _, d := range wireless.Dimensions() {
		if _, ok := m[d]; ok {
			out = append(out, d)
		}
	}
	return out
}
