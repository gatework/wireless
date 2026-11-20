package workflow

import (
	"context"

	"golang.org/x/sync/errgroup"

	"github.com/gatework/netops/capture"

	"github.com/gatework/wireless"
)

// Decode turns captures into snapshots with at most workers decoders at a
// time and indexes them in the captures' order. Decoding is CPU-bound and
// independent per controller.
func Decode(ctx context.Context, v Vendor, captures []capture.Capture, workers int) (*wireless.Index, error) {
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(max(1, min(workers, 64)))
	snapshots := make([]*wireless.Snapshot, len(captures))
	for i, c := range captures {
		g.Go(func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			snapshots[i] = v.Decode(c)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return wireless.NewIndex(snapshots...), nil
}
