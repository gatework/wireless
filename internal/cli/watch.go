package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/batch"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
)

// minInterval keeps watch from hammering controllers.
const minInterval = 30 * time.Second

func (a *app) watchCommand() *cobra.Command {
	var interval time.Duration
	var rounds int
	cmd := &cobra.Command{
		Use: "watch", Short: shortWatch, Args: cobra.NoArgs,
		Example: "  wireless watch --interval 2m          # Ctrl-C 结束\n  wireless watch -c SZX10 --interval 1m",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if interval < minInterval {
				return fmt.Errorf("cli: --interval must be at least %s", minInterval)
			}
			return a.watch(cmd.Context(), interval, rounds)
		},
	}
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Minute, flagInterval)
	cmd.Flags().IntVar(&rounds, "rounds", 0, flagRounds)
	return cmd
}

// watch collects client lists every interval until cancelled or rounds
// are done, appending each round to the sighting journal. A failed round
// is reported and the next one still runs.
func (a *app) watch(ctx context.Context, interval time.Duration, rounds int) error {
	dims := []evidence.Dimension{wireless.DimensionClients}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for n := 1; rounds <= 0 || n <= rounds; n++ {
		started := a.env.Now()
		res, err := a.collect(ctx, dims, 0, true)
		switch {
		case errors.Is(err, context.Canceled) || ctx.Err() != nil:
			return nil
		case err != nil && len(res.Summary.Devices) == 0:
			fmt.Fprintf(a.env.Stderr, msgWatchFailed, n, failureText(err))
		default:
			fmt.Fprintf(a.env.Stderr, msgWatchRound, n, len(res.Summary.Devices), res.Summary.Counts[batch.StateSucceeded],
				durationCell(a.env.Now().Sub(started)))
		}
		if rounds > 0 && n == rounds {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
	return nil
}
