package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/batch"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/failure"
	"github.com/gatework/netops/job"
	"github.com/gatework/netops/ops"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/internal/bootstrap"
	"github.com/gatework/wireless/internal/workflow"
)

// Watch job names, shown in status.
const (
	jobClients = "clients"
	jobSweep   = "sweep"
)

func (a *app) watchCommand() *cobra.Command {
	var interval time.Duration
	var rounds int
	cmd := &cobra.Command{
		Use: "watch", Short: shortWatch, Args: cobra.NoArgs,
		Example: "  wireless watch --interval 2m          # Ctrl-C 结束\n  wireless watch -c SZX10 --interval 1m",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if interval != 0 && interval < bootstrap.MinWatchInterval {
				return fmt.Errorf("cli: --interval must be at least %s", bootstrap.MinWatchInterval)
			}
			return a.watch(cmd.Context(), interval, rounds)
		},
	}
	cmd.Flags().DurationVar(&interval, "interval", 0, flagInterval)
	cmd.Flags().IntVar(&rounds, "rounds", 0, flagRounds)
	return cmd
}

// watch runs the client sampling job, and the configured full sweep, on
// their schedules until cancelled or rounds sampling runs are done. The
// first sampling runs at once. Runs never overlap, every run is recorded,
// and failures go to the event log and webhook.
func (a *app) watch(ctx context.Context, interval time.Duration, rounds int) error {
	cfg, err := a.config(ctx)
	if err != nil {
		return err
	}
	if interval == 0 {
		interval = cfg.Watch.Interval
	}
	bus, err := cfg.Events()
	if err != nil {
		return err
	}
	history, err := cfg.Runs()
	if err != nil {
		return err
	}
	notify := ops.Notify{Publisher: bus, Tool: "wireless", OnError: func(err error) {
		fmt.Fprintf(a.env.Stderr, msgEventUndelivered, failureText(err))
	}}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	every, err := job.ParseSpec(fmt.Sprintf("@every %s", interval), cfg.Location)
	if err != nil {
		return err
	}
	n := 0
	clients := job.Job{Name: jobClients, Spec: every, Timeout: 2 * interval, Run: func(ctx context.Context) (string, error) {
		n++
		summary, err := a.watchRound(ctx, n, []evidence.Dimension{wireless.DimensionClients}, notify)
		if rounds > 0 && n >= rounds {
			cancel()
		}
		return summary, err
	}}
	jobs := []job.Job{clients}
	if cfg.Watch.Sweep != nil {
		jobs = append(jobs, job.Job{Name: jobSweep, Spec: *cfg.Watch.Sweep, Run: func(ctx context.Context) (string, error) {
			return a.watchRound(ctx, 0, nil, notify)
		}})
	}
	s, err := job.NewScheduler(jobs, job.Options{History: history, Events: bus, Source: "wireless", Now: a.env.Now})
	if err != nil {
		return err
	}
	s.RunNow(ctx, clients)
	if ctx.Err() != nil {
		return nil
	}
	if err := s.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// watchRound collects dims (every dimension when nil) and reports the round
// on stderr. It fails only when no controller could be read.
func (a *app) watchRound(ctx context.Context, n int, dims []evidence.Dimension, notify ops.Notify) (string, error) {
	started := a.env.Now()
	res, err := a.collectNotify(ctx, dims, 0, true, notify)
	ok := res.Summary.Counts[batch.StateSucceeded]
	summary := fmt.Sprintf("%d/%d controllers complete", ok, len(res.Summary.Devices))
	switch {
	case ctx.Err() != nil:
		return summary, ctx.Err()
	case err != nil && len(res.Summary.Devices) == 0:
		fmt.Fprintf(a.env.Stderr, msgWatchFailed, n, failureText(err))
		return "", err
	case len(res.Summary.Devices) > 0 && ok == 0:
		fmt.Fprintf(a.env.Stderr, msgWatchRound, n, len(res.Summary.Devices), ok, durationCell(a.env.Now().Sub(started)))
		return summary, failure.New(firstCode(res, err), "watch: no controller answered")
	}
	fmt.Fprintf(a.env.Stderr, msgWatchRound, n, len(res.Summary.Devices), ok, durationCell(a.env.Now().Sub(started)))
	return summary, nil
}

// firstCode names why a round read nothing: the first controller's code,
// else the run error's.
func firstCode(res workflow.Collected, err error) failure.Code {
	for _, d := range res.Summary.Devices {
		if len(d.Codes) > 0 {
			return d.Codes[0]
		}
	}
	if c := failure.Primary(err); c != failure.CodeUnset {
		return c
	}
	return failure.CodeUnreachable
}

// watchStatus prints the last run of each watch job.
func (a *app) watchStatus(ctx context.Context, cfg *bootstrap.Config) {
	h, err := cfg.Runs()
	if err != nil {
		return
	}
	for _, name := range []string{jobClients, jobSweep} {
		last, err := h.Last(ctx, name, 1)
		if err != nil || len(last) == 0 {
			continue
		}
		r := last[0]
		state := statusWords[string(r.Status)]
		if len(r.Codes) > 0 {
			state += "（" + failureText(failure.New(r.Codes[0], "")) + "）"
		}
		a.printf(statusWatchLine, name, a.age(r.Finished), state, r.Summary)
	}
}
