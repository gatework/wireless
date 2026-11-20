package workflow

import (
	"context"
	"fmt"
	"time"

	"github.com/gatework/netops/apply"
	"github.com/gatework/netops/change"
	"github.com/gatework/netops/failure"
	"github.com/gatework/netops/ops"
	"github.com/gatework/netops/rollout"

	"github.com/gatework/wireless/action"
)

// ApplyRequest executes station actions, one plan per controller.
type ApplyRequest struct {
	Plans    []*change.Plan[action.State]
	Renderer action.Renderer
	Dialer   ops.Dialer
	Journal  func(p *change.Plan[action.State]) apply.Journal
	// Save persists the configuration after a verified block or unblock.
	Save bool
	// DryRun reads every station's state and stops before writing.
	DryRun bool
	Now    func() time.Time
}

// Apply runs the plans. Actions on different controllers run at once;
// several actions on one controller run one after another, each round in
// its own session, so that every plan keeps its own journal and outcome.
// There is no canary or failure budget: the actions are independent.
func Apply(ctx context.Context, r ApplyRequest) ([]ops.Outcome, error) {
	mode := apply.ModeExecute
	if r.DryRun {
		mode = apply.ModeDryRun
	}
	var out []ops.Outcome
	for _, round := range rounds(r.Plans) {
		rep, err := ops.Deploy(ctx, ops.DeployRequest[action.State]{
			Plans: round, Dialer: r.Dialer, Read: readback(r.Renderer), Journal: r.Journal,
			Strategy: rollout.Strategy{WaveSize: len(round), MaxFailures: len(round)},
			Mode:     mode, Save: r.Save, Now: r.Now,
		})
		for _, w := range rep.Waves {
			out = append(out, w.Outcomes...)
		}
		if err != nil {
			return out, fmt.Errorf("workflow: apply: %w", err)
		}
	}
	return out, nil
}

// rounds splits plans so that each round holds at most one plan per
// device, keeping the plans' order.
func rounds(plans []*change.Plan[action.State]) [][]*change.Plan[action.State] {
	var out [][]*change.Plan[action.State]
	seen := map[string]int{}
	for _, p := range plans {
		id := p.Target().ID
		i := seen[id]
		seen[id]++
		if i == len(out) {
			out = append(out, nil)
		}
		out[i] = append(out[i], p)
	}
	return out
}

// readback reads a station's state with the plan's readback command.
func readback(rd action.Renderer) func(context.Context, ops.Session, *change.Plan[action.State]) (action.State, error) {
	return func(ctx context.Context, s ops.Session, p *change.Plan[action.State]) (action.State, error) {
		c, ok := action.Of(p)
		if !ok {
			return action.State{}, failure.New(failure.CodeProtocol, "workflow: not a station action")
		}
		got, err := s.Collect(ctx, []string{c.Script.Readback})
		if err != nil {
			return action.State{}, err
		}
		o, ok := got.Answer(c.Script.Readback)
		if !ok {
			return action.State{}, failure.New(failure.CodeRejected, "workflow: readback")
		}
		st, err := rd.Observe(c.Action, c.MAC, o.Raw)
		if err != nil {
			return action.State{}, failure.Wrap(failure.CodeRejected, "workflow: readback", err)
		}
		return st, nil
	}
}
