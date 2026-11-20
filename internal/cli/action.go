package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/apply"
	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/change"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/failure"
	"github.com/gatework/netops/ops"
	"github.com/gatework/netops/term"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/action"
	"github.com/gatework/wireless/internal/bootstrap"
	"github.com/gatework/wireless/internal/workflow"
	"github.com/gatework/wireless/vendors/h3c"
)

// errAborted marks an action the operator did not confirm.
var errAborted = errors.New("cli: aborted")

// maxTargets bounds one invocation; a larger list is almost certainly a
// mistake in a file.
const maxTargets = 500

// actionFlags are shared by every action command.
type actionFlags struct {
	yes, planOnly, save, all bool
	file                     string
}

func (f *actionFlags) bind(cmd *cobra.Command, save bool) {
	cmd.Flags().BoolVar(&f.yes, "yes", false, flagYes)
	cmd.Flags().BoolVar(&f.planOnly, "plan", false, flagPlanOnly)
	cmd.Flags().BoolVar(&f.all, "all", false, flagAll)
	cmd.Flags().StringVarP(&f.file, "file", "f", "", flagFile)
	if save {
		cmd.Flags().BoolVar(&f.save, "save", false, flagSave)
	}
}

func (a *app) kickCommand() *cobra.Command {
	var f actionFlags
	cmd := &cobra.Command{
		Use: "kick <MAC|IP|账号>...", Short: shortKick, Args: cobra.ArbitraryArgs,
		Example: "  wireless kick 10.158.8.247 --plan\n  wireless kick aa32-ed65-d5c7\n  wireless kick -f list.txt --yes",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runAction(cmd.Context(), action.KindKick, args, f)
		},
	}
	f.bind(cmd, false)
	return cmd
}

func (a *app) blockCommand() *cobra.Command {
	block := &cobra.Command{Use: "block", Short: shortBlock}
	var add, del actionFlags
	addCmd := &cobra.Command{
		Use: "add <MAC|IP|账号>...", Short: shortBlockAdd, Args: cobra.ArbitraryArgs,
		Example: "  wireless block add 10.158.8.247 --plan   # 全网所有控制器\n  wireless block add aa32-ed65-d5c7 -c SZX10\n  wireless block add -f incident.txt --save",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runAction(cmd.Context(), action.KindBlock, args, add)
		},
	}
	add.bind(addCmd, true)
	delCmd := &cobra.Command{
		Use: "remove <MAC|IP|账号>...", Aliases: []string{"rm", "del"}, Short: shortBlockDel, Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runAction(cmd.Context(), action.KindUnblock, args, del)
		},
	}
	del.bind(delCmd, true)
	listCmd := &cobra.Command{
		Use: "list", Short: shortBlockList, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.listBlacklist(cmd.Context()) },
	}
	block.AddCommand(addCmd, delCmd, listCmd)
	return block
}

// runAction resolves what the operator typed to stations, plans the
// action on the right controllers, confirms once and runs every plan.
func (a *app) runAction(ctx context.Context, kind action.Kind, args []string, f actionFlags) error {
	inputs, err := a.actionInputs(args, f.file)
	if err != nil {
		return err
	}
	cfg, err := a.config(ctx)
	if err != nil {
		return err
	}
	// Resolve targets on current data: a station may have roamed since the
	// cache was written. Without credentials the cache is all there is,
	// and the banner says how old it is.
	if cfg.Cache.Mode == workflow.ModeAuto {
		cfg.Cache.Mode = workflow.ModeLive
		defer func() { cfg.Cache.Mode = workflow.ModeAuto }()
	}
	ix, err := a.index(ctx, wireless.DimensionClients, wireless.DimensionDot1X, wireless.DimensionMAC)
	if err != nil && !errors.Is(err, errNotFound) {
		return err
	}
	targets, err := a.resolveTargets(ix, inputs, f.all)
	if err != nil {
		return err
	}
	plans, err := a.planTargets(ctx, kind, targets, ix)
	if err != nil {
		return err
	}
	a.renderPlans(plans)
	if f.planOnly {
		return nil
	}
	if err := a.confirm(kind, targets, len(plans), f.yes); err != nil {
		return err
	}
	dialer, err := cfg.Dialer(ctx)
	if err != nil {
		return err
	}
	j, err := cfg.Journal()
	if err != nil {
		return err
	}
	for _, p := range plans {
		e, err := p.Envelope()
		if err != nil {
			return fmt.Errorf("cli: %w", err)
		}
		if err := j.SavePlan(ctx, e, operator(a.env)); err != nil {
			return err
		}
	}
	outcomes, err := workflow.Apply(ctx, workflow.ApplyRequest{
		Plans: plans, Renderer: cfg.Vendor(), Dialer: dialer,
		Journal: func(p *change.Plan[action.State]) apply.Journal { return j.Execution(p.Meta().ID, p.Target().ID) },
		Save:    f.save && kind != action.KindKick, Now: a.env.Now,
	})
	if err != nil && ctx.Err() == nil && len(outcomes) == 0 {
		return err
	}
	return a.finishAction(ctx, cfg.JournalDir, outcomes, f.save && kind != action.KindKick)
}

// operator names who runs the action, for the audit trail.
func operator(env Env) string {
	for _, kv := range env.Environ {
		if u, ok := strings.CutPrefix(kv, "USER="); ok {
			return u
		}
	}
	return ""
}

// actionInputs gathers targets from arguments and the --file list.
func (a *app) actionInputs(args []string, file string) ([]string, error) {
	inputs := slices.Clone(args)
	if file != "" {
		lines, err := readTargets(file)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, lines...)
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("cli: give a MAC, IP or username, or --file")
	}
	if len(inputs) > maxTargets {
		return nil, fmt.Errorf("cli: %d targets exceed the limit of %d", len(inputs), maxTargets)
	}
	return inputs, nil
}

// resolveTargets turns each input into exactly one station, or into
// several only with --all; anything ambiguous or unknown stops the run
// before a command is planned.
func (a *app) resolveTargets(ix *wireless.Index, inputs []string, all bool) ([]wireless.Target, error) {
	if ix == nil {
		ix = wireless.NewIndex()
	}
	var out []wireless.Target
	failed := false
	for _, in := range inputs {
		q, err := wireless.ParseQuery(in)
		if err != nil {
			return nil, err
		}
		found := ix.Resolve(q)
		act := wireless.Actionable(found)
		switch {
		case len(act) == 0:
			a.printf(msgResolveNone, in, hintsText(found))
			failed = true
		case len(act) > 1 && !all:
			a.printf(msgResolveMany, in, len(act), targetsText(act))
			failed = true
		default:
			for _, t := range act {
				if !slices.ContainsFunc(out, func(x wireless.Target) bool { return x.MAC == t.MAC }) {
					out = append(out, t)
				}
			}
		}
	}
	if failed {
		return nil, errNotFound
	}
	return out, nil
}

// planTargets plans each station: a kick where it is online, a block or
// unblock on every selected controller.
func (a *app) planTargets(ctx context.Context, kind action.Kind, targets []wireless.Target, ix *wireless.Index) ([]*change.Plan[action.State], error) {
	cfg, err := a.config(ctx)
	if err != nil {
		return nil, err
	}
	var fleet []device.Device
	if kind != action.KindKick {
		if fleet, err = a.fleet(ctx, ix); err != nil {
			return nil, err
		}
	}
	now := a.env.Now().UTC()
	var plans []*change.Plan[action.State]
	for _, t := range targets {
		ctrls := fleet
		if kind == action.KindKick {
			ctrls = a.onlineSelected(t)
			if len(ctrls) == 0 {
				a.printf(msgNotOnline, t.MAC.H3C())
				continue
			}
		}
		online := func(d device.Device) bool {
			return slices.ContainsFunc(t.Online, func(c wireless.Controller) bool { return c.Host == d.Mgmt.String() })
		}
		meta := change.Meta{
			ID:      fmt.Sprintf("%s-%s-%s", kind, now.Format("20060102T150405Z"), strings.ReplaceAll(t.MAC.H3C(), "-", "")),
			Author:  operator(a.env),
			Reason:  string(kind),
			Created: now,
		}
		batch, err := action.Batch(meta, kind, t.MAC, ctrls, online, cfg.Vendor())
		if err != nil {
			return nil, err
		}
		plans = append(plans, batch...)
	}
	if len(plans) == 0 {
		return nil, errNotFound
	}
	return plans, nil
}

// fleet returns the selected controllers: the configured ones, or, when
// none are configured, those present in the snapshot.
func (a *app) fleet(ctx context.Context, ix *wireless.Index) ([]device.Device, error) {
	cfg, err := a.config(ctx)
	if err != nil {
		return nil, err
	}
	devices, err := cfg.Targets(ctx, a.controllers)
	if err == nil {
		return devices, nil
	}
	if !errors.Is(err, bootstrap.ErrNoTargets) || ix == nil {
		return nil, err
	}
	var out []device.Device
	for _, s := range ix.Snapshots() {
		if d, ok := controllerDevice(s.Controller); ok {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, err
	}
	return out, nil
}

// onlineSelected returns the controllers where t is online, limited by
// --controller.
func (a *app) onlineSelected(t wireless.Target) []device.Device {
	var out []device.Device
	for _, c := range t.Online {
		if !a.selects(c.Host, c.Name) {
			continue
		}
		if d, ok := controllerDevice(c); ok {
			out = append(out, d)
		}
	}
	return out
}

// controllerDevice converts a controller seen in a snapshot to a device.
func controllerDevice(c wireless.Controller) (device.Device, bool) {
	addr, err := netip.ParseAddr(c.Host)
	if err != nil {
		return device.Device{}, false
	}
	return device.Device{ID: addr.String(), Name: c.Name, Mgmt: addr, Platform: h3c.Platform, Version: c.Version}, true
}

func (a *app) renderPlans(plans []*change.Plan[action.State]) {
	a.printf(msgPlanTitle, len(plans))
	t := newTable(headPlan...)
	for _, p := range plans {
		c, _ := action.Of(p)
		cmds := make([]string, 0, len(p.Commands()))
		for _, cmd := range p.Commands() {
			cmds = append(cmds, cmd.Display())
		}
		t.add(p.Target().Label(), c.MAC.H3C(), string(c.Action), strings.Join(cmds, " ; "), c.Script.Readback)
	}
	_ = t.render(a.env.Stdout)
}

// confirm requires the operator to type the action and the MAC (one
// station) or the number of plans (several), unless --yes.
func (a *app) confirm(kind action.Kind, targets []wireless.Target, plans int, yes bool) error {
	want := strings.ToUpper(string(kind)) + " " + fmt.Sprint(plans)
	if len(targets) == 1 {
		want = strings.ToUpper(string(kind)) + " " + targets[0].MAC.H3C()
	}
	p := term.Prompt{In: a.env.Stdin, Out: a.env.Stdout, Interactive: a.env.Interactive}
	if !yes && !a.env.Interactive {
		a.printf(msgNeedTTY)
		return errAborted
	}
	if err := p.Confirm(fmt.Sprintf(msgConfirmLead, plans), want, yes); err != nil {
		a.printf(msgAborted)
		return errAborted
	}
	return nil
}

// finishAction reports every outcome. Anything not verified (or already
// in effect) exits incomplete.
func (a *app) finishAction(ctx context.Context, journalDir string, outcomes []ops.Outcome, save bool) error {
	t := newTable(headOutcome...)
	rows := make([]outcomeJSON, 0, len(outcomes))
	incomplete := false
	for _, o := range outcomes {
		status := string(o.Record.Status)
		note := ""
		if save && o.Record.Status == apply.StatusVerified {
			note = msgSaveFailed
			if o.Saved {
				note = msgSavedShort
			}
		}
		incomplete = incomplete || !o.Succeeded()
		row := outcomeJSON{Controller: o.Device, Plan: o.Plan, Commands: o.Record.Commands, Status: status, Saved: o.Saved}
		if !o.Succeeded() {
			row.Diagnostics = o.Record.Diagnostics
			row.Codes = o.Codes
		}
		t.add(o.Device.Label(), o.Plan, statusText(status), dash(journalDir), dash(note))
		rows = append(rows, row)
	}
	if a.json {
		if err := a.emitJSON(rows); err != nil {
			return err
		}
	} else if err := t.render(a.env.Stdout); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if incomplete {
		return errIncomplete
	}
	return nil
}

// outcomeJSON is the machine-readable result of one plan; diagnostics are
// safe codes, never device output.
type outcomeJSON struct {
	Controller  device.Device      `json:"controller"`
	Plan        string             `json:"plan"`
	Commands    []string           `json:"commands"`
	Status      string             `json:"status"`
	Saved       bool               `json:"saved,omitempty"`
	Diagnostics []apply.Diagnostic `json:"diagnostics,omitempty"`
	Codes       []failure.Code     `json:"codes,omitempty"`
}

// listBlacklist reads the static blacklist of every selected controller
// and flags entries missing on some of them: a station blocked on one
// controller can still join through another.
func (a *app) listBlacklist(ctx context.Context) error {
	cfg, err := a.config(ctx)
	if err != nil {
		return err
	}
	targets, err := cfg.Targets(ctx, a.controllers)
	if err != nil {
		return err
	}
	dialer, err := cfg.Dialer(ctx)
	if err != nil {
		return err
	}
	vendor := cfg.Vendor()
	on := map[wireless.MAC][]string{}
	var order []wireless.MAC
	read := 0
	for _, t := range targets {
		var c capture.Capture
		opErr, closeErr := dialer.Open(ctx, t, func(ctx context.Context, s ops.Session) error {
			var err error
			c, err = s.Collect(ctx, []string{h3c.CommandStaticBlacklist})
			return err
		})
		if err := errors.Join(opErr, closeErr); err != nil {
			a.printf(msgListFailed, t.Label(), failureText(err))
			continue
		}
		o, ok := c.Answer(h3c.CommandStaticBlacklist)
		if !ok {
			continue
		}
		read++
		for _, e := range vendor.StaticBlacklist(ctx, o) {
			if on[e.MAC] == nil {
				order = append(order, e.MAC)
			}
			on[e.MAC] = append(on[e.MAC], t.Label())
		}
	}
	if a.json {
		return a.emitJSON(map[string]any{"controllers": read, "entries": on})
	}
	a.printf(msgBlacklist, len(order), read)
	tbl := newTable(headBlacklist...)
	for _, m := range order {
		state := msgConsistent
		if len(on[m]) < read {
			state = fmt.Sprintf(msgPartialBlock, len(on[m]), read)
		}
		tbl.add(m.H3C(), state, strings.Join(on[m], ", "))
	}
	return tbl.render(a.env.Stdout)
}

// failureText renders the failure codes of an error in Chinese.
func failureText(err error) string {
	codes := failure.Classify(err)
	out := make([]string, len(codes))
	for i, c := range codes {
		out[i] = term.Chinese().Text(string(c))
	}
	return strings.Join(out, "，")
}

// readTargets reads one target per line; blank lines and "#" comments
// are skipped.
func readTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cli: %w", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cli: %w", err)
	}
	return out, nil
}

func targetsText(ts []wireless.Target) string {
	parts := make([]string, 0, len(ts))
	for _, t := range ts {
		where := "-"
		if len(t.Online) > 0 {
			where = t.Online[0].Label()
		}
		parts = append(parts, t.MAC.H3C()+"@"+where)
	}
	return strings.Join(parts, ", ")
}

func hintsText(ts []wireless.Target) string {
	if len(ts) == 0 {
		return ""
	}
	return fmt.Sprintf(msgConflictHint, targetsText(ts))
}

func statusText(s string) string {
	if w, ok := outcomeWords[s]; ok {
		return w
	}
	return dash(s)
}
