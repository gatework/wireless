package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/assess"
)

func (a *app) healthCommand() *cobra.Command {
	var detail bool
	var failOn string
	cmd := &cobra.Command{
		Use: "health", Short: shortHealth, Args: cobra.NoArgs,
		Example: "  wireless health                  # 按规则汇总\n  wireless health --detail -c SZX9  # 逐条明细\n  wireless health --fail-on high   # 用于 cron/监控：有高危即退出码 1",
		RunE: func(cmd *cobra.Command, _ []string) error {
			threshold, err := parseSeverity(failOn)
			if err != nil {
				return err
			}
			ix, err := a.index(cmd.Context())
			if err != nil {
				return err
			}
			cfg, err := a.config(cmd.Context())
			if err != nil {
				return err
			}
			in, err := cfg.Inspector(cmd.Context())
			if err != nil {
				return err
			}
			tracks, err := a.tracks(cmd.Context(), defaultSince, nil)
			if err != nil {
				return err
			}
			report, err := in.Run(cmd.Context(), ix, tracks)
			if err != nil {
				return err
			}
			findings := report.Findings()
			if a.json {
				if err := a.emitJSON(report); err != nil {
					return err
				}
			} else if err := a.renderHealth(findings, report.Controllers, tracks == nil, detail); err != nil {
				return err
			}
			if threshold != assess.SeverityUnset && len(findings) > 0 && findings[0].Severity >= threshold {
				return errIncomplete
			}
			_, skipped := ruleCounts(report.Controllers)
			if len(skipped) > 0 {
				return errIncomplete
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&detail, "detail", false, flagDetail)
	cmd.Flags().StringVar(&failOn, "fail-on", "", flagFailOn)
	return cmd
}

func (a *app) renderHealth(findings []assess.Finding, reports []healthReport, noHistory, detail bool) error {
	ran, skipped := ruleCounts(reports)
	if noHistory {
		a.printf(msgNoHistory)
	}
	if len(findings) == 0 {
		a.printf(msgHealthNone, ran, len(skipped))
	} else if detail {
		t := newTable(headHealth...)
		for _, f := range findings {
			t.add(severityWords[f.Severity.String()], f.Title, subjectText(f.Subject), clip(actualText(f.Actual), clipActual), clip(f.Detail, clipDetail))
		}
		if err := a.list(t); err != nil {
			return err
		}
	} else if err := a.healthSummary(findings); err != nil {
		return err
	}
	if len(skipped) > 0 {
		a.printf(msgHealthSkipped, strings.Join(skipped, ", "))
	}
	return nil
}

// healthSummary shows one row per rule: severity, count, controllers and
// a few examples, most severe first.
func (a *app) healthSummary(findings []assess.Finding) error {
	type row struct {
		f        assess.Finding
		count    int
		ctrls    []string
		examples []string
	}
	var order []assess.RuleID
	rows := map[assess.RuleID]*row{}
	for _, f := range findings {
		r, ok := rows[f.Rule]
		if !ok {
			r = &row{f: f}
			rows[f.Rule] = r
			order = append(order, f.Rule)
		}
		r.count++
		ctrl, obj := splitSubject(f.Subject)
		if !slices.Contains(r.ctrls, ctrl) {
			r.ctrls = append(r.ctrls, ctrl)
		}
		if len(r.examples) < summaryExamples && obj != "" {
			r.examples = append(r.examples, obj)
		}
	}
	t := newTable(headHealthSummary...)
	for _, id := range order {
		r := rows[id]
		t.add(severityWords[r.f.Severity.String()], r.f.Title, fmt.Sprint(r.count), clip(strings.Join(r.ctrls, " "), clipControllers),
			clip(strings.Join(r.examples, "，"), clipDetail))
	}
	if err := t.render(a.env.Stdout); err != nil {
		return err
	}
	a.printf(msgHealthDetailHint)
	return nil
}

// Display bounds of health columns, in terminal columns.
const (
	summaryExamples = 3
	clipActual      = 24
	clipDetail      = 60
	clipControllers = 40
)

// subjectText renders "controller:AC(1.2.3.4)/ap:X/radio:1" as
// "AC › AP X › 射频 1".
func subjectText(s assess.Subject) string {
	ctrl, obj := splitSubject(s)
	if obj == "" {
		return ctrl
	}
	return ctrl + " › " + obj
}

// splitSubject returns the controller name and the path below it.
func splitSubject(s assess.Subject) (string, string) {
	chain := s.Parts()
	ctrl := ""
	var parts []string
	for _, c := range chain {
		if c.Kind == "controller" {
			ctrl, _, _ = strings.Cut(c.Key, "(")
			continue
		}
		key := c.Key
		if w, ok := policyShort[key]; ok && c.Kind == "policy" {
			key = w
		}
		parts = append(parts, strings.TrimSpace(kindWords[c.Kind]+" "+key))
	}
	return ctrl, strings.Join(parts, " › ")
}

// clip shortens s to at most n terminal columns.
func clip(s string, n int) string {
	if displayWidth(s) <= n {
		return s
	}
	var b strings.Builder
	w := 0
	for _, r := range s {
		rw := displayWidth(string(r))
		if w+rw > n-1 {
			break
		}
		b.WriteRune(r)
		w += rw
	}
	return b.String() + "…"
}

func parseSeverity(s string) (assess.Severity, error) {
	if s == "" {
		return assess.SeverityUnset, nil
	}
	sev, err := assess.ParseSeverity(strings.ToLower(s))
	if err != nil {
		return assess.SeverityUnset, fmt.Errorf("cli: --fail-on %q: %w", s, err)
	}
	return sev, nil
}
