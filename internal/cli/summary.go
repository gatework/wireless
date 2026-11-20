package cli

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/health"
)

func (a *app) summaryCommand() *cobra.Command {
	return &cobra.Command{
		Use: "summary", Short: shortSummary, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ix, err := a.index(cmd.Context())
			if err != nil {
				return err
			}
			rows := summaries(ix)
			ssids := ssidStats(ix)
			if a.json {
				return a.emitJSON(map[string]any{"controllers": rows, "ssids": ssids})
			}
			t := newTable(headSummary...)
			for _, r := range rows {
				t.add(r.Controller.Label(), dash(r.Controller.Version), fmt.Sprintf("%d/%d", r.Capacity.Connected, r.Capacity.Total),
					fmt.Sprintf("%d/%d", r.Capacity.LicensesRemaining, r.Capacity.Licenses), fmt.Sprint(r.Clients),
					fmt.Sprint(r.Dot1X), fmt.Sprint(r.MAC), fmt.Sprint(r.RecentConflicts), r.coverageText())
			}
			if err := t.render(a.env.Stdout); err != nil {
				return err
			}
			a.printf(msgSSIDTitle)
			s := newTable(headSSID...)
			for _, r := range ssids {
				s.add(r.SSID, fmt.Sprint(r.Clients), fmt.Sprint(r.Band24), fmt.Sprint(r.Band5), r.accessText(),
					fmt.Sprintf("%.0f", r.MeanRSSI), fmt.Sprintf("%.0f%%", r.WeakPercent))
			}
			return s.render(a.env.Stdout)
		},
	}
}

// controllerSummary is one row of the fleet overview.
type controllerSummary struct {
	Controller      wireless.Controller `json:"controller"`
	Capacity        wireless.APCapacity `json:"capacity"`
	Clients         int                 `json:"clients"`
	Dot1X           int                 `json:"dot1x_sessions"`
	MAC             int                 `json:"mac_sessions"`
	RecentConflicts int                 `json:"recent_conflicts"`
	Coverage        evidence.Coverage   `json:"coverage"`
}

func (s controllerSummary) coverageText() string {
	var partial []string
	for _, d := range wireless.Dimensions() {
		if st := s.Coverage.Status(d); st != evidence.StatusComplete {
			partial = append(partial, string(d)+"="+statusWords[string(st)])
		}
	}
	if len(partial) == 0 {
		return statusWords[string(evidence.StatusComplete)]
	}
	return strings.Join(partial, " ")
}

func summaries(ix *wireless.Index) []controllerSummary {
	var out []controllerSummary
	for _, s := range ix.Snapshots() {
		since := s.CollectedAt.AddDate(0, 0, -7)
		recent := 0
		for _, c := range s.Conflicts.Facts {
			if !c.At.Before(since) {
				recent++
			}
		}
		out = append(out, controllerSummary{
			Controller: s.Controller, Capacity: s.Capacity, Clients: len(s.Clients.Facts),
			Dot1X: len(s.Dot1X.Facts), MAC: len(s.MAC.Facts), RecentConflicts: recent, Coverage: s.Coverage(),
		})
	}
	return out
}

// ssidSummary is the fleet-wide picture of one SSID.
type ssidSummary struct {
	SSID        string                        `json:"ssid"`
	Clients     int                           `json:"clients"`
	Band24      int                           `json:"band_24"`
	Band5       int                           `json:"band_5"`
	Access      map[wireless.AccessMethod]int `json:"access"`
	MeanRSSI    float64                       `json:"mean_rssi"`
	WeakPercent float64                       `json:"weak_percent"`
}

func (s ssidSummary) accessText() string {
	keys := make([]wireless.AccessMethod, 0, len(s.Access))
	for k := range s.Access {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b wireless.AccessMethod) int { return cmp.Compare(s.Access[b], s.Access[a]) })
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s:%d", dash(k.String()), s.Access[k])
	}
	return strings.Join(parts, " ")
}

// weakRSSI is the RSSI below which the overview counts a client as weak.
const weakRSSI = 20

func ssidStats(ix *wireless.Index) []ssidSummary {
	byName := map[string]*ssidSummary{}
	sums := map[string]int{}
	weak := map[string]int{}
	for v := range ix.Clients() {
		c := v.Client
		s, ok := byName[c.SSID]
		if !ok {
			s = &ssidSummary{SSID: c.SSID, Access: map[wireless.AccessMethod]int{}}
			byName[c.SSID] = s
		}
		s.Clients++
		switch c.Band() {
		case wireless.Band2G4:
			s.Band24++
		case wireless.Band5G:
			s.Band5++
		case wireless.BandUnset, wireless.Band6G:
		}
		s.Access[v.Access]++
		sums[c.SSID] += c.RSSI
		if c.RSSI < weakRSSI {
			weak[c.SSID]++
		}
	}
	out := make([]ssidSummary, 0, len(byName))
	for name, s := range byName {
		s.MeanRSSI = float64(sums[name]) / float64(s.Clients)
		s.WeakPercent = float64(weak[name]) * 100 / float64(s.Clients)
		out = append(out, *s)
	}
	slices.SortFunc(out, func(a, b ssidSummary) int {
		return cmp.Or(cmp.Compare(b.Clients, a.Clients), cmp.Compare(a.SSID, b.SSID))
	})
	return out
}

// healthReport is one controller's assessment.
type healthReport = health.ControllerReport

// ruleCounts returns how many rule runs happened and which rules were
// skipped on which controller for incomplete evidence.
func ruleCounts(reports []healthReport) (int, []string) {
	ran := 0
	var skipped []string
	for _, r := range reports {
		for _, o := range r.Assessment.Rules {
			switch o.State {
			case assess.RuleRan:
				ran++
			case assess.RuleSkipped, assess.RuleFailed:
				// No roaming history is a choice, not missing evidence.
				if o.State == assess.RuleSkipped && slices.Equal(o.Missing, []evidence.Dimension{health.DimensionRoaming}) {
					continue
				}
				skipped = append(skipped, r.Controller.Name+":"+string(o.Rule))
			case assess.RuleDisabled:
			}
		}
	}
	return ran, skipped
}

func actualText(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
