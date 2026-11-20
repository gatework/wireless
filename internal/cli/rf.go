package cli

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/quality"
	"github.com/gatework/wireless/roam"
)

func (a *app) rfCommand() *cobra.Command {
	var band string
	var top int
	cmd := &cobra.Command{
		Use: "rf", Short: shortRF, Args: cobra.NoArgs,
		Example: "  wireless rf\n  wireless rf --band 5g -c SZX10 --top 30",
		RunE: func(cmd *cobra.Command, _ []string) error {
			want, err := parseBand(band)
			if err != nil {
				return err
			}
			ix, err := a.index(cmd.Context(), wireless.DimensionAccessPoints, wireless.DimensionClients)
			if err != nil {
				return err
			}
			cfg, err := a.config(cmd.Context())
			if err != nil {
				return err
			}
			report := rfReport{
				Channels: channelPlan(ix, want),
				APs:      apQuality(ix, cfg.Models.Quality),
				Policies: policyIssues(ix),
			}
			if a.json {
				return a.emitJSON(report)
			}
			return a.renderRF(report, top)
		},
	}
	cmd.Flags().StringVar(&band, "band", "", flagBand)
	cmd.Flags().IntVar(&top, "top", 20, flagTop)
	return cmd
}

// rfReport is the fleet RF picture.
type rfReport struct {
	Channels []channelRow   `json:"channels"`
	APs      []apQualityRow `json:"aps"`
	Policies []policyRow    `json:"policies"`
}

// channelRow is the channel plan of one AP group on one band.
type channelRow struct {
	Controller wireless.Controller `json:"controller"`
	Group      string              `json:"group"`
	Band       wireless.Band       `json:"band"`
	Radios     int                 `json:"radios"`
	Channels   map[int]int         `json:"channels"`
	Busy       int                 `json:"busy"`
	Noisy      int                 `json:"noisy"`
	PowerMin   int                 `json:"power_min"`
	PowerMax   int                 `json:"power_max"`
}

// busyUsage and noisyFloor mark radios worth a look in the channel plan.
const (
	busyUsage  = 70
	noisyFloor = -80
)

func channelPlan(ix *wireless.Index, want wireless.Band) []channelRow {
	type key struct {
		host, group string
		band        wireless.Band
	}
	rows := map[key]*channelRow{}
	var order []key
	for v := range ix.AccessPoints() {
		if !v.AP.Running() {
			continue
		}
		for _, r := range v.AP.Radios {
			b := r.Band()
			if !r.Up || r.Channel == 0 || want != wireless.BandUnset && b != want {
				continue
			}
			k := key{v.Controller.Host, v.AP.Group, b}
			row, ok := rows[k]
			if !ok {
				row = &channelRow{Controller: v.Controller, Group: v.AP.Group, Band: b, Channels: map[int]int{}, PowerMin: math.MaxInt}
				rows[k] = row
				order = append(order, k)
			}
			row.Radios++
			row.Channels[r.Channel]++
			if r.Usage >= busyUsage {
				row.Busy++
			}
			if n, ok := r.Noise(); ok && n > noisyFloor {
				row.Noisy++
			}
			row.PowerMin, row.PowerMax = min(row.PowerMin, r.MaxPower), max(row.PowerMax, r.MaxPower)
		}
	}
	out := make([]channelRow, 0, len(order))
	for _, k := range order {
		out = append(out, *rows[k])
	}
	return out
}

// apQualityRow summarizes the link quality of one AP's clients.
type apQualityRow struct {
	Controller wireless.Controller `json:"controller"`
	AP         string              `json:"ap"`
	Clients    int                 `json:"clients"`
	Band24     int                 `json:"band_24"`
	Mean       int                 `json:"mean"`
	P10        int                 `json:"p10"`
	Poor       int                 `json:"poor"`
	Cause      quality.Cause       `json:"cause,omitempty"`
}

// minRanked is the fewest clients for an AP's percentile to mean much.
const minRanked = 3

// apQuality scores every client and aggregates per AP, worst first by
// the 10th percentile — the experience of the unluckiest users.
func apQuality(ix *wireless.Index, p quality.Profile) []apQualityRow {
	type acc struct {
		row    apQualityRow
		scores []int
		causes map[quality.Cause]int
	}
	per := map[string]*acc{}
	var order []string
	for v := range ix.Clients() {
		s := p.Assess(quality.InputOf(&v))
		if s.Grade == quality.GradeUnknown {
			continue
		}
		k := v.Controller.Host + "/" + v.Client.APName
		x, ok := per[k]
		if !ok {
			x = &acc{row: apQualityRow{Controller: v.Controller, AP: v.Client.APName}, causes: map[quality.Cause]int{}}
			per[k] = x
			order = append(order, k)
		}
		x.row.Clients++
		x.scores = append(x.scores, s.Total)
		if v.Client.Band() == wireless.Band2G4 {
			x.row.Band24++
		}
		if s.Grade == quality.GradeFair || s.Grade == quality.GradePoor {
			x.row.Poor++
			x.causes[s.Cause]++
		}
	}
	out := make([]apQualityRow, 0, len(order))
	for _, k := range order {
		x := per[k]
		if len(x.scores) < minRanked {
			continue
		}
		slices.Sort(x.scores)
		sum := 0
		for _, s := range x.scores {
			sum += s
		}
		x.row.Mean = sum / len(x.scores)
		x.row.P10 = x.scores[len(x.scores)/10]
		for c, n := range x.causes {
			if n > x.causes[x.row.Cause] || n == x.causes[x.row.Cause] && c < x.row.Cause {
				x.row.Cause = c
			}
		}
		out = append(out, x.row)
	}
	slices.SortStableFunc(out, func(a, b apQualityRow) int { return cmp.Or(cmp.Compare(a.P10, b.P10), cmp.Compare(b.Poor, a.Poor)) })
	return out
}

// policyRow is one radio policy issue.
type policyRow struct {
	Controller wireless.Controller `json:"controller"`
	Issue      roam.PolicyIssue    `json:"issue"`
}

func policyIssues(ix *wireless.Index) []policyRow {
	var out []policyRow
	for _, s := range ix.Snapshots() {
		cfg, ok := s.Config()
		if !ok {
			continue
		}
		for i := range s.AccessPoints.Facts {
			for _, issue := range roam.CheckPolicy(cfg, &s.AccessPoints.Facts[i]) {
				out = append(out, policyRow{Controller: s.Controller, Issue: issue})
			}
		}
	}
	return out
}

func (a *app) renderRF(r rfReport, top int) error {
	a.printf(msgRFChannels)
	t := newTable(headChannels...)
	for _, c := range r.Channels {
		t.add(c.Controller.Label(), dash(c.Group), c.Band.String(), fmt.Sprint(c.Radios), channelText(c.Channels),
			intCell(c.Busy), intCell(c.Noisy), fmt.Sprintf("%d–%d dBm", c.PowerMin, c.PowerMax))
	}
	if err := t.render(a.env.Stdout); err != nil {
		return err
	}
	a.printf(msgRFQuality, min(top, len(r.APs)))
	q := newTable(headAPQuality...)
	for _, row := range r.APs[:min(top, len(r.APs))] {
		q.add(row.Controller.Label(), row.AP, fmt.Sprint(row.Clients), fmt.Sprintf("%d/%d", row.Band24, row.Clients-row.Band24),
			fmt.Sprint(row.Mean), fmt.Sprint(row.P10), intCell(row.Poor), dash(row.Cause.Word()))
	}
	if err := q.render(a.env.Stdout); err != nil {
		return err
	}
	if len(r.Policies) == 0 {
		return nil
	}
	a.printf(msgRFPolicy, len(r.Policies))
	p := newTable(headPolicy...)
	for _, row := range r.Policies[:min(top, len(r.Policies))] {
		p.add(row.Controller.Label(), row.Issue.AP, intCell(row.Issue.RadioID), row.Issue.Code.Word())
	}
	return p.render(a.env.Stdout)
}

// channelText lists channels by use: "36:4 44:2 149:1".
func channelText(m map[int]int) string {
	chs := make([]int, 0, len(m))
	for ch := range m {
		chs = append(chs, ch)
	}
	slices.SortFunc(chs, func(a, b int) int { return cmp.Or(cmp.Compare(m[b], m[a]), cmp.Compare(a, b)) })
	parts := make([]string, len(chs))
	for i, ch := range chs {
		parts[i] = fmt.Sprintf("%d:%d", ch, m[ch])
	}
	return strings.Join(parts, " ")
}

func parseBand(s string) (wireless.Band, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return wireless.BandUnset, nil
	case "2.4g", "2.4", "2g", "24":
		return wireless.Band2G4, nil
	case "5g", "5":
		return wireless.Band5G, nil
	case "6g", "6":
		return wireless.Band6G, nil
	}
	return wireless.BandUnset, fmt.Errorf("cli: unknown band %q", s)
}
