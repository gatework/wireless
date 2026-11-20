package health

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/quality"
	"github.com/gatework/wireless/roam"
)

// DimensionRoaming is the station sighting history. It is complete when a
// history was supplied to [Inspector.Run], so the ping-pong rule never
// concludes "no ping-pong" without one.
const DimensionRoaming evidence.Dimension = "roaming_history"

// RF and roaming rule identifiers.
const (
	RuleStickyClients    assess.RuleID = "wireless.sticky_clients"
	RulePoorQualityShare assess.RuleID = "wireless.poor_quality_share"
	RuleCochannel        assess.RuleID = "wireless.cochannel_density"
	RuleBandImbalance    assess.RuleID = "wireless.band_imbalance"
	RulePolicyConflict   assess.RuleID = "wireless.policy_conflict"
	RulePingPong         assess.RuleID = "wireless.pingpong"
)

var rfRequired = []evidence.Dimension{wireless.DimensionClients, wireless.DimensionAccessPoints}

func rfRules() []assess.Rule[Controller] {
	return []assess.Rule[Controller]{
		assess.Check(assess.Meta{
			ID: RuleStickyClients, Title: "AP 下有疑似粘滞终端", Severity: assess.SeverityMedium,
			Category: assess.CategoryRuntime, Requires: append(slices.Clone(rfRequired), wireless.DimensionConfiguration),
			Verify: rfRequired, Params: []assess.Param{assess.Integer("min_clients", 2)},
		}, stickyClients),
		assess.Check(assess.Meta{
			ID: RulePoorQualityShare, Title: "AP 下链路质量差的终端占比高", Severity: assess.SeverityMedium,
			Category: assess.CategoryCapacity, Requires: rfRequired, Verify: rfRequired,
			Params: []assess.Param{assess.Number("share_percent", 30), assess.Integer("min_clients", 5)},
		}, poorQualityShare),
		assess.Check(assess.Meta{
			ID: RuleCochannel, Title: "同 AP 组信道规划不佳（同频密集或 2.4G 重叠信道）", Severity: assess.SeverityLow,
			Category: assess.CategoryCapacity, Requires: []evidence.Dimension{wireless.DimensionAccessPoints},
			Params: []assess.Param{assess.Integer("min_radios", 5), assess.Number("share_percent", 40)},
		}, cochannel),
		assess.Check(assess.Meta{
			ID: RuleBandImbalance, Title: "双频 AP 上 2.4G 终端占比过高", Severity: assess.SeverityLow,
			Category: assess.CategoryCapacity, Requires: append(slices.Clone(rfRequired), wireless.DimensionConfiguration),
			Params: []assess.Param{assess.Number("share_percent", 50), assess.Integer("min_clients", 10)},
		}, bandImbalance),
		assess.Check(assess.Meta{
			ID: RulePolicyConflict, Title: "射频策略妨碍漫游", Severity: assess.SeverityMedium,
			Category: assess.CategoryConfiguration, Requires: []evidence.Dimension{wireless.DimensionAccessPoints, wireless.DimensionConfiguration},
		}, policyConflict),
		assess.Check(assess.Meta{
			ID: RulePingPong, Title: "终端乒乓漫游", Severity: assess.SeverityMedium,
			Category: assess.CategoryRuntime, Requires: []evidence.Dimension{DimensionRoaming},
		}, pingPong),
	}
}

// clientViews returns the views of this controller's clients.
func (c Controller) clientViews() []wireless.ClientView {
	var out []wireless.ClientView
	for v := range c.Index.Clients() {
		if v.Controller.Host == c.Snapshot.Controller.Host {
			out = append(out, v)
		}
	}
	return out
}

func stickyClients(in assess.Input[Controller]) []assess.Finding {
	per := map[string][]string{}
	var order []string
	for _, v := range in.Model.clientViews() {
		if st := in.Model.Roaming.Sticky(in.Model.Index, &v); st.Suspected {
			if per[v.Client.APName] == nil {
				order = append(order, v.Client.APName)
			}
			per[v.Client.APName] = append(per[v.Client.APName], fmt.Sprintf("%s(RSSI %d)", v.Client.MAC.H3C(), v.Client.RSSI))
		}
	}
	var out []assess.Finding
	for _, ap := range order {
		if macs := per[ap]; len(macs) >= in.Params.Integer("min_clients") {
			out = append(out, assess.Finding{Subject: in.Model.ap(ap), Actual: strconv.Itoa(len(macs)), Detail: sample(macs)})
		}
	}
	return out
}

func poorQualityShare(in assess.Input[Controller]) []assess.Finding {
	type tally struct {
		total, poor int
		causes      map[quality.Cause]int
	}
	per := map[string]*tally{}
	var order []string
	for _, v := range in.Model.clientViews() {
		s := in.Model.Quality.Assess(quality.InputOf(&v))
		t, ok := per[v.Client.APName]
		if !ok {
			t = &tally{causes: map[quality.Cause]int{}}
			per[v.Client.APName] = t
			order = append(order, v.Client.APName)
		}
		t.total++
		if s.Grade == quality.GradeFair || s.Grade == quality.GradePoor {
			t.poor++
			t.causes[s.Cause]++
		}
	}
	var out []assess.Finding
	for _, ap := range order {
		t := per[ap]
		pct := float64(t.poor) * 100 / float64(t.total)
		if t.total < in.Params.Integer("min_clients") || pct < in.Params.Number("share_percent") {
			continue
		}
		top := quality.CauseNone
		for c, n := range t.causes {
			if n > t.causes[top] || n == t.causes[top] && c < top {
				top = c
			}
		}
		out = append(out, assess.Finding{Subject: in.Model.ap(ap), Actual: fmt.Sprintf("%.0f%%", pct),
			Detail: fmt.Sprintf(detailPoorQuality, t.poor, t.total, top.Word(), top.Advice())})
	}
	return out
}

// cochannel checks channel plans per AP group: on 5 GHz too many radios
// on one channel; on 2.4 GHz any radio off the non-overlapping 1/6/11.
func cochannel(in assess.Input[Controller]) []assess.Finding {
	return append(denseChannels(in), overlappingChannels(in)...)
}

// runningRadios calls f for every radio that is up on a running AP.
func runningRadios(s *wireless.Snapshot, f func(ap *wireless.AccessPoint, r *wireless.Radio)) {
	for i := range s.AccessPoints.Facts {
		ap := &s.AccessPoints.Facts[i]
		if !ap.Running() {
			continue
		}
		for j := range ap.Radios {
			if r := &ap.Radios[j]; r.Up && r.Channel != 0 {
				f(ap, r)
			}
		}
	}
}

// denseChannels reports AP groups whose 5 GHz radios crowd one channel.
func denseChannels(in assess.Input[Controller]) []assess.Finding {
	channels := map[string]map[int]int{}
	runningRadios(in.Model.Snapshot, func(ap *wireless.AccessPoint, r *wireless.Radio) {
		if r.Band() != wireless.Band5G {
			return
		}
		if channels[ap.Group] == nil {
			channels[ap.Group] = map[int]int{}
		}
		channels[ap.Group][r.Channel]++
	})
	var out []assess.Finding
	for _, group := range sortedKeys(channels) {
		total, busiest, count := 0, 0, 0
		for ch, n := range channels[group] {
			total += n
			if n > count || n == count && ch < busiest {
				busiest, count = ch, n
			}
		}
		if total >= in.Params.Integer("min_radios") && float64(count)*100/float64(total) >= in.Params.Number("share_percent") {
			out = append(out, assess.Finding{Subject: in.Model.subject().Child("group", group).Child("band", wireless.Band5G.String()),
				Actual: fmt.Sprintf(detailChannelShare, busiest, count, total)})
		}
	}
	return out
}

// overlappingChannels reports 2.4 GHz radios off channels 1, 6 and 11.
func overlappingChannels(in assess.Input[Controller]) []assess.Finding {
	overlap := map[string][]string{}
	runningRadios(in.Model.Snapshot, func(ap *wireless.AccessPoint, r *wireless.Radio) {
		if r.Band() == wireless.Band2G4 && r.Channel != 1 && r.Channel != 6 && r.Channel != 11 {
			overlap[ap.Group] = append(overlap[ap.Group], fmt.Sprintf("%s/ch%d", ap.Name, r.Channel))
		}
	})
	var out []assess.Finding
	for _, g := range sortedKeys(overlap) {
		out = append(out, assess.Finding{Subject: in.Model.subject().Child("group", g).Child("band", wireless.Band2G4.String()),
			Actual: strconv.Itoa(len(overlap[g])), Detail: fmt.Sprintf(detailOverlap, sample(overlap[g]))})
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func bandImbalance(in assess.Input[Controller]) []assess.Finding {
	cfg, _ := in.Model.Snapshot.Config()
	navigation := cfg != nil && cfg.RRM.BandNavigation
	type tally struct{ total, low int }
	per := map[string]*tally{}
	for _, c := range in.Model.Snapshot.Clients.Facts {
		t, ok := per[c.APName]
		if !ok {
			t = &tally{}
			per[c.APName] = t
		}
		t.total++
		if c.Band() == wireless.Band2G4 {
			t.low++
		}
	}
	var out []assess.Finding
	for _, ap := range in.Model.Snapshot.AccessPoints.Facts {
		t := per[ap.Name]
		if t == nil || !dualBand(ap) || t.total < in.Params.Integer("min_clients") {
			continue
		}
		if pct := float64(t.low) * 100 / float64(t.total); pct >= in.Params.Number("share_percent") {
			detail := fmt.Sprintf(detailBand, t.low, t.total)
			if !navigation {
				detail += detailNoNavigation
			}
			out = append(out, assess.Finding{Subject: in.Model.ap(ap.Name), Actual: fmt.Sprintf("%.0f%%", pct), Detail: detail})
		}
	}
	return out
}

func dualBand(ap wireless.AccessPoint) bool {
	var low, high bool
	for _, r := range ap.Radios {
		low = low || r.Up && r.Band() == wireless.Band2G4
		high = high || r.Up && r.Band() == wireless.Band5G
	}
	return low && high
}

// policyConflict aggregates per-AP policy issues by kind.
func policyConflict(in assess.Input[Controller]) []assess.Finding {
	cfg, ok := in.Model.Snapshot.Config()
	if !ok {
		return nil
	}
	per := map[roam.PolicyCode][]string{}
	examples := map[roam.PolicyCode]roam.PolicyIssue{}
	for i := range in.Model.Snapshot.AccessPoints.Facts {
		ap := &in.Model.Snapshot.AccessPoints.Facts[i]
		for _, issue := range roam.CheckPolicy(cfg, ap) {
			if !slices.Contains(per[issue.Code], issue.AP) {
				per[issue.Code] = append(per[issue.Code], issue.AP)
			}
			examples[issue.Code] = issue
		}
	}
	var out []assess.Finding
	for _, code := range []roam.PolicyCode{roam.PolicyStickyLoop, roam.PolicyPower24Above5, roam.PolicyWide24} {
		aps := per[code]
		if len(aps) == 0 {
			continue
		}
		e := examples[code]
		actual := fmt.Sprint(len(aps))
		if e.Low != 0 || e.High != 0 {
			actual = fmt.Sprintf(detailPolicyValues, len(aps), e.Low, e.High)
		}
		out = append(out, assess.Finding{Subject: in.Model.subject().Child("policy", string(code)), Actual: actual,
			Detail: code.Word() + "：" + sample(aps)})
	}
	return out
}

// pingPong aggregates ping-pong stations of this controller.
func pingPong(in assess.Input[Controller]) []assess.Finding {
	var items []string
	for _, t := range in.Model.Tracks {
		if t.PingPong != nil && t.Host == in.Model.Snapshot.Controller.Host {
			items = append(items, fmt.Sprintf("%s[%s×%d]", t.MAC.H3C(), strings.Join(t.PingPong.APs, "↔"), t.PingPong.Bounces))
		}
	}
	if len(items) == 0 {
		return nil
	}
	return []assess.Finding{{Subject: in.Model.subject(), Actual: strconv.Itoa(len(items)), Detail: sample(items)}}
}
