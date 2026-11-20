package health

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
)

// Rule identifiers.
const (
	RuleAPNotRunning    assess.RuleID = "wireless.ap_not_running"
	RuleAPEchoLoss      assess.RuleID = "wireless.ap_echo_loss"
	RuleRadioDown       assess.RuleID = "wireless.radio_down"
	RuleRadioBusy       assess.RuleID = "wireless.radio_busy"
	RuleCoverageHole    assess.RuleID = "wireless.coverage_hole"
	RuleLicenseLow      assess.RuleID = "wireless.license_low"
	RuleLegacySecurity  assess.RuleID = "wireless.legacy_security"
	RuleSharedKeyOnly   assess.RuleID = "wireless.shared_key_only"
	RuleClientNoIPv4    assess.RuleID = "wireless.client_no_ipv4"
	RuleRecentConflicts assess.RuleID = "wireless.ip_conflict_recent"
	RuleDuplicateMAC    assess.RuleID = "wireless.duplicate_mac"
	RuleClientNoSession assess.RuleID = "wireless.client_no_session"
)

var (
	apRequired     = []evidence.Dimension{wireless.DimensionAccessPoints}
	clientRequired = []evidence.Dimension{wireless.DimensionClients}
)

// rules returns the catalog in report order.
func rules() []assess.Rule[Controller] {
	return []assess.Rule[Controller]{
		assess.Check(assess.Meta{
			ID: RuleAPNotRunning, Title: "AP 未处于 Run 状态", Severity: assess.SeverityHigh,
			Category: assess.CategoryRuntime, Requires: apRequired, Verify: apRequired,
		}, apNotRunning),
		assess.Check(assess.Meta{
			ID: RuleAPEchoLoss, Title: "AP 与 AC 的 CAPWAP Echo 丢失偏高", Severity: assess.SeverityMedium,
			Category: assess.CategoryRuntime, Requires: apRequired, Verify: apRequired,
			Params: []assess.Param{assess.Number("max_loss_percent", 1.0), assess.Integer("min_requests", 1000)},
		}, apEchoLoss),
		assess.Check(assess.Meta{
			ID: RuleRadioDown, Title: "运行中 AP 的射频处于 Down", Severity: assess.SeverityInfo,
			Category: assess.CategoryRuntime, Requires: apRequired, Verify: apRequired,
		}, radioDown),
		assess.Check(assess.Meta{
			ID: RuleRadioBusy, Title: "射频信道利用率过高", Severity: assess.SeverityMedium,
			Category: assess.CategoryCapacity, Requires: apRequired, Verify: apRequired,
			Params: []assess.Param{assess.Integer("busy_percent", 70)},
		}, radioBusy),
		assess.Check(assess.Meta{
			ID: RuleCoverageHole, Title: "覆盖空洞：弱信号终端多且同组无其他 AP", Severity: assess.SeverityMedium,
			Category: assess.CategoryCapacity, Requires: []evidence.Dimension{wireless.DimensionClients, wireless.DimensionAccessPoints},
			Verify: clientRequired, Params: []assess.Param{assess.Integer("weak_rssi", 20), assess.Number("weak_percent", 30), assess.Integer("min_clients", 5)},
		}, coverageHole),
		assess.Check(assess.Meta{
			ID: RuleLicenseLow, Title: "AP License 余量不足", Severity: assess.SeverityMedium,
			Category: assess.CategoryCapacity, Requires: apRequired, Verify: apRequired,
			Params: []assess.Param{assess.Integer("min_remaining", 5)},
		}, licenseLow),
		assess.Check(assess.Meta{
			ID: RuleLegacySecurity, Title: "服务模板仍启用 TKIP/WPA", Severity: assess.SeverityMedium,
			Category: assess.CategorySecurity, Requires: []evidence.Dimension{wireless.DimensionConfiguration},
		}, legacySecurity),
		assess.Check(assess.Meta{
			ID: RuleSharedKeyOnly, Title: "SSID 仅预共享密钥接入，无用户认证", Severity: assess.SeverityInfo,
			Category: assess.CategorySecurity, Requires: []evidence.Dimension{wireless.DimensionConfiguration},
		}, sharedKeyOnly),
		assess.Check(assess.Meta{
			ID: RuleClientNoIPv4, Title: "终端已关联但没有 IPv4 地址", Severity: assess.SeverityMedium,
			Category: assess.CategoryRuntime, Requires: clientRequired, Verify: clientRequired,
			Params: []assess.Param{assess.Integer("grace_seconds", 120)},
		}, clientNoIPv4),
		assess.Check(assess.Meta{
			ID: RuleRecentConflicts, Title: "近期发生 IP 地址冲突的地址数", Severity: assess.SeverityMedium,
			Category: assess.CategoryRuntime, Requires: []evidence.Dimension{wireless.DimensionConflicts},
			Verify: []evidence.Dimension{wireless.DimensionConflicts}, Params: []assess.Param{assess.Integer("days", 7)},
		}, recentConflicts),
		assess.Check(assess.Meta{
			ID: RuleDuplicateMAC, Title: "同一 MAC 出现在多台控制器", Severity: assess.SeverityLow,
			Category: assess.CategoryConsistency, Requires: clientRequired, Verify: clientRequired,
		}, duplicateMAC),
		assess.Check(assess.Meta{
			ID: RuleClientNoSession, Title: "需认证的终端没有认证会话", Severity: assess.SeverityLow,
			Category: assess.CategoryConsistency,
			Requires: []evidence.Dimension{wireless.DimensionClients, wireless.DimensionDot1X, wireless.DimensionMAC, wireless.DimensionConfiguration},
		}, clientNoSession),
	}
}

func apNotRunning(in assess.Input[Controller]) []assess.Finding {
	var out []assess.Finding
	for _, ap := range in.Model.Snapshot.AccessPoints.Facts {
		if ap.Running() {
			continue
		}
		actual := string(ap.State)
		detail := fmt.Sprintf(detailAPNotRunning, ap.Model, ap.Serial, addrText(ap.IP.String(), ap.IP.IsValid()))
		if neverOnline(ap) {
			actual += actualNeverOnline
		} else if reason := ap.Extra["Tunnel down reason"]; reason != "" {
			detail += fmt.Sprintf(detailTunnelDown, reason)
		}
		out = append(out, assess.Finding{Subject: in.Model.ap(ap.Name), Actual: actual, Expected: string(wireless.APRun), Detail: detail})
	}
	return out
}

// neverOnline reports an AP that looks configured but never joined, or
// decommissioned: no address, no uptime, and a placeholder name (its MAC
// or a bare number) that nobody assigned on site.
func neverOnline(ap wireless.AccessPoint) bool {
	if ap.IP.IsValid() || ap.Online > 0 {
		return false
	}
	if _, err := wireless.ParseMAC(ap.Name); err == nil {
		return true
	}
	_, err := strconv.Atoi(ap.Name)
	return err == nil
}

func apEchoLoss(in assess.Input[Controller]) []assess.Finding {
	limit := in.Params.Number("max_loss_percent") / 100
	minRequests := in.Params.Integer("min_requests")
	var out []assess.Finding
	for _, ap := range in.Model.Snapshot.AccessPoints.Facts {
		if ap.EchoRequests >= minRequests && ap.EchoLoss() > limit {
			out = append(out, assess.Finding{Subject: in.Model.ap(ap.Name), Actual: fmt.Sprintf("%.2f%%", ap.EchoLoss()*100),
				Detail: fmt.Sprintf(detailEchoLoss, ap.EchoRequests, ap.LostEchoes)})
		}
	}
	return out
}

// radioDown aggregates down radios of running APs per band: a radio is
// often disabled on purpose, so one finding per band keeps the report
// readable and names the APs.
func radioDown(in assess.Input[Controller]) []assess.Finding {
	byBand := map[wireless.Band][]string{}
	for _, ap := range in.Model.Snapshot.AccessPoints.Facts {
		if !ap.Running() {
			continue
		}
		for _, r := range ap.Radios {
			if !r.Up {
				byBand[r.Band()] = append(byBand[r.Band()], fmt.Sprintf("%s/%d", ap.Name, r.ID))
			}
		}
	}
	var out []assess.Finding
	for _, b := range []wireless.Band{wireless.Band2G4, wireless.Band5G, wireless.Band6G, wireless.BandUnset} {
		if names := byBand[b]; len(names) > 0 {
			out = append(out, assess.Finding{Subject: in.Model.subject().Child("band", dashBand(b)), Actual: strconv.Itoa(len(names)), Detail: sample(names)})
		}
	}
	return out
}

func radioBusy(in assess.Input[Controller]) []assess.Finding {
	busy := in.Params.Integer("busy_percent")
	var out []assess.Finding
	for _, ap := range in.Model.Snapshot.AccessPoints.Facts {
		for _, r := range ap.Radios {
			if r.Up && r.Usage >= busy {
				out = append(out, assess.Finding{Subject: in.Model.ap(ap.Name).Child("radio", fmt.Sprint(r.ID)),
					Actual: fmt.Sprintf("%d%%", r.Usage), Detail: fmt.Sprintf(detailRadioBusy, r.Band(), r.Channel)})
			}
		}
	}
	return out
}

// coverageHole flags APs where many clients are weak and the AP group
// offers nowhere else to go. Weak clients on an AP with neighbours are
// sticky clients instead, reported by the sticky rule.
func coverageHole(in assess.Input[Controller]) []assess.Finding {
	weak := in.Params.Integer("weak_rssi")
	share := in.Params.Number("weak_percent")
	minClients := in.Params.Integer("min_clients")
	running := map[string]int{}
	groupOf := map[string]string{}
	for _, ap := range in.Model.Snapshot.AccessPoints.Facts {
		groupOf[ap.Name] = ap.Group
		if ap.Running() {
			running[ap.Group]++
		}
	}
	type tally struct{ total, weak int }
	per := map[string]*tally{}
	var order []string
	for _, c := range in.Model.Snapshot.Clients.Facts {
		t, ok := per[c.APName]
		if !ok {
			t = &tally{}
			per[c.APName] = t
			order = append(order, c.APName)
		}
		t.total++
		if c.RSSI > 0 && c.RSSI < weak {
			t.weak++
		}
	}
	var out []assess.Finding
	for _, name := range order {
		t := per[name]
		if running[groupOf[name]] > 1 {
			continue
		}
		if pct := float64(t.weak) * 100 / float64(t.total); t.total >= minClients && pct >= share {
			out = append(out, assess.Finding{Subject: in.Model.ap(name), Actual: fmt.Sprintf("%.0f%%", pct),
				Detail: fmt.Sprintf(detailCoverageHole, t.weak, t.total, weak)})
		}
	}
	return out
}

func licenseLow(in assess.Input[Controller]) []assess.Finding {
	c := in.Model.Snapshot.Capacity
	if c.Licenses == 0 || c.LicensesRemaining >= in.Params.Integer("min_remaining") {
		return nil
	}
	return []assess.Finding{{Subject: in.Model.subject(), Actual: strconv.Itoa(c.LicensesRemaining),
		Detail: fmt.Sprintf(detailLicense, c.Licenses, c.LicensesRemaining, c.Connected)}}
}

func legacySecurity(in assess.Input[Controller]) []assess.Finding {
	cfg, ok := in.Model.Snapshot.Config()
	if !ok {
		return nil
	}
	var out []assess.Finding
	for _, t := range sortedTemplates(cfg) {
		if t.Enabled && t.Legacy() {
			out = append(out, assess.Finding{Subject: in.Model.subject().Child("template", t.Name),
				Actual: strings.Join(append(append([]string{}, t.CipherSuites...), t.SecurityIEs...), ","), Detail: fmt.Sprintf(detailSSID, t.SSID)})
		}
	}
	return out
}

func sharedKeyOnly(in assess.Input[Controller]) []assess.Finding {
	cfg, ok := in.Model.Snapshot.Config()
	if !ok {
		return nil
	}
	var out []assess.Finding
	for _, t := range sortedTemplates(cfg) {
		if t.Enabled && t.Access() == wireless.AccessPSK {
			out = append(out, assess.Finding{Subject: in.Model.subject().Child("template", t.Name), Detail: fmt.Sprintf(detailSSID, t.SSID)})
		}
	}
	return out
}

func clientNoIPv4(in assess.Input[Controller]) []assess.Finding {
	grace := time.Duration(in.Params.Integer("grace_seconds")) * time.Second
	var out []assess.Finding
	for _, c := range in.Model.Snapshot.Clients.Facts {
		if !c.IPv4.IsValid() && c.Online >= grace {
			out = append(out, assess.Finding{Subject: in.Model.client(c.MAC),
				Detail: fmt.Sprintf(detailNoIPv4, c.APName, c.SSID, c.VLAN, c.Online.Round(time.Second))})
		}
	}
	return out
}

// recentConflicts reports, per controller, how many addresses conflicted
// recently and which conflicted most.
func recentConflicts(in assess.Input[Controller]) []assess.Finding {
	s := in.Model.Snapshot
	since := s.CollectedAt.AddDate(0, 0, -in.Params.Integer("days"))
	count := map[string]int{}
	for _, c := range s.Conflicts.Facts {
		if !c.At.Before(since) {
			count[c.IP.String()]++
		}
	}
	if len(count) == 0 {
		return nil
	}
	ips := make([]string, 0, len(count))
	for ip := range count {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, func(a, b string) int { return cmp.Or(cmp.Compare(count[b], count[a]), cmp.Compare(a, b)) })
	top := make([]string, 0, len(ips))
	for _, ip := range ips {
		top = append(top, fmt.Sprintf("%s×%d", ip, count[ip]))
	}
	return []assess.Finding{{Subject: in.Model.subject(), Actual: strconv.Itoa(len(ips)), Detail: sample(top)}}
}

func duplicateMAC(in assess.Input[Controller]) []assess.Finding {
	var out []assess.Finding
	for _, c := range in.Model.Snapshot.Clients.Facts {
		elsewhere := in.Model.Index.Controllers(c.MAC)
		if len(elsewhere) < 2 || elsewhere[0].Host != in.Model.Snapshot.Controller.Host {
			continue // reported once, by the first controller
		}
		labels := make([]string, len(elsewhere))
		for i, e := range elsewhere {
			labels[i] = e.Label()
		}
		out = append(out, assess.Finding{Subject: in.Model.client(c.MAC), Actual: strings.Join(labels, ", ")})
	}
	return out
}

func clientNoSession(in assess.Input[Controller]) []assess.Finding {
	var out []assess.Finding
	for v := range in.Model.Index.Clients() {
		if v.Controller.Host != in.Model.Snapshot.Controller.Host || len(v.Sessions) > 0 {
			continue
		}
		switch v.Access {
		case wireless.AccessDot1X, wireless.AccessPSKMAC, wireless.AccessMAC, wireless.AccessMACPortal:
			out = append(out, assess.Finding{Subject: in.Model.client(v.Client.MAC), Actual: v.Access.String(),
				Detail: fmt.Sprintf(detailNoSession, v.Client.SSID, v.Client.APName)})
		case wireless.AccessUnknown, wireless.AccessPSK, wireless.AccessPortal, wireless.AccessOpen:
		}
	}
	return out
}

func sortedTemplates(cfg *wireless.Configuration) []wireless.ServiceTemplate {
	out := make([]wireless.ServiceTemplate, 0, len(cfg.Templates))
	for _, t := range cfg.Templates {
		out = append(out, t)
	}
	slicesSortByName(out)
	return out
}

func addrText(text string, valid bool) string {
	if !valid {
		return "-"
	}
	return text
}

// sampleSize bounds the names listed in one finding.
const sampleSize = 8

// sample lists up to sampleSize items and the number left out.
func sample(items []string) string {
	if len(items) <= sampleSize {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf(detailMore, strings.Join(items[:sampleSize], ", "), len(items)-sampleSize)
}

func dashBand(b wireless.Band) string {
	if b == wireless.BandUnset {
		return "unknown"
	}
	return b.String()
}
