package roam

import (
	"strings"

	"github.com/gatework/wireless"
)

// PolicyCode identifies a radio configuration that works against roaming.
type PolicyCode string

// Policy codes.
const (
	// PolicyStickyLoop: the anti-sticky threshold is above the reject
	// threshold, so a station between the two is disconnected and then
	// accepted again by the same AP, over and over.
	PolicyStickyLoop PolicyCode = "anti_sticky_above_reject"
	// PolicyPower24Above5: the 2.4 GHz radio transmits stronger than the
	// 5 GHz one, which pulls dual-band stations onto the slower band.
	PolicyPower24Above5 PolicyCode = "power_24_above_5"
	// PolicyWide24: 40 MHz on 2.4 GHz overlaps most of the band.
	PolicyWide24 PolicyCode = "wide_24"
)

// Word returns the operator-facing explanation.
func (c PolicyCode) Word() string { return policyWords[c] }

// PolicyIssue is one finding on one AP.
type PolicyIssue struct {
	Code    PolicyCode `json:"code"`
	AP      string     `json:"ap"`
	RadioID int        `json:"radio_id,omitempty"`
	// Low and High are the two values in conflict, for example the reject
	// and anti-sticky RSSI, or the 5 GHz and 2.4 GHz power.
	Low  int `json:"low,omitempty"`
	High int `json:"high,omitempty"`
}

// CheckPolicy inspects one AP's radios against its configured policy.
func CheckPolicy(cfg *wireless.Configuration, ap *wireless.AccessPoint) []PolicyIssue {
	var out []PolicyIssue
	power24, power5 := 0, 0
	for _, r := range ap.Radios {
		if !r.Up {
			continue
		}
		p := cfg.PolicyFor(ap.Group, ap.Model, ap.Name, r.ID)
		if p.AntiSticky && p.AntiStickyRSSI > 0 && p.RejectRSSI > 0 && p.AntiStickyRSSI > p.RejectRSSI {
			out = append(out, PolicyIssue{Code: PolicyStickyLoop, AP: ap.Name, RadioID: r.ID, Low: p.RejectRSSI, High: p.AntiStickyRSSI})
		}
		switch r.Band() {
		case wireless.Band2G4:
			power24 = max(power24, r.MaxPower)
			if strings.HasPrefix(r.Bandwidth, "40") || p.Bandwidth == 40 {
				out = append(out, PolicyIssue{Code: PolicyWide24, AP: ap.Name, RadioID: r.ID})
			}
		case wireless.Band5G:
			power5 = max(power5, r.MaxPower)
		case wireless.Band6G, wireless.BandUnset:
		}
	}
	if power24 > 0 && power5 > 0 && power24 > power5 {
		out = append(out, PolicyIssue{Code: PolicyPower24Above5, AP: ap.Name, Low: power5, High: power24})
	}
	return out
}
