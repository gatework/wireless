package roam

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/wireless"
)

// ErrInvalidParams reports unusable roaming parameters.
var ErrInvalidParams = errors.New("roam: invalid parameters")

// Params tune the roaming analysis.
type Params struct {
	// StickyRSSI is the RSSI below which a station that does not roam is
	// suspected sticky, unless the radio's anti-sticky threshold says
	// otherwise.
	StickyRSSI int `yaml:"sticky_rssi" json:"sticky_rssi"`
	// Dwell is how long a weak station must stay associated to count.
	Dwell time.Duration `yaml:"dwell" json:"dwell"`
	// Window is the ping-pong window: A→B→A within it is ping-pong.
	Window time.Duration `yaml:"window" json:"window"`
	// Burst roams within an hour among at most BurstAPs APs is ping-pong
	// too, even without a strict A→B→A.
	Burst    int `yaml:"burst" json:"burst"`
	BurstAPs int `yaml:"burst_aps" json:"burst_aps"`
	// EdgeLow and EdgeHigh bound the marginal RSSI band in which two
	// overlapping cells keep handing a station back and forth.
	EdgeLow  int `yaml:"edge_low" json:"edge_low"`
	EdgeHigh int `yaml:"edge_high" json:"edge_high"`
	// AreaPattern, when set, extracts an area such as a floor from AP
	// names with its first non-empty capture group, for example
	// "^(\\d+F)" for "6FAP01". Neighbours are then APs of the same area
	// rather than of the whole AP group, which may span a building.
	AreaPattern string `yaml:"area_pattern" json:"area_pattern,omitempty"`
}

// DefaultParams returns field-tested defaults.
func DefaultParams() Params {
	return Params{
		StickyRSSI: 25, Dwell: 5 * time.Minute,
		Window: 10 * time.Minute, Burst: 6, BurstAPs: 3,
		EdgeLow: 15, EdgeHigh: 25,
	}
}

// Validate rejects non-positive values and an empty edge band.
func (p Params) Validate() error {
	if p.StickyRSSI <= 0 || p.Dwell < 0 || p.Window <= 0 || p.Burst < 2 || p.BurstAPs < 2 || p.EdgeLow >= p.EdgeHigh {
		return ErrInvalidParams
	}
	if p.AreaPattern != "" {
		if _, err := regexp.Compile(p.AreaPattern); err != nil {
			return fmt.Errorf("%w: area_pattern: %w", ErrInvalidParams, err)
		}
	}
	return nil
}

// Confidence ranks how sure a suspicion is.
type Confidence uint8

// Confidences.
const (
	ConfidenceNone Confidence = iota
	ConfidenceLow
	ConfidenceMedium
	ConfidenceHigh
)

var confidenceNames = [...]string{ConfidenceNone: "none", ConfidenceLow: "low", ConfidenceMedium: "medium", ConfidenceHigh: "high"}

// String returns the confidence name.
func (c Confidence) String() string {
	if int(c) < len(confidenceNames) {
		return confidenceNames[c]
	}
	return fmt.Sprintf("Confidence(%d)", uint8(c))
}

// Word returns the operator-facing word.
func (c Confidence) Word() string {
	if int(c) < len(confidenceWords) {
		return confidenceWords[c]
	}
	return ""
}

// MarshalText encodes c as its name.
func (c Confidence) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// Reason explains part of a sticky verdict.
type Reason string

// Reasons.
const (
	ReasonWeakAndStaying Reason = "weak_and_staying"
	ReasonNoBTM          Reason = "client_no_btm"
	ReasonLongDwell      Reason = "long_dwell"
	ReasonVeryWeak       Reason = "very_weak"
	ReasonBetterAPSeen   Reason = "better_ap_seen"
	ReasonSSIDNoBTM      Reason = "ssid_no_btm"
	ReasonNoAntiSticky   Reason = "radio_no_anti_sticky"
	ReasonNoAlternative  Reason = "no_alternative_ap"
)

// Word returns the operator-facing explanation.
func (r Reason) Word() string { return reasonWords[r] }

// Sticky is the verdict on one station.
type Sticky struct {
	Suspected  bool       `json:"suspected"`
	Confidence Confidence `json:"confidence"`
	Reasons    []Reason   `json:"reasons,omitempty"`
	// Threshold is the RSSI the verdict used.
	Threshold int `json:"threshold"`
	// Alternatives counts other running APs nearby: in the same area when
	// an area pattern is configured, otherwise in the same AP group.
	Alternatives int `json:"alternatives"`
	// Basis is "area" or "group", what Alternatives was counted over.
	Basis string `json:"basis"`
}

// Neighbourhood bases.
const (
	BasisArea  = "area"
	BasisGroup = "group"
)

// Confidence evidence: staying longDwell times the dwell, or being more
// than veryWeak dB below the threshold.
const (
	longDwell = 6
	veryWeak  = 10
)

// Sticky judges whether the station in v is stuck on its AP. A weak
// station with nowhere else to go is a coverage hole, not a sticky
// client, and is reported as such through ReasonNoAlternative.
func (p Params) Sticky(ix *wireless.Index, v *wireless.ClientView) Sticky {
	return p.StickyTrack(ix, v, nil)
}

// StickyTrack is Sticky with the station's roaming history: having been
// seen with a much better signal on another AP is direct evidence that a
// better AP is within reach.
func (p Params) StickyTrack(ix *wireless.Index, v *wireless.ClientView, t *Track) Sticky {
	c := v.Client
	policy := radioPolicy(v)
	st := Sticky{Threshold: p.StickyRSSI}
	if policy.AntiStickyRSSI > 0 {
		st.Threshold = policy.AntiStickyRSSI
	}
	if c.RSSI <= 0 || c.RSSI >= st.Threshold || c.Online < p.Dwell {
		return st
	}
	st.Alternatives, st.Basis = p.alternatives(ix, v)
	if st.Alternatives == 0 {
		st.Reasons = []Reason{ReasonNoAlternative}
		return st
	}
	st.Suspected = true
	st.Reasons = []Reason{ReasonWeakAndStaying}
	// Confidence comes from the station's own evidence: it cannot be
	// steered, it has stayed far longer than the dwell, or it is far below
	// the threshold. Configuration gaps explain why nothing intervened and
	// are listed, but they say nothing about this station.
	evidence := 0
	if strings.EqualFold(c.Extra["BTM mode"], "Inactive") {
		st.Reasons = append(st.Reasons, ReasonNoBTM)
		evidence++
	}
	if c.Online >= longDwell*p.Dwell {
		st.Reasons = append(st.Reasons, ReasonLongDwell)
		evidence++
	}
	if c.RSSI < st.Threshold-veryWeak {
		st.Reasons = append(st.Reasons, ReasonVeryWeak)
		evidence++
	}
	if betterSeen(t, v.Client.APName, st.Threshold+veryWeak) {
		st.Reasons = append(st.Reasons, ReasonBetterAPSeen)
		evidence++
	}
	if v.Template != nil && !v.Template.BTM {
		st.Reasons = append(st.Reasons, ReasonSSIDNoBTM)
	}
	if !policy.AntiSticky {
		st.Reasons = append(st.Reasons, ReasonNoAntiSticky)
	}
	st.Confidence = Confidence(min(1+evidence, int(ConfidenceHigh)))
	return st
}

// radioPolicy resolves the serving radio's policy, or the zero policy.
func radioPolicy(v *wireless.ClientView) wireless.RadioPolicy {
	if v.AP == nil || v.Config == nil {
		return wireless.RadioPolicy{}
	}
	return v.Config.PolicyFor(v.AP.Group, v.AP.Model, v.AP.Name, v.Client.RadioID)
}

// alternatives counts the other running APs near the station's AP.
func (p Params) alternatives(ix *wireless.Index, v *wireless.ClientView) (int, string) {
	s, ok := ix.Snapshot(v.Controller.Host)
	if !ok || v.AP == nil {
		return 0, BasisGroup
	}
	re := p.areaPattern()
	area, byArea := areaOf(re, v.AP.Name)
	n := 0
	for _, ap := range s.AccessPoints.Facts {
		if ap.Name == v.AP.Name || !ap.Running() {
			continue
		}
		if byArea {
			if a, ok := areaOf(re, ap.Name); ok && a == area {
				n++
			}
		} else if ap.Group == v.AP.Group {
			n++
		}
	}
	if byArea {
		return n, BasisArea
	}
	return n, BasisGroup
}

// areaPattern compiles the configured area pattern; Validate has already
// rejected an invalid one, which compiles to nil here.
func (p Params) areaPattern() *regexp.Regexp {
	if p.AreaPattern == "" {
		return nil
	}
	re, err := regexp.Compile(p.AreaPattern)
	if err != nil {
		return nil
	}
	return re
}

// areaOf extracts the area of an AP name with the pattern.
func areaOf(re *regexp.Regexp, name string) (string, bool) {
	if re == nil {
		return "", false
	}
	m := re.FindStringSubmatch(name)
	for _, g := range m[min(1, len(m)):] {
		if g != "" {
			return g, true
		}
	}
	return "", false
}

// betterSeen reports a sighting on another AP at or above rssi.
func betterSeen(t *Track, current string, rssi int) bool {
	if t == nil {
		return false
	}
	for _, e := range t.Events {
		for _, o := range []Observation{e.From, e.To} {
			if o.AP != current && o.RSSI >= rssi {
				return true
			}
		}
	}
	return false
}
