package wireless

import "slices"

// RadioPolicy is the roaming and RF configuration that applies to one
// radio. Zero values mean "not configured", which on H3C means the
// feature is off or at its default.
type RadioPolicy struct {
	// RejectRSSI refuses new associations below this RSSI
	// ("option client reject enable rssi N").
	RejectRSSI int `json:"reject_rssi,omitempty"`
	// AntiSticky disconnects associated stations whose RSSI stays low
	// ("sacp anti-sticky enable [rssi N] interval S").
	AntiSticky         bool `json:"anti_sticky,omitempty"`
	AntiStickyRSSI     int  `json:"anti_sticky_rssi,omitempty"`
	AntiStickyInterval int  `json:"anti_sticky_interval,omitempty"`
	// RoamNavigationRSSI steers stations below this RSSI to roam
	// ("option roam-navigation enable rssi N").
	RoamNavigationRSSI int `json:"roam_navigation_rssi,omitempty"`
	MaxPower           int `json:"max_power,omitempty"`
	// Bandwidth is the configured channel width in MHz.
	Bandwidth int `json:"bandwidth,omitempty"`
	Channel   int `json:"channel,omitempty"`
}

// Merge returns p with every configured field of override applied, which
// is how a per-AP setting overrides its group's.
func (p RadioPolicy) Merge(o RadioPolicy) RadioPolicy {
	set := func(dst *int, v int) {
		if v != 0 {
			*dst = v
		}
	}
	set(&p.RejectRSSI, o.RejectRSSI)
	set(&p.AntiStickyRSSI, o.AntiStickyRSSI)
	set(&p.AntiStickyInterval, o.AntiStickyInterval)
	set(&p.RoamNavigationRSSI, o.RoamNavigationRSSI)
	set(&p.MaxPower, o.MaxPower)
	set(&p.Bandwidth, o.Bandwidth)
	set(&p.Channel, o.Channel)
	p.AntiSticky = p.AntiSticky || o.AntiSticky
	return p
}

// APGroup is one "wlan ap-group": its member APs and the radio policy per
// AP model.
type APGroup struct {
	Name string   `json:"name"`
	APs  []string `json:"aps,omitempty"`
	// Models maps an AP model to its radio policies by radio ID.
	Models map[string]map[int]RadioPolicy `json:"models,omitempty"`
}

// APConfig is one "wlan ap": its model and per-radio overrides.
type APConfig struct {
	Name   string              `json:"name"`
	Model  string              `json:"model,omitempty"`
	Radios map[int]RadioPolicy `json:"radios,omitempty"`
}

// RRM is the controller-wide radio resource management switches.
type RRM struct {
	BandNavigation     bool `json:"band_navigation,omitempty"`
	LoadBalance        bool `json:"load_balance,omitempty"`
	ChannelCalibration bool `json:"channel_calibration,omitempty"`
	PowerCalibration   bool `json:"power_calibration,omitempty"`
}

// PolicyFor resolves the policy of one radio: the AP's group policy for
// its model, overridden by the AP's own radio settings. group may be
// empty, in which case the group listing the AP is used.
func (c *Configuration) PolicyFor(group, model, ap string, radio int) RadioPolicy {
	if group == "" {
		group = c.groupOf(ap)
	}
	var p RadioPolicy
	if g, ok := c.Groups[group]; ok {
		p = g.Models[model][radio]
	}
	if a, ok := c.APs[ap]; ok {
		p = p.Merge(a.Radios[radio])
	}
	return p
}

func (c *Configuration) groupOf(ap string) string {
	for name, g := range c.Groups {
		if slices.Contains(g.APs, ap) {
			return name
		}
	}
	return ""
}
