package wireless

import (
	"net/netip"
	"strings"
	"time"
)

// APState is the controller's view of an AP's CAPWAP state. Values other
// than the declared ones are kept verbatim as the device printed them.
type APState string

// AP states.
const (
	APRun  APState = "Run"
	APIdle APState = "Idle"
)

// AccessPoint is one AP as the controller reports it.
type AccessPoint struct {
	Name   string     `json:"name"`
	ID     int        `json:"id"`
	Group  string     `json:"group,omitempty"`
	State  APState    `json:"state"`
	Model  string     `json:"model,omitempty"`
	Serial string     `json:"serial,omitempty"`
	MAC    MAC        `json:"mac,omitzero"`
	IP     netip.Addr `json:"ip,omitzero"`

	Software     string        `json:"software,omitempty"`
	Online       time.Duration `json:"online_ns,omitempty"`
	Uptime       time.Duration `json:"uptime_ns,omitempty"`
	RebootReason string        `json:"reboot_reason,omitempty"`
	Power        string        `json:"power,omitempty"`
	Description  string        `json:"description,omitempty"`

	// EchoRequests and LostEchoes count CAPWAP keepalives; losses point at
	// an unstable path between the AP and the controller.
	EchoRequests int `json:"echo_requests,omitempty"`
	LostEchoes   int `json:"lost_echoes,omitempty"`

	Radios []Radio           `json:"radios,omitempty"`
	Extra  map[string]string `json:"extra,omitempty"`
}

// Running reports whether the AP is joined and serving.
func (a *AccessPoint) Running() bool { return a.State == APRun }

// EchoLoss returns the fraction of keepalives lost, or zero when none were
// sent.
func (a *AccessPoint) EchoLoss() float64 {
	if a.EchoRequests <= 0 {
		return 0
	}
	return float64(a.LostEchoes) / float64(a.EchoRequests)
}

// Radio returns the radio with the given ID.
func (a *AccessPoint) Radio(id int) (*Radio, bool) {
	for i := range a.Radios {
		if a.Radios[i].ID == id {
			return &a.Radios[i], true
		}
	}
	return nil, false
}

// Radio is one AP radio.
type Radio struct {
	ID    int  `json:"id"`
	BSSID MAC  `json:"bssid,omitzero"`
	Up    bool `json:"up"`
	// Type is the PHY and band, for example "802.11ax(5GHz)".
	Type    string `json:"type,omitempty"`
	Channel int    `json:"channel,omitempty"`
	// ChannelMode is the annotation beside the channel, such as "auto"
	// or "avoid radar".
	ChannelMode string `json:"channel_mode,omitempty"`
	Bandwidth   string `json:"bandwidth,omitempty"`
	// Usage is the channel utilization in percent, as busy airtime.
	Usage int `json:"usage_percent"`
	// MaxPower is the transmit power ceiling in dBm.
	MaxPower int `json:"max_power_dbm,omitempty"`
	// NoiseFloor is in dBm; zero means not measured.
	NoiseFloor int `json:"noise_floor_dbm,omitempty"`

	Extra map[string]string `json:"extra,omitempty"`
}

// Plausible noise floor range. Controllers print 0 or values such as -35
// for radios that did not measure, which must not count as noise.
const (
	minNoiseFloor = -110
	maxNoiseFloor = -60
)

// Noise returns the noise floor when it is a plausible measurement.
func (r *Radio) Noise() (int, bool) {
	if r.NoiseFloor < minNoiseFloor || r.NoiseFloor > maxNoiseFloor {
		return 0, false
	}
	return r.NoiseFloor, true
}

// Measured reports whether the radio's utilization is a measurement: a
// radio that is down reports zero usage, which means nothing.
func (r *Radio) Measured() bool { return r.Up }

// Band derives the band from the radio type, falling back to the channel.
func (r *Radio) Band() Band {
	switch t := strings.ToLower(r.Type); {
	case strings.Contains(t, "6ghz"):
		return Band6G
	case strings.Contains(t, "5ghz"):
		return Band5G
	case strings.Contains(t, "2.4ghz"):
		return Band2G4
	}
	return BandOfChannel(r.Channel)
}

// BSS is one advertised network on one radio.
type BSS struct {
	APName   string `json:"ap_name"`
	RadioID  int    `json:"radio_id"`
	BSSID    MAC    `json:"bssid"`
	Template string `json:"template"`
	SSID     string `json:"ssid"`
	VLAN     int    `json:"vlan,omitempty"`
	AKM      string `json:"akm,omitempty"`
	UserAuth string `json:"user_auth,omitempty"`
}

// APCapacity is the controller's AP and license accounting.
type APCapacity struct {
	Total             int `json:"total"`
	Connected         int `json:"connected"`
	Max               int `json:"max"`
	Licenses          int `json:"licenses"`
	LicensesRemaining int `json:"licenses_remaining"`
}
