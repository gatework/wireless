package wireless

import (
	"net/netip"
	"time"
)

// Client is one associated station as the controller reports it. It is a
// fact record: fields hold what the device printed, normalized, and zero
// values mean "not reported".
type Client struct {
	MAC      MAC        `json:"mac"`
	IPv4     netip.Addr `json:"ipv4,omitzero"`
	IPv6     netip.Addr `json:"ipv6,omitzero"`
	Username string     `json:"username,omitempty"`

	APID    int    `json:"ap_id,omitempty"`
	APName  string `json:"ap_name"`
	RadioID int    `json:"radio_id,omitempty"`
	Channel int    `json:"channel,omitempty"`
	SSID    string `json:"ssid"`
	BSSID   MAC    `json:"bssid,omitzero"`
	VLAN    int    `json:"vlan,omitempty"`

	// Mode is the negotiated PHY, for example "802.11ax".
	Mode string `json:"mode,omitempty"`
	// Bandwidth is the negotiated channel width, for example "80MHz".
	Bandwidth string `json:"bandwidth,omitempty"`
	// RSSI is the vendor's received signal indicator. On H3C it is the
	// signal level in dB above the radio's noise floor, so it reads like
	// an SNR; see [Client.SignalDBm].
	RSSI int `json:"rssi"`
	// RxRate and TxRate are the last PHY data rates in Mbps.
	RxRate float64 `json:"rx_rate_mbps,omitempty"`
	TxRate float64 `json:"tx_rate_mbps,omitempty"`
	// RxKbps and TxKbps are the measured throughput in kbit/s.
	RxKbps float64 `json:"rx_kbps,omitempty"`
	TxKbps float64 `json:"tx_kbps,omitempty"`

	// AKM is "802.1x", "psk", [AKMNone] or empty when not reported.
	AKM      string `json:"akm,omitempty"`
	UserAuth string `json:"user_auth,omitempty"`
	Cipher   string `json:"cipher,omitempty"`
	Security string `json:"security,omitempty"`

	Roam       string        `json:"roam,omitempty"`
	Online     time.Duration `json:"online_ns"`
	SleepCount int           `json:"sleep_count,omitempty"`

	// Extra keeps reported attributes the model does not name, keyed by
	// the device label, so detail views lose nothing.
	Extra map[string]string `json:"extra,omitempty"`
}

// Band derives the band from the channel.
func (c *Client) Band() Band { return BandOfChannel(c.Channel) }

// SignalDBm estimates the received signal strength from the vendor RSSI
// and the serving radio's noise floor. It reports false when the noise
// floor is unknown (zero).
func (c *Client) SignalDBm(noiseFloor int) (int, bool) {
	if noiseFloor == 0 {
		return 0, false
	}
	return noiseFloor + c.RSSI, true
}

// Access classifies how the station authenticated from what the client
// record alone says. Portal methods need the service template; see
// [ServiceTemplate.Access].
func (c *Client) Access() AccessMethod {
	return classifyAccess(c.AKM, c.UserAuth, false)
}

// AKMNone is the normalized AKM of an open SSID. An empty AKM means the
// device did not report one, which decides nothing.
const AKMNone = "none"

// classifyAccess maps an AKM and user authentication mode to a method.
// The inputs are normalized vendor words: akm "802.1x", "psk", AKMNone or
// "" (unknown); auth "802.1x", "mac", "bypass" or "".
func classifyAccess(akm, auth string, portal bool) AccessMethod {
	switch {
	case akm == "802.1x" || auth == "802.1x":
		return AccessDot1X
	case akm == "psk" && auth == "mac":
		return AccessPSKMAC
	case akm == "psk":
		return AccessPSK
	case portal && auth == "mac":
		return AccessMACPortal
	case portal:
		return AccessPortal
	case auth == "mac":
		return AccessMAC
	case akm == AKMNone && (auth == "bypass" || auth == ""):
		return AccessOpen
	}
	return AccessUnknown
}
