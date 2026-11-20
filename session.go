package wireless

import (
	"net/netip"
	"time"
)

// AuthSession is one online authentication held by the controller's
// 802.1X or MAC authenticator. It carries what the client record lacks:
// the RADIUS identity, domain, and the VLAN the server authorized.
type AuthSession struct {
	Kind     AuthKind `json:"kind"`
	MAC      MAC      `json:"mac"`
	Username string   `json:"username,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	// Method is the protocol toward RADIUS, for example "EAP" or "PAP".
	Method string     `json:"method,omitempty"`
	IPv4   netip.Addr `json:"ipv4,omitzero"`
	IPv6   netip.Addr `json:"ipv6,omitzero"`

	APName  string `json:"ap_name,omitempty"`
	RadioID int    `json:"radio_id,omitempty"`
	SSID    string `json:"ssid,omitempty"`
	BSSID   MAC    `json:"bssid,omitzero"`

	InitialVLAN    int    `json:"initial_vlan,omitempty"`
	AuthorizedVLAN int    `json:"authorized_vlan,omitempty"`
	ACL            string `json:"acl,omitempty"`
	UserProfile    string `json:"user_profile,omitempty"`

	// OnlineSince is the authentication time in the controller's clock.
	OnlineSince time.Time     `json:"online_since,omitzero"`
	Online      time.Duration `json:"online_ns,omitempty"`

	Extra map[string]string `json:"extra,omitempty"`
}

// VLANOverridden reports whether RADIUS moved the station off the SSID's
// VLAN, which is the usual reason a user lands in an unexpected subnet.
func (s *AuthSession) VLANOverridden() bool {
	return s.AuthorizedVLAN != 0 && s.InitialVLAN != 0 && s.AuthorizedVLAN != s.InitialVLAN
}

// IPConflict is one entry of the controller's client IP conflict history:
// a new station claimed an address an existing station held.
type IPConflict struct {
	IP      netip.Addr `json:"ip"`
	NewMAC  MAC        `json:"new_mac"`
	NewAPID int        `json:"new_ap_id"`
	OldMAC  MAC        `json:"old_mac"`
	OldAPID int        `json:"old_ap_id"`
	At      time.Time  `json:"at"`
}

// BlockedMAC is one station the controller refuses to associate.
type BlockedMAC struct {
	MAC MAC `json:"mac"`
	// Source names the list, for example "client-security" or "static".
	Source string `json:"source"`
	Detail string `json:"detail,omitempty"`
}
