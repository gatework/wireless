package h3c

import (
	"net/netip"
	"strings"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"

	"github.com/gatework/wireless"
)

// parseClients decodes "display wlan client verbose".
func parseClients(o capture.Output) evidence.Observation[wireless.Client] {
	var sc parse.Scanner
	res := parseFlat(body(o), flatSpec{start: "mac", labels: clientLabels}, &sc)
	clients := make([]wireless.Client, 0, len(res.records))
	for _, r := range res.records {
		c, ok := client(r)
		if !ok {
			sc.Issue("invalid_mac", r.line)
			continue
		}
		clients = append(clients, c)
	}
	// An empty table prints no total at all, which means zero clients.
	total, known := res.reported("total number of clients")
	return observe(wireless.DimensionClients, o, clients, &sc, countCheck(total, known, len(res.records))...)
}

func client(r *record) (wireless.Client, bool) {
	mac := r.mac("mac")
	if mac.IsZero() {
		return wireless.Client{}, false
	}
	c := wireless.Client{
		MAC:        mac,
		IPv4:       addr(r.str("ipv4")),
		IPv6:       addr(r.str("ipv6")),
		Username:   r.str("username"),
		APID:       r.num("ap_id"),
		APName:     r.str("ap_name"),
		RadioID:    r.num("radio"),
		Channel:    r.num("channel"),
		SSID:       r.str("ssid"),
		BSSID:      r.mac("bssid"),
		VLAN:       r.num("vlan"),
		Mode:       r.str("mode"),
		Bandwidth:  r.str("bandwidth"),
		RSSI:       r.num("rssi"),
		AKM:        r.akm("akm"),
		UserAuth:   r.lower("user_auth"),
		Cipher:     r.lower("cipher"),
		Security:   r.str("security"),
		Roam:       r.str("roam"),
		SleepCount: r.num("sleep"),
		Extra:      r.extras(),
	}
	c.RxRate, c.TxRate, _ = pair(r.str("rate"))
	c.RxKbps, c.TxKbps, _ = pair(r.str("speed"))
	c.Online, _ = duration(r.str("online"))
	return c, true
}

// parseSessions decodes "display dot1x connection" and
// "display mac-authentication connection", which share one layout.
func parseSessions(dim evidence.Dimension, kind wireless.AuthKind, o capture.Output, loc *time.Location) evidence.Observation[wireless.AuthSession] {
	var sc parse.Scanner
	res := parseFlat(body(o), flatSpec{start: "mac", labels: sessionLabels}, &sc)
	sessions := make([]wireless.AuthSession, 0, len(res.records))
	for _, r := range res.records {
		s := session(kind, r, loc)
		if s.MAC.IsZero() {
			sc.Issue("invalid_mac", r.line)
			continue
		}
		sessions = append(sessions, s)
	}
	total, known := res.reported("total connections")
	return observe(dim, o, sessions, &sc, countCheck(total, known, len(res.records))...)
}

func session(kind wireless.AuthKind, r *record, loc *time.Location) wireless.AuthSession {
	s := wireless.AuthSession{
		Kind:           kind,
		MAC:            r.mac("mac"),
		Username:       r.str("username"),
		Domain:         r.str("domain"),
		Method:         r.str("method"),
		IPv4:           addr(r.str("ipv4")),
		IPv6:           addr(r.str("ipv6")),
		APName:         r.str("ap_name"),
		RadioID:        r.num("radio"),
		SSID:           r.str("ssid"),
		BSSID:          r.mac("bssid"),
		InitialVLAN:    r.num("initial_vlan"),
		AuthorizedVLAN: r.num("auth_vlan"),
		ACL:            r.str("acl"),
		UserProfile:    r.str("profile"),
		Extra:          r.extras(),
	}
	if t, err := time.ParseInLocation("2006/01/02 15:04:05", r.str("since"), loc); err == nil {
		s.OnlineSince = t
	}
	s.Online, _ = duration(r.str("online"))
	return s
}

// parseBSS decodes "display wlan bss all verbose".
func parseBSS(o capture.Output) evidence.Observation[wireless.BSS] {
	var sc parse.Scanner
	res := parseFlat(body(o), flatSpec{start: "ap_name", labels: bssLabels}, &sc)
	out := make([]wireless.BSS, 0, len(res.records))
	for _, r := range res.records {
		b := wireless.BSS{
			APName:   r.str("ap_name"),
			RadioID:  r.num("radio"),
			BSSID:    r.mac("bssid"),
			Template: r.str("template"),
			SSID:     r.str("ssid"),
			VLAN:     r.num("vlan"),
			AKM:      r.akm("akm"),
			UserAuth: r.lower("user_auth"),
		}
		out = append(out, b)
	}
	return observe(wireless.DimensionBSS, o, out, &sc)
}

// addr parses an IPv4 or IPv6 address, or returns the zero Addr.
func addr(text string) netip.Addr {
	a, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}
