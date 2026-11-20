package wireless

import (
	"slices"
	"strings"
)

// Configuration is the part of the controller configuration that explains
// how stations are admitted: service templates, authentication domains,
// RADIUS schemes and portal servers. Secrets are never parsed or kept.
type Configuration struct {
	Sysname       string                     `json:"sysname,omitempty"`
	Version       string                     `json:"version,omitempty"`
	DefaultDomain string                     `json:"default_domain,omitempty"`
	Templates     map[string]ServiceTemplate `json:"templates"`
	Domains       map[string]Domain          `json:"domains"`
	Radius        map[string]RadiusScheme    `json:"radius"`
	// PortalServers maps a portal web server name to its URL.
	PortalServers map[string]string `json:"portal_servers,omitempty"`
	// Groups and APs carry the per-radio roaming and RF policy.
	Groups map[string]APGroup  `json:"groups,omitempty"`
	APs    map[string]APConfig `json:"aps,omitempty"`
	RRM    RRM                 `json:"rrm"`
}

// TemplateForSSID returns the enabled template advertising ssid. Several
// templates may share an SSID; the first in name order wins and ok reports
// whether any matched.
func (c *Configuration) TemplateForSSID(ssid string) (ServiceTemplate, bool) {
	names := make([]string, 0, len(c.Templates))
	for name := range c.Templates {
		names = append(names, name)
	}
	slices.Sort(names)
	var fallback *ServiceTemplate
	for _, name := range names {
		t := c.Templates[name]
		if t.SSID != ssid {
			continue
		}
		if t.Enabled {
			return t, true
		}
		if fallback == nil {
			fallback = &t
		}
	}
	if fallback != nil {
		return *fallback, true
	}
	return ServiceTemplate{}, false
}

// Chain resolves the authentication path for a template: the domain used
// by its authenticator and the RADIUS scheme that domain points at.
func (c *Configuration) Chain(t ServiceTemplate) AuthChain {
	chain := AuthChain{Template: t.Name, Access: t.Access()}
	chain.Domain = t.Domain()
	if chain.Domain == "" {
		chain.Domain = c.DefaultDomain
	}
	d, ok := c.Domains[chain.Domain]
	if !ok {
		return chain
	}
	service := "lan-access"
	if t.Portal {
		service = "portal"
	}
	chain.Scheme = d.Authentication[service]
	if r, ok := c.Radius[chain.Scheme]; ok {
		chain.Servers = slices.Clone(r.Authentication)
	}
	if t.Portal {
		chain.PortalURL = c.PortalServers[t.PortalWebServer]
	}
	return chain
}

// ServiceTemplate is one wlan service-template: the SSID and how stations
// on it are secured and authenticated.
type ServiceTemplate struct {
	Name    string `json:"name"`
	SSID    string `json:"ssid"`
	VLAN    int    `json:"vlan,omitempty"`
	Enabled bool   `json:"enabled"`
	// AKM is "dot1x", "psk" or empty for open.
	AKM          string   `json:"akm,omitempty"`
	CipherSuites []string `json:"cipher_suites,omitempty"`
	SecurityIEs  []string `json:"security_ies,omitempty"`
	// ClientSecurity is the user authentication mode: "dot1x", "mac" or
	// empty.
	ClientSecurity string `json:"client_security,omitempty"`
	// IgnoreAuthentication admits a station even when MAC authentication
	// fails, which with a portal is the MAC-trigger pattern.
	IgnoreAuthentication bool   `json:"ignore_authentication,omitempty"`
	Dot1XDomain          string `json:"dot1x_domain,omitempty"`
	MACDomain            string `json:"mac_domain,omitempty"`
	Portal               bool   `json:"portal,omitempty"`
	PortalDomain         string `json:"portal_domain,omitempty"`
	PortalWebServer      string `json:"portal_web_server,omitempty"`
	// BTM is 802.11v BSS transition management, which lets the controller
	// ask a station to roam.
	BTM bool `json:"btm,omitempty"`
}

// Access classifies the template's admission method.
func (t ServiceTemplate) Access() AccessMethod {
	akm := strings.ReplaceAll(t.AKM, "dot1x", "802.1x")
	if akm == "" {
		akm = AKMNone
	}
	auth := strings.ReplaceAll(t.ClientSecurity, "dot1x", "802.1x")
	if auth == "" && akm == "psk" {
		auth = "bypass"
	}
	return classifyAccess(akm, auth, t.Portal)
}

// Domain returns the authentication domain the template's authenticator
// uses, or empty for the global default.
func (t ServiceTemplate) Domain() string {
	switch {
	case t.Portal && t.PortalDomain != "":
		return t.PortalDomain
	case t.ClientSecurity == "dot1x":
		return t.Dot1XDomain
	case t.ClientSecurity == "mac":
		return t.MACDomain
	}
	return ""
}

// Legacy reports whether the template still offers TKIP or WPA(1), which
// slows every station on the BSS to legacy rates and weakens security.
func (t ServiceTemplate) Legacy() bool {
	return slices.Contains(t.CipherSuites, "tkip") || slices.Contains(t.SecurityIEs, "wpa")
}

// Domain is one ISP domain: which scheme serves each access service.
type Domain struct {
	Name string `json:"name"`
	// Authentication maps a service ("lan-access", "portal") to a scheme.
	Authentication map[string]string `json:"authentication,omitempty"`
}

// RadiusScheme is one RADIUS scheme; only addresses, never keys.
type RadiusScheme struct {
	Name string `json:"name"`
	// Authentication lists the primary then secondary servers.
	Authentication []string `json:"authentication,omitempty"`
	Accounting     []string `json:"accounting,omitempty"`
	NASIP          string   `json:"nas_ip,omitempty"`
}

// AuthChain is the resolved authentication path of one SSID.
type AuthChain struct {
	Template  string       `json:"template"`
	Access    AccessMethod `json:"access"`
	Domain    string       `json:"domain,omitempty"`
	Scheme    string       `json:"scheme,omitempty"`
	Servers   []string     `json:"servers,omitempty"`
	PortalURL string       `json:"portal_url,omitempty"`
}
