package h3c

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"

	"github.com/gatework/wireless"
)

// timezone matches "clock timezone <name> add|minus hh:mm:ss".
var timezone = regexp.MustCompile(`^clock timezone (\S+) (add|minus) (\d{1,2}):(\d{2})(?::(\d{2}))?$`)

// section is one top-level configuration block: its header line and the
// indented lines below it, up to the next "#" or top-level line.
type section struct {
	header string
	lines  []string
	// indents holds the leading spaces of each line, for nested blocks.
	indents []int
}

// parseConfiguration decodes the admission-related part of
// "display current-configuration". Only names, addresses and modes are
// read; key, password and pre-shared-key lines are skipped unread.
func parseConfiguration(o capture.Output) (evidence.Observation[wireless.Configuration], *time.Location) {
	var sc parse.Scanner
	content, err := parse.New(context.Background(), o.Normalized(), parse.Limits{})
	if err != nil {
		return failed[wireless.Configuration](wireless.DimensionConfiguration, o.Command, "input_limit"), nil
	}
	cfg := wireless.Configuration{
		Templates:     map[string]wireless.ServiceTemplate{},
		Domains:       map[string]wireless.Domain{},
		Radius:        map[string]wireless.RadiusScheme{},
		PortalServers: map[string]string{},
		Groups:        map[string]wireless.APGroup{},
		APs:           map[string]wireless.APConfig{},
	}
	var loc *time.Location
	for s := range sections(content.Cursor()) {
		switch kind, name := sectionName(s.header); kind {
		case "wlan service-template":
			cfg.Templates[name] = serviceTemplate(name, s.lines)
		case "domain":
			cfg.Domains[name] = domain(name, s.lines)
		case "radius scheme":
			cfg.Radius[name] = radiusScheme(name, s.lines)
		case "portal web-server":
			cfg.PortalServers[name] = firstValue(s.lines, "url ")
		case "wlan ap-group":
			cfg.Groups[name] = apGroup(name, s)
		case "wlan ap":
			ap := apConfig(name, s)
			cfg.APs[ap.Name] = ap
		case "wlan global-configuration":
			rrm(&cfg.RRM, s.lines)
		case "":
			globals(&cfg, s.lines, &loc)
			rrm(&cfg.RRM, s.lines)
		}
	}
	return observe(wireless.DimensionConfiguration, o, []wireless.Configuration{cfg}, &sc), loc
}

// sections yields configuration blocks. Lines before the first header and
// indented lines between "#" markers form header-less blocks of globals.
func sections(c *parse.Cursor) func(yield func(section) bool) {
	return func(yield func(section) bool) {
		var cur section
		flush := func() bool {
			if cur.header == "" && len(cur.lines) == 0 {
				return true
			}
			ok := yield(cur)
			cur = section{}
			return ok
		}
		for line, ok := c.Next(); ok; line, ok = c.Next() {
			text := strings.TrimRight(line.Text, " \t")
			switch {
			case strings.TrimSpace(text) == "" || strings.HasPrefix(text, "#"):
				if !flush() {
					return
				}
			case !strings.HasPrefix(text, " "):
				if !flush() {
					return
				}
				cur.header = text
			default:
				trimmed := strings.TrimSpace(text)
				cur.lines = append(cur.lines, trimmed)
				cur.indents = append(cur.indents, len(text)-len(strings.TrimLeft(text, " ")))
			}
		}
		flush()
	}
}

// sectionName splits a header into its kind and name for the blocks this
// package reads, or returns empty kind for others.
func sectionName(header string) (kind, name string) {
	if header == "" {
		return "", ""
	}
	if strings.TrimSpace(header) == "wlan global-configuration" {
		return "wlan global-configuration", ""
	}
	for _, k := range []string{"wlan service-template", "wlan ap-group", "wlan ap", "radius scheme", "portal web-server", "domain"} {
		if rest, ok := strings.CutPrefix(header, k+" "); ok {
			return k, strings.TrimSpace(rest)
		}
	}
	return "other", ""
}

func serviceTemplate(name string, lines []string) wireless.ServiceTemplate {
	t := wireless.ServiceTemplate{Name: name}
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "ssid "):
			t.SSID = strings.TrimPrefix(l, "ssid ")
		case strings.HasPrefix(l, "vlan "):
			t.VLAN, _ = strconv.Atoi(strings.TrimPrefix(l, "vlan "))
		case strings.HasPrefix(l, "akm mode "):
			t.AKM = strings.TrimPrefix(l, "akm mode ")
		case strings.HasPrefix(l, "cipher-suite "):
			t.CipherSuites = append(t.CipherSuites, strings.TrimPrefix(l, "cipher-suite "))
		case strings.HasPrefix(l, "security-ie "):
			t.SecurityIEs = append(t.SecurityIEs, strings.TrimPrefix(l, "security-ie "))
		case strings.HasPrefix(l, "client-security authentication-mode "):
			t.ClientSecurity = strings.TrimPrefix(l, "client-security authentication-mode ")
		case l == "client-security ignore-authentication":
			t.IgnoreAuthentication = true
		case strings.HasPrefix(l, "dot1x domain "):
			t.Dot1XDomain = strings.TrimPrefix(l, "dot1x domain ")
		case strings.HasPrefix(l, "mac-authentication domain "):
			t.MACDomain = strings.TrimPrefix(l, "mac-authentication domain ")
		case strings.HasPrefix(l, "portal enable"):
			t.Portal = true
		case strings.HasPrefix(l, "portal domain "):
			t.PortalDomain = strings.TrimPrefix(l, "portal domain ")
		case strings.HasPrefix(l, "portal apply web-server "):
			t.PortalWebServer = strings.TrimPrefix(l, "portal apply web-server ")
		case l == "service-template enable":
			t.Enabled = true
		case l == "bss transition-management enable":
			t.BTM = true
		case l == "undo bss transition-management enable":
			t.BTM = false
		}
	}
	return t
}

// domain reads "authentication <service> radius-scheme <name>" lines.
func domain(name string, lines []string) wireless.Domain {
	d := wireless.Domain{Name: name, Authentication: map[string]string{}}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) >= 4 && f[0] == "authentication" && f[2] == "radius-scheme" {
			d.Authentication[f[1]] = f[3]
		}
	}
	return d
}

// radiusScheme reads server addresses. The address is the token after
// the role; any key material that follows on the line is never read.
func radiusScheme(name string, lines []string) wireless.RadiusScheme {
	r := wireless.RadiusScheme{Name: name}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] != "primary" && f[0] != "secondary" {
			if len(f) == 2 && f[0] == "nas-ip" {
				r.NASIP = f[1]
			}
			continue
		}
		switch f[1] {
		case "authentication":
			r.Authentication = append(r.Authentication, f[2])
		case "accounting":
			r.Accounting = append(r.Accounting, f[2])
		}
	}
	return r
}

func globals(cfg *wireless.Configuration, lines []string, loc **time.Location) {
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "sysname "):
			cfg.Sysname = strings.TrimPrefix(l, "sysname ")
		case strings.HasPrefix(l, "version "):
			cfg.Version = strings.TrimPrefix(l, "version ")
		case strings.HasPrefix(l, "domain default enable "):
			cfg.DefaultDomain = strings.TrimPrefix(l, "domain default enable ")
		case strings.HasPrefix(l, "clock timezone "):
			if z, ok := zone(l); ok {
				*loc = z
			}
		}
	}
}

// zone builds the fixed zone of a "clock timezone" line.
func zone(line string) (*time.Location, bool) {
	m := timezone.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	h, _ := strconv.Atoi(m[3])
	mi, _ := strconv.Atoi(m[4])
	s, _ := strconv.Atoi(m[5])
	offset := h*3600 + mi*60 + s
	if m[2] == "minus" {
		offset = -offset
	}
	return time.FixedZone(m[1], offset), true
}

func firstValue(lines []string, prefix string) string {
	for _, l := range lines {
		if v, ok := strings.CutPrefix(l, prefix); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
