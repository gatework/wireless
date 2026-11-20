package h3c_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/failure"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/vendors/h3c"
)

var recordedAt = time.Date(2026, 11, 13, 7, 47, 0, 0, time.UTC)

var fixtures = map[string]string{
	h3c.CommandClients:       "clients.txt",
	h3c.CommandAccessPoints:  "aps.txt",
	h3c.CommandBSS:           "bss.txt",
	h3c.CommandDot1X:         "dot1x.txt",
	h3c.CommandMAC:           "mac.txt",
	h3c.CommandConflicts:     "conflicts.txt",
	h3c.CommandBlocked:       "blocked.txt",
	h3c.CommandConfiguration: "config.txt",
}

// capture loads every fixture; crlf converts line endings to the "\r\r\n"
// Comware sends over SSH.
func fixtures2(t *testing.T, crlf bool) capture.Capture {
	t.Helper()
	c := capture.Capture{Host: netip.MustParseAddr("198.51.100.1"), Prompt: "\x00<AC-1>"}
	for _, command := range h3c.New(h3c.Options{}).CollectCommands() {
		body, err := os.ReadFile(filepath.Join("testdata", fixtures[command]))
		if err != nil {
			t.Fatal(err)
		}
		text := strings.TrimSuffix(string(body), "\n")
		if crlf {
			text = strings.ReplaceAll(text, "\n", "\r\r\n")
		}
		c.Outputs = append(c.Outputs, capture.Output{Command: command, Raw: text, RecordedAt: recordedAt})
	}
	return c
}

func decode(t *testing.T, crlf bool) *wireless.Snapshot {
	t.Helper()
	return h3c.New(h3c.Options{}).Decode(fixtures2(t, crlf))
}

func TestVendor_Decode_coverage(t *testing.T) {
	t.Parallel()
	for _, crlf := range []bool{false, true} {
		s := decode(t, crlf)
		cov := s.Coverage()
		for _, dim := range cov.Dimensions() {
			if status := cov.Status(dim); status != evidence.StatusComplete {
				t.Errorf("crlf=%v %s: status %s", crlf, dim, status)
			}
		}
		if s.Controller.Name != "AC-1" || s.Controller.Version != "7.1.064, Release 5489P02" {
			t.Errorf("controller = %+v", s.Controller)
		}
	}
}

func TestVendor_Decode_clients(t *testing.T) {
	t.Parallel()
	s := decode(t, true)
	if got := len(s.Clients.Facts); got != 2 {
		t.Fatalf("clients = %d, want 2", got)
	}
	c := s.Clients.Facts[0]
	checks := []struct {
		name      string
		got, want any
	}{
		{"mac", c.MAC.H3C(), "0200-5e10-0001"},
		{"ipv4", c.IPv4, netip.MustParseAddr("192.0.2.10")},
		{"ipv6 N/A", c.IPv6.IsValid(), false},
		{"username before blank line", c.Username, "alice"},
		{"ap", c.APName, "AP-1F-01"},
		{"channel", c.Channel, 44},
		{"vlan", c.VLAN, 100},
		{"rssi", c.RSSI, 42},
		{"rx rate", c.RxRate, 143.4},
		{"tx kbps", c.TxKbps, 588.672},
		{"akm", c.AKM, "802.1x"},
		{"access", c.Access(), wireless.AccessDot1X},
		{"online", c.Online, time.Hour + 33*time.Minute + 43*time.Second},
		{"continuation", c.Extra["Supported HT MCS set"], "0, 1, 2, 3, 4, 5, 6, 7"},
		{"bandwidth trimmed", c.Bandwidth, "20MHz"},
	}
	for _, tc := range checks {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	second := s.Clients.Facts[1]
	if second.Access() != wireless.AccessPSKMAC || second.IPv6 != netip.MustParseAddr("2001:db8::11") || !second.MAC.Randomized() {
		t.Errorf("second client = %+v", second)
	}
}

func TestVendor_Decode_accessPoints(t *testing.T) {
	t.Parallel()
	s := decode(t, false)
	want := wireless.APCapacity{Total: 2, Connected: 1, Max: 512, Licenses: 64, LicensesRemaining: 3}
	if s.Capacity != want {
		t.Errorf("capacity = %+v, want %+v", s.Capacity, want)
	}
	aps := s.AccessPoints.Facts
	if len(aps) != 2 {
		t.Fatalf("aps = %d", len(aps))
	}
	ap := aps[0]
	if !ap.Running() || ap.EchoLoss() != 0.03 || ap.Uptime != 2*time.Hour || ap.Extra["PoE status"] != "Port 2 Disabled" {
		t.Errorf("ap = %+v", ap)
	}
	if len(ap.Radios) != 2 {
		t.Fatalf("radios = %d", len(ap.Radios))
	}
	r1, r2 := ap.Radios[0], ap.Radios[1]
	if r1.Usage != 82 || r1.NoiseFloor != -95 || r1.MaxPower != 20 || r1.Band() != wireless.Band5G ||
		r1.Extra["Operational HT MCS Set/Supported"] != "0, 1, 2, 3, 4, 5, 6, 7" {
		t.Errorf("radio 1 = %+v", r1)
	}
	// Release 5631 spells BSSID, State and Type differently.
	if r2.BSSID.H3C() != "0200-5e20-0022" || !r2.Up || r2.Channel != 6 || r2.ChannelMode != "auto" || r2.Band() != wireless.Band2G4 {
		t.Errorf("radio 2 = %+v", r2)
	}
	idle := aps[1]
	if idle.Running() || !idle.MAC.IsZero() || idle.IP.IsValid() || idle.Online != 0 {
		t.Errorf("idle ap = %+v", idle)
	}
}

func TestVendor_Decode_sessions(t *testing.T) {
	t.Parallel()
	s := decode(t, false)
	if len(s.Dot1X.Facts) != 1 || len(s.MAC.Facts) != 1 {
		t.Fatalf("sessions = %d/%d", len(s.Dot1X.Facts), len(s.MAC.Facts))
	}
	d := s.Dot1X.Facts[0]
	beijing := time.FixedZone("beijing", 8*3600)
	if d.Username != "alice" || d.Domain != "corp-domain" || d.Method != "EAP" || !d.VLANOverridden() ||
		!d.OnlineSince.Equal(time.Date(2026, 11, 13, 11, 13, 37, 0, beijing)) || d.Online != 4*time.Hour+34*time.Minute+20*time.Second {
		t.Errorf("dot1x = %+v", d)
	}
	if m := s.MAC.Facts[0]; m.Kind != wireless.AuthMAC || m.Online != 349*time.Hour+14*time.Minute+42*time.Second {
		t.Errorf("mac = %+v", m)
	}
}

func TestVendor_Decode_conflicts(t *testing.T) {
	t.Parallel()
	s := decode(t, false)
	got := s.Conflicts.Facts
	if len(got) != 3 {
		t.Fatalf("conflicts = %d", len(got))
	}
	beijing := time.FixedZone("beijing", 8*3600)
	// 12-30 is after the collection date, so it belongs to the previous year.
	if want := time.Date(2025, 12, 30, 9, 0, 0, 0, beijing); !got[1].At.Equal(want) {
		t.Errorf("year inference: %v, want %v", got[1].At, want)
	}
	if got[2].IP != netip.MustParseAddr("2001:db8::1234") || got[2].OldAPID != 4 {
		t.Errorf("ipv6 row = %+v", got[2])
	}
}

func TestVendor_Decode_configuration(t *testing.T) {
	t.Parallel()
	s := decode(t, false)
	cfg, ok := s.Config()
	if !ok {
		t.Fatal("no configuration")
	}
	tests := []struct {
		template string
		access   wireless.AccessMethod
		legacy   bool
	}{
		{"corp", wireless.AccessDot1X, false},
		{"staff", wireless.AccessPSKMAC, true},
		{"guest", wireless.AccessMACPortal, false},
	}
	for _, tc := range tests {
		tpl := cfg.Templates[tc.template]
		if tpl.Access() != tc.access || tpl.Legacy() != tc.legacy || !tpl.Enabled {
			t.Errorf("%s: access %v legacy %v enabled %v", tc.template, tpl.Access(), tpl.Legacy(), tpl.Enabled)
		}
	}
	chain := cfg.Chain(cfg.Templates["guest"])
	if chain.Domain != "portal-domain" || chain.Scheme != "rad" || chain.PortalURL != "http://portal.example.com/login" ||
		strings.Join(chain.Servers, ",") != "198.51.100.5,198.51.100.6" {
		t.Errorf("chain = %+v", chain)
	}
	if cfg.DefaultDomain != "corp-domain" || cfg.Radius["rad"].NASIP != "198.51.100.1" {
		t.Errorf("globals = %q %+v", cfg.DefaultDomain, cfg.Radius["rad"])
	}
}

func TestVendor_Decode_neverKeepsSecrets(t *testing.T) {
	t.Parallel()
	s := decode(t, false)
	for _, obs := range []any{s.Configuration.Facts, s.Clients.Facts} {
		if strings.Contains(strings.ToLower(jsonText(t, obs)), "secret") {
			t.Fatalf("secret material leaked into %T", obs)
		}
	}
}

func TestVendor_Decode_countMismatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		total  int
		status evidence.Status
		code   string
	}{
		{"drift within tolerance stays complete", 4, evidence.StatusComplete, "count_drift"},
		{"large gap is partial", 40, evidence.StatusPartial, "count_mismatch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := fixtures2(t, false)
			for i := range c.Outputs {
				if c.Outputs[i].Command == h3c.CommandClients {
					c.Outputs[i].Raw = strings.Replace(c.Outputs[i].Raw, "Total number of clients: 2", "Total number of clients: "+itoa(tc.total), 1)
				}
			}
			s := h3c.New(h3c.Options{}).Decode(c)
			if s.Clients.Status != tc.status || len(s.Clients.Issues) != 1 || s.Clients.Issues[0].Code != tc.code {
				t.Errorf("status %s issues %+v", s.Clients.Status, s.Clients.Issues)
			}
		})
	}
}

func TestVendor_Decode_emptyAndFailed(t *testing.T) {
	t.Parallel()
	c := capture.Capture{
		Host: netip.MustParseAddr("198.51.100.1"), Prompt: "<AC-2>",
		Outputs: []capture.Output{
			{Command: h3c.CommandClients, Raw: "display wlan client verbose\r\r\n<AC-2>"},
			{Command: h3c.CommandDot1X, Failure: failure.CodeRejected},
		},
	}
	s := h3c.New(h3c.Options{}).Decode(c)
	if s.Clients.Status != evidence.StatusComplete || len(s.Clients.Facts) != 0 {
		t.Errorf("empty clients: %s %d", s.Clients.Status, len(s.Clients.Facts))
	}
	if s.Dot1X.Status != evidence.StatusFailed || s.AccessPoints.Status != evidence.StatusNotRequested {
		t.Errorf("dot1x %s, aps %s", s.Dot1X.Status, s.AccessPoints.Status)
	}
}

func TestVendor_Commands(t *testing.T) {
	t.Parallel()
	got := h3c.New(h3c.Options{}).CollectCommands(wireless.DimensionDot1X, wireless.DimensionClients)
	want := []string{h3c.CommandClients, h3c.CommandDot1X}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("commands = %q, want %q", got, want)
	}
}
