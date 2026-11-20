package diagnose_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/diagnose"
	"github.com/gatework/wireless/roam"
)

func mac(s string) wireless.MAC {
	m, err := wireless.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func complete[T any](d evidence.Dimension, facts ...T) evidence.Observation[T] {
	o, err := evidence.NewObservation(d, evidence.StatusComplete, time.Time{}, facts, nil, nil)
	if err != nil {
		panic(err)
	}
	return o
}

// station builds a one-controller index around one client.
func station(c wireless.Client, mutate func(*wireless.Snapshot)) (*wireless.Index, wireless.ClientView) {
	s := wireless.NewSnapshot(wireless.Controller{Host: "198.51.100.1", Name: "AC"}, time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC))
	s.Clients = complete(wireless.DimensionClients, c)
	s.Dot1X = complete[wireless.AuthSession](wireless.DimensionDot1X)
	s.MAC = complete[wireless.AuthSession](wireless.DimensionMAC)
	s.AccessPoints = complete(wireless.DimensionAccessPoints, wireless.AccessPoint{
		Name: "AP-1", State: wireless.APRun, Uptime: 400 * time.Hour, EchoRequests: 1000,
		Radios: []wireless.Radio{{ID: 1, Up: true, Type: "802.11ax(2.4GHz)", Channel: 6, Usage: 85, NoiseFloor: -92}, {ID: 2, Up: true, Type: "802.11ax(5GHz)", Channel: 36}},
	})
	if mutate != nil {
		mutate(s)
	}
	ix := wireless.NewIndex(s)
	for v := range ix.Clients() {
		return ix, v
	}
	panic("no client")
}

func codes(r diagnose.Report) []diagnose.Code {
	out := make([]diagnose.Code, len(r.Findings))
	for i, f := range r.Findings {
		out[i] = f.Code
	}
	return out
}

func TestDiagnoser_Client(t *testing.T) {
	t.Parallel()
	d, err := diagnose.New(diagnose.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	base := wireless.Client{
		MAC: mac("0200-5e10-0001"), IPv4: netip.MustParseAddr("192.0.2.10"), APName: "AP-1", RadioID: 1, Channel: 6,
		SSID: "Corp", RSSI: 12, AKM: "802.1x", UserAuth: "802.1x", Online: time.Hour, RxRate: 6, TxRate: 9,
	}
	tests := []struct {
		name   string
		client func(*wireless.Client)
		snap   func(*wireless.Snapshot)
		want   []diagnose.Code
		level  diagnose.Level
	}{
		{name: "weak signal on a busy 2.4G channel without session", want: []diagnose.Code{
			diagnose.CodeQuality, diagnose.CodeSignal, diagnose.CodeBand24, diagnose.CodeNoSession, diagnose.CodeCoverageGap,
		}, level: diagnose.LevelFail},
		{name: "weak and staying with another AP in the group is sticky", snap: func(s *wireless.Snapshot) {
			s.AccessPoints.Facts = append(s.AccessPoints.Facts, wireless.AccessPoint{Name: "AP-2", State: wireless.APRun})
		}, want: []diagnose.Code{diagnose.CodeSticky}},
		{name: "no address after DHCP grace", client: func(c *wireless.Client) { c.IPv4 = netip.Addr{} }, want: []diagnose.Code{diagnose.CodeNoIPv4}, level: diagnose.LevelFail},
		{name: "link-local address", client: func(c *wireless.Client) { c.IPv4 = netip.MustParseAddr("169.254.1.1") }, want: []diagnose.Code{diagnose.CodeLinkLocal}},
		{name: "randomized MAC on MAC authentication", client: func(c *wireless.Client) {
			c.MAC, c.AKM, c.UserAuth = mac("0600-5e10-0001"), "psk", "mac"
		}, want: []diagnose.Code{diagnose.CodeRandomizedMACAuth}},
		{name: "partial sessions suppress no-session", snap: func(s *wireless.Snapshot) { s.Dot1X.Status = evidence.StatusPartial },
			want: []diagnose.Code{diagnose.CodeEvidencePartial}},
		{name: "blacklisted", snap: func(s *wireless.Snapshot) {
			s.Blocked = complete(wireless.DimensionBlocked, wireless.BlockedMAC{MAC: mac("0200-5e10-0001"), Source: "static"})
		}, want: []diagnose.Code{diagnose.CodeBlocked}, level: diagnose.LevelFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := base
			if tc.client != nil {
				tc.client(&c)
			}
			ix, v := station(c, tc.snap)
			r := d.Client(ix, &v, nil)
			got := codes(r)
			for _, w := range tc.want {
				if !slices.Contains(got, w) {
					t.Errorf("missing %s in %v", w, got)
				}
			}
			if tc.name == "partial sessions suppress no-session" && slices.Contains(got, diagnose.CodeNoSession) {
				t.Errorf("no_session concluded from partial evidence: %v", got)
			}
			if tc.level != diagnose.LevelOK && r.Level != tc.level {
				t.Errorf("level = %s, want %s", r.Level, tc.level)
			}
		})
	}
}

func TestDiagnoser_signalEstimate(t *testing.T) {
	t.Parallel()
	d, _ := diagnose.New(diagnose.DefaultOptions())
	ix, v := station(wireless.Client{MAC: mac("0200-5e10-0001"), APName: "AP-1", RadioID: 1, RSSI: 40, IPv4: netip.MustParseAddr("192.0.2.1")}, nil)
	r := d.Client(ix, &v, nil)
	if !r.Signal.Estimated || r.Signal.DBm != -52 || r.Quality.Total == 0 {
		t.Errorf("signal = %+v quality = %+v", r.Signal, r.Quality)
	}
}

func TestDiagnoser_pingPong(t *testing.T) {
	t.Parallel()
	d, _ := diagnose.New(diagnose.DefaultOptions())
	ix, v := station(wireless.Client{MAC: mac("0200-5e10-0001"), APName: "AP-1", RadioID: 1, RSSI: 40, IPv4: netip.MustParseAddr("192.0.2.1")}, nil)
	t0 := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	obs := []roam.Observation{
		{At: t0, Host: "h", AP: "A", Start: true}, {At: t0.Add(time.Minute), Host: "h", AP: "B", Start: true},
		{At: t0.Add(2 * time.Minute), Host: "h", AP: "A", Start: true},
	}
	track := d.Roaming().Analyze(obs)
	r := d.Client(ix, &v, &track)
	if !slices.Contains(codes(r), diagnose.CodePingPong) || r.Level != diagnose.LevelWarn {
		t.Errorf("codes %v level %s", codes(r), r.Level)
	}
}

func TestNew_rejectsInvalidOptions(t *testing.T) {
	t.Parallel()
	o := diagnose.DefaultOptions()
	o.Thresholds.EchoLoss = 2
	if _, err := diagnose.New(o); err == nil {
		t.Error("invalid thresholds accepted")
	}
}
