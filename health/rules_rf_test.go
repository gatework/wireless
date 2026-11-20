package health_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/gatework/netops/assess"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/health"
	"github.com/gatework/wireless/roam"
)

func rfSnapshot() *wireless.Snapshot {
	at := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	s := wireless.NewSnapshot(wireless.Controller{Host: "198.51.100.1", Name: "AC"}, at)
	radios := func() []wireless.Radio {
		return []wireless.Radio{
			{ID: 1, Up: true, Type: "802.11ax(5GHz)", Channel: 36, MaxPower: 10, NoiseFloor: -95},
			{ID: 2, Up: true, Type: "802.11ax(2.4GHz)", Channel: 3, MaxPower: 20, NoiseFloor: -90},
		}
	}
	var aps []wireless.AccessPoint
	for i := range 5 {
		aps = append(aps, wireless.AccessPoint{Name: fmt.Sprintf("AP-%d", i), Group: "G", Model: "M", State: wireless.APRun, Radios: radios()})
	}
	s.AccessPoints = complete(wireless.DimensionAccessPoints, aps...)
	var clients []wireless.Client
	for i := range 12 {
		m, _ := wireless.ParseMAC(fmt.Sprintf("0200-5e10-%04x", i))
		c := wireless.Client{MAC: m, APName: "AP-0", RadioID: 2, Channel: 3, RSSI: 40, Online: time.Hour, Mode: "802.11ax"}
		if i < 3 {
			c.RSSI = 12
		}
		clients = append(clients, c)
	}
	s.Clients = complete(wireless.DimensionClients, clients...)
	s.Configuration = complete(wireless.DimensionConfiguration, wireless.Configuration{
		Groups: map[string]wireless.APGroup{"G": {Name: "G", Models: map[string]map[int]wireless.RadioPolicy{
			"M": {1: {RejectRSSI: 20, AntiSticky: true, AntiStickyRSSI: 25}},
		}}},
	})
	return s
}

func TestInspector_Run_rfRules(t *testing.T) {
	t.Parallel()
	in, err := health.New(assess.Policy{}, nil, options())
	if err != nil {
		t.Fatal(err)
	}
	m, _ := wireless.ParseMAC("0200-5e10-0001")
	t0 := time.Date(2026, 11, 13, 7, 0, 0, 0, time.UTC)
	track := roam.DefaultParams().Analyze([]roam.Observation{
		{At: t0, Host: "198.51.100.1", MAC: m, AP: "AP-0", Start: true},
		{At: t0.Add(time.Minute), Host: "198.51.100.1", MAC: m, AP: "AP-1", Start: true},
		{At: t0.Add(2 * time.Minute), Host: "198.51.100.1", MAC: m, AP: "AP-0", Start: true},
	})
	r, err := in.Run(t.Context(), wireless.NewIndex(rfSnapshot()), []roam.Track{track})
	if err != nil {
		t.Fatal(err)
	}
	var got []assess.RuleID
	for _, f := range r.Findings() {
		got = append(got, f.Rule)
	}
	for _, want := range []assess.RuleID{
		health.RuleStickyClients, health.RuleCochannel, health.RuleBandImbalance, health.RulePolicyConflict, health.RulePingPong,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if slices.Contains(got, health.RuleCoverageHole) {
		t.Error("weak clients with neighbour APs reported as a coverage hole")
	}
}
