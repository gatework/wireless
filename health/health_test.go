package health_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/health"
	"github.com/gatework/wireless/quality"
	"github.com/gatework/wireless/roam"
)

func complete[T any](d evidence.Dimension, facts ...T) evidence.Observation[T] {
	o, err := evidence.NewObservation(d, evidence.StatusComplete, time.Time{}, facts, nil, nil)
	if err != nil {
		panic(err)
	}
	return o
}

func snapshot() *wireless.Snapshot {
	at := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	s := wireless.NewSnapshot(wireless.Controller{Host: "198.51.100.1", Name: "AC"}, at)
	s.Capacity = wireless.APCapacity{Total: 2, Connected: 1, Licenses: 10, LicensesRemaining: 1}
	s.AccessPoints = complete(wireless.DimensionAccessPoints,
		wireless.AccessPoint{Name: "AP-1", State: wireless.APRun, EchoRequests: 10000, LostEchoes: 500,
			Radios: []wireless.Radio{{ID: 1, Up: true, Usage: 90, Channel: 36}, {ID: 2, Up: false, Type: "802.11n(2.4GHz)"}}},
		wireless.AccessPoint{Name: "AP-2", State: wireless.APIdle},
	)
	m, _ := wireless.ParseMAC("0200-5e10-0001")
	s.Clients = complete(wireless.DimensionClients, wireless.Client{MAC: m, APName: "AP-1", Online: time.Hour})
	s.Conflicts = complete(wireless.DimensionConflicts, wireless.IPConflict{IP: netip.MustParseAddr("192.0.2.1"), At: at.Add(-time.Hour)})
	s.Configuration = complete(wireless.DimensionConfiguration, wireless.Configuration{Templates: map[string]wireless.ServiceTemplate{
		"old": {Name: "old", SSID: "Old", Enabled: true, AKM: "psk", CipherSuites: []string{"tkip"}},
	}})
	return s
}

func TestInspector_Run(t *testing.T) {
	t.Parallel()
	in, err := health.New(assess.Policy{}, nil, options())
	if err != nil {
		t.Fatal(err)
	}
	r, err := in.Run(t.Context(), wireless.NewIndex(snapshot()), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []assess.RuleID
	for _, f := range r.Findings() {
		got = append(got, f.Rule)
	}
	for _, want := range []assess.RuleID{
		health.RuleAPNotRunning, health.RuleAPEchoLoss, health.RuleRadioBusy, health.RuleRadioDown,
		health.RuleLicenseLow, health.RuleLegacySecurity, health.RuleSharedKeyOnly, health.RuleClientNoIPv4, health.RuleRecentConflicts,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if f := r.Findings(); f[0].Severity < f[len(f)-1].Severity {
		t.Error("findings not ordered by severity")
	}
}

func TestInspector_Run_skipsIncompleteEvidence(t *testing.T) {
	t.Parallel()
	s := snapshot()
	s.AccessPoints.Status = evidence.StatusPartial
	in, _ := health.New(assess.Policy{}, nil, options())
	r, err := in.Run(t.Context(), wireless.NewIndex(s), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range r.Controllers[0].Assessment.Rules {
		if o.Rule == health.RuleAPNotRunning && o.State != assess.RuleSkipped {
			t.Errorf("ap rule ran on partial evidence: %s", o.State)
		}
	}
}

func TestCatalog(t *testing.T) {
	t.Parallel()
	c, err := health.Catalog()
	if err != nil || c.Len() != 18 {
		t.Fatalf("catalog = %v, %v", c, err)
	}
}

func options() health.Options {
	return health.Options{Quality: quality.DefaultProfile(), Roaming: roam.DefaultParams()}
}
