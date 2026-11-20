package roam_test

import (
	"slices"
	"testing"
	"time"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/roam"
)

func TestParams_Sticky(t *testing.T) {
	t.Parallel()
	m, _ := wireless.ParseMAC("0200-5e10-0001")
	build := func(rssi int, online time.Duration, btm string, neighbours bool) (*wireless.Index, wireless.ClientView) {
		s := wireless.NewSnapshot(wireless.Controller{Host: "h"}, time.Now())
		aps := []wireless.AccessPoint{{Name: "A", Group: "G", State: wireless.APRun}}
		if neighbours {
			aps = append(aps, wireless.AccessPoint{Name: "B", Group: "G", State: wireless.APRun})
		}
		s.AccessPoints, _ = evidence.NewObservation(wireless.DimensionAccessPoints, evidence.StatusComplete, time.Time{}, aps, nil, nil)
		c := wireless.Client{MAC: m, APName: "A", RSSI: rssi, Online: online, Extra: map[string]string{"BTM mode": btm}}
		s.Clients, _ = evidence.NewObservation(wireless.DimensionClients, evidence.StatusComplete, time.Time{}, []wireless.Client{c}, nil, nil)
		ix := wireless.NewIndex(s)
		for v := range ix.Clients() {
			return ix, v
		}
		panic("no client")
	}
	p := roam.DefaultParams()
	tests := []struct {
		name       string
		rssi       int
		online     time.Duration
		btm        string
		neighbours bool
		suspected  bool
		confidence roam.Confidence
	}{
		{"strong signal", 40, time.Hour, "Active", true, false, roam.ConfidenceNone},
		{"weak but just arrived", 18, time.Minute, "Active", true, false, roam.ConfidenceNone},
		{"weak and staying", 20, 10 * time.Minute, "Active", true, true, roam.ConfidenceLow},
		{"weak, staying long, no BTM", 20, time.Hour, "Inactive", true, true, roam.ConfidenceHigh},
		{"nowhere to go is a coverage hole", 12, time.Hour, "Inactive", false, false, roam.ConfidenceNone},
	}
	for _, tc := range tests {
		ix, v := build(tc.rssi, tc.online, tc.btm, tc.neighbours)
		st := p.Sticky(ix, &v)
		if st.Suspected != tc.suspected || st.Confidence != tc.confidence {
			t.Errorf("%s: %+v", tc.name, st)
		}
	}
}

func TestParams_Sticky_area(t *testing.T) {
	t.Parallel()
	m, _ := wireless.ParseMAC("0200-5e10-0001")
	s := wireless.NewSnapshot(wireless.Controller{Host: "h"}, time.Now())
	aps := []wireless.AccessPoint{
		{Name: "6FAP01", Group: "G", State: wireless.APRun},
		{Name: "7FAP01", Group: "G", State: wireless.APRun},
	}
	s.AccessPoints, _ = evidence.NewObservation(wireless.DimensionAccessPoints, evidence.StatusComplete, time.Time{}, aps, nil, nil)
	c := wireless.Client{MAC: m, APName: "6FAP01", RSSI: 18, Online: time.Hour}
	s.Clients, _ = evidence.NewObservation(wireless.DimensionClients, evidence.StatusComplete, time.Time{}, []wireless.Client{c}, nil, nil)
	ix := wireless.NewIndex(s)
	var v wireless.ClientView
	for x := range ix.Clients() {
		v = x
	}
	p := roam.DefaultParams()
	if st := p.Sticky(ix, &v); !st.Suspected || st.Basis != roam.BasisGroup {
		t.Errorf("group basis: %+v", st)
	}
	p.AreaPattern = `^(\d+F)`
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	// Another floor is no neighbour: a coverage gap, not a sticky client.
	if st := p.Sticky(ix, &v); st.Suspected || st.Basis != roam.BasisArea {
		t.Errorf("area basis: %+v", st)
	}
	track := p.Analyze([]roam.Observation{
		{At: time.Now().Add(-time.Hour), Host: "h", MAC: m, AP: "6FAP02", RSSI: 40},
		{At: time.Now(), Host: "h", MAC: m, AP: "6FAP01", RSSI: 18},
	})
	p.AreaPattern = ""
	st := p.StickyTrack(ix, &v, &track)
	if !slices.Contains(st.Reasons, roam.ReasonBetterAPSeen) || st.Confidence < roam.ConfidenceMedium {
		t.Errorf("track evidence: %+v", st)
	}
	p.AreaPattern = "("
	if p.Validate() == nil {
		t.Error("bad pattern accepted")
	}
}
