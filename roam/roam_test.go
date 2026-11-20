package roam_test

import (
	"testing"
	"time"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/roam"
)

var t0 = time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)

func sight(minute int, host, ap string, ch, rssi int, online time.Duration) roam.Observation {
	m, _ := wireless.ParseMAC("0200-5e10-0001")
	return roam.Observation{At: t0.Add(time.Duration(minute) * time.Minute), Host: host, MAC: m, AP: ap, Channel: ch, RSSI: rssi, Online: online}
}

func TestParams_Analyze(t *testing.T) {
	t.Parallel()
	p := roam.DefaultParams()
	tests := []struct {
		name         string
		obs          []roam.Observation
		events       []roam.EventKind
		pingPong     bool
		bounces      int
		insufficient bool
		edge         bool
	}{
		{
			name: "A to B and back within the window",
			obs: []roam.Observation{
				sight(0, "ac1", "A", 36, 20, time.Hour), sight(2, "ac1", "B", 36, 22, time.Minute),
				sight(4, "ac1", "A", 36, 19, time.Minute), sight(6, "ac1", "B", 36, 21, time.Minute),
			},
			events: []roam.EventKind{roam.EventRoam, roam.EventRoam, roam.EventRoam}, pingPong: true, bounces: 2, edge: true,
		},
		{
			name:   "steady station has no events",
			obs:    []roam.Observation{sight(0, "ac1", "A", 36, 40, time.Hour), sight(2, "ac1", "A", 36, 40, time.Hour+2*time.Minute)},
			events: nil,
		},
		{
			name:   "association restarted on the same AP",
			obs:    []roam.Observation{sight(0, "ac1", "A", 36, 40, time.Hour), sight(5, "ac1", "A", 36, 40, time.Minute)},
			events: []roam.EventKind{roam.EventReassoc},
		},
		{
			name:   "move across controllers",
			obs:    []roam.Observation{sight(0, "ac1", "A", 36, 30, time.Hour), sight(2, "ac2", "X", 40, 30, time.Minute)},
			events: []roam.EventKind{roam.EventInterAC},
		},
		{
			name:         "hourly sightings cannot see ping-pong",
			obs:          []roam.Observation{sight(0, "ac1", "A", 1, 30, time.Hour), sight(60, "ac1", "A", 1, 30, 2*time.Hour), sight(120, "ac1", "A", 1, 30, 3*time.Hour)},
			insufficient: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tr := p.Analyze(tc.obs)
			if len(tr.Events) != len(tc.events) {
				t.Fatalf("events = %+v", tr.Events)
			}
			for i, k := range tc.events {
				if tr.Events[i].Kind != k {
					t.Errorf("event %d = %s, want %s", i, tr.Events[i].Kind, k)
				}
			}
			if (tr.PingPong != nil) != tc.pingPong || tr.Insufficient != tc.insufficient {
				t.Fatalf("ping-pong %+v insufficient %v", tr.PingPong, tr.Insufficient)
			}
			if tc.pingPong && (tr.PingPong.Bounces != tc.bounces || tr.PingPong.Edge != tc.edge || !tr.PingPong.SameChannel) {
				t.Errorf("ping-pong = %+v", tr.PingPong)
			}
		})
	}
}

func TestFromRoamTrack(t *testing.T) {
	t.Parallel()
	m, _ := wireless.ParseMAC("5250-0012-0411")
	records := []wireless.RoamRecord{
		{CreatedAt: t0.Add(8 * time.Minute), APName: "ap1"},
		{CreatedAt: t0.Add(4 * time.Minute), APName: "ap2"},
		{CreatedAt: t0, APName: "ap1"},
	}
	tr := roam.DefaultParams().Analyze(roam.FromRoamTrack("ac1", m, records))
	if len(tr.Events) != 2 || tr.PingPong == nil || tr.PingPong.Bounces != 1 || tr.Insufficient {
		t.Errorf("track = %+v", tr)
	}
}
