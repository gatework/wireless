package wireless_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
)

func mac(s string) wireless.MAC {
	m, err := wireless.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func observation[T any](d evidence.Dimension, facts ...T) evidence.Observation[T] {
	o, err := evidence.NewObservation(d, evidence.StatusComplete, time.Time{}, facts, nil, nil)
	if err != nil {
		panic(err)
	}
	return o
}

// fleet is two controllers sharing one roaming station.
func fleet() *wireless.Index {
	at := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	a := wireless.NewSnapshot(wireless.Controller{Host: "198.51.100.1", Name: "AC-A"}, at)
	a.Clients = observation(wireless.DimensionClients,
		wireless.Client{MAC: mac("0200-5e10-0001"), IPv4: netip.MustParseAddr("192.0.2.10"), Username: "alice", APName: "AP-1", RadioID: 1, SSID: "Corp", AKM: "802.1x", UserAuth: "802.1x"},
		wireless.Client{MAC: mac("0200-5e10-0002"), IPv4: netip.MustParseAddr("192.0.2.11"), APName: "AP-1", RadioID: 2, SSID: "Guest", UserAuth: "mac"},
	)
	a.Dot1X = observation(wireless.DimensionDot1X,
		wireless.AuthSession{Kind: wireless.AuthDot1X, MAC: mac("0200-5e10-0001"), Username: "alice"},
		wireless.AuthSession{Kind: wireless.AuthDot1X, MAC: mac("0200-5e10-0099"), Username: "bob", IPv4: netip.MustParseAddr("192.0.2.99")},
	)
	a.AccessPoints = observation(wireless.DimensionAccessPoints, wireless.AccessPoint{
		Name: "AP-1", State: wireless.APRun, IP: netip.MustParseAddr("198.51.100.21"), MAC: mac("0200-5e20-0010"),
		Radios: []wireless.Radio{{ID: 1, BSSID: mac("0200-5e20-0011"), Up: true, NoiseFloor: -95}, {ID: 2, Up: true}},
	})
	a.Configuration = observation(wireless.DimensionConfiguration, wireless.Configuration{
		Templates: map[string]wireless.ServiceTemplate{
			"guest": {Name: "guest", SSID: "Guest", Enabled: true, ClientSecurity: "mac", Portal: true, PortalDomain: "p"},
		},
	})
	a.Conflicts = observation(wireless.DimensionConflicts, wireless.IPConflict{IP: netip.MustParseAddr("192.0.2.10"), NewMAC: mac("0200-5e10-0001"), OldMAC: mac("0200-5e10-0003")})

	b := wireless.NewSnapshot(wireless.Controller{Host: "198.51.100.2", Name: "AC-B"}, at)
	b.Clients = observation(wireless.DimensionClients,
		wireless.Client{MAC: mac("0200-5e10-0001"), APName: "AP-9", SSID: "Corp"},
	)
	return wireless.NewIndex(a, b)
}

func find(t *testing.T, ix *wireless.Index, text string) wireless.Result {
	t.Helper()
	q, err := wireless.ParseQuery(text)
	if err != nil {
		t.Fatal(err)
	}
	return ix.Find(q)
}

func TestIndex_Find(t *testing.T) {
	t.Parallel()
	ix := fleet()
	tests := []struct {
		query                         string
		clients, sessions, aps, confl int
	}{
		{"192.0.2.10", 1, 0, 0, 1},
		{"192.0.2.0/24", 2, 1, 0, 1},
		{"0200-5e10-0001", 2, 0, 0, 1},
		{"10-0001", 2, 0, 0, 1},
		{"alice", 1, 0, 0, 0},
		{"BOB", 0, 1, 0, 0},
		{"ap-1", 0, 0, 1, 0},
		{"198.51.100.21", 0, 0, 1, 0},
		{"0200-5e20-0011", 0, 0, 1, 0},
		{"nobody", 0, 0, 0, 0},
	}
	for _, tc := range tests {
		r := find(t, ix, tc.query)
		got := []int{len(r.Clients), len(r.Sessions), len(r.APs), len(r.Conflicts)}
		want := []int{tc.clients, tc.sessions, tc.aps, tc.confl}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("Find(%q) = clients/sessions/aps/conflicts %v, want %v", tc.query, got, want)
		}
	}
}

func TestIndex_clientView(t *testing.T) {
	t.Parallel()
	ix := fleet()
	r := find(t, ix, "192.0.2.10")
	v := r.Clients[0]
	if v.Controller.Name != "AC-A" || v.AP == nil || v.Radio == nil || v.Radio.NoiseFloor != -95 {
		t.Fatalf("view = %+v", v)
	}
	if s, ok := v.Session(); !ok || s.Username != "alice" {
		t.Errorf("session = %+v", s)
	}
	if len(v.Elsewhere) != 1 || v.Elsewhere[0].Name != "AC-B" {
		t.Errorf("elsewhere = %+v", v.Elsewhere)
	}
	if len(v.Conflicts) != 1 || v.Access != wireless.AccessDot1X {
		t.Errorf("conflicts %d access %v", len(v.Conflicts), v.Access)
	}
	guest := find(t, ix, "192.0.2.11").Clients[0]
	if guest.Access != wireless.AccessMACPortal || guest.Template == nil {
		t.Errorf("portal access from template = %v", guest.Access)
	}
	if got := ix.Controllers(mac("0200-5e10-0001")); len(got) != 2 {
		t.Errorf("controllers = %v", got)
	}
}

func TestParseQuery(t *testing.T) {
	t.Parallel()
	if _, err := wireless.ParseQuery("  "); err == nil {
		t.Error("empty query accepted")
	}
	q, _ := wireless.ParseQuery("18620346")
	if !q.Textual() || !q.MatchName("18620346") || !q.MatchMAC(mac("0018-6203-4600")) {
		t.Error("numeric text should match both usernames and MAC fragments")
	}
}
