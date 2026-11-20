package conflict_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/conflict"
)

func mac(s string) wireless.MAC {
	m, err := wireless.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func TestAnalyze(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	s := wireless.NewSnapshot(wireless.Controller{Host: "h"}, t0)
	var clients []wireless.Client
	for i := range 50 {
		clients = append(clients, wireless.Client{MAC: mac(fmt.Sprintf("0200-5e00-%04x", i)), IPv4: netip.AddrFrom4([4]byte{10, 158, 1, byte(i)})})
	}
	s.Clients, _ = evidence.NewObservation(wireless.DimensionClients, evidence.StatusComplete, time.Time{}, clients, nil, nil)
	rogue := netip.MustParseAddr("192.168.1.80")
	pair := netip.MustParseAddr("10.158.1.200")
	once := netip.MustParseAddr("10.158.1.201")
	var facts []wireless.IPConflict
	for i := range 4 {
		facts = append(facts, wireless.IPConflict{IP: rogue, NewMAC: mac(fmt.Sprintf("6879-c423-00%02x", i)), OldMAC: mac("6879-c423-00ff"), At: t0})
		facts = append(facts, wireless.IPConflict{IP: pair, NewMAC: mac("0200-5e00-0001"), OldMAC: mac("0200-5e00-0002"), At: t0})
	}
	facts = append(facts, wireless.IPConflict{IP: once, NewMAC: mac("0200-5e00-0003"), OldMAC: mac("0200-5e00-0004"), At: t0})
	s.Conflicts, _ = evidence.NewObservation(wireless.DimensionConflicts, evidence.StatusComplete, time.Time{}, facts, nil, nil)
	got := conflict.Analyze(s, time.Time{})
	want := map[netip.Addr]conflict.Pattern{rogue: conflict.PatternShared, pair: conflict.PatternPair, once: conflict.PatternSporadic}
	if len(got) != 3 {
		t.Fatalf("groups = %+v", got)
	}
	for _, g := range got {
		if g.Pattern != want[g.IP] {
			t.Errorf("%s: %s, want %s", g.IP, g.Pattern, want[g.IP])
		}
	}
	r := got[0]
	if r.IP != rogue || !r.Foreign || len(r.Batches) != 1 || r.Batches[0].OUI != "6879-c4" || r.Batches[0].Count != 5 {
		t.Errorf("rogue group = %+v", r)
	}
	if got[1].Foreign {
		t.Errorf("in-plan address flagged foreign: %+v", got[1])
	}
}
