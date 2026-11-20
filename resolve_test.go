package wireless_test

import (
	"testing"

	"github.com/gatework/wireless"
)

func TestIndex_Resolve(t *testing.T) {
	t.Parallel()
	ix := fleet()
	tests := []struct {
		query      string
		actionable []string
		hints      int
	}{
		{"192.0.2.10", []string{"0200-5e10-0001"}, 1},
		{"alice", []string{"0200-5e10-0001"}, 0},
		{"ali", nil, 0}, // substrings never resolve for actions
		{"bob", []string{"0200-5e10-0099"}, 0},
		{"0200-5e10-00aa", []string{"0200-5e10-00aa"}, 0}, // not seen, still blockable
		{"10-000*", nil, 0},
		{"*10-0001", []string{"0200-5e10-0001"}, 0},
	}
	for _, tc := range tests {
		q, _ := wireless.ParseQuery(tc.query)
		all := ix.Resolve(q)
		act := wireless.Actionable(all)
		var got []string
		for _, a := range act {
			got = append(got, a.MAC.H3C())
		}
		if len(got) != len(tc.actionable) || len(all)-len(act) != tc.hints {
			t.Errorf("Resolve(%q) = %v (+%d hints), want %v (+%d)", tc.query, got, len(all)-len(act), tc.actionable, tc.hints)
			continue
		}
		for i := range got {
			if got[i] != tc.actionable[i] {
				t.Errorf("Resolve(%q)[%d] = %s, want %s", tc.query, i, got[i], tc.actionable[i])
			}
		}
	}
	q, _ := wireless.ParseQuery("0200-5e10-0001")
	if r := ix.Resolve(q); len(r[0].Online) != 2 {
		t.Errorf("online controllers = %v", r[0].Online)
	}
}
