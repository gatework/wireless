package h3c_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/store/snapshot"

	"github.com/gatework/wireless/vendors/h3c"
)

// TestPrivateCorpus decodes real controller snapshots kept outside the
// repository. It runs only when WIRELESS_CORPUS names a snapshot root and
// prints aggregates only, never device output.
func TestPrivateCorpus(t *testing.T) {
	root := os.Getenv("WIRELESS_CORPUS")
	if root == "" {
		t.Skip("WIRELESS_CORPUS not set")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var captures []capture.Capture
	for _, e := range entries {
		if _, err := netip.ParseAddr(e.Name()); err != nil || !e.IsDir() {
			continue
		}
		c, err := snapshot.ReadDir(t.Context(), filepath.Join(root, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		captures = append(captures, c)
	}
	if len(captures) == 0 {
		t.Fatal("no controllers in corpus")
	}
	v := h3c.New(h3c.Options{})
	for _, c := range captures {
		s := v.Decode(c)
		cov := s.Coverage()
		for _, dim := range cov.Dimensions() {
			if status := cov.Status(dim); status != evidence.StatusComplete {
				t.Errorf("%s %s: %s", c.Host, dim, status)
			}
		}
		for _, issues := range [][]evidence.Issue{s.Clients.Issues, s.AccessPoints.Issues, s.BSS.Issues, s.Dot1X.Issues, s.MAC.Issues, s.Conflicts.Issues} {
			for _, i := range issues {
				if i.Code != "count_drift" {
					line := 0
					if i.Source != nil {
						line = i.Source.Line
					}
					t.Errorf("%s: issue %s at line %d", c.Host, i.Code, line)
				}
			}
		}
		cfg, ok := s.Config()
		if !ok || len(cfg.Groups) == 0 {
			t.Errorf("%s: no AP group policy parsed", c.Host)
		}
		t.Logf("%s: groups %d", c.Host, len(cfg.Groups))
		t.Logf("%s: clients %d aps %d bss %d dot1x %d mac %d conflicts %d", s.Controller.Label(),
			len(s.Clients.Facts), len(s.AccessPoints.Facts), len(s.BSS.Facts), len(s.Dot1X.Facts), len(s.MAC.Facts), len(s.Conflicts.Facts))
	}
}
