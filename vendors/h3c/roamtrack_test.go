package h3c_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/wireless"
	"github.com/gatework/wireless/vendors/h3c"
)

func TestVendor_RoamTrack(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(filepath.Join("testdata", "roamtrack.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := wireless.ParseMAC("5250-0012-0411")
	v := h3c.New(h3c.Options{})
	got, err := v.RoamTrack(t.Context(), capture.Output{Command: h3c.RoamTrackCommand(m), Raw: string(body)})
	if err != nil || len(got) != 2 {
		t.Fatalf("records = %+v, %v", got, err)
	}
	first := got[0] // oldest first
	if first.APName != "ap2" || first.RadioID != 2 || first.AC != netip.MustParseAddr("127.0.0.1") ||
		first.Online != 40*time.Minute+46*time.Second || !first.CreatedAt.Equal(time.Date(2016, 6, 14, 11, 12, 5, 0, time.UTC)) {
		t.Errorf("first = %+v", first)
	}
	if got[1].BSSID.H3C() != "3ce5-a68d-2280" {
		t.Errorf("second = %+v", got[1])
	}
	legacy := " BSSID          Online-time(d:h:m:s) AC-IP-address\n 000f-e25d-f3e0 0000:00:02:44        202.0.0.101\n 000f-e26c-2805 0000:00:02:11        -HOME AC-\n"
	old, err := v.RoamTrack(t.Context(), capture.Output{Raw: legacy})
	if err != nil || len(old) != 2 || old[1].Online != 2*time.Minute+44*time.Second || old[0].AC.IsValid() {
		t.Errorf("legacy = %+v, %v", old, err)
	}
	if r, err := v.RoamTrack(t.Context(), capture.Output{Raw: "Total entries: 0\n"}); err != nil || len(r) != 0 {
		t.Errorf("empty = %+v %v", r, err)
	}
	if _, err := v.RoamTrack(t.Context(), capture.Output{Raw: "% Unrecognized command found at '^' position.\n"}); err == nil {
		t.Error("rejection accepted")
	}
}
