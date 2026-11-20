package h3c_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/action"
	"github.com/gatework/wireless/vendors/h3c"
)

func TestVendor_Render(t *testing.T) {
	t.Parallel()
	mac, _ := wireless.ParseMAC("02:00:5e:10:00:01")
	tests := []struct {
		kind     action.Kind
		commands []string
		readback string
	}{
		{action.KindKick, []string{"reset wlan client mac-address 0200-5e10-0001"}, "display wlan client mac-address 0200-5e10-0001 verbose"},
		{action.KindBlock, []string{"system-view", "wlan static-blacklist mac-address 0200-5e10-0001", "return"}, h3c.CommandStaticBlacklist},
		{action.KindUnblock, []string{"system-view", "undo wlan static-blacklist mac-address 0200-5e10-0001", "return"}, h3c.CommandStaticBlacklist},
	}
	v := h3c.New(h3c.Options{})
	for _, tc := range tests {
		s, err := v.Render(tc.kind, mac)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Commands) != len(tc.commands) || s.Readback != tc.readback {
			t.Fatalf("%s: %+v", tc.kind, s)
		}
		for i := range s.Commands {
			if s.Commands[i] != tc.commands[i] {
				t.Errorf("%s command %d = %q, want %q", tc.kind, i, s.Commands[i], tc.commands[i])
			}
		}
	}
	if _, err := v.Render("reboot", mac); err == nil {
		t.Error("unknown kind rendered")
	}
}

func TestVendor_Observe(t *testing.T) {
	t.Parallel()
	v := h3c.New(h3c.Options{})
	present, _ := wireless.ParseMAC("0200-5e10-0001")
	absent, _ := wireless.ParseMAC("0200-5e10-00ff")
	body, err := os.ReadFile(filepath.Join("testdata", "clients.txt"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.Observe(action.KindKick, present, string(body))
	if err != nil || !s.Present || s.Online != time.Hour+33*time.Minute+43*time.Second || s.Digest == "" {
		t.Errorf("kick present: %+v %v", s, err)
	}
	if s, err := v.Observe(action.KindKick, absent, string(body)); err != nil || s.Present {
		t.Errorf("kick absent: %+v %v", s, err)
	}
	list := "MAC address      Duration\n0200-5e10-0001   permanent\n"
	if s, err := v.Observe(action.KindBlock, present, list); err != nil || !s.Present {
		t.Errorf("blacklisted: %+v %v", s, err)
	}
	if _, err := v.Observe(action.KindBlock, present, "                ^\n% Unrecognized command found at '^' position.\n"); err == nil {
		t.Error("rejected readback accepted")
	}
}
