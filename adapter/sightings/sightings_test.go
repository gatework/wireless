package sightings_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/adapter/sightings"
	"github.com/gatework/wireless/roam"
)

func TestJournal(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	j := sightings.Open(root, 48*time.Hour, func() time.Time { return now })
	m, _ := wireless.ParseMAC("0200-5e10-0001")
	other, _ := wireless.ParseMAC("0200-5e10-0002")
	old := roam.Observation{At: now.AddDate(0, 0, -5), MAC: m, AP: "old"}
	if err := j.Append(t.Context(), []roam.Observation{old}); err != nil {
		t.Fatal(err)
	}
	obs := []roam.Observation{
		{At: now.Add(-time.Hour), Host: "198.51.100.1", MAC: m, AP: "A", RSSI: 30},
		{At: now, Host: "198.51.100.1", MAC: m, AP: "B", RSSI: 22},
		{At: now, Host: "198.51.100.1", MAC: other, AP: "B"},
	}
	if err := j.Append(t.Context(), obs); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "journal", "2026-11-14.jsonl")); !os.IsNotExist(err) {
		t.Errorf("expired day kept: %v", err)
	}
	got, err := j.Read(t.Context(), now.Add(-2*time.Hour), func(o roam.Observation) bool { return o.MAC == m })
	if err != nil || len(got) != 2 || got[1].AP != "B" || got[1].RSSI != 22 {
		t.Fatalf("read = %+v, %v", got, err)
	}
}
