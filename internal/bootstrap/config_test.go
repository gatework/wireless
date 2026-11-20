package bootstrap_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/wireless/internal/bootstrap"
)

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "wireless.yml"), `
snapshot: ~/snap
parallel: 4
timezone: Asia/Shanghai
controllers:
  - {host: 198.51.100.1, name: AC-A}
  - {host: 198.51.100.2, name: AC-B}
thresholds:
  echo_loss: 0.02
quality:
  slack: {signal: 10}
roaming:
  sticky_rssi: 22
history_days: 3
`, 0o600)
	write(t, filepath.Join(dir, ".env"), "NC_DEVICE_USERNAME=ops\nNC_DEVICE_PASSWORD=pw\n", 0o600)
	home := t.TempDir()
	cfg, err := bootstrap.Load(t.Context(), bootstrap.Options{ConfigPath: filepath.Join(dir, "wireless.yml"), Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Snapshot != filepath.Join(home, "snap") || cfg.Parallel != 4 || cfg.Models.Thresholds.EchoLoss != 0.02 ||
		cfg.Models.Roaming.StickyRSSI != 22 || cfg.Models.Roaming.Window == 0 || cfg.History != 72*time.Hour {
		t.Errorf("config = %+v", cfg)
	}
	if _, err := cfg.Dialer(t.Context()); err != nil {
		t.Errorf("dialer: %v", err)
	}
	targets, err := cfg.Targets(t.Context(), []string{"ac-b"})
	if err != nil || len(targets) != 1 || targets[0].Mgmt.String() != "198.51.100.2" {
		t.Errorf("targets = %+v %v", targets, err)
	}
	if _, err := cfg.Targets(t.Context(), []string{"203.0.113.0/24"}); !errors.Is(err, bootstrap.ErrNoTargets) {
		t.Errorf("no match err = %v", err)
	}
}

func TestLoad_rejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, config, env string
		envMode           os.FileMode
	}{
		{"unknown key", "snapshots: x\n", "", 0o600},
		{"world-readable credentials", "parallel: 1\n", "NC_DEVICE_PASSWORD=pw\n", 0o644},
		{"invalid thresholds", "thresholds: {echo_loss: 3}\n", "", 0o600},
		{"invalid roaming", "roaming: {burst: 1}\n", "", 0o600},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			write(t, filepath.Join(dir, "wireless.yml"), tc.config, 0o600)
			if tc.env != "" {
				write(t, filepath.Join(dir, ".env"), tc.env, tc.envMode)
				if err := os.Chmod(filepath.Join(dir, ".env"), tc.envMode); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := bootstrap.Load(t.Context(), bootstrap.Options{ConfigPath: filepath.Join(dir, "wireless.yml")}); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestDialer_requiresCredentials(t *testing.T) {
	t.Parallel()
	cfg, err := bootstrap.Load(t.Context(), bootstrap.Options{Environ: []string{"WIRELESS_CONFIG=" + filepath.Join(t.TempDir(), "none.yml")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Dialer(t.Context()); !errors.Is(err, bootstrap.ErrCredentials) {
		t.Errorf("err = %v", err)
	}
}
