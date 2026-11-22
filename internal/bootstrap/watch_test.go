package bootstrap_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/event"

	"github.com/gatework/wireless/internal/bootstrap"
)

func TestLoad_watch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "wireless.yml"), `
timezone: Asia/Shanghai
watch:
  interval: 1m
  sweep: "0 */6 * * *"
  events:
    webhook: https://hooks.example/wireless
    min_severity: high
`, 0o600)
	home := t.TempDir()
	cfg, err := bootstrap.Load(t.Context(), bootstrap.Options{ConfigPath: filepath.Join(dir, "wireless.yml"), Home: home})
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.Watch
	if w.Interval != time.Minute || w.Sweep == nil || w.WebhookMinSeverity != assess.SeverityHigh {
		t.Fatalf("watch = %+v", w)
	}
	if want := filepath.Join(cfg.DataDir, "events.jsonl"); w.EventFile != want {
		t.Errorf("event file %q, want %q", w.EventFile, want)
	}
	bus, err := cfg.Events()
	if err != nil {
		t.Fatal(err)
	}
	e, _ := event.New(event.Event{Kind: event.KindCollectFailed, Severity: assess.SeverityLow, At: time.Now(), Summary: "x"})
	if err := bus.Publish(context.Background(), e); err != nil {
		t.Errorf("low event reached the high-only webhook: %v", err)
	}
	if body, err := os.ReadFile(w.EventFile); err != nil || len(body) == 0 {
		t.Errorf("event log %v", err)
	}
	if _, err := cfg.Runs(); err != nil {
		t.Error(err)
	}
}

func TestLoad_watchRejects(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"fast interval": "watch: {interval: 5s}\n",
		"bad sweep":     "watch: {sweep: \"every hour\"}\n",
		"bad severity":  "watch: {events: {min_severity: loud}}\n",
	} {
		dir := t.TempDir()
		write(t, filepath.Join(dir, "wireless.yml"), body, 0o600)
		if _, err := bootstrap.Load(t.Context(), bootstrap.Options{ConfigPath: filepath.Join(dir, "wireless.yml"), Home: t.TempDir()}); !errors.Is(err, bootstrap.ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
