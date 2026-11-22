package bootstrap

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/event"
	"github.com/gatework/netops/job"
	"github.com/gatework/netops/notify"
	"github.com/gatework/netops/secret"
	"github.com/gatework/netops/store/runs"
)

// MinWatchInterval keeps watch from hammering controllers.
const MinWatchInterval = 30 * time.Second

// Watch is the configuration of wireless watch.
type Watch struct {
	// Interval is the client sampling period.
	Interval time.Duration
	// Sweep, when set, also collects every dimension on this schedule, so
	// that health and configuration evidence stay fresh.
	Sweep *job.Spec
	// EventFile receives every event as JSON Lines; empty disables it.
	EventFile string
	// Webhook, when set, receives events at or above WebhookMinSeverity,
	// signed with $WIRELESS_WEBHOOK_SECRET.
	Webhook            string
	WebhookMinSeverity assess.Severity
}

func watchConfig(f watchFile, loc *time.Location, data, home string) (Watch, error) {
	w := Watch{Interval: f.Interval, Webhook: f.Events.Webhook, WebhookMinSeverity: assess.SeverityMedium}
	if w.Interval == 0 {
		w.Interval = 2 * time.Minute
	}
	if w.Interval < MinWatchInterval {
		return Watch{}, fmt.Errorf("%w: watch.interval must be at least %s", ErrConfig, MinWatchInterval)
	}
	if f.Sweep != "" {
		s, err := job.ParseSpec(f.Sweep, loc)
		if err != nil {
			return Watch{}, fmt.Errorf("%w: watch.sweep: %w", ErrConfig, err)
		}
		w.Sweep = &s
	}
	switch f.Events.File {
	case "-":
	case "":
		w.EventFile = filepath.Join(data, "events.jsonl")
	default:
		w.EventFile = resolve(f.Events.File, home)
	}
	if f.Events.MinSeverity != "" {
		s, err := assess.ParseSeverity(f.Events.MinSeverity)
		if err != nil {
			return Watch{}, fmt.Errorf("%w: watch.events.min_severity: %w", ErrConfig, err)
		}
		w.WebhookMinSeverity = s
	}
	return w, nil
}

// Events builds the event bus of watch: the JSON Lines log and, when
// configured, the signed webhook.
func (c *Config) Events() (*event.Bus, error) {
	var routes []event.Route
	if c.Watch.EventFile != "" {
		f, err := notify.NewFile(c.Watch.EventFile)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: events: %w", err)
		}
		routes = append(routes, event.Route{Name: "file", Sink: f})
	}
	if c.Watch.Webhook != "" {
		wh, err := notify.NewWebhook(notify.WebhookOptions{URL: c.Watch.Webhook, Secret: secret.New(c.env["WIRELESS_WEBHOOK_SECRET"])})
		if err != nil {
			return nil, fmt.Errorf("%w: watch.events.webhook: %w", ErrConfig, err)
		}
		routes = append(routes, event.Route{Name: "webhook", Sink: wh, Filter: event.Filter{MinSeverity: c.Watch.WebhookMinSeverity}})
	}
	bus, err := event.NewBus(routes...)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: events: %w", err)
	}
	return bus, nil
}

// Runs opens the run history of scheduled jobs.
func (c *Config) Runs() (*runs.History, error) {
	h, err := runs.Open(filepath.Join(c.DataDir, "runs"), 0)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: runs: %w", err)
	}
	return h, nil
}
