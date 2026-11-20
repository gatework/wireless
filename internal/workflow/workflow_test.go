package workflow_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gatework/netops/apply"
	"github.com/gatework/netops/batch"
	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/change"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/failure"
	"github.com/gatework/netops/ops"
	"github.com/gatework/netops/store/snapshot"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/action"
	"github.com/gatework/wireless/internal/workflow"
	"github.com/gatework/wireless/roam"
	"github.com/gatework/wireless/vendors/h3c"
)

var t0 = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

// controller is a fake H3C controller: fixture answers and a static
// blacklist.
type controller struct {
	mu          sync.Mutex
	answers     map[string]string
	blacklist   []string
	writes      []string
	unreachable bool
}

func newController(t *testing.T) *controller {
	t.Helper()
	c := &controller{answers: map[string]string{}}
	body, err := os.ReadFile(filepath.Join("..", "..", "vendors", "h3c", "testdata", "clients.txt"))
	if err != nil {
		t.Fatal(err)
	}
	c.answers[h3c.CommandClients] = string(body)
	return c
}

type dialer struct {
	mu    sync.Mutex
	acs   map[netip.Addr]*controller
	opens int
}

func (f *dialer) CanConnect(context.Context, device.Device) bool { return true }

func (f *dialer) Open(ctx context.Context, d device.Device, fn func(context.Context, ops.Session) error) (error, error) {
	f.mu.Lock()
	f.opens++
	c := f.acs[d.Mgmt]
	f.mu.Unlock()
	if c == nil || c.unreachable {
		return failure.New(failure.CodeUnreachable, "fake"), nil
	}
	return fn(ctx, session{c: c}), nil
}

type session struct{ c *controller }

func (s session) Collect(_ context.Context, commands []string) (capture.Capture, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	out := capture.Capture{Prompt: "<AC-1>"}
	for _, cmd := range commands {
		o := capture.Output{Command: cmd, RecordedAt: t0, Prompt: "<AC-1>"}
		switch body, ok := s.c.answers[cmd]; {
		case cmd == h3c.CommandStaticBlacklist:
			o.Raw = cmd + "\n" + strings.Join(s.c.blacklist, "\n") + "\n<AC-1>"
		case ok:
			o.Raw = body // fixtures carry their own echo and prompt
		default:
			o.Failure = failure.CodeRejected
		}
		out.Outputs = append(out.Outputs, o)
	}
	return out, nil
}

func (s session) Write(_ context.Context, cmd change.Command) error {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	s.c.writes = append(s.c.writes, cmd.Text)
	if m, ok := strings.CutPrefix(cmd.Text, "wlan static-blacklist mac-address "); ok {
		s.c.blacklist = append(s.c.blacklist, m)
	}
	return nil
}

func (session) Save(context.Context) error { return nil }
func (session) CanCheckpoint() bool        { return false }
func (session) Checkpoint(context.Context, string) error {
	return failure.New(failure.CodeUnsupported, "fake")
}
func (session) Rollback(context.Context, string) error {
	return failure.New(failure.CodeUnsupported, "fake")
}

type recorder struct {
	mu  sync.Mutex
	obs []roam.Observation
}

func (r *recorder) Append(_ context.Context, obs []roam.Observation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.obs = append(r.obs, obs...)
	return nil
}

func acs(n int) []device.Device {
	out := make([]device.Device, n)
	for i := range n {
		a := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})
		out[i] = device.Device{ID: a.String(), Mgmt: a, Platform: h3c.Platform}
	}
	return out
}

func TestCollectAndRefresh(t *testing.T) {
	t.Parallel()
	targets := acs(2)
	f := &dialer{acs: map[netip.Addr]*controller{targets[0].Mgmt: newController(t), targets[1].Mgmt: {unreachable: true}}}
	st, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	dims := []evidence.Dimension{wireless.DimensionClients}
	res, err := workflow.Collect(t.Context(), workflow.CollectRequest{
		Targets: targets, Dimensions: dims, Vendor: h3c.New(h3c.Options{}), Dialer: f, Store: st, Sightings: rec,
		Now: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Counts[batch.StateSucceeded] != 1 || res.Summary.Counts[batch.StateFailed] != 1 {
		t.Errorf("summary %+v", res.Summary.Counts)
	}
	if ds := res.Dimensions[targets[0].ID][wireless.DimensionClients]; ds.Facts != 2 || ds.Status != evidence.StatusComplete {
		t.Errorf("dimension summary %+v", ds)
	}
	if len(rec.obs) != 2 {
		t.Errorf("sightings %d", len(rec.obs))
	}
	opens := f.opens
	p := workflow.DefaultPolicy()
	caps, fresh, err := workflow.Refresh(t.Context(), workflow.RefreshRequest{
		Targets: targets[:1], Dimensions: dims, Vendor: h3c.New(h3c.Options{}), Dialer: f, Cache: st, Policy: p,
		Now: func() time.Time { return t0.Add(time.Minute) },
	})
	if err != nil || len(caps) != 1 || f.opens != opens {
		t.Fatalf("refresh within TTL: %d captures, %d opens, %v", len(caps), f.opens-opens, err)
	}
	if len(fresh.Controllers) != 1 || fresh.Controllers[0].Host != "198.51.100.1" || len(fresh.Controllers[0].Stale) != 0 {
		t.Errorf("freshness %+v", fresh.Controllers)
	}
}

func TestApply_roundsPerController(t *testing.T) {
	t.Parallel()
	targets := acs(1)
	ac := newController(t)
	f := &dialer{acs: map[netip.Addr]*controller{targets[0].Mgmt: ac}}
	meta := change.Meta{ID: "block", Created: t0}
	var plans []*change.Plan[action.State]
	for i, s := range []string{"0200-5e10-0001", "0200-5e10-0002"} {
		m, _ := wireless.ParseMAC(s)
		meta.ID = "block-" + string(rune('a'+i))
		ps, err := action.Batch(meta, action.KindBlock, m, targets, nil, h3c.New(h3c.Options{}))
		if err != nil {
			t.Fatal(err)
		}
		plans = append(plans, ps...)
	}
	j := &journal{}
	outcomes, err := workflow.Apply(t.Context(), workflow.ApplyRequest{
		Plans: plans, Renderer: h3c.New(h3c.Options{}), Dialer: f,
		Journal: func(*change.Plan[action.State]) apply.Journal { return j },
		Now:     func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 2 || !outcomes[0].Succeeded() || !outcomes[1].Succeeded() {
		t.Fatalf("outcomes %+v", outcomes)
	}
	if f.opens != 2 || len(ac.blacklist) != 2 || !slices.Contains(ac.writes, "system-view") {
		t.Errorf("opens %d blacklist %v", f.opens, ac.blacklist)
	}
}

type journal struct {
	mu sync.Mutex
	n  int
}

func (j *journal) Write(context.Context, apply.Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.n++
	return nil
}
