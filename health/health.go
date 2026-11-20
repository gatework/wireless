package health

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/quality"
	"github.com/gatework/wireless/roam"
)

// Controller is the model one rule run sees: one controller's snapshot and
// the fleet index for cross-controller checks.
type Controller struct {
	Snapshot *wireless.Snapshot
	Index    *wireless.Index
	// Quality and Roaming are the models the RF rules apply.
	Quality quality.Profile
	Roaming roam.Params
	// Tracks are the analyzed sighting histories of the fleet, or nil.
	Tracks []roam.Track
}

func (c Controller) subject() assess.Subject {
	return assess.NewSubject("controller", c.Snapshot.Controller.Label())
}

func (c Controller) ap(name string) assess.Subject { return c.subject().Child("ap", name) }

func (c Controller) client(m wireless.MAC) assess.Subject {
	return c.subject().Child("client", m.H3C())
}

// Inspector runs the fleet health catalog.
type Inspector struct {
	engine  *assess.Engine[Controller]
	quality quality.Profile
	roaming roam.Params
}

// Options are the models the inspector's RF rules use.
type Options struct {
	Quality quality.Profile
	Roaming roam.Params
}

// New returns an inspector under policy. verify resolves the commands that
// re-check a finding and may be nil.
func New(policy assess.Policy, verify assess.VerifyCommands, o Options) (*Inspector, error) {
	if err := errors.Join(o.Quality.Validate(), o.Roaming.Validate()); err != nil {
		return nil, fmt.Errorf("health: %w", err)
	}
	catalog, err := Catalog()
	if err != nil {
		return nil, err
	}
	engine, err := assess.NewEngine(catalog, policy, assess.Options{Verify: verify})
	if err != nil {
		return nil, fmt.Errorf("health: %w", err)
	}
	return &Inspector{engine: engine, quality: o.Quality, roaming: o.Roaming}, nil
}

// Catalog returns the rule catalog.
func Catalog() (*assess.Catalog[Controller], error) {
	c, err := assess.NewCatalog(append(rules(), rfRules()...)...)
	if err != nil {
		return nil, fmt.Errorf("health: %w", err)
	}
	return c, nil
}

// Report is the assessment of every controller.
type Report struct {
	Controllers []ControllerReport `json:"controllers"`
}

// ControllerReport is one controller's assessment.
type ControllerReport struct {
	Controller wireless.Controller `json:"controller"`
	Assessment assess.Assessment   `json:"assessment"`
}

// Findings returns every finding across controllers, most severe first.
func (r Report) Findings() []assess.Finding {
	var out []assess.Finding
	for _, c := range r.Controllers {
		out = append(out, c.Assessment.Findings...)
	}
	slices.SortStableFunc(out, func(a, b assess.Finding) int { return cmp.Compare(b.Severity, a.Severity) })
	return out
}

// Run assesses each indexed controller. Each controller's evidence gates
// its own rules, so one partial controller does not silence the others.
// tracks is the analyzed sighting history; nil skips the roaming rules.
func (in *Inspector) Run(ctx context.Context, ix *wireless.Index, tracks []roam.Track) (Report, error) {
	var r Report
	for _, s := range ix.Snapshots() {
		cov := s.Coverage().With(DimensionRoaming, evidence.StatusNotRequested)
		if tracks != nil {
			cov = cov.With(DimensionRoaming, evidence.StatusComplete)
		}
		model := Controller{Snapshot: s, Index: ix, Quality: in.quality, Roaming: in.roaming, Tracks: tracks}
		a, err := in.engine.Run(ctx, model, cov)
		r.Controllers = append(r.Controllers, ControllerReport{Controller: s.Controller, Assessment: a})
		if err != nil {
			return r, fmt.Errorf("health: %w", err)
		}
	}
	return r, nil
}

func slicesSortByName(ts []wireless.ServiceTemplate) {
	slices.SortFunc(ts, func(a, b wireless.ServiceTemplate) int { return cmp.Compare(a.Name, b.Name) })
}
