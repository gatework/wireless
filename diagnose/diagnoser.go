package diagnose

import (
	"errors"
	"fmt"
	"slices"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/quality"
	"github.com/gatework/wireless/roam"
)

// Diagnoser explains one station layer by layer. It is immutable and safe
// for concurrent use.
type Diagnoser struct {
	t       Thresholds
	quality quality.Profile
	roaming roam.Params
	checks  []check
}

// check examines one aspect of a station and returns its findings.
type check func(d *Diagnoser, s *subject) []Finding

// subject is everything a check may consult about one station.
type subject struct {
	index    *wireless.Index
	view     *wireless.ClientView
	snapshot *wireless.Snapshot
	quality  quality.Score
	sticky   roam.Sticky
	track    *roam.Track
}

// Options configures a Diagnoser.
type Options struct {
	Thresholds Thresholds
	Quality    quality.Profile
	Roaming    roam.Params
}

// DefaultOptions returns the default models.
func DefaultOptions() Options {
	return Options{Thresholds: DefaultThresholds(), Quality: quality.DefaultProfile(), Roaming: roam.DefaultParams()}
}

// New returns a diagnoser after validating every model.
func New(o Options) (*Diagnoser, error) {
	if err := errors.Join(o.Thresholds.Validate(), o.Quality.Validate(), o.Roaming.Validate()); err != nil {
		return nil, fmt.Errorf("diagnose: %w", err)
	}
	return &Diagnoser{t: o.Thresholds, quality: o.Quality, roaming: o.Roaming, checks: []check{
		checkEvidence,
		checkAssociation, checkRoaming, checkTrack,
		checkQuality, checkPHY,
		checkAccess, checkVLAN,
		checkAddress, checkConflicts,
		checkBlocked,
		checkAP, checkPolicy,
	}}, nil
}

// Quality returns the diagnoser's quality model.
func (d *Diagnoser) Quality() quality.Profile { return d.quality }

// Roaming returns the diagnoser's roaming parameters.
func (d *Diagnoser) Roaming() roam.Params { return d.roaming }

// Client diagnoses a station found in ix. track is the station's roaming
// history, or nil when none was collected. Findings are ordered by layer,
// then by decreasing level.
func (d *Diagnoser) Client(ix *wireless.Index, v *wireless.ClientView, track *roam.Track) Report {
	s := &subject{index: ix, view: v, track: track}
	s.snapshot, _ = ix.Snapshot(v.Controller.Host)
	s.quality = d.quality.Assess(quality.InputOf(v))
	s.sticky = d.roaming.StickyTrack(ix, v, track)
	r := Report{
		Controller: v.Controller, MAC: v.Client.MAC, Signal: d.signal(v),
		Quality: s.quality, Sticky: s.sticky, Track: track, Findings: []Finding{},
	}
	for _, c := range d.checks {
		r.Findings = append(r.Findings, c(d, s)...)
	}
	order := Layers()
	slices.SortStableFunc(r.Findings, func(a, b Finding) int {
		if la, lb := slices.Index(order, a.Layer), slices.Index(order, b.Layer); la != lb {
			return la - lb
		}
		return int(b.Level) - int(a.Level)
	})
	for _, f := range r.Findings {
		r.Level = max(r.Level, f.Level)
	}
	return r
}

func (d *Diagnoser) signal(v *wireless.ClientView) Signal {
	s := Signal{RSSI: v.Client.RSSI}
	if v.Radio != nil {
		s.NoiseFloor, _ = v.Radio.Noise()
		s.ChannelUsage = v.Radio.Usage
	}
	s.DBm, s.Estimated = v.SignalDBm()
	return s
}

// Report is the diagnosis of one station.
type Report struct {
	Controller wireless.Controller `json:"controller"`
	MAC        wireless.MAC        `json:"mac"`
	Signal     Signal              `json:"signal"`
	Quality    quality.Score       `json:"quality"`
	Sticky     roam.Sticky         `json:"sticky"`
	Track      *roam.Track         `json:"track,omitempty"`
	// Level is the highest level among the findings.
	Level    Level     `json:"level"`
	Findings []Finding `json:"findings"`
}

// Signal summarizes the radio link.
type Signal struct {
	RSSI int `json:"rssi"`
	// DBm is the estimated signal strength; Estimated reports whether the
	// noise floor was known.
	DBm          int  `json:"dbm,omitempty"`
	Estimated    bool `json:"estimated"`
	NoiseFloor   int  `json:"noise_floor_dbm,omitempty"`
	ChannelUsage int  `json:"channel_usage_percent"`
}

// checkEvidence reports dimensions whose evidence is incomplete, because
// an absent record there does not mean "not present".
func checkEvidence(_ *Diagnoser, s *subject) []Finding {
	if s.snapshot == nil {
		return nil
	}
	var out []Finding
	cov := s.snapshot.Coverage()
	for _, dim := range []evidence.Dimension{
		wireless.DimensionClients, wireless.DimensionAccessPoints,
		wireless.DimensionDot1X, wireless.DimensionMAC, wireless.DimensionConfiguration,
	} {
		if st := cov.Status(dim); st != evidence.StatusComplete && st != evidence.StatusNotRequested {
			out = append(out, newFinding(LayerControl, LevelInfo, CodeEvidencePartial, dim))
		}
	}
	return out
}
