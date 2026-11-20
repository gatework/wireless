package quality

import (
	"fmt"
	"math"
	"strings"

	"github.com/gatework/wireless"
)

// Grade is the overall quality of a link.
type Grade uint8

// Grades from best to worst. GradeUnknown means the signal was not
// reported, so no score was computed.
const (
	GradeUnknown Grade = iota
	GradeExcellent
	GradeGood
	GradeFair
	GradePoor
)

var gradeNames = [...]string{GradeUnknown: "unknown", GradeExcellent: "excellent", GradeGood: "good", GradeFair: "fair", GradePoor: "poor"}

// String returns the grade name.
func (g Grade) String() string {
	if int(g) < len(gradeNames) {
		return gradeNames[g]
	}
	return fmt.Sprintf("Grade(%d)", uint8(g))
}

// Word returns the operator-facing word for the grade.
func (g Grade) Word() string {
	if int(g) < len(gradeWords) {
		return gradeWords[g]
	}
	return ""
}

// MarshalText encodes g as its name.
func (g Grade) MarshalText() ([]byte, error) { return []byte(g.String()), nil }

// Cause is the main reason a link is not excellent.
type Cause string

// Causes.
const (
	CauseNone         Cause = ""
	CauseWeakSignal   Cause = "weak_signal"
	CauseCongestion   Cause = "congestion"
	CauseInterference Cause = "interference"
	CauseNoise        Cause = "noise"
	CauseLegacyClient Cause = "legacy_client"
	CausePowerSave    Cause = "power_save"
	CauseLowRate      Cause = "low_rate"
)

// Word returns the operator-facing name of the cause.
func (c Cause) Word() string { return causeWords[c] }

// Advice returns what an operator should check for the cause.
func (c Cause) Advice() string { return causeAdvice[c] }

// Input is everything the model scores about one link. Zero values mean
// unknown and leave the factor out.
type Input struct {
	RSSI int
	// Rate is the best of the last Rx/Tx PHY rates in Mbps; MaxRate is
	// the link's theoretical rate.
	Rate, MaxRate float64
	Mode          string
	Streams       int
	// Usage is the serving radio's channel utilization percent; it counts
	// only when UsageKnown.
	Usage      int
	UsageKnown bool
	NoiseFloor int
	// Clients is the number of clients on the serving radio, and
	// Throughput their summed throughput in kbit/s.
	Clients    int
	Throughput float64
	PowerSave  bool
}

// InputOf gathers the input of a client view.
func InputOf(v *wireless.ClientView) Input {
	c := v.Client
	in := Input{
		RSSI: c.RSSI, Rate: max(c.RxRate, c.TxRate), Mode: c.Mode,
		Streams: Streams(c, v.Radio), Clients: v.RadioLoad.Clients,
		Throughput: v.RadioLoad.RxKbps + v.RadioLoad.TxKbps,
		PowerSave:  strings.EqualFold(c.Extra["SM power save"], "Enabled"),
	}
	in.MaxRate = MaxRate(c.Mode, c.Bandwidth, in.Streams)
	if r := v.Radio; r != nil {
		in.Usage, in.UsageKnown = r.Usage, r.Measured()
		in.NoiseFloor, _ = r.Noise()
	}
	return in
}

// Score is the assessment of one link.
type Score struct {
	// Total is 0–100; it is meaningful only when Grade is known.
	Total int   `json:"total"`
	Grade Grade `json:"grade"`
	// Factors holds the score of every factor that was measured.
	Factors map[Factor]int `json:"factors"`
	Cause   Cause          `json:"cause,omitempty"`
}

// Assess scores a link. A link whose RSSI is unknown is not scored.
func (p Profile) Assess(in Input) Score {
	if in.RSSI <= 0 {
		return Score{Factors: map[Factor]int{}}
	}
	factors := map[Factor]float64{FactorSignal: p.Signal.Score(float64(in.RSSI))}
	if in.Rate > 0 && in.MaxRate > 0 {
		factors[FactorEfficiency] = p.Efficiency.Score(in.Rate / in.MaxRate)
	}
	if in.UsageKnown {
		factors[FactorAirtime] = p.Airtime.Score(float64(in.Usage))
	}
	if in.NoiseFloor != 0 {
		factors[FactorNoise] = p.Noise.Score(float64(in.NoiseFloor))
	}
	if in.Clients > 0 {
		factors[FactorLoad] = p.Load.Score(float64(in.Clients))
	}
	var sum, weights float64
	limit := 100.0
	for f, s := range factors {
		sum += s * p.Weights[f]
		weights += p.Weights[f]
		limit = min(limit, s+p.Slack[f])
	}
	total := min(sum/weights, limit)
	out := Score{Total: int(math.Round(total)), Factors: make(map[Factor]int, len(factors))}
	for f, s := range factors {
		out.Factors[f] = int(math.Round(s))
	}
	out.Grade = p.grade(out.Total)
	if out.Grade != GradeExcellent {
		out.Cause = p.cause(in, factors)
	}
	return out
}

func (p Profile) grade(total int) Grade {
	switch {
	case total >= p.Excellent:
		return GradeExcellent
	case total >= p.Good:
		return GradeGood
	case total >= p.Fair:
		return GradeFair
	}
	return GradePoor
}

// cause picks the weakest poor factor and interprets it in context:
//
//   - busy airtime with many clients is congestion, with few it is
//     interference — the air is busy but not with this radio's traffic;
//   - low efficiency on a good, quiet link is a legacy client, power
//     save, or otherwise an unexplained low rate (often retries).
func (p Profile) cause(in Input, factors map[Factor]float64) Cause {
	weakest, low := Factor(""), p.Poor
	for _, f := range Factors() {
		if s, ok := factors[f]; ok && s < low {
			weakest, low = f, s
		}
	}
	switch weakest {
	case FactorSignal:
		return CauseWeakSignal
	case FactorAirtime:
		if in.Clients >= p.BusyClients {
			return CauseCongestion
		}
		return CauseInterference
	case FactorNoise:
		return CauseNoise
	case FactorLoad:
		return CauseCongestion
	case FactorEfficiency:
		switch {
		case Legacy(in.Mode) || generation(in.Mode) == phyHT && in.Streams == 1:
			return CauseLegacyClient
		case in.PowerSave:
			return CausePowerSave
		}
		return CauseLowRate
	}
	return CauseNone
}
