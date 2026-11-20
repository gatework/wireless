package quality

import "fmt"

// Factor is one dimension of link quality.
type Factor string

// Factors in report order.
const (
	FactorSignal     Factor = "signal"
	FactorEfficiency Factor = "efficiency"
	FactorAirtime    Factor = "airtime"
	FactorNoise      Factor = "noise"
	FactorLoad       Factor = "load"
)

// Factors returns every factor in report order.
func Factors() []Factor {
	return []Factor{FactorSignal, FactorEfficiency, FactorAirtime, FactorNoise, FactorLoad}
}

// Profile is the scoring model. Each factor maps a measurement to 0–100
// through a curve; the total is a weighted mean limited by the weakest
// factor, so one severe problem is never averaged away.
type Profile struct {
	// Signal scores RSSI (dB above the noise floor).
	Signal Curve `yaml:"signal" json:"signal"`
	// Efficiency scores the best of Rx/Tx rate as a fraction of the
	// link's theoretical PHY rate.
	Efficiency Curve `yaml:"efficiency" json:"efficiency"`
	// Airtime scores the serving radio's channel utilization percent.
	Airtime Curve `yaml:"airtime" json:"airtime"`
	// Noise scores the radio noise floor in dBm.
	Noise Curve `yaml:"noise" json:"noise"`
	// Load scores the number of clients on the serving radio.
	Load Curve `yaml:"load" json:"load"`

	Weights map[Factor]float64 `yaml:"weights" json:"weights"`
	// Slack caps the total at each factor's score plus its slack, so a
	// poor factor limits the grade however good the others are. Signal
	// has the tightest slack: nothing compensates for a link that barely
	// reaches the AP.
	Slack map[Factor]float64 `yaml:"slack" json:"slack"`
	// Excellent, Good and Fair are the lower bounds of each grade.
	Excellent int `yaml:"excellent" json:"excellent"`
	Good      int `yaml:"good" json:"good"`
	Fair      int `yaml:"fair" json:"fair"`
	// Poor is the factor score below which a factor is a cause.
	Poor float64 `yaml:"poor" json:"poor"`
	// BusyClients is the client count above which a busy channel is
	// attributed to the radio's own clients (congestion) rather than to
	// interference.
	BusyClients int `yaml:"busy_clients" json:"busy_clients"`
}

// DefaultProfile returns the field-tested model.
func DefaultProfile() Profile {
	return Profile{
		Signal:     Curve{{10, 0}, {15, 25}, {20, 45}, {25, 65}, {35, 90}, {40, 100}},
		Efficiency: Curve{{0.05, 10}, {0.15, 40}, {0.3, 70}, {0.6, 100}},
		Airtime:    Curve{{30, 100}, {50, 80}, {70, 50}, {90, 10}},
		Noise:      Curve{{-90, 100}, {-85, 85}, {-80, 60}, {-75, 30}, {-70, 10}},
		Load:       Curve{{15, 100}, {30, 70}, {50, 40}},
		Weights: map[Factor]float64{
			FactorSignal: 0.40, FactorEfficiency: 0.20, FactorAirtime: 0.20, FactorNoise: 0.10, FactorLoad: 0.10,
		},
		Slack: map[Factor]float64{
			FactorSignal: 15, FactorEfficiency: 40, FactorAirtime: 30, FactorNoise: 40, FactorLoad: 40,
		},
		Excellent: 80, Good: 60, Fair: 40, Poor: 50, BusyClients: 20,
	}
}

// Validate checks every curve, positive weights for every factor and
// ordered grade bounds.
func (p Profile) Validate() error {
	for _, f := range Factors() {
		if err := p.curve(f).Validate(); err != nil {
			return fmt.Errorf("%w: %s curve", ErrInvalidProfile, f)
		}
		if p.Weights[f] <= 0 || p.Slack[f] < 0 {
			return fmt.Errorf("%w: %s weight or slack", ErrInvalidProfile, f)
		}
	}
	if p.Excellent <= p.Good || p.Good <= p.Fair || p.Fair <= 0 || p.Poor <= 0 || p.BusyClients <= 0 {
		return fmt.Errorf("%w: bounds", ErrInvalidProfile)
	}
	return nil
}

func (p Profile) curve(f Factor) Curve {
	switch f {
	case FactorSignal:
		return p.Signal
	case FactorEfficiency:
		return p.Efficiency
	case FactorAirtime:
		return p.Airtime
	case FactorNoise:
		return p.Noise
	case FactorLoad:
		return p.Load
	}
	return nil
}
