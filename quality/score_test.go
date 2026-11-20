package quality_test

import (
	"testing"

	"github.com/gatework/wireless/quality"
)

func TestCurve_Score(t *testing.T) {
	t.Parallel()
	c := quality.Curve{{10, 0}, {20, 50}, {40, 100}}
	tests := map[float64]float64{0: 0, 10: 0, 15: 25, 20: 50, 30: 75, 40: 100, 99: 100}
	for in, want := range tests {
		if got := c.Score(in); got != want {
			t.Errorf("Score(%v) = %v, want %v", in, got, want)
		}
	}
	if (quality.Curve{{1, 0}}).Validate() == nil || (quality.Curve{{2, 0}, {1, 9}}).Validate() == nil {
		t.Error("invalid curves accepted")
	}
}

func TestProfile_Assess(t *testing.T) {
	t.Parallel()
	p := quality.DefaultProfile()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	good := quality.Input{RSSI: 42, Rate: 286, MaxRate: 286.8, Mode: "802.11ax", Streams: 2, Usage: 10, UsageKnown: true, NoiseFloor: -95, Clients: 5}
	tests := []struct {
		name  string
		edit  func(*quality.Input)
		grade quality.Grade
		cause quality.Cause
	}{
		{"excellent", func(*quality.Input) {}, quality.GradeExcellent, quality.CauseNone},
		{"weak signal dominates", func(in *quality.Input) { in.RSSI = 12 }, quality.GradePoor, quality.CauseWeakSignal},
		{"busy with many clients is congestion", func(in *quality.Input) { in.Usage, in.Clients = 92, 45 }, quality.GradeFair, quality.CauseCongestion},
		{"busy with few clients is interference", func(in *quality.Input) { in.Usage = 92 }, quality.GradeFair, quality.CauseInterference},
		{"noisy", func(in *quality.Input) { in.NoiseFloor = -72 }, quality.GradeFair, quality.CauseNoise},
		{"slightly noisy", func(in *quality.Input) { in.NoiseFloor = -84 }, quality.GradeExcellent, quality.CauseNone},
		{"marginal signal caps the grade", func(in *quality.Input) { in.RSSI = 22 }, quality.GradeGood, quality.CauseNone},
		{"legacy client", func(in *quality.Input) { in.Mode, in.Rate, in.MaxRate = "802.11g", 2, 54 }, quality.GradeFair, quality.CauseLegacyClient},
		{"power save", func(in *quality.Input) { in.Rate, in.PowerSave = 6, true }, quality.GradeFair, quality.CausePowerSave},
		{"unexplained low rate", func(in *quality.Input) { in.Rate = 6 }, quality.GradeFair, quality.CauseLowRate},
		{"unknown signal is not scored", func(in *quality.Input) { in.RSSI = 0 }, quality.GradeUnknown, quality.CauseNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := good
			tc.edit(&in)
			s := p.Assess(in)
			if s.Grade != tc.grade || s.Cause != tc.cause {
				t.Errorf("score %+v, want grade %s cause %q", s, tc.grade, tc.cause)
			}
		})
	}
}

func TestMaxRate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mode, bw string
		nss      int
		want     float64
	}{
		{"802.11ax", "20MHz", 1, 143.4},
		{"802.11ax", "80MHz", 2, 1201},
		{"802.11gax", "20MHz", 2, 286.8},
		{"802.11ac", "80MHz", 1, 433.3},
		{"802.11an", "40MHz", 1, 150},
		{"802.11g", "", 1, 54},
		{"unknown", "", 1, 0},
	}
	for _, tc := range tests {
		if got := quality.MaxRate(tc.mode, tc.bw, tc.nss); got != tc.want {
			t.Errorf("MaxRate(%s,%s,%d) = %v, want %v", tc.mode, tc.bw, tc.nss, got, tc.want)
		}
	}
}
