package quality

import (
	"errors"
	"slices"
)

// ErrInvalidProfile reports a profile that cannot score.
var ErrInvalidProfile = errors.New("quality: invalid profile")

// Anchor maps one measured value to a score.
type Anchor struct {
	Value float64 `yaml:"value" json:"value"`
	Score float64 `yaml:"score" json:"score"`
}

// Curve is a piecewise linear scoring function through its anchors, which
// are ordered by increasing Value. Values outside the anchors take the
// nearest end's score.
type Curve []Anchor

// Score interpolates v on the curve.
func (c Curve) Score(v float64) float64 {
	if len(c) == 0 {
		return 0
	}
	if v <= c[0].Value {
		return c[0].Score
	}
	for i := 1; i < len(c); i++ {
		lo, hi := c[i-1], c[i]
		if v <= hi.Value {
			return lo.Score + (v-lo.Value)/(hi.Value-lo.Value)*(hi.Score-lo.Score)
		}
	}
	return c[len(c)-1].Score
}

// Validate requires at least two anchors with strictly increasing values
// and scores within 0–100.
func (c Curve) Validate() error {
	if len(c) < 2 {
		return ErrInvalidProfile
	}
	increasing := slices.IsSortedFunc(c, func(a, b Anchor) int {
		switch {
		case a.Value < b.Value:
			return -1
		case a.Value > b.Value:
			return 1
		}
		return 0
	})
	for i, a := range c {
		if a.Score < 0 || a.Score > 100 || i > 0 && a.Value == c[i-1].Value {
			return ErrInvalidProfile
		}
	}
	if !increasing {
		return ErrInvalidProfile
	}
	return nil
}
