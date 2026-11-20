package diagnose

import (
	"errors"
	"time"
)

// ErrInvalidThresholds reports thresholds that are out of order or range.
var ErrInvalidThresholds = errors.New("diagnose: invalid thresholds")

// Thresholds tune the conclusions that the quality model does not cover.
type Thresholds struct {
	// EchoLoss is the CAPWAP keepalive loss fraction considered unstable.
	EchoLoss float64 `yaml:"echo_loss"`
	// RecentReboot is how long after a reboot an AP counts as recently
	// restarted.
	RecentReboot time.Duration `yaml:"recent_reboot"`
	// DHCPGrace is how long a newly associated station may lack an IPv4
	// address before it is reported.
	DHCPGrace time.Duration `yaml:"dhcp_grace"`
}

// DefaultThresholds returns field-tested defaults.
func DefaultThresholds() Thresholds {
	return Thresholds{EchoLoss: 0.01, RecentReboot: 24 * time.Hour, DHCPGrace: time.Minute}
}

// Validate requires sane ranges.
func (t Thresholds) Validate() error {
	if t.EchoLoss < 0 || t.EchoLoss > 1 || t.RecentReboot < 0 || t.DHCPGrace < 0 {
		return ErrInvalidThresholds
	}
	return nil
}
