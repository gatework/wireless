package workflow

import (
	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/ops"

	"github.com/gatework/wireless"
)

// Vendor is a controller vendor: its probes and its decoder.
type Vendor interface {
	ops.Probes
	Decode(c capture.Capture) *wireless.Snapshot
}
