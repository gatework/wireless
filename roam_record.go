package wireless

import (
	"net/netip"
	"time"
)

// RoamRecord is one association in a controller's own roam history for a
// station, as "display wlan mobility roam-track" reports it.
type RoamRecord struct {
	BSSID MAC `json:"bssid"`
	// CreatedAt is when the association began, in the controller's clock.
	CreatedAt time.Time `json:"created_at"`
	// Online is how long the association lasted, or lasts.
	Online time.Duration `json:"online_ns"`
	// AC is the controller that served it; 127.0.0.1 means the reporting
	// controller itself.
	AC      netip.Addr `json:"ac,omitzero"`
	RadioID int        `json:"radio_id,omitempty"`
	APName  string     `json:"ap_name,omitempty"`
}
