package action

import (
	"fmt"

	"github.com/gatework/netops/change"
	"github.com/gatework/netops/device"

	"github.com/gatework/wireless"
)

// Batch plans one action on one station across several controllers. A
// static blacklist lives on each controller separately, so blocking a
// station on one controller only lets it join through another; a block
// therefore normally targets every controller. For a block, online reports
// the controllers where the station is associated now; those plans also
// kick it, after listing it. Plan IDs are meta.ID suffixed with the
// controller's ID.
func Batch(meta change.Meta, kind Kind, mac wireless.MAC, controllers []device.Device, online func(device.Device) bool, r Renderer) ([]*change.Plan[State], error) {
	if len(controllers) == 0 {
		return nil, ErrInvalid
	}
	out := make([]*change.Plan[State], 0, len(controllers))
	for _, d := range controllers {
		m := meta
		m.ID = fmt.Sprintf("%s-%s", meta.ID, d.Mgmt)
		p, err := NewPlan(m, Request{Kind: kind, MAC: mac, Device: d, Kick: kind == KindBlock && online != nil && online(d)}, r)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
