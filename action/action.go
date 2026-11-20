package action

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gatework/netops/change"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
)

// ErrInvalid reports an action that cannot be planned.
var ErrInvalid = errors.New("action: invalid request")

// Kind is an operator action on one station.
type Kind string

// Actions.
const (
	// KindKick disconnects the station; it may reassociate at once.
	KindKick Kind = "kick"
	// KindBlock adds the station to the static blacklist.
	KindBlock Kind = "block"
	// KindUnblock removes the station from the static blacklist.
	KindUnblock Kind = "unblock"
)

// Valid reports whether k is a declared action.
func (k Kind) Valid() bool { return k == KindKick || k == KindBlock || k == KindUnblock }

// Script is a vendor's rendering of one action.
type Script struct {
	// Commands are sent in order in one session.
	Commands []string `json:"commands"`
	// Rollback undoes the commands; empty when the action cannot be undone.
	Rollback []string `json:"rollback,omitempty"`
	// Readback is the command whose output shows the station's state.
	Readback string `json:"readback"`
}

// State is what a readback shows about the station.
type State struct {
	// Present is true when the station is online (kick) or listed in the
	// blacklist (block, unblock).
	Present bool `json:"present"`
	// Online is the station's association time when present, for kick.
	Online time.Duration `json:"online_ns,omitempty"`
	// Digest identifies the readback text.
	Digest evidence.Digest `json:"digest"`
}

// Fingerprint identifies the part of a state an action depends on: only
// presence, since the association time grows by itself.
func Fingerprint(s State) evidence.Digest {
	return evidence.NewHasher("wireless/action-state/v1").Bool("present", s.Present).Sum()
}

// Renderer is a vendor's syntax for actions.
type Renderer interface {
	// Render returns the commands, rollback and readback of an action.
	Render(kind Kind, mac wireless.MAC) (Script, error)
	// Observe decodes a readback response.
	Observe(kind Kind, mac wireless.MAC, response string) (State, error)
}

// Request is an operator's intent.
type Request struct {
	Kind   Kind          `json:"kind"`
	MAC    wireless.MAC  `json:"mac"`
	Device device.Device `json:"device"`
	// Kick, for a block, also disconnects the station after listing it,
	// so that it cannot stay on its current association.
	Kick bool `json:"kick,omitempty"`
}

// Validate rejects unknown kinds, group or zero MACs, an invalid device and
// a kick on anything but a block.
func (r Request) Validate() error {
	if !r.Kind.Valid() || r.MAC.IsZero() || !r.MAC.Unicast() || r.Device.Normalize().Validate() != nil || r.Kick && r.Kind != KindBlock {
		return ErrInvalid
	}
	return nil
}

// Change is a rendered action. It implements change.Change[State] and
// change.Effect[State], and encodes to JSON for plan envelopes.
type Change struct {
	Action Kind         `json:"action"`
	MAC    wireless.MAC `json:"mac"`
	Kick   bool         `json:"kick,omitempty"`
	Script Script       `json:"script"`
}

var (
	_ change.Change[State] = Change{}
	_ change.Effect[State] = Change{}
)

// Kind returns the change kind, "wlan.kick", "wlan.block" or
// "wlan.unblock".
func (c Change) Kind() change.Kind { return change.Kind("wlan." + string(c.Action)) }

// Validate checks the rendered action.
func (c Change) Validate() error {
	if !c.Action.Valid() || c.MAC.IsZero() || !c.MAC.Unicast() || len(c.Script.Commands) == 0 || c.Script.Readback == "" {
		return ErrInvalid
	}
	return nil
}

// Eligible always holds: an action applies in any state, and a state where
// it is already in effect is Satisfied.
func (Change) Eligible(State) error { return nil }

// Satisfied reports whether the action is already in effect: the station
// is gone (kick), listed (block) or unlisted (unblock).
func (c Change) Satisfied(s State) bool {
	if c.Action == KindBlock {
		return s.Present
	}
	return !s.Present
}

// Effective verifies the effect. A kicked station counts as disconnected
// when it is gone or has reassociated since, which shows as a shorter
// association time.
func (c Change) Effective(before, after State) bool {
	if c.Action == KindKick {
		return !after.Present || after.Online < before.Online
	}
	return c.Satisfied(after)
}

// Render returns the script.
func (c Change) Render(State) (change.Script, error) {
	return change.Script{Commands: change.Commands(c.Script.Commands...), Rollback: change.Commands(c.Script.Rollback...)}, nil
}

// NewPlan validates and renders the request for the device. The plan
// assumes the action's precondition; at execution the station is read back
// and an action already in effect is skipped.
func NewPlan(meta change.Meta, r Request, renderer Renderer) (*change.Plan[State], error) {
	c, err := Render(r, renderer)
	if err != nil {
		return nil, err
	}
	assumed := State{Present: r.Kind != KindBlock}
	p, err := change.NewPlan(meta, r.Device, assumed, change.Change[State](c), Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("action: plan %s: %w", r.Kind, err)
	}
	return p, nil
}

// Render returns the change for a request.
func Render(r Request, renderer Renderer) (Change, error) {
	if err := r.Validate(); err != nil {
		return Change{}, err
	}
	script, err := renderer.Render(r.Kind, r.MAC)
	if err != nil {
		return Change{}, fmt.Errorf("action: render %s: %w", r.Kind, err)
	}
	if r.Kick {
		kick, err := renderer.Render(KindKick, r.MAC)
		if err != nil {
			return Change{}, fmt.Errorf("action: render kick: %w", err)
		}
		script.Commands = append(slices.Clone(script.Commands), kick.Commands...)
	}
	c := Change{Action: r.Kind, MAC: r.MAC, Kick: r.Kick, Script: script}
	if err := c.Validate(); err != nil {
		return Change{}, err
	}
	return c, nil
}

// Codec decodes action plan envelopes.
func Codec() (*change.Codec[State], error) {
	return change.NewCodec(Fingerprint,
		change.DecodeAs[State, Change]("wlan.kick"),
		change.DecodeAs[State, Change]("wlan.block"),
		change.DecodeAs[State, Change]("wlan.unblock"),
	)
}

// Of returns the action of a plan.
func Of(p *change.Plan[State]) (Change, bool) {
	c, ok := p.Change().(Change)
	return c, ok
}
