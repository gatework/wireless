package h3c

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/action"
)

// errRejected reports a readback the device refused, such as a command
// unsupported by the release.
var errRejected = errors.New("h3c: command rejected by device")

var _ action.Renderer = (*Vendor)(nil)

// Render returns the Comware commands of an action. Kicking runs in user
// view; the static blacklist is configuration and is changed in system
// view, then the session returns to user view for the readback.
func (*Vendor) Render(kind action.Kind, mac wireless.MAC) (action.Script, error) {
	m := mac.H3C()
	switch kind {
	case action.KindKick:
		return action.Script{
			Commands: []string{"reset wlan client mac-address " + m},
			Readback: "display wlan client mac-address " + m + " verbose",
		}, nil
	case action.KindBlock:
		return action.Script{
			Commands: []string{"system-view", "wlan static-blacklist mac-address " + m, "return"},
			Rollback: []string{"system-view", "undo wlan static-blacklist mac-address " + m, "return"},
			Readback: CommandStaticBlacklist,
		}, nil
	case action.KindUnblock:
		return action.Script{
			Commands: []string{"system-view", "undo wlan static-blacklist mac-address " + m, "return"},
			Rollback: []string{"system-view", "wlan static-blacklist mac-address " + m, "return"},
			Readback: CommandStaticBlacklist,
		}, nil
	}
	return action.Script{}, fmt.Errorf("h3c: %w: %q", action.ErrInvalid, kind)
}

// Observe decodes a readback. For a kick it parses the verbose client
// record; for the blacklist it looks for the MAC among the listed entries.
func (*Vendor) Observe(kind action.Kind, mac wireless.MAC, response string) (action.State, error) {
	o := capture.Output{Raw: response}
	lines := body(o)
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l.Text), "%") {
			return action.State{}, errRejected
		}
	}
	state := action.State{Digest: evidence.DigestString(response)}
	if kind == action.KindKick {
		for _, c := range parseClients(o).Facts {
			if c.MAC == mac {
				state.Present, state.Online = true, c.Online
			}
		}
		return state, nil
	}
	for _, e := range listedMACs(lines) {
		state.Present = state.Present || e.MAC == mac
	}
	return state, nil
}

// StaticBlacklist decodes "display wlan blacklist static".
func (*Vendor) StaticBlacklist(ctx context.Context, o capture.Output) []wireless.BlockedMAC {
	return listedMACs(bodyContext(ctx, o))
}

// listedMACs returns every MAC that starts a line, with the rest of the
// line as detail.
func listedMACs(lines []parse.Line) []wireless.BlockedMAC {
	var out []wireless.BlockedMAC
	for _, l := range lines {
		first, rest, _ := strings.Cut(strings.TrimSpace(l.Text), " ")
		if m, err := wireless.ParseMAC(first); err == nil {
			out = append(out, wireless.BlockedMAC{MAC: m, Source: "static", Detail: strings.Join(strings.Fields(rest), " ")})
		}
	}
	return out
}

// Commands resolves the collection command of a dimension, so that health
// findings can tell the operator how to re-check them; it implements
// assess.VerifyCommands.
func (*Vendor) Commands(d evidence.Dimension) []string {
	if c, ok := commands[d]; ok {
		return []string{c}
	}
	return nil
}
