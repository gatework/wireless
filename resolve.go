package wireless

import (
	"slices"
	"strings"
)

// Evidence kinds explain why a MAC became an action target.
const (
	EvidenceTyped    = "typed"    // the operator typed the full MAC
	EvidenceClient   = "client"   // an associated client matched
	EvidenceSession  = "session"  // an authentication session matched
	EvidenceBlocked  = "blocked"  // a blacklist entry matched
	EvidenceConflict = "conflict" // seen only in IP conflict history
)

// Target is one station an action may apply to: its MAC, the controllers
// where it is associated now, and what matched it.
type Target struct {
	MAC MAC `json:"mac"`
	// Online lists controllers reporting the station associated.
	Online []Controller `json:"online,omitempty"`
	// Evidence lists the kinds of records that matched, without repeats.
	Evidence []string `json:"evidence"`
	// Hint marks a target found only in conflict history: it may have
	// held the address once, so it is shown but never acted on by itself.
	Hint bool `json:"hint,omitempty"`
}

// Resolve turns what an operator typed into action targets. Actions are
// destructive, so resolution is stricter than [Index.Find]:
//
//   - a full MAC resolves to itself even when no controller reports it,
//     so a station can be blocked before it joins;
//   - an IP or subnet resolves to the clients and sessions holding it now;
//     MACs seen only in conflict history are returned as hints;
//   - text resolves by exact username, never by substring;
//   - a MAC pattern resolves to every MAC it matches.
//
// Targets are ordered by MAC. Callers decide what to do with several.
func (ix *Index) Resolve(q Query) []Target {
	r := resolver{byMAC: map[MAC]*Target{}}
	if m, ok := q.MAC(); ok {
		r.add(m, EvidenceTyped, nil)
	}
	exact := func(name string) bool { return q.Textual() && name != "" && strings.EqualFold(name, q.String()) }
	for _, s := range ix.snapshots {
		for _, c := range s.Clients.Facts {
			if q.MatchMAC(c.MAC) || q.MatchAddr(c.IPv4) || q.MatchAddr(c.IPv6) || exact(c.Username) {
				ctrl := s.Controller
				r.add(c.MAC, EvidenceClient, &ctrl)
			}
		}
		for _, a := range s.Sessions() {
			if q.MatchMAC(a.MAC) || q.MatchAddr(a.IPv4) || q.MatchAddr(a.IPv6) || exact(a.Username) {
				r.add(a.MAC, EvidenceSession, nil)
			}
		}
		for _, b := range s.Blocked.Facts {
			if q.MatchMAC(b.MAC) {
				r.add(b.MAC, EvidenceBlocked, nil)
			}
		}
		for _, c := range s.Conflicts.Facts {
			if q.MatchAddr(c.IP) {
				r.hint(c.NewMAC)
				r.hint(c.OldMAC)
			}
		}
	}
	return r.targets()
}

type resolver struct {
	byMAC map[MAC]*Target
}

func (r *resolver) add(m MAC, evidence string, online *Controller) {
	if m.IsZero() {
		return
	}
	t, ok := r.byMAC[m]
	if !ok {
		t = &Target{MAC: m}
		r.byMAC[m] = t
	}
	t.Hint = false
	if !slices.Contains(t.Evidence, evidence) {
		t.Evidence = append(t.Evidence, evidence)
	}
	if online != nil && !slices.ContainsFunc(t.Online, func(c Controller) bool { return c.Host == online.Host }) {
		t.Online = append(t.Online, *online)
	}
}

func (r *resolver) hint(m MAC) {
	if m.IsZero() {
		return
	}
	if _, ok := r.byMAC[m]; ok {
		return
	}
	r.byMAC[m] = &Target{MAC: m, Evidence: []string{EvidenceConflict}, Hint: true}
}

func (r *resolver) targets() []Target {
	out := make([]Target, 0, len(r.byMAC))
	for _, t := range r.byMAC {
		out = append(out, *t)
	}
	slices.SortFunc(out, func(a, b Target) int { return strings.Compare(a.MAC.Hex(), b.MAC.Hex()) })
	return out
}

// Actionable returns the targets that are not mere hints.
func Actionable(targets []Target) []Target {
	return slices.DeleteFunc(slices.Clone(targets), func(t Target) bool { return t.Hint })
}
