// Package conflict explains a controller's client IP conflict history.
// A raw list of conflicts says that addresses collided; operators need to
// know why, because the fix differs:
//
//   - many stations claiming one address point at a static address
//     configured on devices, or a rogue DHCP server; an address outside
//     the controller's usual subnets confirms it, and a shared vendor
//     prefix among the MACs points at one batch of devices;
//   - two stations trading one address again and again are usually one
//     device with two interfaces, or a phone switching between its
//     private and real MAC;
//   - anything else is sporadic, typically a stale DHCP lease.
//
// The package does no I/O.
package conflict

import (
	"cmp"
	"net/netip"
	"slices"
	"time"

	"github.com/gatework/wireless"
)

// Pattern is the kind of conflict an address shows.
type Pattern string

// Patterns.
const (
	PatternShared   Pattern = "shared_ip"
	PatternPair     Pattern = "pair_flip"
	PatternSporadic Pattern = "sporadic"
)

// Word returns the operator-facing name.
func (p Pattern) Word() string { return patternWords[p] }

// Advice returns what to check for the pattern.
func (p Pattern) Advice() string { return patternAdvice[p] }

// Thresholds of the classification.
const (
	sharedMACs = 3
	pairRepeat = 3
	// knownShare is the fraction of current clients a /16 must hold to
	// count as one of the controller's usual subnets.
	knownShare = 0.01
	// batchMACs is how many MACs must share a vendor prefix to call them
	// one batch of devices.
	batchMACs = 2
)

// Group is the conflict history of one address on one controller.
type Group struct {
	Controller wireless.Controller `json:"controller"`
	IP         netip.Addr          `json:"ip"`
	Count      int                 `json:"count"`
	Latest     time.Time           `json:"latest"`
	MACs       []wireless.MAC      `json:"macs"`
	Pattern    Pattern             `json:"pattern"`
	// Foreign reports an address outside every subnet the controller's
	// clients normally use.
	Foreign bool `json:"foreign,omitempty"`
	// Batches lists vendor prefixes (OUI) shared by several of the MACs.
	Batches []Batch `json:"batches,omitempty"`
}

// Batch is a vendor prefix shared by several conflicting MACs.
type Batch struct {
	OUI   string `json:"oui"`
	Count int    `json:"count"`
}

// Analyze groups the snapshot's conflicts at or after since by address
// and classifies each group, most frequent first.
func Analyze(s *wireless.Snapshot, since time.Time) []Group {
	known := usualSubnets(s)
	index := map[netip.Addr]int{}
	pairs := map[netip.Addr]map[[2]wireless.MAC]int{}
	var out []Group
	for _, c := range s.Conflicts.Facts {
		if c.At.Before(since) {
			continue
		}
		i, ok := index[c.IP]
		if !ok {
			i = len(out)
			index[c.IP] = i
			out = append(out, Group{Controller: s.Controller, IP: c.IP})
			pairs[c.IP] = map[[2]wireless.MAC]int{}
		}
		g := &out[i]
		g.Count++
		if c.At.After(g.Latest) {
			g.Latest = c.At
		}
		for _, m := range []wireless.MAC{c.NewMAC, c.OldMAC} {
			if !m.IsZero() && !slices.Contains(g.MACs, m) {
				g.MACs = append(g.MACs, m)
			}
		}
		pairs[c.IP][pairKey(c.NewMAC, c.OldMAC)]++
	}
	for i := range out {
		g := &out[i]
		g.Pattern = classify(g, pairs[g.IP])
		g.Foreign = g.IP.Is4() && len(known) > 0 && !slices.Contains(known, prefix16(g.IP))
		g.Batches = batches(g.MACs)
	}
	slices.SortStableFunc(out, func(a, b Group) int { return cmp.Or(cmp.Compare(b.Count, a.Count), b.Latest.Compare(a.Latest)) })
	return out
}

func classify(g *Group, pairs map[[2]wireless.MAC]int) Pattern {
	if len(g.MACs) >= sharedMACs {
		return PatternShared
	}
	for _, n := range pairs {
		if n >= pairRepeat {
			return PatternPair
		}
	}
	return PatternSporadic
}

// usualSubnets returns the IPv4 /16 prefixes holding at least knownShare
// of the controller's current clients.
func usualSubnets(s *wireless.Snapshot) []netip.Prefix {
	counts := map[netip.Prefix]int{}
	total := 0
	for _, c := range s.Clients.Facts {
		if c.IPv4.IsValid() {
			counts[prefix16(c.IPv4)]++
			total++
		}
	}
	var out []netip.Prefix
	for p, n := range counts {
		if float64(n) >= knownShare*float64(total) {
			out = append(out, p)
		}
	}
	return out
}

// batches finds vendor prefixes shared by several MACs. Locally
// administered (random) MACs carry no vendor and are skipped.
func batches(macs []wireless.MAC) []Batch {
	counts := map[string]int{}
	for _, m := range macs {
		if !m.Randomized() {
			counts[m.Hex()[:6]]++
		}
	}
	var out []Batch
	for oui, n := range counts {
		if n >= batchMACs {
			out = append(out, Batch{OUI: oui[:4] + "-" + oui[4:], Count: n})
		}
	}
	slices.SortFunc(out, func(a, b Batch) int { return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.OUI, b.OUI)) })
	return out
}

func prefix16(a netip.Addr) netip.Prefix {
	p, _ := a.Prefix(16)
	return p
}

func pairKey(a, b wireless.MAC) [2]wireless.MAC {
	if a.Hex() > b.Hex() {
		a, b = b, a
	}
	return [2]wireless.MAC{a, b}
}
