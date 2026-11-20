package roam

import (
	"cmp"
	"net/netip"
	"slices"
	"time"

	"github.com/gatework/wireless"
)

// Observation is one sighting of a station: where it was associated at a
// moment. Periodic collections produce sightings with Start unset; a
// controller's roam history produces association starts.
type Observation struct {
	At      time.Time     `json:"t"`
	Host    string        `json:"ctrl"`
	MAC     wireless.MAC  `json:"mac"`
	AP      string        `json:"ap"`
	Radio   int           `json:"radio,omitempty"`
	Channel int           `json:"ch,omitempty"`
	RSSI    int           `json:"rssi,omitempty"`
	IP      netip.Addr    `json:"ip,omitzero"`
	Online  time.Duration `json:"online,omitempty"`
	// Start marks At as the beginning of the association.
	Start bool `json:"start,omitempty"`
}

// Observe turns a snapshot's clients into sightings.
func Observe(s *wireless.Snapshot) []Observation {
	at := s.CollectedAt
	if !s.Clients.ObservedAt.IsZero() {
		at = s.Clients.ObservedAt
	}
	out := make([]Observation, 0, len(s.Clients.Facts))
	for _, c := range s.Clients.Facts {
		out = append(out, Observation{
			At: at, Host: s.Controller.Host, MAC: c.MAC, AP: c.APName, Radio: c.RadioID,
			Channel: c.Channel, RSSI: c.RSSI, IP: c.IPv4, Online: c.Online,
		})
	}
	return out
}

// FromRoamTrack turns a controller's roam history into association
// starts, oldest first.
func FromRoamTrack(host string, mac wireless.MAC, records []wireless.RoamRecord) []Observation {
	out := make([]Observation, 0, len(records))
	for _, r := range records {
		ap := r.APName
		if ap == "" {
			ap = r.BSSID.H3C()
		}
		out = append(out, Observation{At: r.CreatedAt, Host: host, MAC: mac, AP: ap, Radio: r.RadioID, Online: r.Online, Start: true})
	}
	slices.SortStableFunc(out, func(a, b Observation) int { return a.At.Compare(b.At) })
	return out
}

// EventKind is a change between two sightings.
type EventKind string

// Events.
const (
	// EventRoam moved to another AP on the same controller.
	EventRoam EventKind = "roam"
	// EventInterAC moved to another controller.
	EventInterAC EventKind = "inter_ac_roam"
	// EventReassoc reassociated to the same AP: its association time
	// restarted between the sightings.
	EventReassoc EventKind = "reassoc"
)

// Event is one detected change.
type Event struct {
	Kind EventKind `json:"kind"`
	// At is when it happened, as precisely as the sightings allow.
	At   time.Time   `json:"at"`
	From Observation `json:"from"`
	To   Observation `json:"to"`
}

// PingPong describes back-and-forth roaming.
type PingPong struct {
	// APs are the APs involved, in first-visit order.
	APs []string `json:"aps"`
	// Bounces counts returns to an AP left within the window.
	Bounces int `json:"bounces"`
	// Fastest is the shortest A→B→A round trip seen.
	Fastest time.Duration `json:"fastest_ns"`
	// SameChannel reports that the bouncing APs share a channel.
	SameChannel bool `json:"same_channel,omitempty"`
	// Edge reports that the station sat in the marginal RSSI band on
	// both sides, the signature of overlapping cells.
	Edge bool `json:"edge,omitempty"`
}

// Track is the analysis of one station's sightings.
type Track struct {
	MAC wireless.MAC `json:"mac"`
	// Host is the controller of the latest sighting.
	Host      string        `json:"host"`
	Sightings int           `json:"sightings"`
	Span      time.Duration `json:"span_ns"`
	Events    []Event       `json:"events"`
	PingPong  *PingPong     `json:"ping_pong,omitempty"`
	// Insufficient reports sightings too sparse to see ping-pong: the
	// median gap exceeds the window, so a bounce could pass unseen.
	Insufficient bool `json:"insufficient,omitempty"`
}

// reassocSlack absorbs clock and print skew between the controller's
// association time and the collection timestamp.
const reassocSlack = 30 * time.Second

// Analyze reads one station's sightings in any order.
func (p Params) Analyze(obs []Observation) Track {
	obs = slices.Clone(obs)
	slices.SortStableFunc(obs, func(a, b Observation) int { return a.At.Compare(b.At) })
	t := Track{Sightings: len(obs), Events: []Event{}}
	if len(obs) == 0 {
		return t
	}
	t.MAC, t.Host = obs[0].MAC, obs[len(obs)-1].Host
	t.Span = obs[len(obs)-1].At.Sub(obs[0].At)
	gaps := make([]time.Duration, 0, len(obs))
	for i := 1; i < len(obs); i++ {
		a, b := obs[i-1], obs[i]
		gaps = append(gaps, b.At.Sub(a.At))
		if e, ok := event(a, b); ok {
			t.Events = append(t.Events, e)
		}
	}
	if len(gaps) > 0 {
		slices.Sort(gaps)
		t.Insufficient = gaps[len(gaps)/2] > p.Window && !obs[0].Start
	}
	t.PingPong = p.pingPong(t.Events)
	return t
}

// Tracks groups sightings by station and analyzes each, most eventful
// first.
func (p Params) Tracks(obs []Observation) []Track {
	by := map[wireless.MAC][]Observation{}
	for _, o := range obs {
		by[o.MAC] = append(by[o.MAC], o)
	}
	out := make([]Track, 0, len(by))
	for _, list := range by {
		out = append(out, p.Analyze(list))
	}
	slices.SortFunc(out, func(a, b Track) int {
		return cmp.Or(cmp.Compare(bounces(b), bounces(a)), cmp.Compare(len(b.Events), len(a.Events)), cmp.Compare(a.MAC.Hex(), b.MAC.Hex()))
	})
	return out
}

func bounces(t Track) int {
	if t.PingPong == nil {
		return 0
	}
	return t.PingPong.Bounces
}

// event classifies the change between two consecutive sightings.
func event(a, b Observation) (Event, bool) {
	gap := b.At.Sub(a.At)
	at := b.At
	if !b.Start && b.Online > 0 && b.Online < gap {
		at = b.At.Add(-b.Online) // the new association began here
	}
	e := Event{At: at, From: a, To: b}
	switch {
	case b.Host != a.Host:
		e.Kind = EventInterAC
	case b.AP != a.AP:
		e.Kind = EventRoam
	case b.Start || b.Online+reassocSlack < gap && b.Online < a.Online:
		e.Kind = EventReassoc
	default:
		return Event{}, false
	}
	return e, true
}

// pingPong finds A→B→A returns within the window, or a burst of roams
// among few APs within an hour.
func (p Params) pingPong(events []Event) *PingPong {
	var moves []Event
	for _, e := range events {
		if e.Kind == EventRoam || e.Kind == EventInterAC {
			moves = append(moves, e)
		}
	}
	pp := &PingPong{}
	for i := 1; i < len(moves); i++ {
		prev, cur := moves[i-1], moves[i]
		if cur.To.AP != prev.From.AP || cur.To.Host != prev.From.Host {
			continue
		}
		if trip := cur.At.Sub(prev.At); trip <= p.Window {
			pp.Bounces++
			if pp.Fastest == 0 || trip < pp.Fastest {
				pp.Fastest = trip
			}
			pp.SameChannel = pp.SameChannel || prev.From.Channel != 0 && prev.From.Channel == prev.To.Channel
			pp.Edge = pp.Edge || p.edge(prev.From.RSSI) && p.edge(prev.To.RSSI)
		}
	}
	if pp.Bounces == 0 && !p.burst(moves) {
		return nil
	}
	pp.APs = visited(moves)
	return pp
}

// burst reports Burst or more moves within an hour among at most
// BurstAPs distinct APs.
func (p Params) burst(moves []Event) bool {
	for i := range moves {
		j := i
		aps := map[string]bool{}
		for j < len(moves) && moves[j].At.Sub(moves[i].At) <= time.Hour {
			aps[moves[j].From.AP], aps[moves[j].To.AP] = true, true
			j++
		}
		if j-i >= p.Burst && len(aps) <= p.BurstAPs {
			return true
		}
	}
	return false
}

func (p Params) edge(rssi int) bool { return rssi >= p.EdgeLow && rssi <= p.EdgeHigh }

func visited(moves []Event) []string {
	var out []string
	add := func(ap string) {
		if !slices.Contains(out, ap) {
			out = append(out, ap)
		}
	}
	for _, m := range moves {
		add(m.From.AP)
		add(m.To.AP)
	}
	return out
}
