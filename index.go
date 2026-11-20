package wireless

import (
	"iter"
	"slices"
	"strings"
)

// Index joins the snapshots of many controllers so that a station can be
// located and explained across all of them: client record, serving AP and
// radio, authentication sessions, service template, blacklist entries and
// IP conflict history.
//
// Views returned by an Index borrow the indexed snapshots; callers must
// not modify them. An Index is immutable and safe for concurrent reads.
type Index struct {
	snapshots []*Snapshot
	sessions  map[stationKey][]*AuthSession
	blocked   map[stationKey][]BlockedMAC
	aps       map[apKey]*AccessPoint
	load      map[apKey]int
	radios    map[radioKey]RadioLoad
	byMAC     map[MAC][]int
}

type radioKey struct {
	snapshot int
	ap       string
	radio    int
}

// RadioLoad is the client side of one radio's load.
type RadioLoad struct {
	Clients int `json:"clients"`
	// RxKbps and TxKbps sum the clients' measured throughput.
	RxKbps float64 `json:"rx_kbps"`
	TxKbps float64 `json:"tx_kbps"`
}

type stationKey struct {
	snapshot int
	mac      MAC
}

type apKey struct {
	snapshot int
	name     string
}

// NewIndex indexes snapshots in the given order, which is also the order
// of every result. Nil snapshots are skipped.
func NewIndex(snapshots ...*Snapshot) *Index {
	ix := &Index{
		sessions: map[stationKey][]*AuthSession{},
		blocked:  map[stationKey][]BlockedMAC{},
		aps:      map[apKey]*AccessPoint{},
		load:     map[apKey]int{},
		radios:   map[radioKey]RadioLoad{},
		byMAC:    map[MAC][]int{},
	}
	for _, s := range snapshots {
		if s != nil {
			ix.add(s)
		}
	}
	return ix
}

// Snapshots returns the indexed snapshots in order.
func (ix *Index) Snapshots() []*Snapshot { return slices.Clone(ix.snapshots) }

// Find returns everything the query matches on every controller.
func (ix *Index) Find(q Query) Result {
	r := Result{Clients: []ClientView{}, Sessions: []SessionView{}, APs: []APView{}, Conflicts: []ConflictView{}, Blocked: []BlockedView{}}
	for i, s := range ix.snapshots {
		seen := map[MAC]bool{}
		for j := range s.Clients.Facts {
			c := &s.Clients.Facts[j]
			if q.MatchMAC(c.MAC) || q.MatchAddr(c.IPv4) || q.MatchAddr(c.IPv6) || q.MatchName(c.Username) {
				r.Clients = append(r.Clients, ix.clientView(i, c))
				seen[c.MAC] = true
			}
		}
		r.Sessions = append(r.Sessions, ix.orphanSessions(i, q, seen)...)
		r.APs = append(r.APs, ix.matchAPs(i, q)...)
		r.Conflicts = append(r.Conflicts, matchConflicts(s, q)...)
		for _, b := range s.Blocked.Facts {
			if q.MatchMAC(b.MAC) {
				r.Blocked = append(r.Blocked, BlockedView{Controller: s.Controller, Entry: b})
			}
		}
	}
	return r
}

// Clients iterates the view of every client on every controller.
func (ix *Index) Clients() iter.Seq[ClientView] {
	return func(yield func(ClientView) bool) {
		for i, s := range ix.snapshots {
			for j := range s.Clients.Facts {
				if !yield(ix.clientView(i, &s.Clients.Facts[j])) {
					return
				}
			}
		}
	}
}

// AccessPoints iterates the view of every AP on every controller.
func (ix *Index) AccessPoints() iter.Seq[APView] {
	return func(yield func(APView) bool) {
		for i, s := range ix.snapshots {
			for j := range s.AccessPoints.Facts {
				if !yield(ix.apView(i, &s.AccessPoints.Facts[j])) {
					return
				}
			}
		}
	}
}

// Snapshot returns the indexed snapshot of the controller at host.
func (ix *Index) Snapshot(host string) (*Snapshot, bool) {
	for _, s := range ix.snapshots {
		if s.Controller.Host == host {
			return s, true
		}
	}
	return nil, false
}

// Controllers returns every controller that reports a client with MAC m,
// in index order.
func (ix *Index) Controllers(m MAC) []Controller {
	out := make([]Controller, 0, len(ix.byMAC[m]))
	for _, i := range ix.byMAC[m] {
		out = append(out, ix.snapshots[i].Controller)
	}
	return out
}

// RadioLoad returns the client load of one radio on the controller at
// host.
func (ix *Index) RadioLoad(host, ap string, radio int) RadioLoad {
	for i, s := range ix.snapshots {
		if s.Controller.Host == host {
			return ix.radios[radioKey{i, ap, radio}]
		}
	}
	return RadioLoad{}
}

func (ix *Index) add(s *Snapshot) {
	i := len(ix.snapshots)
	ix.snapshots = append(ix.snapshots, s)
	for _, list := range [][]AuthSession{s.Dot1X.Facts, s.MAC.Facts} {
		for j := range list {
			k := stationKey{i, list[j].MAC}
			ix.sessions[k] = append(ix.sessions[k], &list[j])
		}
	}
	for _, b := range s.Blocked.Facts {
		k := stationKey{i, b.MAC}
		ix.blocked[k] = append(ix.blocked[k], b)
	}
	for j := range s.AccessPoints.Facts {
		ap := &s.AccessPoints.Facts[j]
		ix.aps[apKey{i, ap.Name}] = ap
	}
	for _, c := range s.Clients.Facts {
		ix.load[apKey{i, c.APName}]++
		rk := radioKey{i, c.APName, c.RadioID}
		rl := ix.radios[rk]
		rl.Clients++
		rl.RxKbps += c.RxKbps
		rl.TxKbps += c.TxKbps
		ix.radios[rk] = rl
		if !slices.Contains(ix.byMAC[c.MAC], i) {
			ix.byMAC[c.MAC] = append(ix.byMAC[c.MAC], i)
		}
	}
}

func (ix *Index) clientView(i int, c *Client) ClientView {
	s := ix.snapshots[i]
	v := ClientView{
		Controller: s.Controller,
		Client:     c,
		Sessions:   slices.Clone(ix.sessions[stationKey{i, c.MAC}]),
		Blocked:    slices.Clone(ix.blocked[stationKey{i, c.MAC}]),
		Access:     c.Access(),
	}
	if ap, ok := ix.aps[apKey{i, c.APName}]; ok {
		v.AP = ap
		v.Radio, _ = ap.Radio(c.RadioID)
	}
	v.RadioLoad = ix.radios[radioKey{i, c.APName, c.RadioID}]
	if cfg, ok := s.Config(); ok {
		v.Config = cfg
		if t, ok := cfg.TemplateForSSID(c.SSID); ok {
			v.Template = &t
			v.Chain = cfg.Chain(t)
			if v.Access == AccessMAC || v.Access == AccessUnknown || v.Access == AccessOpen {
				if a := t.Access(); a != AccessUnknown {
					v.Access = a
				}
			}
		}
	}
	for _, conflict := range s.Conflicts.Facts {
		if conflict.NewMAC == c.MAC || conflict.OldMAC == c.MAC || c.IPv4.IsValid() && conflict.IP == c.IPv4 {
			v.Conflicts = append(v.Conflicts, conflict)
		}
	}
	for _, other := range ix.byMAC[c.MAC] {
		if other != i {
			v.Elsewhere = append(v.Elsewhere, ix.snapshots[other].Controller)
		}
	}
	return v
}

func (ix *Index) apView(i int, ap *AccessPoint) APView {
	return APView{Controller: ix.snapshots[i].Controller, AP: ap, Clients: ix.load[apKey{i, ap.Name}]}
}

func (ix *Index) orphanSessions(i int, q Query, associated map[MAC]bool) []SessionView {
	s := ix.snapshots[i]
	var out []SessionView
	for _, list := range [][]AuthSession{s.Dot1X.Facts, s.MAC.Facts} {
		for j := range list {
			a := &list[j]
			if associated[a.MAC] {
				continue
			}
			if q.MatchMAC(a.MAC) || q.MatchAddr(a.IPv4) || q.MatchAddr(a.IPv6) || q.MatchName(a.Username) {
				out = append(out, SessionView{Controller: s.Controller, Session: a})
			}
		}
	}
	return out
}

func (ix *Index) matchAPs(i int, q Query) []APView {
	s := ix.snapshots[i]
	var out []APView
	for j := range s.AccessPoints.Facts {
		ap := &s.AccessPoints.Facts[j]
		match := q.MatchName(ap.Name) || q.MatchMAC(ap.MAC) || q.MatchAddr(ap.IP) ||
			q.Textual() && strings.EqualFold(ap.Serial, q.String())
		for _, r := range ap.Radios {
			match = match || q.hasMAC && q.MatchMAC(r.BSSID)
		}
		if match {
			out = append(out, ix.apView(i, ap))
		}
	}
	return out
}

func matchConflicts(s *Snapshot, q Query) []ConflictView {
	if q.Textual() && q.pattern.digits == "" {
		return nil
	}
	var out []ConflictView
	for _, c := range s.Conflicts.Facts {
		if q.MatchAddr(c.IP) || q.MatchMAC(c.NewMAC) || q.MatchMAC(c.OldMAC) {
			out = append(out, ConflictView{Controller: s.Controller, Conflict: c})
		}
	}
	return out
}

// Result is everything one query matched.
type Result struct {
	Clients   []ClientView   `json:"clients"`
	Sessions  []SessionView  `json:"sessions"`
	APs       []APView       `json:"access_points"`
	Conflicts []ConflictView `json:"conflicts"`
	Blocked   []BlockedView  `json:"blocked"`
}

// Empty reports whether nothing matched.
func (r Result) Empty() bool {
	return len(r.Clients)+len(r.Sessions)+len(r.APs)+len(r.Conflicts)+len(r.Blocked) == 0
}

// ClientView is one client joined with everything that explains it.
type ClientView struct {
	Controller Controller   `json:"controller"`
	Client     *Client      `json:"client"`
	AP         *AccessPoint `json:"-"`
	Radio      *Radio       `json:"radio,omitempty"`
	// RadioLoad is the load of the serving radio.
	RadioLoad RadioLoad `json:"radio_load"`
	// Sessions are the authenticator sessions for the client's MAC.
	Sessions []*AuthSession `json:"sessions,omitempty"`
	// Config is the controller configuration, for policy lookups.
	Config *Configuration `json:"-"`
	// Template is the service template serving the client's SSID.
	Template *ServiceTemplate `json:"template,omitempty"`
	Chain    AuthChain        `json:"chain,omitzero"`
	Access   AccessMethod     `json:"access"`
	Blocked  []BlockedMAC     `json:"blocked,omitempty"`
	// Conflicts are IP conflict entries involving the client's MAC or IP.
	Conflicts []IPConflict `json:"conflicts,omitempty"`
	// Elsewhere lists other controllers that also report this MAC, which
	// means an inter-controller roam in progress or a duplicated address.
	Elsewhere []Controller `json:"elsewhere,omitempty"`
}

// Session returns the first authenticator session, if any.
func (v *ClientView) Session() (*AuthSession, bool) {
	if len(v.Sessions) == 0 {
		return nil, false
	}
	return v.Sessions[0], true
}

// SignalDBm estimates the client's signal from its radio's noise floor.
func (v *ClientView) SignalDBm() (int, bool) {
	if v.Radio == nil {
		return 0, false
	}
	noise, ok := v.Radio.Noise()
	if !ok {
		return 0, false
	}
	return v.Client.SignalDBm(noise)
}

// SessionView is an authenticator session without an associated client
// record on the same controller: the station authenticated but is no
// longer, or not yet, associated.
type SessionView struct {
	Controller Controller   `json:"controller"`
	Session    *AuthSession `json:"session"`
}

// APView is one AP with its current client count.
type APView struct {
	Controller Controller   `json:"controller"`
	AP         *AccessPoint `json:"ap"`
	Clients    int          `json:"clients"`
}

// ConflictView is one IP conflict entry on one controller.
type ConflictView struct {
	Controller Controller `json:"controller"`
	Conflict   IPConflict `json:"conflict"`
}

// BlockedView is one blacklist entry on one controller.
type BlockedView struct {
	Controller Controller `json:"controller"`
	Entry      BlockedMAC `json:"entry"`
}
