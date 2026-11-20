package wireless

import (
	"time"

	"github.com/gatework/netops/evidence"
)

// Dimensions a vendor can observe. Each one maps to one or more commands.
const (
	DimensionClients       evidence.Dimension = "clients"
	DimensionAccessPoints  evidence.Dimension = "access_points"
	DimensionBSS           evidence.Dimension = "bss"
	DimensionDot1X         evidence.Dimension = "dot1x_sessions"
	DimensionMAC           evidence.Dimension = "mac_sessions"
	DimensionConflicts     evidence.Dimension = "ip_conflicts"
	DimensionBlocked       evidence.Dimension = "blocked_macs"
	DimensionConfiguration evidence.Dimension = "configuration"
)

// Dimensions returns every dimension in collection order.
func Dimensions() []evidence.Dimension {
	return []evidence.Dimension{
		DimensionClients, DimensionDot1X, DimensionMAC, DimensionAccessPoints,
		DimensionBSS, DimensionConflicts, DimensionBlocked, DimensionConfiguration,
	}
}

// Controller identifies one wireless controller.
type Controller struct {
	// Host is the management address the controller was reached at.
	Host string `json:"host"`
	// Name is the sysname from the prompt or configuration.
	Name     string `json:"name,omitempty"`
	Platform string `json:"platform,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Label returns "name(host)" or the host alone.
func (c Controller) Label() string {
	if c.Name == "" {
		return c.Host
	}
	return c.Name + "(" + c.Host + ")"
}

// Snapshot is everything observed on one controller at one time. Every
// dimension carries its own completeness; a dimension that was not
// collected has status not_requested and no facts.
type Snapshot struct {
	Controller  Controller `json:"controller"`
	CollectedAt time.Time  `json:"collected_at"`
	Capacity    APCapacity `json:"capacity"`

	Clients       evidence.Observation[Client]        `json:"clients"`
	AccessPoints  evidence.Observation[AccessPoint]   `json:"access_points"`
	BSS           evidence.Observation[BSS]           `json:"bss"`
	Dot1X         evidence.Observation[AuthSession]   `json:"dot1x_sessions"`
	MAC           evidence.Observation[AuthSession]   `json:"mac_sessions"`
	Conflicts     evidence.Observation[IPConflict]    `json:"ip_conflicts"`
	Blocked       evidence.Observation[BlockedMAC]    `json:"blocked_macs"`
	Configuration evidence.Observation[Configuration] `json:"configuration"`
}

// NewSnapshot returns a snapshot in which no dimension was requested.
func NewSnapshot(c Controller, at time.Time) *Snapshot {
	return &Snapshot{
		Controller:    c,
		CollectedAt:   at,
		Clients:       notRequested[Client](DimensionClients),
		AccessPoints:  notRequested[AccessPoint](DimensionAccessPoints),
		BSS:           notRequested[BSS](DimensionBSS),
		Dot1X:         notRequested[AuthSession](DimensionDot1X),
		MAC:           notRequested[AuthSession](DimensionMAC),
		Conflicts:     notRequested[IPConflict](DimensionConflicts),
		Blocked:       notRequested[BlockedMAC](DimensionBlocked),
		Configuration: notRequested[Configuration](DimensionConfiguration),
	}
}

// Coverage reports the status of every dimension.
func (s *Snapshot) Coverage() evidence.Coverage {
	return evidence.Cover(s.Clients, s.AccessPoints, s.BSS, s.Dot1X, s.MAC, s.Conflicts, s.Blocked, s.Configuration)
}

// Config returns the parsed configuration, if it was observed.
func (s *Snapshot) Config() (*Configuration, bool) {
	if len(s.Configuration.Facts) == 0 {
		return nil, false
	}
	return &s.Configuration.Facts[0], true
}

// AccessPoint returns the AP with the given name.
func (s *Snapshot) AccessPoint(name string) (*AccessPoint, bool) {
	for i := range s.AccessPoints.Facts {
		if s.AccessPoints.Facts[i].Name == name {
			return &s.AccessPoints.Facts[i], true
		}
	}
	return nil, false
}

// Sessions returns both authenticators' sessions.
func (s *Snapshot) Sessions() []AuthSession {
	out := make([]AuthSession, 0, len(s.Dot1X.Facts)+len(s.MAC.Facts))
	out = append(out, s.Dot1X.Facts...)
	return append(out, s.MAC.Facts...)
}

func notRequested[T any](d evidence.Dimension) evidence.Observation[T] {
	return evidence.NotRequested[T](d)
}

// Observed returns the status, fact count and issues of one dimension.
// An unknown dimension reports not_requested.
func (s *Snapshot) Observed(d evidence.Dimension) (evidence.Status, int, []evidence.Issue) {
	switch d {
	case DimensionClients:
		return summary(s.Clients)
	case DimensionAccessPoints:
		return summary(s.AccessPoints)
	case DimensionBSS:
		return summary(s.BSS)
	case DimensionDot1X:
		return summary(s.Dot1X)
	case DimensionMAC:
		return summary(s.MAC)
	case DimensionConflicts:
		return summary(s.Conflicts)
	case DimensionBlocked:
		return summary(s.Blocked)
	case DimensionConfiguration:
		return summary(s.Configuration)
	}
	return evidence.StatusNotRequested, 0, nil
}

func summary[T any](o evidence.Observation[T]) (evidence.Status, int, []evidence.Issue) {
	return o.Status, len(o.Facts), o.Issues
}
