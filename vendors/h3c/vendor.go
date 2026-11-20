package h3c

import (
	"slices"
	"strings"
	"time"

	"github.com/gatework/netops/device"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
)

// Platform is the net-connector platform key of H3C wireless controllers.
const Platform = "h3c_wireless"

// Commands. The net-connector h3c driver disables paging after login.
const (
	CommandClients       = "display wlan client verbose"
	CommandDot1X         = "display dot1x connection"
	CommandMAC           = "display mac-authentication connection"
	CommandAccessPoints  = "display wlan ap all verbose"
	CommandBSS           = "display wlan bss all verbose"
	CommandConflicts     = "display wlan statistics client-ip-conflict"
	CommandBlocked       = "display wlan client-security block-mac"
	CommandConfiguration = "display current-configuration"
	// CommandStaticBlacklist lists the operator-managed blacklist. It is
	// read for actions and on demand, not as a collected dimension.
	CommandStaticBlacklist = "display wlan blacklist static"
)

var commands = map[evidence.Dimension]string{
	wireless.DimensionClients:       CommandClients,
	wireless.DimensionDot1X:         CommandDot1X,
	wireless.DimensionMAC:           CommandMAC,
	wireless.DimensionAccessPoints:  CommandAccessPoints,
	wireless.DimensionBSS:           CommandBSS,
	wireless.DimensionConflicts:     CommandConflicts,
	wireless.DimensionBlocked:       CommandBlocked,
	wireless.DimensionConfiguration: CommandConfiguration,
}

// Options configures a Vendor.
type Options struct {
	// Location is the controller's time zone for timestamps it prints
	// without one. The "clock timezone" line of a captured configuration
	// takes precedence; nil means UTC.
	Location *time.Location
}

// Vendor decodes H3C Comware V7 wireless controller output.
type Vendor struct {
	location *time.Location
}

// New returns an H3C vendor.
func New(o Options) *Vendor {
	loc := o.Location
	if loc == nil {
		loc = time.UTC
	}
	return &Vendor{location: loc}
}

// Platform returns [Platform].
func (*Vendor) Platform() string { return Platform }

// CollectCommands returns the collection commands of dims (every
// dimension when none are given) in collection order.
func (*Vendor) CollectCommands(dims ...evidence.Dimension) []string {
	if len(dims) == 0 {
		dims = wireless.Dimensions()
	}
	var out []string
	for _, d := range wireless.Dimensions() {
		if c, ok := commands[d]; ok && slices.Contains(dims, d) {
			out = append(out, c)
		}
	}
	return out
}

// Command returns the command that collects dim; it implements ops.Probes.
func (*Vendor) Command(_ device.Device, dim evidence.Dimension) (string, bool) {
	c, ok := commands[dim]
	return c, ok
}

// Decode turns a capture into a snapshot. A command that is absent from
// the capture leaves its dimension not_requested; a response that did not
// complete is decoded as far as it goes and marked partial.
func (v *Vendor) Decode(c capture.Capture) *wireless.Snapshot {
	ctrl := wireless.Controller{Host: c.Host.String(), Name: sysname(c.Prompt), Platform: Platform}
	s := wireless.NewSnapshot(ctrl, c.RecordedAt())
	loc := v.location
	if o, ok := c.Answer(CommandConfiguration); ok {
		var cfgLoc *time.Location
		s.Configuration, cfgLoc = parseConfiguration(o)
		if cfgLoc != nil {
			loc = cfgLoc
		}
		if cfg, ok := s.Config(); ok {
			s.Controller.Version = cfg.Version
			if s.Controller.Name == "" {
				s.Controller.Name = cfg.Sysname
			}
		}
	}
	if o, ok := c.Answer(CommandClients); ok {
		s.Clients = parseClients(o)
	}
	if o, ok := c.Answer(CommandDot1X); ok {
		s.Dot1X = parseSessions(wireless.DimensionDot1X, wireless.AuthDot1X, o, loc)
	}
	if o, ok := c.Answer(CommandMAC); ok {
		s.MAC = parseSessions(wireless.DimensionMAC, wireless.AuthMAC, o, loc)
	}
	if o, ok := c.Answer(CommandAccessPoints); ok {
		s.AccessPoints, s.Capacity = parseAccessPoints(o)
	}
	if o, ok := c.Answer(CommandBSS); ok {
		s.BSS = parseBSS(o)
	}
	if o, ok := c.Answer(CommandConflicts); ok {
		s.Conflicts = parseConflicts(o, loc)
	}
	if o, ok := c.Answer(CommandBlocked); ok {
		s.Blocked = parseBlocked(o)
	}
	markFailures(s, c)
	return s
}

// markFailures records dimensions whose command failed.
func markFailures(s *wireless.Snapshot, c capture.Capture) {
	for _, out := range c.Failures() {
		if _, answered := c.Answer(out.Command); answered {
			continue
		}
		f := struct{ Command, Code string }{out.Command, string(out.Failure)}
		switch f.Command {
		case CommandClients:
			s.Clients = failed[wireless.Client](wireless.DimensionClients, f.Command, f.Code)
		case CommandDot1X:
			s.Dot1X = failed[wireless.AuthSession](wireless.DimensionDot1X, f.Command, f.Code)
		case CommandMAC:
			s.MAC = failed[wireless.AuthSession](wireless.DimensionMAC, f.Command, f.Code)
		case CommandAccessPoints:
			s.AccessPoints = failed[wireless.AccessPoint](wireless.DimensionAccessPoints, f.Command, f.Code)
		case CommandBSS:
			s.BSS = failed[wireless.BSS](wireless.DimensionBSS, f.Command, f.Code)
		case CommandConflicts:
			s.Conflicts = failed[wireless.IPConflict](wireless.DimensionConflicts, f.Command, f.Code)
		case CommandBlocked:
			s.Blocked = failed[wireless.BlockedMAC](wireless.DimensionBlocked, f.Command, f.Code)
		case CommandConfiguration:
			s.Configuration = failed[wireless.Configuration](wireless.DimensionConfiguration, f.Command, f.Code)
		}
	}
}

// sysname extracts "AC-1" from "<AC-1>" or "[AC-1]".
func sysname(prompt string) string {
	p := strings.Trim(strings.TrimSpace(strings.ReplaceAll(prompt, "\x00", "")), "<>[]")
	return p
}
