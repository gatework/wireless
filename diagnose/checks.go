package diagnose

import (
	"slices"
	"strings"
	"time"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/quality"
)

func checkAssociation(_ *Diagnoser, s *subject) []Finding {
	v := s.view
	var out []Finding
	if v.Client.Roam != "" {
		out = append(out, newFinding(LayerAssociation, LevelInfo, CodeRoam, v.Client.Roam))
	}
	if len(v.Elsewhere) > 0 {
		labels := make([]string, len(v.Elsewhere))
		for i, c := range v.Elsewhere {
			labels[i] = c.Label()
		}
		out = append(out, newFinding(LayerAssociation, LevelWarn, CodeElsewhere, strings.Join(labels, ", ")))
	}
	if v.Client.MAC.Randomized() {
		switch v.Access {
		case wireless.AccessPSKMAC, wireless.AccessMAC, wireless.AccessMACPortal:
			out = append(out, newFinding(LayerAssociation, LevelWarn, CodeRandomizedMACAuth))
		case wireless.AccessUnknown, wireless.AccessDot1X, wireless.AccessPSK, wireless.AccessPortal, wireless.AccessOpen:
			out = append(out, newFinding(LayerAssociation, LevelInfo, CodeRandomizedMAC))
		}
	}
	return out
}

// checkQuality reports the scored link quality and its main cause, then
// the signal detail an operator compares against the AP's coverage.
func checkQuality(d *Diagnoser, s *subject) []Finding {
	v, q := s.view, s.quality
	if q.Grade == quality.GradeUnknown {
		return []Finding{newFinding(LayerRadio, LevelInfo, CodeSignalUnknown, v.Client.RSSI)}
	}
	level := map[quality.Grade]Level{
		quality.GradeExcellent: LevelOK, quality.GradeGood: LevelInfo, quality.GradeFair: LevelWarn, quality.GradePoor: LevelFail,
	}[q.Grade]
	out := []Finding{newFinding(LayerRadio, level, CodeQuality, q.Grade.Word(), q.Total, causeText(q.Cause))}
	if dbm, ok := v.SignalDBm(); ok {
		out = append(out, newFinding(LayerRadio, LevelOK, CodeSignal, v.Client.RSSI, dbm))
	}
	return out
}

func checkPHY(_ *Diagnoser, s *subject) []Finding {
	v := s.view
	var out []Finding
	switch strings.ToLower(v.Client.Mode) {
	case "802.11b", "802.11g", "802.11a":
		out = append(out, newFinding(LayerRadio, LevelWarn, CodeLegacyPHY, v.Client.Mode))
	}
	if v.Client.Band() == wireless.Band2G4 && v.AP != nil && slices.ContainsFunc(v.AP.Radios, func(r wireless.Radio) bool {
		return r.Up && r.Band() == wireless.Band5G
	}) {
		out = append(out, newFinding(LayerRadio, LevelInfo, CodeBand24))
	}
	return out
}

func checkAccess(_ *Diagnoser, s *subject) []Finding {
	v := s.view
	var out []Finding
	out = append(out, newFinding(LayerAuth, LevelOK, CodeAccess, accessLabel(v.Access), accessDetail(v)))
	if v.Access == wireless.AccessPSK {
		out = append(out, newFinding(LayerAuth, LevelInfo, CodeSharedKey))
	}
	if want, ok := sessionKind(v.Access); ok && len(v.Sessions) == 0 && s.complete(sessionDimension(want)) {
		out = append(out, newFinding(LayerAuth, LevelWarn, CodeNoSession, want.String()))
	}
	if v.Template != nil && v.Template.Legacy() {
		out = append(out, newFinding(LayerAuth, LevelWarn, CodeLegacySecurity, v.Template.Name))
	}
	return out
}

func checkVLAN(_ *Diagnoser, s *subject) []Finding {
	v := s.view
	a, ok := v.Session()
	if !ok {
		return nil
	}
	var out []Finding
	if a.VLANOverridden() {
		out = append(out, newFinding(LayerAuth, LevelInfo, CodeVLANOverride, a.AuthorizedVLAN, a.InitialVLAN))
	}
	if a.AuthorizedVLAN != 0 && v.Client.VLAN != 0 && a.AuthorizedVLAN != v.Client.VLAN {
		out = append(out, newFinding(LayerAuth, LevelWarn, CodeVLANMismatch, v.Client.VLAN, a.AuthorizedVLAN))
	}
	return out
}

func checkAddress(d *Diagnoser, s *subject) []Finding {
	v := s.view
	c := v.Client
	switch {
	case !c.IPv4.IsValid():
		if c.Online < d.t.DHCPGrace {
			return nil
		}
		return []Finding{newFinding(LayerAddress, LevelFail, CodeNoIPv4, c.Online.Round(time.Second), c.VLAN)}
	case c.IPv4.IsLinkLocalUnicast():
		return []Finding{newFinding(LayerAddress, LevelFail, CodeLinkLocal, c.IPv4)}
	}
	q, err := wireless.ParseQuery(c.IPv4.String())
	if err != nil {
		return nil
	}
	var others []string
	for _, o := range s.index.Find(q).Clients {
		if o.Client.MAC != c.MAC {
			others = append(others, o.Client.MAC.H3C()+"@"+o.Controller.Label())
		}
	}
	if len(others) == 0 {
		return nil
	}
	return []Finding{newFinding(LayerAddress, LevelFail, CodeDuplicateIP, c.IPv4, strings.Join(others, ", "))}
}

func checkConflicts(_ *Diagnoser, s *subject) []Finding {
	conflicts := s.view.Conflicts
	if len(conflicts) == 0 {
		return nil
	}
	latest := slices.MaxFunc(conflicts, func(a, b wireless.IPConflict) int { return a.At.Compare(b.At) })
	return []Finding{newFinding(LayerAddress, LevelWarn, CodeConflicts, len(conflicts), latest.At.Format("2006-01-02 15:04:05"))}
}

func checkBlocked(_ *Diagnoser, s *subject) []Finding {
	var out []Finding
	for _, b := range s.view.Blocked {
		out = append(out, newFinding(LayerControl, LevelFail, CodeBlocked, b.Source))
	}
	return out
}

func checkAP(d *Diagnoser, s *subject) []Finding {
	v := s.view
	ap := v.AP
	if ap == nil {
		if s.complete(wireless.DimensionAccessPoints) {
			return []Finding{newFinding(LayerAP, LevelInfo, CodeAPUnknown, v.Client.APName)}
		}
		return nil
	}
	var out []Finding
	if loss := ap.EchoLoss(); loss > d.t.EchoLoss {
		out = append(out, newFinding(LayerAP, LevelWarn, CodeEchoLoss, ap.Name, loss*100))
	}
	if ap.Uptime > 0 && ap.Uptime < d.t.RecentReboot {
		out = append(out, newFinding(LayerAP, LevelInfo, CodeAPRebooted, ap.Name, ap.Uptime.Round(time.Minute), ap.RebootReason))
	}
	return out
}

// complete reports whether the station's controller observed dim fully.
func (s *subject) complete(dim evidence.Dimension) bool {
	return s.snapshot != nil && s.snapshot.Coverage().Status(dim) == evidence.StatusComplete
}

// sessionKind is the authenticator an access method must have a session
// with, if any.
func sessionKind(a wireless.AccessMethod) (wireless.AuthKind, bool) {
	switch a {
	case wireless.AccessDot1X:
		return wireless.AuthDot1X, true
	case wireless.AccessPSKMAC, wireless.AccessMAC, wireless.AccessMACPortal:
		return wireless.AuthMAC, true
	case wireless.AccessUnknown, wireless.AccessPSK, wireless.AccessPortal, wireless.AccessOpen:
		return "", false
	}
	return "", false
}

func sessionDimension(k wireless.AuthKind) evidence.Dimension {
	if k == wireless.AuthDot1X {
		return wireless.DimensionDot1X
	}
	return wireless.DimensionMAC
}

// accessDetail describes the admission path: who, through which domain
// and servers.
func accessDetail(v *wireless.ClientView) string {
	var parts []string
	if a, ok := v.Session(); ok {
		parts = append(parts, labelled(labelAccount, a.Username), labelled(labelDomain, a.Domain), labelled(labelMethod, a.Method))
	} else if v.Client.Username != "" {
		parts = append(parts, labelled(labelAccount, v.Client.Username))
	}
	parts = append(parts, labelled("SSID", v.Client.SSID), labelled(labelTemplate, v.Chain.Template))
	if v.Chain.Scheme != "" {
		parts = append(parts, labelled("RADIUS", v.Chain.Scheme+" "+strings.Join(v.Chain.Servers, "/")))
	}
	if v.Chain.PortalURL != "" {
		parts = append(parts, labelled("Portal", v.Chain.PortalURL))
	}
	return strings.Join(slices.DeleteFunc(parts, func(p string) bool { return p == "" }), detailSeparator)
}

func accessLabel(a wireless.AccessMethod) string {
	if a == wireless.AccessUnknown {
		return labelUnknown
	}
	return a.String()
}

func labelled(label, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return label + " " + value
}
