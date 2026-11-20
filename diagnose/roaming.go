package diagnose

import (
	"strings"
	"time"

	"github.com/gatework/wireless/quality"
	"github.com/gatework/wireless/roam"
)

// checkRoaming reports a sticky station, or a weak one with nowhere to
// roam, which is a coverage gap rather than a client problem.
func checkRoaming(_ *Diagnoser, s *subject) []Finding {
	st := s.sticky
	switch {
	case st.Suspected:
		level := LevelInfo
		if st.Confidence >= roam.ConfidenceMedium {
			level = LevelWarn
		}
		basis := labelSameGroup
		if st.Basis == roam.BasisArea {
			basis = labelSameArea
		}
		return []Finding{newFinding(LayerAssociation, level, CodeSticky, st.Confidence.Word(), s.view.Client.RSSI, st.Threshold, basis, st.Alternatives, reasonText(st.Reasons))}
	case len(st.Reasons) > 0 && st.Reasons[0] == roam.ReasonNoAlternative:
		return []Finding{newFinding(LayerAssociation, LevelWarn, CodeCoverageGap, s.view.Client.RSSI)}
	}
	return nil
}

// checkTrack reports ping-pong roaming and how much history there was.
func checkTrack(_ *Diagnoser, s *subject) []Finding {
	t := s.track
	if t == nil {
		return nil
	}
	var out []Finding
	if pp := t.PingPong; pp != nil {
		var hints []string
		if pp.SameChannel {
			hints = append(hints, hintSameChannel)
		}
		if pp.Edge {
			hints = append(hints, hintEdge)
		}
		out = append(out, newFinding(LayerAssociation, LevelWarn, CodePingPong, strings.Join(pp.APs, "↔"), pp.Bounces,
			pp.Fastest.Round(time.Second), strings.Join(hints, detailSeparator)))
	}
	if moves := len(t.Events); moves > 0 && t.PingPong == nil {
		out = append(out, newFinding(LayerAssociation, LevelInfo, CodeRoamHistory, t.Span.Round(time.Minute), moves))
	}
	if t.Insufficient {
		out = append(out, newFinding(LayerAssociation, LevelInfo, CodeTrackSparse))
	}
	return out
}

// checkPolicy reports radio policies of the serving AP that work against
// roaming.
func checkPolicy(_ *Diagnoser, s *subject) []Finding {
	v := s.view
	if v.AP == nil || v.Config == nil {
		return nil
	}
	var out []Finding
	for _, issue := range roam.CheckPolicy(v.Config, v.AP) {
		if issue.RadioID == 0 || issue.RadioID == v.Client.RadioID {
			out = append(out, newFinding(LayerAP, LevelWarn, CodePolicy, issue.AP, issue.Code.Word()))
		}
	}
	return out
}

func reasonText(reasons []roam.Reason) string {
	words := make([]string, 0, len(reasons))
	for _, r := range reasons {
		words = append(words, r.Word())
	}
	return strings.Join(words, detailSeparator)
}

func causeText(c quality.Cause) string {
	if c == quality.CauseNone {
		return labelNoCause
	}
	return c.Word() + "，" + c.Advice()
}
