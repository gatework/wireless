package h3c

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/gatework/wireless"
)

var (
	radioLine     = regexp.MustCompile(`^radio (\d+)$`)
	rejectRSSI    = regexp.MustCompile(`^option client reject enable rssi (\d+)`)
	antiSticky    = regexp.MustCompile(`^sacp anti-sticky enable(?: rssi (\d+))?(?: interval (\d+))?`)
	roamNavigate  = regexp.MustCompile(`^option roam-navigation enable rssi (\d+)`)
	maxPower      = regexp.MustCompile(`^max-power (\d+)`)
	bandwidth     = regexp.MustCompile(`^channel band-width (\d+)`)
	channelNumber = regexp.MustCompile(`^channel (\d+)$`)
)

// apGroup reads "wlan ap-group NAME":
//
//	wlan ap-group g
//	 ap AP-1
//	 ap-model WA6338-HI
//	  radio 1
//	   option client reject enable rssi 20
//	   sacp anti-sticky enable interval 2
func apGroup(name string, s section) wireless.APGroup {
	g := wireless.APGroup{Name: name, Models: map[string]map[int]wireless.RadioPolicy{}}
	model, radio, modelIndent := "", 0, -1
	for i, l := range s.lines {
		indent := s.indents[i]
		switch {
		case strings.HasPrefix(l, "ap-model "):
			model, radio, modelIndent = strings.TrimSpace(strings.TrimPrefix(l, "ap-model ")), 0, indent
			if g.Models[model] == nil {
				g.Models[model] = map[int]wireless.RadioPolicy{}
			}
		case strings.HasPrefix(l, "ap ") && indent <= max(modelIndent, 1):
			g.APs = append(g.APs, strings.TrimSpace(strings.TrimPrefix(l, "ap ")))
			model, radio = "", 0
		case model != "" && indent > modelIndent:
			if m := radioLine.FindStringSubmatch(l); m != nil {
				radio, _ = strconv.Atoi(m[1])
				continue
			}
			if radio != 0 {
				p := g.Models[model][radio]
				radioSetting(&p, l)
				g.Models[model][radio] = p
			}
		}
	}
	return g
}

// apConfig reads "wlan ap NAME model MODEL" and its per-radio overrides.
func apConfig(header string, s section) wireless.APConfig {
	fields := strings.Fields(header)
	a := wireless.APConfig{Name: fields[0], Radios: map[int]wireless.RadioPolicy{}}
	if len(fields) >= 3 && fields[1] == "model" {
		a.Model = fields[2]
	}
	radio, radioIndent := 0, -1
	for i, l := range s.lines {
		indent := s.indents[i]
		if m := radioLine.FindStringSubmatch(l); m != nil {
			radio, _ = strconv.Atoi(m[1])
			radioIndent = indent
			continue
		}
		if radio == 0 || indent <= radioIndent {
			radio = 0
			continue
		}
		p := a.Radios[radio]
		radioSetting(&p, l)
		a.Radios[radio] = p
	}
	return a
}

// radioSetting applies one radio-view line to p.
func radioSetting(p *wireless.RadioPolicy, l string) {
	atoi := func(s string) int {
		n, _ := strconv.Atoi(s)
		return n
	}
	switch {
	case rejectRSSI.MatchString(l):
		p.RejectRSSI = atoi(rejectRSSI.FindStringSubmatch(l)[1])
	case antiSticky.MatchString(l):
		m := antiSticky.FindStringSubmatch(l)
		p.AntiSticky, p.AntiStickyRSSI, p.AntiStickyInterval = true, atoi(m[1]), atoi(m[2])
	case roamNavigate.MatchString(l):
		p.RoamNavigationRSSI = atoi(roamNavigate.FindStringSubmatch(l)[1])
	case maxPower.MatchString(l):
		p.MaxPower = atoi(maxPower.FindStringSubmatch(l)[1])
	case bandwidth.MatchString(l):
		p.Bandwidth = atoi(bandwidth.FindStringSubmatch(l)[1])
	case channelNumber.MatchString(l):
		p.Channel = atoi(channelNumber.FindStringSubmatch(l)[1])
	}
}

// rrm reads the controller-wide RRM switches, which Comware prints either
// under "wlan global-configuration" or as global lines.
func rrm(r *wireless.RRM, lines []string) {
	for _, l := range lines {
		switch {
		case l == "wlan band-navigation enable" || l == "band-navigation enable":
			r.BandNavigation = true
		case l == "wlan load-balance enable" || l == "load-balance enable":
			r.LoadBalance = true
		case strings.HasPrefix(l, "calibrate-channel self-decisive enable"):
			r.ChannelCalibration = true
		case strings.HasPrefix(l, "calibrate-power self-decisive enable"):
			r.PowerCalibration = true
		}
	}
}
