package quality

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/gatework/wireless"
)

// PHY generations, from the station's negotiated wireless mode.
const (
	phyLegacyB = "b"
	phyLegacyG = "g"
	phyHT      = "n"
	phyVHT     = "ac"
	phyHE      = "ax"
)

// phyMax holds the highest single-stream data rate in Mbps by generation
// and channel width, with the short guard interval: HT MCS7, VHT MCS8
// (MCS9 at 40/80/160), HE MCS11.
var phyMax = map[string]map[int]float64{
	phyHT:  {20: 72.2, 40: 150},
	phyVHT: {20: 86.7, 40: 200, 80: 433.3, 160: 866.7},
	phyHE:  {20: 143.4, 40: 286.8, 80: 600.5, 160: 1201},
}

var (
	nssPattern = regexp.MustCompile(`NSS(\d)`)
	widthMHz   = regexp.MustCompile(`(\d+)\s*MHz`)
)

// generation classifies a mode such as "802.11ax", "802.11gax" (HE on
// 2.4 GHz), "802.11an" or "802.11g".
func generation(mode string) string {
	m, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(mode)), "802.11")
	if !ok {
		return ""
	}
	switch {
	case strings.HasSuffix(m, "ax"):
		return phyHE
	case strings.HasSuffix(m, "ac"):
		return phyVHT
	case strings.HasSuffix(m, "n"):
		return phyHT
	case m == "b":
		return phyLegacyB
	case m == "g" || m == "a":
		return phyLegacyG
	}
	return ""
}

// Legacy reports whether the mode predates 802.11n.
func Legacy(mode string) bool {
	g := generation(mode)
	return g == phyLegacyB || g == phyLegacyG
}

// MaxRate is the theoretical PHY rate of a link in Mbps, or zero when the
// mode is unknown. Width defaults to 20 MHz and streams to one.
func MaxRate(mode, bandwidth string, nss int) float64 {
	g := generation(mode)
	switch g {
	case phyLegacyB:
		return 11
	case phyLegacyG:
		return 54
	case "":
		return 0
	}
	width := 20
	if m := widthMHz.FindStringSubmatch(bandwidth); m != nil {
		width, _ = strconv.Atoi(m[1])
	}
	rate, ok := phyMax[g][width]
	if !ok {
		rate = phyMax[g][20]
	}
	return rate * float64(max(nss, 1))
}

// Streams estimates the spatial streams of a station from the MCS sets it
// advertises, capped by the serving radio's MIMO ("2*2"). It returns 1
// when nothing is known.
func Streams(c *wireless.Client, r *wireless.Radio) int {
	nss := 1
	for _, key := range []string{"Supported HE-MCS set", "Supported VHT-MCS set"} {
		for _, m := range nssPattern.FindAllStringSubmatch(c.Extra[key], -1) {
			n, _ := strconv.Atoi(m[1])
			nss = max(nss, n)
		}
	}
	if ht := c.Extra["Supported HT MCS set"]; ht != "" {
		top := 0
		for f := range strings.FieldsFuncSeq(ht, func(r rune) bool { return r == ',' || r == ' ' }) {
			if n, err := strconv.Atoi(f); err == nil {
				top = max(top, n)
			}
		}
		nss = max(nss, top/8+1)
	}
	if r != nil {
		for _, key := range []string{"MIMO", "mimo"} {
			if v, ok := r.Extra[key]; ok {
				if n, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(v, "*", 2)[0])); err == nil && n > 0 {
					nss = min(nss, n)
				}
			}
		}
	}
	return nss
}
