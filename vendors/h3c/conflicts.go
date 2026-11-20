package h3c

import (
	"strconv"
	"strings"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"

	"github.com/gatework/wireless"
)

// parseConflicts decodes "display wlan statistics client-ip-conflict":
//
//	IP            New-MAC/APID        Old-MAC/APID        Time
//	10.158.70.7   72a0-24f4-aae8/56   b0be-837f-02c1/14   10-23 18:18:45
//
// The time has no year; it is taken as the latest such time not after the
// collection time, in the controller's zone.
func parseConflicts(o capture.Output, loc *time.Location) evidence.Observation[wireless.IPConflict] {
	var sc parse.Scanner
	now := o.RecordedAt.In(loc)
	var out []wireless.IPConflict
	for _, l := range body(o) {
		fields := strings.Fields(l.Text)
		switch {
		case len(fields) == 0:
		case fields[0] == "IP" && strings.Contains(l.Text, "MAC/APID"):
		case len(fields) == 5:
			c, ok := conflict(fields, now, loc)
			if !ok {
				sc.Issue(parse.IssueUnparsed, l.Number)
				continue
			}
			out = append(out, c)
		default:
			sc.Issue(parse.IssueUnparsed, l.Number)
		}
	}
	return observe(wireless.DimensionConflicts, o, out, &sc)
}

func conflict(f []string, now time.Time, loc *time.Location) (wireless.IPConflict, bool) {
	ip := addr(f[0])
	newMAC, newAP, ok1 := macAP(f[1])
	oldMAC, oldAP, ok2 := macAP(f[2])
	at, ok3 := yearless(f[3]+" "+f[4], now, loc)
	if !ip.IsValid() || !ok1 || !ok2 || !ok3 {
		return wireless.IPConflict{}, false
	}
	return wireless.IPConflict{IP: ip, NewMAC: newMAC, NewAPID: newAP, OldMAC: oldMAC, OldAPID: oldAP, At: at}, true
}

// macAP splits "72a0-24f4-aae8/56".
func macAP(text string) (wireless.MAC, int, bool) {
	macText, apText, ok := strings.Cut(text, "/")
	if !ok {
		return wireless.MAC{}, 0, false
	}
	mac, err := wireless.ParseMAC(macText)
	ap, errAP := strconv.Atoi(apText)
	return mac, ap, err == nil && errAP == nil
}

// yearless resolves "MM-DD hh:mm:ss" to the latest matching instant not
// after now. When now is unknown the current year of the zero time would
// be meaningless, so the year is left unresolved and parsing fails.
func yearless(text string, now time.Time, loc *time.Location) (time.Time, bool) {
	if now.IsZero() {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("01-02 15:04:05", text, loc)
	if err != nil {
		return time.Time{}, false
	}
	t = t.AddDate(now.Year()-t.Year(), 0, 0)
	if t.After(now) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}

// parseBlocked decodes "display wlan client-security block-mac". Each
// entry line starts with a MAC; lines before the first entry are headers.
func parseBlocked(o capture.Output) evidence.Observation[wireless.BlockedMAC] {
	var sc parse.Scanner
	var out []wireless.BlockedMAC
	total, known := 0, false
	for _, l := range body(o) {
		text := strings.TrimSpace(l.Text)
		if text == "" {
			continue
		}
		if label, value, ok := parse.SplitLabel(text, ":"); ok && strings.EqualFold(label, "Total entries") {
			total, known = number(value)
			continue
		}
		first, rest, _ := strings.Cut(text, " ")
		mac, err := wireless.ParseMAC(first)
		switch {
		case err == nil:
			out = append(out, wireless.BlockedMAC{MAC: mac, Source: "client-security", Detail: strings.Join(strings.Fields(rest), " ")})
		case len(out) > 0:
			sc.Issue(parse.IssueUnparsed, l.Number)
		}
	}
	return observe(wireless.DimensionBlocked, o, out, &sc, countCheck(total, known, len(out))...)
}
