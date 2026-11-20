package h3c

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/netops/capture"

	"github.com/gatework/wireless"
)

// ErrRoamTrack reports a roam-track response with no recognizable row.
var ErrRoamTrack = errors.New("h3c: unrecognized roam-track output")

var (
	createdAt = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)
	// trackOnline matches "00hr 48min 46sec" (V7) and "0000:00:02:44"
	// (d:h:m:s, earlier releases).
	trackOnline = regexp.MustCompile(`\d+hr \d+min \d+sec|\d+:\d{2}:\d{2}:\d{2}`)
)

// RoamTrackCommand returns the command that prints a station's roam
// history on the controller that is its home.
func RoamTrackCommand(mac wireless.MAC) string {
	return "display wlan mobility roam-track mac-address " + mac.H3C()
}

// RoamTrack decodes the roam history table:
//
//	BSSID          Created at           Online time       AC IP address  RID  AP name
//	3ce5-a68d-2280 2016-06-14 11:12:28  00hr 48min 46sec 127.0.0.1      2    ap1
//
// Rows are recognized by a leading BSSID; columns are found by their
// content rather than position, so releases that omit or reorder columns
// still parse. Records are returned oldest first.
func (v *Vendor) RoamTrack(ctx context.Context, o capture.Output) ([]wireless.RoamRecord, error) {
	var out []wireless.RoamRecord
	for _, l := range bodyContext(ctx, o) {
		text := strings.TrimSpace(l.Text)
		if strings.HasPrefix(text, "%") {
			return nil, errRejected
		}
		first, _, _ := strings.Cut(text, " ")
		bssid, err := wireless.ParseMAC(first)
		if err != nil {
			continue
		}
		out = append(out, v.roamRow(bssid, text))
	}
	if len(out) == 0 && !emptyTrack(ctx, o) {
		return nil, ErrRoamTrack
	}
	// The controller prints newest first. Sort by start time when every
	// row has one; otherwise reverse the printed order.
	if slices.ContainsFunc(out, func(r wireless.RoamRecord) bool { return r.CreatedAt.IsZero() }) {
		slices.Reverse(out)
	} else {
		slices.SortStableFunc(out, func(a, b wireless.RoamRecord) int { return a.CreatedAt.Compare(b.CreatedAt) })
	}
	return out, nil
}

func (v *Vendor) roamRow(bssid wireless.MAC, text string) wireless.RoamRecord {
	r := wireless.RoamRecord{BSSID: bssid}
	rest := strings.TrimSpace(strings.TrimPrefix(text, strings.Fields(text)[0]))
	if m := createdAt.FindString(rest); m != "" {
		r.CreatedAt, _ = time.ParseInLocation("2006-01-02 15:04:05", m, v.location)
		rest = strings.Replace(rest, m, "", 1)
	}
	if m := trackOnline.FindString(rest); m != "" {
		r.Online = trackDuration(m)
		rest = strings.Replace(rest, m, "", 1)
	}
	fields := strings.Fields(rest)
	for i, f := range fields {
		a, err := netip.ParseAddr(f)
		if err != nil {
			continue
		}
		r.AC = a
		tail := fields[i+1:]
		if len(tail) > 0 {
			if n, err := strconv.Atoi(tail[0]); err == nil {
				r.RadioID, tail = n, tail[1:]
			}
		}
		r.APName = strings.Join(tail, " ")
		break
	}
	return r
}

// trackDuration parses both online-time spellings.
func trackDuration(s string) time.Duration {
	if d, ok := duration(s); ok && strings.Contains(s, "hr") {
		return d
	}
	parts := strings.Split(s, ":")
	if len(parts) != 4 {
		return 0
	}
	units := []time.Duration{24 * time.Hour, time.Hour, time.Minute, time.Second}
	var total time.Duration
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0
		}
		total += time.Duration(n) * units[i]
	}
	return total
}

// emptyTrack reports a response that states it has no entries.
func emptyTrack(ctx context.Context, o capture.Output) bool {
	lines := bodyContext(ctx, o)
	for _, l := range lines {
		if label, value, ok := strings.Cut(strings.TrimSpace(l.Text), ":"); ok && strings.EqualFold(strings.TrimSpace(label), "Total entries") {
			n, _ := number(value)
			return n == 0
		}
	}
	return strings.TrimSpace(o.Raw) == "" || len(lines) == 0
}
