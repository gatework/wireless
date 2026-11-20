package h3c

import (
	"regexp"
	"strings"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"

	"github.com/gatework/wireless"
)

var (
	radioHeader = regexp.MustCompile(`^Radio (\d+)$`)
	channelMode = regexp.MustCompile(`\(([^)]*)\)`)
)

// apParser walks "display wlan ap all verbose". The layout nests three
// levels by indentation: AP fields at column 0, "Radio N:" sections whose
// fields are indented, and rate/MCS subsections indented further.
type apParser struct {
	sc      *parse.Scanner
	header  map[string]string
	aps     []*apRecord
	current *apRecord
	// radio is the open radio section; section is the open subsection
	// label inside it, and sectionIndent the indent of its header.
	radio         *record
	section       string
	sectionIndent int
}

type apRecord struct {
	fields *record
	radios []*record
}

// parseAccessPoints decodes the AP list and the license header.
func parseAccessPoints(o capture.Output) (evidence.Observation[wireless.AccessPoint], wireless.APCapacity) {
	var sc parse.Scanner
	p := &apParser{sc: &sc, header: map[string]string{}}
	for _, l := range body(o) {
		p.line(classify(l))
	}
	aps := make([]wireless.AccessPoint, 0, len(p.aps))
	for _, r := range p.aps {
		aps = append(aps, r.accessPoint())
	}
	capacity := p.capacity()
	return observe(wireless.DimensionAccessPoints, o, aps, &sc, countCheck(capacity.Total, p.has("total number of aps"), len(aps))...), capacity
}

func (p *apParser) line(e entry) {
	switch e.kind {
	case entryBlank:
	case entrySeparator:
		p.radio, p.section = nil, ""
	case entryText:
		p.text(e)
	case entryField:
		p.field(e)
	}
}

func (p *apParser) field(e entry) {
	if key, ok := apLabels.Field(e.label); ok && key == "name" && e.indent == 0 {
		p.current = &apRecord{fields: newRecord(e.Number)}
		p.aps = append(p.aps, p.current)
		p.radio, p.section = nil, ""
	}
	if p.current == nil {
		p.header[parse.NormalizeLabel(e.label)] = e.value
		return
	}
	if m := radioHeader.FindStringSubmatch(e.label); m != nil && e.indent == 0 && e.value == "" {
		p.radio, p.section = newRecord(e.Number), ""
		p.radio.values["id"] = m[1]
		p.current.radios = append(p.current.radios, p.radio)
		return
	}
	if p.radio == nil || e.indent == 0 {
		p.radio, p.section = nil, ""
		p.current.fields.set(apLabels, e.label, e.value)
		return
	}
	p.radioField(e)
}

// radioField stores a field of the open radio. A field with no value opens
// a subsection whose deeper-indented children are kept as "Section/Label".
func (p *apParser) radioField(e entry) {
	if p.section != "" && e.indent > p.sectionIndent {
		p.radio.set(radioLabels, p.section+"/"+e.label, e.value)
		return
	}
	p.section = ""
	if e.value == "" {
		p.section, p.sectionIndent = e.label, e.indent
		return
	}
	p.radio.set(radioLabels, e.label, e.value)
}

func (p *apParser) text(e entry) {
	switch {
	case p.radio != nil:
		p.radio.extend(e.value)
	case p.current != nil:
		p.current.fields.extend(e.value)
	default:
		p.sc.Issue(parse.IssueUnparsed, e.Number)
	}
}

func (p *apParser) has(label string) bool {
	_, ok := p.header[label]
	return ok
}

func (p *apParser) count(label string) int {
	n, _ := number(p.header[label])
	return n
}

func (p *apParser) capacity() wireless.APCapacity {
	return wireless.APCapacity{
		Total:             p.count("total number of aps"),
		Connected:         p.count("total number of connected aps"),
		Max:               p.count("maximum supported aps"),
		Licenses:          p.count("total ap licenses"),
		LicensesRemaining: p.count("remaining local ap licenses"),
	}
}

func (r *apRecord) accessPoint() wireless.AccessPoint {
	f := r.fields
	ap := wireless.AccessPoint{
		Name:         f.str("name"),
		ID:           f.num("id"),
		Group:        f.str("group"),
		State:        wireless.APState(f.str("state")),
		Model:        f.str("model"),
		Serial:       f.str("serial"),
		MAC:          f.mac("mac"),
		IP:           addr(f.str("ip")),
		Software:     f.str("software"),
		RebootReason: f.str("reboot"),
		Power:        f.str("power"),
		Description:  f.str("description"),
		EchoRequests: f.num("echo"),
		LostEchoes:   f.num("lost"),
		Extra:        f.extras(),
	}
	ap.Online, _ = duration(f.str("online"))
	ap.Uptime, _ = duration(f.str("uptime"))
	for _, rr := range r.radios {
		ap.Radios = append(ap.Radios, radio(rr))
	}
	return ap
}

func radio(r *record) wireless.Radio {
	channel := r.str("channel")
	rd := wireless.Radio{
		ID:         r.num("id"),
		BSSID:      r.mac("bssid"),
		Up:         strings.EqualFold(r.str("state"), "up"),
		Type:       r.str("type"),
		Bandwidth:  r.str("bandwidth"),
		Usage:      r.num("usage"),
		MaxPower:   r.num("power"),
		NoiseFloor: r.num("noise"),
		Extra:      r.extras(),
	}
	rd.Channel, _ = number(channel)
	if m := channelMode.FindStringSubmatch(channel); m != nil {
		rd.ChannelMode = m[1]
	}
	return rd
}
