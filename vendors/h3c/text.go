package h3c

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/netops/capture"

	"github.com/gatework/netops/parse"

	"github.com/gatework/wireless"
)

var (
	promptLine   = regexp.MustCompile(`^[<\[][^<>\[\]]+[>\]]$`)
	separator    = regexp.MustCompile(`^-{5,}$`)
	durationPart = regexp.MustCompile(`(\d+)\s*([a-zA-Z]+)`)
	leadingInt   = regexp.MustCompile(`^-?\d+`)
)

// body returns the response lines between the command echo and the final
// prompt, with CR and NUL bytes removed. Line numbers stay those of the
// raw response so issues point at the device output.
func body(o capture.Output) []parse.Line { return bodyContext(context.Background(), o) }

// bodyContext is body for callers that hold a context.
func bodyContext(ctx context.Context, o capture.Output) []parse.Line {
	lines, err := o.Body(ctx, promptLine.MatchString)
	if err != nil {
		return nil
	}
	return lines
}

// entryKind classifies one response line.
type entryKind uint8

const (
	entryBlank entryKind = iota
	entrySeparator
	entryField
	entryText
)

// entry is one classified line: a "Label : value" field, a text line that
// is a continuation or a table row, a separator or a blank.
type entry struct {
	parse.Line
	kind   entryKind
	indent int
	label  string
	value  string
}

func classify(l parse.Line) entry {
	text := strings.TrimRight(l.Text, " \t")
	trimmed := strings.TrimLeft(text, " ")
	e := entry{Line: l, indent: len(text) - len(trimmed)}
	switch {
	case trimmed == "":
		e.kind = entryBlank
	case separator.MatchString(trimmed):
		e.kind = entrySeparator
	default:
		if label, value, ok := parse.SplitLabel(trimmed, ":"); ok {
			e.kind, e.label, e.value = entryField, label, value
			break
		}
		e.kind = entryText
		e.value = strings.TrimSpace(strings.TrimPrefix(trimmed, ":"))
	}
	return e
}

// record accumulates the fields of one device record. Fields named by the
// label table are stored under their canonical name; every other label
// keeps its device spelling in extra.
type record struct {
	line   int
	values map[string]string
	extra  map[string]string
	// lastKey and lastExtra locate the field a continuation line extends.
	lastKey   string
	lastExtra bool
}

func newRecord(line int) *record {
	return &record{line: line, values: map[string]string{}, extra: map[string]string{}}
}

func (r *record) set(table *parse.LabelTable, label, value string) {
	if key, ok := table.Field(label); ok {
		r.values[key], r.lastKey, r.lastExtra = value, key, false
		return
	}
	r.extra[label], r.lastKey, r.lastExtra = value, label, true
}

func (r *record) extend(text string) {
	if r.lastKey == "" {
		return
	}
	target := r.values
	if r.lastExtra {
		target = r.extra
	}
	if target[r.lastKey] == "" {
		target[r.lastKey] = text
		return
	}
	target[r.lastKey] += " " + text
}

// str returns a field's value with device placeholders mapped to empty.
func (r *record) str(key string) string { return clean(r.values[key]) }

// lower returns str lowercased.
func (r *record) lower(key string) string { return strings.ToLower(r.str(key)) }

// akm returns the normalized AKM: "not configured" is an open SSID.
func (r *record) akm(key string) string {
	v := strings.ToLower(strings.TrimSpace(r.values[key]))
	if v == "not configured" {
		return wireless.AKMNone
	}
	return strings.ToLower(clean(v))
}

// num returns the leading integer of a field, or zero.
func (r *record) num(key string) int {
	n, _ := number(r.str(key))
	return n
}

// mac returns a field parsed as a MAC address, or the zero MAC.
func (r *record) mac(key string) wireless.MAC {
	m, _ := wireless.ParseMAC(r.str(key))
	return m
}

// extras returns the non-empty unnamed fields, or nil.
func (r *record) extras() map[string]string {
	out := map[string]string{}
	for k, v := range r.extra {
		if v = clean(v); v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// clean trims a value and maps the device's "nothing here" words to "".
func clean(v string) string {
	v = strings.TrimSpace(v)
	switch strings.ToLower(v) {
	case "n/a", "not configured", "not available", "unknown":
		return ""
	}
	return v
}

// number parses the leading integer of text such as "8 dBm", "-97 dBm"
// or "11(auto)".
func number(text string) (int, bool) {
	digits := leadingInt.FindString(strings.TrimSpace(text))
	if digits == "" {
		return 0, false
	}
	n, err := strconv.Atoi(digits)
	return n, err == nil
}

// pair parses "143.4/108.3 Mbps" or "16.532/588.672Kbps" into two values.
func pair(text string) (float64, float64, bool) {
	first, second, ok := strings.Cut(text, "/")
	if !ok {
		return 0, 0, false
	}
	a, errA := strconv.ParseFloat(strings.TrimSpace(first), 64)
	b, errB := strconv.ParseFloat(strings.TrimRight(strings.TrimSpace(second), "MKGbps "), 64)
	if errA != nil || errB != nil {
		return 0, 0, false
	}
	return a, b, true
}

// duration parses the three spellings Comware uses for elapsed time:
// "0days 1hours 33minutes 43seconds", "229 days 5 hours 35 minutes 39
// seconds" and "349h 14m 42s".
func duration(text string) (time.Duration, bool) {
	matches := durationPart.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return 0, false
	}
	var total time.Duration
	for _, m := range matches {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, false
		}
		var unit time.Duration
		switch strings.ToLower(m[2])[0] {
		case 'd':
			unit = 24 * time.Hour
		case 'h':
			unit = time.Hour
		case 'm':
			unit = time.Minute
		case 's':
			unit = time.Second
		default:
			return 0, false
		}
		total += time.Duration(n) * unit
	}
	return total, true
}
