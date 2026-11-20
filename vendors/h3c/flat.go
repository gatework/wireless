package h3c

import (
	"strconv"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"
)

// flatSpec describes a list of "Label : value" records that each begin
// with the same label, such as clients, BSSs and authentication sessions.
//
// Records are split on their first label, never on blank lines: Comware
// prints usernames with an embedded line break, which leaves a blank line
// inside the record.
type flatSpec struct {
	// start is the canonical field that opens a record.
	start  string
	labels *parse.LabelTable
}

// flatResult is the parsed records plus the summary lines before them.
type flatResult struct {
	records []*record
	header  map[string]string
}

func parseFlat(lines []parse.Line, spec flatSpec, sc *parse.Scanner) flatResult {
	res := flatResult{header: map[string]string{}}
	var current *record
	for _, l := range lines {
		e := classify(l)
		switch e.kind {
		case entryBlank, entrySeparator:
		case entryField:
			if key, ok := spec.labels.Field(e.label); ok && key == spec.start {
				current = newRecord(e.Number)
				res.records = append(res.records, current)
			}
			if current == nil {
				res.header[parse.NormalizeLabel(e.label)] = e.value
				continue
			}
			current.set(spec.labels, e.label, e.value)
		case entryText:
			if current == nil {
				sc.Issue(parse.IssueUnparsed, e.Number)
				continue
			}
			current.extend(e.value)
		}
	}
	return res
}

// reported returns the header count named by label.
func (r flatResult) reported(label string) (int, bool) {
	v, ok := r.header[label]
	if !ok {
		return 0, false
	}
	return number(v)
}

// observe builds a dimension's observation from parsed facts. A response
// that did not end at the prompt, an unparsed line or a count that
// disagrees with the device's own total makes it partial; the facts are
// kept either way.
func observe[T any](dim evidence.Dimension, o capture.Output, facts []T, sc *parse.Scanner, extra ...evidence.Issue) evidence.Observation[T] {
	status := sc.Status(o.OK())
	for _, i := range extra {
		if i.Code != codeCountDrift {
			status = evidence.StatusPartial
		}
	}
	issues := append(sc.Issues(), extra...)
	source := evidence.SourceRef{Command: o.Command, Digest: o.Digest()}
	obs, err := evidence.NewObservation(dim, status, o.RecordedAt, facts, issues, []evidence.SourceRef{source})
	if err != nil {
		obs = evidence.Observation[T]{Dimension: dim, Status: evidence.StatusPartial, ObservedAt: o.RecordedAt, Facts: facts, Issues: issues}
	}
	return obs
}

// Accounting issue codes.
const (
	// codeCountMismatch makes a dimension partial: records are missing or
	// the output was cut.
	codeCountMismatch = "count_mismatch"
	// codeCountDrift is informational: the device's total and the records
	// differ by no more than stations joining or leaving while a large
	// table prints.
	codeCountDrift = "count_drift"
)

// countCheck compares the device's total with the records parsed. The
// table changes while it prints, so a small difference — at most
// max(2, 0.5%) — is drift that leaves the dimension complete; anything
// larger is a mismatch.
func countCheck(expected int, known bool, observed int) []evidence.Issue {
	if !known || expected == observed {
		return nil
	}
	code := codeCountMismatch
	if diff := max(expected-observed, observed-expected); diff <= max(2, expected/200) {
		code = codeCountDrift
	}
	return []evidence.Issue{{Code: code, Fields: []evidence.Field{
		{Key: "expected", Value: strconv.Itoa(expected)}, {Key: "observed", Value: strconv.Itoa(observed)},
	}}}
}

// failed is the observation of a dimension whose command did not run.
func failed[T any](dim evidence.Dimension, command, code string) evidence.Observation[T] {
	return evidence.Failed[T](dim, code, evidence.SourceRef{Command: command})
}
