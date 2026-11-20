package wireless

import (
	"errors"
	"net/netip"
	"strings"
)

// ErrEmptyQuery reports a query with no text.
var ErrEmptyQuery = errors.New("wireless: empty query")

// Query is what an operator typed to locate something: an address, a
// subnet, a full or partial MAC, a username or an AP name. One text may
// mean several things — "18620346" is both a username and a MAC fragment —
// so a query keeps every interpretation and a search unions them.
type Query struct {
	text    string
	folded  string
	mac     MAC
	hasMAC  bool
	pattern MACPattern
	addr    netip.Addr
	prefix  netip.Prefix
}

// ParseQuery interprets text. It fails only on empty input.
func ParseQuery(text string) (Query, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Query{}, ErrEmptyQuery
	}
	q := Query{text: text, folded: strings.ToLower(text)}
	// Addresses typed with full-width digits are still addresses.
	text = normalizeInput(text)
	if addr, err := netip.ParseAddr(text); err == nil {
		q.addr = addr.Unmap()
		return q, nil
	}
	if prefix, err := netip.ParsePrefix(text); err == nil {
		q.prefix = prefix.Masked()
		return q, nil
	}
	if m, err := ParseMAC(text); err == nil {
		q.mac, q.hasMAC = m, true
		return q, nil
	}
	if p, ok := ParseMACPattern(text); ok {
		q.pattern = p
	}
	return q, nil
}

// String returns the text as typed.
func (q Query) String() string { return q.text }

// MAC returns the full MAC the query names.
func (q Query) MAC() (MAC, bool) { return q.mac, q.hasMAC }

// Addr returns the IP address the query names.
func (q Query) Addr() (netip.Addr, bool) { return q.addr, q.addr.IsValid() }

// Prefix returns the subnet the query names.
func (q Query) Prefix() (netip.Prefix, bool) { return q.prefix, q.prefix.IsValid() }

// Textual reports whether the query may be a name rather than an address.
func (q Query) Textual() bool { return !q.hasMAC && !q.addr.IsValid() && !q.prefix.IsValid() }

// MatchMAC reports whether m is the queried MAC or contains the fragment.
func (q Query) MatchMAC(m MAC) bool {
	if m.IsZero() {
		return false
	}
	if q.hasMAC {
		return m == q.mac
	}
	return q.pattern.Match(m)
}

// MatchAddr reports whether a is the queried address or inside the subnet.
func (q Query) MatchAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if q.addr.IsValid() {
		return a == q.addr
	}
	return q.prefix.IsValid() && q.prefix.Contains(a)
}

// MatchName reports whether name equals the query, ignoring case, or
// contains it when the query is at least three characters long.
func (q Query) MatchName(name string) bool {
	if !q.Textual() || name == "" {
		return false
	}
	folded := strings.ToLower(name)
	return folded == q.folded || len(q.folded) >= 3 && strings.Contains(folded, q.folded)
}
