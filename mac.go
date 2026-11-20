package wireless

import (
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/text/width"
)

// ErrInvalidMAC reports text that is not a 48-bit MAC address.
var ErrInvalidMAC = errors.New("wireless: invalid MAC address")

// MAC is a 48-bit IEEE 802 address. The zero value is the all-zero address,
// which [MAC.IsZero] reports and which never identifies a real station.
type MAC [6]byte

// ParseMAC accepts every notation operators and devices use: H3C/Huawei
// "aabb-ccdd-eeff", Cisco "aabb.ccdd.eeff", octets separated by "-", ":",
// "." or spaces, bare hex and "0x"-prefixed hex. Case is ignored, and
// full-width characters typed with a Chinese input method ("：", "－",
// "ＡＢ") are folded to ASCII first.
func ParseMAC(text string) (MAC, error) {
	digits, ok := macDigits(normalizeInput(text))
	if !ok || len(digits) != 12 {
		return MAC{}, ErrInvalidMAC
	}
	var m MAC
	if _, err := hex.Decode(m[:], []byte(digits)); err != nil {
		return MAC{}, ErrInvalidMAC
	}
	return m, nil
}

// String returns the canonical lowercase colon form "aa:bb:cc:dd:ee:ff".
func (m MAC) String() string {
	var b strings.Builder
	b.Grow(17)
	for i, octet := range m {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex.EncodeToString([]byte{octet}))
	}
	return b.String()
}

// H3C returns the Comware form "aabb-ccdd-eeff" used in device commands.
func (m MAC) H3C() string {
	h := m.Hex()
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12]
}

// Hex returns the twelve lowercase hex digits without separators.
func (m MAC) Hex() string { return hex.EncodeToString(m[:]) }

// IsZero reports whether m is the all-zero address.
func (m MAC) IsZero() bool { return m == MAC{} }

// Unicast reports whether m is an individual (not group) address.
func (m MAC) Unicast() bool { return m[0]&0x01 == 0 }

// Randomized reports whether m is locally administered. Modern phones and
// laptops use such private addresses per SSID, so the same device may show
// a different MAC on another network or after a reset.
func (m MAC) Randomized() bool { return m[0]&0x02 != 0 }

// MarshalText encodes m in canonical form.
func (m MAC) MarshalText() ([]byte, error) { return []byte(m.String()), nil }

// UnmarshalText decodes any notation accepted by [ParseMAC].
func (m *MAC) UnmarshalText(text []byte) error {
	parsed, err := ParseMAC(string(text))
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}

// MACPattern is a partial MAC typed by an operator: hex digits with
// optional separators, matched anywhere in the address, or anchored with
// "*": "aa32*" is a prefix, "*d5c7" a suffix. At least four digits are
// required, since fewer would match too many stations to be useful.
type MACPattern struct {
	digits string
	anchor patternAnchor
}

type patternAnchor uint8

const (
	anchorContains patternAnchor = iota
	anchorPrefix
	anchorSuffix
)

// ParseMACPattern interprets text as a partial MAC. It reports false for
// text that is not hex digits, separators and one leading or trailing "*".
func ParseMACPattern(text string) (MACPattern, bool) {
	text = normalizeInput(text)
	p := MACPattern{}
	switch {
	case strings.HasSuffix(text, "*") && !strings.HasPrefix(text, "*"):
		p.anchor, text = anchorPrefix, strings.TrimSuffix(text, "*")
	case strings.HasPrefix(text, "*") && !strings.HasSuffix(text, "*"):
		p.anchor, text = anchorSuffix, strings.TrimPrefix(text, "*")
	case strings.HasPrefix(text, "*") && strings.HasSuffix(text, "*"):
		text = strings.Trim(text, "*")
	}
	digits, ok := macDigits(text)
	if !ok || len(digits) < 4 || len(digits) > 12 {
		return MACPattern{}, false
	}
	p.digits = digits
	return p, true
}

// Match reports whether m matches the pattern. The zero MAC never matches.
func (p MACPattern) Match(m MAC) bool {
	if p.digits == "" || m.IsZero() {
		return false
	}
	h := m.Hex()
	switch p.anchor {
	case anchorPrefix:
		return strings.HasPrefix(h, p.digits)
	case anchorSuffix:
		return strings.HasSuffix(h, p.digits)
	case anchorContains:
	}
	return strings.Contains(h, p.digits)
}

// String returns the normalized pattern, for example "*d5c7".
func (p MACPattern) String() string {
	switch p.anchor {
	case anchorPrefix:
		return p.digits + "*"
	case anchorSuffix:
		return "*" + p.digits
	case anchorContains:
	}
	return p.digits
}

// normalizeInput folds full-width characters, trims space, lowercases and
// drops a "0x" prefix.
func normalizeInput(text string) string {
	text = strings.ToLower(strings.TrimSpace(width.Fold.String(text)))
	return strings.TrimPrefix(text, "0x")
}

// macDigits strips the separators device notations use and lowercases the
// result. It rejects any other character.
func macDigits(text string) (string, bool) {
	var b strings.Builder
	b.Grow(len(text))
	for i := range len(text) {
		c := text[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			b.WriteByte(c)
		case c >= 'A' && c <= 'F':
			b.WriteByte(c + 'a' - 'A')
		case c == '-' || c == ':' || c == '.' || c == ' ' || c == '_':
		default:
			return "", false
		}
	}
	return b.String(), b.Len() > 0
}
