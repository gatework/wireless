package wireless

import "fmt"

// Band is a radio frequency band.
type Band uint8

// Bands. BandUnset means the band could not be derived.
const (
	BandUnset Band = iota
	Band2G4
	Band5G
	Band6G
)

// BandOfChannel derives the band from a channel number. Channels 1–14 are
// 2.4 GHz and 32–177 are 5 GHz; 6 GHz shares numbers with 2.4 GHz and 5 GHz,
// so it can only be known from the radio type, never from the channel alone.
func BandOfChannel(channel int) Band {
	switch {
	case channel >= 1 && channel <= 14:
		return Band2G4
	case channel >= 32 && channel <= 177:
		return Band5G
	default:
		return BandUnset
	}
}

// String returns the label operators use: "2.4G", "5G" or "6G".
func (b Band) String() string {
	switch b {
	case Band2G4:
		return "2.4G"
	case Band5G:
		return "5G"
	case Band6G:
		return "6G"
	case BandUnset:
		return ""
	}
	return fmt.Sprintf("Band(%d)", uint8(b))
}

// Valid reports whether b is a declared band, including BandUnset.
func (b Band) Valid() bool { return b <= Band6G }

// MarshalText encodes b as its label.
func (b Band) MarshalText() ([]byte, error) {
	if !b.Valid() {
		return nil, fmt.Errorf("wireless: invalid band %d", uint8(b))
	}
	return []byte(b.String()), nil
}

// UnmarshalText decodes a label produced by MarshalText.
func (b *Band) UnmarshalText(text []byte) error {
	for _, candidate := range []Band{BandUnset, Band2G4, Band5G, Band6G} {
		if candidate.String() == string(text) {
			*b = candidate
			return nil
		}
	}
	return fmt.Errorf("wireless: unknown band %q", text)
}
