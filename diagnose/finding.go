package diagnose

import (
	"fmt"
	"slices"
)

// Level ranks a finding. The zero value is LevelOK.
type Level uint8

// Levels in increasing severity.
const (
	LevelOK Level = iota
	LevelInfo
	LevelWarn
	LevelFail
)

var levelNames = [...]string{LevelOK: "ok", LevelInfo: "info", LevelWarn: "warn", LevelFail: "fail"}

// String returns "ok", "info", "warn" or "fail".
func (l Level) String() string {
	if l.Valid() {
		return levelNames[l]
	}
	return fmt.Sprintf("Level(%d)", uint8(l))
}

// Valid reports whether l is a declared level.
func (l Level) Valid() bool { return int(l) < len(levelNames) }

// MarshalText encodes l as its name.
func (l Level) MarshalText() ([]byte, error) {
	if !l.Valid() {
		return nil, fmt.Errorf("diagnose: invalid level %d", uint8(l))
	}
	return []byte(l.String()), nil
}

// UnmarshalText decodes a name produced by MarshalText.
func (l *Level) UnmarshalText(text []byte) error {
	i := slices.Index(levelNames[:], string(text))
	if i < 0 {
		return fmt.Errorf("diagnose: unknown level %q", text)
	}
	*l = Level(i)
	return nil
}

// Layer is where in the station's path a finding sits, from the radio link
// up to the controller. Troubleshooting works bottom-up: a failure in a
// lower layer usually explains the symptoms above it.
type Layer string

// Layers in troubleshooting order.
const (
	LayerAssociation Layer = "association"
	LayerRadio       Layer = "radio"
	LayerAuth        Layer = "auth"
	LayerAddress     Layer = "address"
	LayerControl     Layer = "control"
	LayerAP          Layer = "ap"
)

// Layers returns every layer in troubleshooting order.
func Layers() []Layer {
	return []Layer{LayerAssociation, LayerRadio, LayerAuth, LayerAddress, LayerControl, LayerAP}
}

// Finding is one conclusion about a station.
type Finding struct {
	Layer Layer `json:"layer"`
	Level Level `json:"level"`
	// Code is a stable identifier; Message is its operator-facing text.
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

// newFinding renders the message of code with args.
func newFinding(layer Layer, level Level, code Code, args ...any) Finding {
	return Finding{Layer: layer, Level: level, Code: code, Message: fmt.Sprintf(messages[code], args...)}
}
