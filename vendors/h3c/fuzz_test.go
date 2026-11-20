package h3c_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/netops/capture"
	"github.com/gatework/wireless/vendors/h3c"
)

// FuzzDecode feeds arbitrary text to every parser; decoding must never
// panic and must never return more clients than there are lines.
func FuzzDecode(f *testing.F) {
	for _, name := range fixtures {
		body, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(body))
	}
	f.Add("MAC address : \n : \nRadio 1:\n    : x\n")
	v := h3c.New(h3c.Options{})
	f.Fuzz(func(t *testing.T, text string) {
		c := capture.Capture{Host: netip.MustParseAddr("198.51.100.1"), Prompt: "<AC>"}
		for _, command := range v.CollectCommands() {
			c.Outputs = append(c.Outputs, capture.Output{Command: command, Raw: text, RecordedAt: recordedAt})
		}
		s := v.Decode(c)
		if len(s.Clients.Facts) > len(text) {
			t.Fatalf("%d clients from %d bytes", len(s.Clients.Facts), len(text))
		}
	})
}
