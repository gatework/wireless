package wireless_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/gatework/wireless"
)

func TestParseMAC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"aabb-ccdd-eeff", "aa:bb:cc:dd:ee:ff", true},
		{"AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff", true},
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", true},
		{"aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff", true},
		{" aabbccddeeff ", "aa:bb:cc:dd:ee:ff", true},
		{"aa bb cc dd ee ff", "aa:bb:cc:dd:ee:ff", true},
		{"0xAABBCCDDEEFF", "aa:bb:cc:dd:ee:ff", true},
		{"ａａｂｂ－ｃｃｄｄ－ｅｅｆｆ", "aa:bb:cc:dd:ee:ff", true},
		{"aa：bb：cc：dd：ee：ff", "aa:bb:cc:dd:ee:ff", true},
		{"aabb-ccdd-eef", "", false},
		{"aabb-ccdd-eefg", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		m, err := wireless.ParseMAC(tc.in)
		if (err == nil) != tc.ok || tc.ok && m.String() != tc.want {
			t.Errorf("ParseMAC(%q) = %v, %v", tc.in, m, err)
		}
	}
}

func TestMAC_forms(t *testing.T) {
	t.Parallel()
	m, _ := wireless.ParseMAC("06:00:5e:10:00:02")
	if m.H3C() != "0600-5e10-0002" || m.Hex() != "06005e100002" || !m.Randomized() || !m.Unicast() || m.IsZero() {
		t.Errorf("forms of %v", m)
	}
	b, err := json.Marshal(m)
	if err != nil || string(b) != `"06:00:5e:10:00:02"` {
		t.Fatalf("marshal = %s %v", b, err)
	}
	var back wireless.MAC
	if err := json.Unmarshal([]byte(`"0600-5e10-0002"`), &back); err != nil || back != m {
		t.Errorf("unmarshal = %v %v", back, err)
	}
}

func TestParseMACPattern(t *testing.T) {
	t.Parallel()
	m, _ := wireless.ParseMAC("aa32-ed65-d5c7")
	tests := []struct {
		in    string
		ok    bool
		match bool
	}{
		{"d5c7", true, true},
		{"ed:65:d5", true, true},
		{"aa32*", true, true},
		{"*d5c7", true, true},
		{"*aa32", true, false},
		{"d5c7*", true, false},
		{"ＤＥ６５", true, false},
		{"abc", false, false},
		{"xyz1", false, false},
		{"0011223344556677", false, false},
	}
	for _, tc := range tests {
		p, ok := wireless.ParseMACPattern(tc.in)
		if ok != tc.ok || ok && p.Match(m) != tc.match {
			t.Errorf("ParseMACPattern(%q) ok=%v match=%v", tc.in, ok, ok && p.Match(m))
		}
	}
}

func ExampleParseMAC() {
	m, _ := wireless.ParseMAC("aa32-ED65-d5c7")
	fmt.Println(m, m.H3C())
	// Output: aa:32:ed:65:d5:c7 aa32-ed65-d5c7
}
