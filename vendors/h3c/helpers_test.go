package h3c_test

import (
	"encoding/json"
	"strconv"
	"testing"
)

func jsonText(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func itoa(n int) string { return strconv.Itoa(n) }
