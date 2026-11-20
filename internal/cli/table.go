package cli

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/gatework/netops/term"

	"github.com/gatework/wireless"
)

// table renders aligned columns with netops/term: East Asian wide
// characters count two columns and every cell is sanitized.
type table struct {
	t *term.Table
}

func newTable(header ...string) *table { return &table{t: term.NewTable(header...)} }

func (t *table) add(cells ...string) { t.t.Add(cells...) }

// list renders t limited to the --limit rows, noting how many were left
// out, so a broad query shows its head and its size instead of
// scrolling thousands of lines.
func (a *app) list(t *table) error {
	omitted, err := t.t.Render(a.env.Stdout, a.limit)
	if err != nil {
		return fmt.Errorf("cli: %w", err)
	}
	if omitted > 0 {
		a.printf(msgTruncated, t.t.Len()-omitted, t.t.Len())
	}
	return nil
}

func (t *table) render(w io.Writer) error {
	if _, err := t.t.Render(w, 0); err != nil {
		return fmt.Errorf("cli: %w", err)
	}
	return nil
}

func displayWidth(s string) int { return term.Width(s) }

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func macCell(m wireless.MAC) string {
	if m.IsZero() {
		return "-"
	}
	return m.H3C()
}

func addrCell(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.String()
}

func intCell(n int) string {
	if n == 0 {
		return "-"
	}
	return fmt.Sprint(n)
}

// durationCell prints the two largest units: "3d4h", "4h34m", "12m5s".
func durationCell(d time.Duration) string { return term.Duration(d) }

func timeCell(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

func percentCell(n int) string { return fmt.Sprintf("%d%%", n) }
