package cli

import "github.com/gatework/netops/term"

// safe escapes control and invisible format characters in device text
// before it reaches the terminal.
func safe(s string) string { return term.Sanitize(s) }

// safeArgs applies safe to every string argument.
func safeArgs(args []any) []any {
	out := make([]any, len(args))
	for i, a := range args {
		if s, ok := a.(string); ok {
			a = safe(s)
		}
		out[i] = a
	}
	return out
}
