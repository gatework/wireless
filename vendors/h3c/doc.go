// Package h3c decodes the CLI output of H3C Comware V7 wireless
// controllers (WX/AC series, releases R5474–R5814) into the wireless
// model, and renders the commands of operator actions.
//
// Parsing is tolerant by design: unknown labels are kept as extra
// attributes, release-specific spellings are declared as label synonyms,
// and a response that disagrees with its own reported totals is marked
// partial rather than rejected, because tables change while they print.
// Configuration secrets (keys, passwords, pre-shared keys) are never read.
package h3c
