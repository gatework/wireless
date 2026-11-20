// Package quality scores the link quality of a wireless station from what
// a controller reports, and names the main cause when it is not
// excellent.
//
// Five factors — signal, rate efficiency, airtime, noise and radio load —
// are each mapped to 0–100 by a piecewise linear curve. The total is
// their weighted mean, capped at the weakest factor plus a slack, so that
// a single severe problem dominates the grade. The cause interprets the
// weakest factor in context: busy airtime is congestion when the radio
// carries many clients and interference when it does not.
//
// All thresholds live in a [Profile] and can be tuned.
package quality
