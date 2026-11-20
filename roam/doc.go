// Package roam analyzes station mobility the way an operator reasons
// about it:
//
//   - sticky clients stay on a far AP with a weak signal although other
//     APs of the same group could serve them; the confidence rises when
//     the station cannot be steered (no 802.11v BTM) or the radio has no
//     anti-sticky protection;
//   - ping-pong roaming bounces between two or three APs within minutes,
//     usually because their cells overlap at a marginal signal or share a
//     channel;
//   - radio policy can itself cause loops, for example an anti-sticky
//     threshold above the association reject threshold.
//
// Sticky detection works on one snapshot. Roaming sequences need a track:
// observations from periodic collections, or the controller's roam
// history. The package does no I/O.
package roam
