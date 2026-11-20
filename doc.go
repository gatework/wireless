// Package wireless is the vendor-neutral model of a campus wireless network
// as an operator sees it from its controllers: access points and radios,
// advertised BSSs, associated clients, 802.1X and MAC authentication
// sessions, IP conflict history, blacklists and the admission
// configuration that ties them together.
//
// The package answers the operator's first questions about a station —
// where is it, how did it get on the network, and is its link healthy —
// across many controllers at once. A vendor package decodes captured
// command output into a [Snapshot] per controller; an [Index] joins snapshots so a
// [Query] by IP, subnet, MAC, MAC fragment, username or AP name finds every
// related record.
//
// Every dimension of a snapshot carries go-netops evidence status. A
// partial dimension still yields facts, but conclusions drawn from it are
// marked accordingly by callers; absence of a record in an incomplete
// dimension never means "not present".
//
// The package performs no I/O.
package wireless
