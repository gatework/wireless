// Package health inspects a fleet of wireless controllers with the
// go-netops assess engine: AP availability and CAPWAP stability, radio
// load and coverage, license headroom, admission security, addressing
// problems and cross-controller consistency.
//
// Rules run per controller and are gated by that controller's evidence,
// so a partial dimension skips the rules that need it instead of letting
// them conclude "healthy".
package health
