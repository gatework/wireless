// Package diagnose explains one wireless station the way an operator
// troubleshoots it: bottom-up through the association, the radio link,
// authentication, addressing, access control and the serving AP. Each
// layer yields findings with a level and an operator-facing message;
// thresholds are explicit and tunable.
//
// Conclusions respect evidence completeness: a missing authentication
// session is reported only when the controller's session list was
// complete.
package diagnose
