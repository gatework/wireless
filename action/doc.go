// Package action plans operator actions on one station (disconnect it, add
// it to or remove it from the static blacklist) as netops change plans.
//
// A plan is executed by the shared apply state machine exactly once: read
// the station's state, skip when the action is already in effect (the
// station is gone, already listed, already unlisted), send the commands,
// read back and verify the effect. A kick is verified relative to the state
// before, because a disconnected station may reassociate at once. Nothing
// is retried; a block can be undone through its rollback commands.
//
// Vendor syntax comes from a [Renderer].
package action
