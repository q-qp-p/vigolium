//go:build !unix

package scratch

import "os"

// Windows has no flock and no signal-0 liveness probe, so collection there stays
// age-only — the behavior every platform had before the lease. The no-ops are
// written out rather than guarded at every call site so sweepDir reads the same
// on both platforms.

func acquireLease(string) (*os.File, error) { return nil, nil }

// leaseHeld always reports "unknown", which sends sweepDir to the pid check;
// pidAlive then reports false, so the age check decides, as it always did.
func leaseHeld(string) (held, known bool) { return false, false }

func pidAlive(int) bool { return false }
