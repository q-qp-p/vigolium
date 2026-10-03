package runner

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// shutdownWriters shuts the given writers down in the order passed and reports the
// combined outcome for a phase.
//
// Order is the caller's: findings before records, because a finding's evidence is
// written through the record writer, so draining records first could leave a
// finding referencing a record that never landed.
//
// A writer's Close() used to return nothing, so a phase could not tell a clean
// drain from one that lost a batch or ran out of its deadline with writes still
// queued — the scan reported success either way. The outcome now goes to both
// consumers: a log line an operator can act on, and the phase's own outcome, so
// the scan row and the event stream carry "persistence_incomplete" rather than
// leaving it buried in a warning nobody greps for.
func (r *Runner) shutdownWriters(phase string, writers ...database.PersistenceShutdowner) database.PersistenceOutcome {
	var combined database.PersistenceOutcome
	for _, w := range writers {
		if w == nil {
			continue
		}
		combined.Merge(w.Shutdown())
	}
	r.reportWriterOutcome(phase, combined)
	r.currentPhase.Load().addPersistence(combined)
	return combined
}

// reportWriterOutcome logs a non-clean persistence outcome to both the process log
// and the scan's own log, and says nothing at all when everything landed.
func (r *Runner) reportWriterOutcome(phase string, o database.PersistenceOutcome) {
	if o.Clean() {
		return
	}

	zap.L().Warn("phase persistence incomplete",
		zap.String("phase", phase),
		zap.String("writer", o.Writer),
		zap.Int64("accepted", o.Accepted),
		zap.Int64("committed", o.Committed),
		zap.Int64("failed", o.Failed),
		zap.Int64("unknown", o.Unknown),
		zap.Bool("timed_out", o.TimedOut))

	if r.scanLogger == nil {
		return
	}
	msg := fmt.Sprintf(
		"persistence incomplete (%s): accepted=%d committed=%d failed=%d unknown=%d",
		o.Writer, o.Accepted, o.Committed, o.Failed, o.Unknown)
	if o.TimedOut {
		msg += "; the writer's flush deadline expired"
	}
	r.scanLogger.Warn(phase, msg)
}
