package database

import (
	"sync"
	"sync/atomic"
	"time"
)

// Shutdown plumbing shared by the buffered writers (RecordWriter, FindingWriter).
// It lives beside them rather than in outcome.go, whose subject is the outcome
// vocabulary a consumer reads; nothing here is part of that vocabulary.

// shutdownBudget is the one-absolute-deadline protocol a buffered writer's
// shutdown runs on, plus the once-only outcome that shutdown computes. Both
// RecordWriter and FindingWriter embed it, so the protocol is stated here once
// instead of in each writer.
//
// The protocol: Shutdown calls publish BEFORE waking the drain, and every
// subsequent step — the wait for in-flight enqueues, each flush the drain
// performs, the wait for the flush loops to exit — derives its own bound from
// that single deadline. Each of those used to start a FlushTimeout of its own,
// so a wedged database could hold a close for two or three times the configured
// budget while the caller learned nothing about what was lost.
type shutdownBudget struct {
	// deadline is the published absolute deadline in unix nanos. Zero means no
	// shutdown has started.
	deadline atomic.Int64
	once     sync.Once
	outcome  PersistenceOutcome
}

// publish records and returns the absolute deadline the whole shutdown shares.
// Call it inside once.Do, before anything that could wake the drain.
func (b *shutdownBudget) publish(d time.Duration) time.Time {
	deadline := time.Now().Add(d)
	b.deadline.Store(deadline.UnixNano())
	return deadline
}

// drainDeadline returns the deadline a drain flush must respect: the one
// Shutdown published, or fallback from now when nothing was published — which
// means the drain woke for some reason other than Shutdown, and fallback is then
// the documented bound.
func (b *shutdownBudget) drainDeadline(fallback time.Duration) time.Time {
	if nanos := b.deadline.Load(); nanos > 0 {
		return time.Unix(0, nanos)
	}
	return time.Now().Add(fallback)
}

// waitBounded waits for wg with a timeout. Returns true if the group completed,
// false if the timeout elapsed first.
//
// A non-positive timeout reports expiry immediately without waiting. Callers
// derive the timeout from a shared absolute deadline, so a non-positive value
// means that deadline has already passed — and spending even one more moment on a
// budget that is gone is what the shared deadline exists to prevent.
func waitBounded(wg *sync.WaitGroup, timeout time.Duration) bool {
	if timeout <= 0 {
		return false
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// nonNegative clamps a derived count to zero. The counters a writer subtracts to
// get Unknown are read without a lock and advance independently, so a drain that
// finishes while Shutdown is computing can make the difference go negative — a
// negative "records that may not have landed" is worse than reporting none.
func nonNegative(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}
