package runner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// scanOutcome accumulates one scan's per-phase outcomes and the single reason the
// scan stopped short, if it did.
//
// It lives on the Runner rather than being threaded through the phase loop
// because the phase loop is not the only writer: the budget guard appends
// skipped outcomes for phases it never launches, and a phase's own teardown
// appends its result from a defer. Reset at the top of RunNativeScan — a Runner
// is reused across agent rescans, and inheriting the previous run's phase list
// would report the earlier scan's curtailment on the later scan's row.
type scanOutcome struct {
	mu         sync.Mutex
	phases     []database.PhaseOutcome
	stopReason string
}

func (s *scanOutcome) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phases = nil
	s.stopReason = ""
}

// append records a phase's outcome, coalescing onto an existing entry for the
// same phase.
//
// One entry per phase, not one per execution: full-native-scan-on-receive runs
// the whole plan once per batch of arriving records, so appending blindly would
// grow the list — and the phase_outcomes column it is serialised into — without
// bound for the life of the run. For an ordinary scan each phase appears once
// and the merge never fires. See PhaseOutcome.Merge for the fold.
func (s *scanOutcome) append(o database.PhaseOutcome) {
	if o.Phase == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.phases {
		if s.phases[i].Phase == o.Phase {
			s.phases[i].Merge(o)
			return
		}
	}
	s.phases = append(s.phases, o)
}

// setStopReason records the scan-level stop reason, keeping the FIRST one set.
// The first is the cause: a scan budget that fires makes every later phase skip,
// and reporting the last reason would name the consequence instead.
func (s *scanOutcome) setStopReason(reason string) {
	if reason == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopReason == "" {
		s.stopReason = reason
	}
}

func (s *scanOutcome) snapshot() ([]database.PhaseOutcome, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	phases := make([]database.PhaseOutcome, len(s.phases))
	copy(phases, s.phases)
	return phases, s.stopReason
}

// trackedPhaseDeadline is phaseDeadline plus one fact: whether the deadline it
// installed is what ended the phase.
//
// A phase's own max_duration used to be invisible in the result. The runner
// checked the OUTER context when it closed a phase out, so a per-phase budget
// firing inside a perfectly healthy scan left no trace anywhere — the phase
// reported "completed", the scan reported "completed", and the half of the input
// it never reached was simply absent. The deadline's cancel func is the one place
// that knows, so the mark is made there.
//
// The DeadlineExceeded-and-live-parent test is what separates "this phase ran out
// of its own budget" from "the whole scan was cancelled or ran out of the total
// budget": the latter is the scan's stop reason, reported once, not a per-phase
// defect repeated for every phase that was still running.
func (r *Runner) trackedPhaseDeadline(ctx context.Context, maxDuration time.Duration) (context.Context, context.CancelFunc) {
	child, cancel := phaseDeadline(ctx, maxDuration)
	if maxDuration <= 0 {
		return child, cancel
	}
	// Captured now rather than re-read in the closure: the phase loop clears
	// r.currentPhase as part of closing a phase out, and a deferred cancel that
	// ran after that would mark nothing.
	tracker := r.currentPhase.Load()
	return child, func() {
		if errors.Is(child.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			tracker.markPartial(database.ReasonPhaseDeadline)
		}
		cancel()
	}
}

// recordSkippedSteps appends a skipped outcome for every enabled step in steps,
// with reason as the explanation, and records that reason as the scan's stop
// reason.
//
// Called when the phase loop stops launching work. The phases it names were
// planned and enabled and then never ran, which is a coverage gap — and the only
// way a consumer can tell "this scan's plan was two phases" from "this scan's
// plan was seven and the budget ran out after two".
func (r *Runner) recordSkippedSteps(steps []NativePhaseStep, reason string) {
	r.scanOutcome.setStopReason(reason)
	for _, step := range steps {
		if !step.Enabled {
			continue
		}
		o := database.PhaseOutcome{
			Phase: string(step.Phase),
			State: database.PhaseSkipped,
		}
		if reason != "" {
			o.Reasons = []string{reason}
		}
		r.scanOutcome.append(o)
	}
}

// targetBudgetExhausted reports whether a per-target context ran out its OWN
// time box, as opposed to being torn down with its parent. Both contexts must be
// non-nil.
//
// Both cases look identical from the child alone — a cancelled parent propagates
// Canceled, but a parent that is itself past a deadline propagates
// DeadlineExceeded — so the parent has to be consulted. Call it BEFORE the
// child's cancel func: cancelling a live child rewrites Err to Canceled and the
// distinction is gone.
func targetBudgetExhausted(target, parent context.Context) bool {
	return errors.Is(target.Err(), context.DeadlineExceeded) && parent.Err() == nil
}

// Completion is the scan-level verdict: whether every phase covered what it was
// given, and if not, the one reason worth reporting.
//
// "complete" is deliberately hard to earn. Every phase must have ended completed
// or been skipped for having nothing to do, and no phase may have set a stop
// reason. Anything else is "partial", including a phase that failed — a scan that
// lost a phase is not a complete scan, whatever the remaining phases managed.
func (r *Runner) Completion() database.ScanCompletion {
	phases, stopReason := r.scanOutcome.snapshot()

	complete := stopReason == ""
	for _, p := range phases {
		switch p.State {
		case database.PhaseCompleted:
			continue
		case database.PhaseSkipped:
			// A phase skipped because there was nothing to do is not a gap. One
			// skipped because the budget ran out is exactly the gap this reports.
			if !p.BenignSkip() {
				complete = false
			}
		default:
			complete = false
		}
	}

	c := database.ScanCompletion{
		Completeness: database.CompletenessComplete,
		StopReason:   stopReason,
		Phases:       phases,
	}
	if !complete {
		c.Completeness = database.CompletenessPartial
		if c.StopReason == "" {
			c.StopReason = firstPhaseReason(phases)
		}
	}
	return c
}

// firstPhaseReason returns the first reason recorded by the first phase that did
// not complete cleanly — the explanation closest to where coverage was lost.
//
// Reasons that describe HOW work was done rather than work not being done are
// taken only as a last resort (see nonStoppingReason). The reasons within a
// phase are sorted, so without that rule an alphabetically early caveat like
// `auth_unavailable` would be reported as the scan's stop reason ahead of the
// `scan_budget` that actually ended it.
func firstPhaseReason(phases []database.PhaseOutcome) string {
	var fallback string
	for _, p := range phases {
		if p.State == database.PhaseCompleted {
			continue
		}
		for _, reason := range p.Reasons {
			if nonStoppingReason(reason) {
				if fallback == "" {
					fallback = reason
				}
				continue
			}
			return reason
		}
		if len(p.Reasons) == 0 && p.State == database.PhaseFailed {
			return database.ReasonError
		}
	}
	return fallback
}

// nonStoppingReason reports whether a reason describes a caveat about work that
// WAS done, rather than work that was not. Such a reason still makes a scan
// partial — the coverage really is reduced — but it never stopped anything, so
// it is a poor answer to "why did this scan stop".
func nonStoppingReason(reason string) bool {
	return reason == database.ReasonAuthUnavailable
}

// partialBannerSuffix renders the "— partial: …" tail of the terminal banner, or
// "" for a complete scan.
//
// On stderr, next to the duration and the finding count, because that line is
// the one an operator reads: a scan that covered two of its seven phases printed
// the same cheerful "Scan finished" as a complete one, and the only way to find
// out otherwise was to query the row afterwards. Names the phases and their
// reasons, not just the verdict, so the next action is obvious from the line.
func partialBannerSuffix(c database.ScanCompletion) string {
	if c.Completeness != database.CompletenessPartial {
		return ""
	}
	parts := make([]string, 0, len(c.Phases))
	for _, p := range c.Phases {
		if p.State == database.PhaseCompleted || p.BenignSkip() {
			continue
		}
		if len(p.Reasons) > 0 {
			parts = append(parts, p.Phase+"("+strings.Join(p.Reasons, ",")+")")
			continue
		}
		parts = append(parts, p.Phase+"("+string(p.State)+")")
	}
	if len(parts) == 0 {
		if c.StopReason == "" {
			return ""
		}
		parts = append(parts, c.StopReason)
	}
	return terminal.Yellow(" — partial: " + strings.Join(parts, ", "))
}

// scanStopReason names why the scan as a whole stopped launching work: the total
// --scanning-max-duration elapsed, or the operator cancelled the run. budgetCtx
// is the (possibly budget-bounded) context the phase loop runs under; runCtx is
// the Runner's own, which carries only cancellation.
func scanStopReason(budgetCtx, runCtx context.Context) string {
	switch {
	case runCtx != nil && runCtx.Err() != nil:
		return database.ReasonCancelled
	case budgetCtx != nil && errors.Is(budgetCtx.Err(), context.DeadlineExceeded):
		return database.ReasonScanBudget
	case budgetCtx != nil && budgetCtx.Err() != nil:
		return database.ReasonCancelled
	default:
		return ""
	}
}
