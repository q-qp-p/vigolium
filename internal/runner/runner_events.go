package runner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/knownissuescan"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// progressInterval is how often a running phase reports phase.progress.
//
// Five seconds, because the counter this reports is the ONLY thing a consumer
// can read during a crawl that runs 5–15 minutes with no other output. Longer
// and a driver cannot distinguish "working" from "wedged" inside a reasonable
// patience window; shorter and a long scan's stream is mostly heartbeat.
const progressInterval = 5 * time.Second

// phaseTracker owns one phase's slice of the event stream: the started line, a
// progress heartbeat for as long as the phase runs, and the finished line with
// the phase's totals.
//
// It is ALSO the phase's outcome ledger, and that part runs whether or not a
// stream is attached. The two were separate once, and the separation was the
// bug: the only record of "this phase was cut short" lived on an event nobody
// emitted unless --events was passed, so a plain CLI scan and the scan row it
// wrote reported a clean completion for a run that had covered half its input.
// Recording always, emitting conditionally, means the database and the stream
// agree and neither depends on the other being switched on.
//
// The request counters are read off the shared requester rather than accumulated
// here, so a phase that dispatches through a clone (every phase does) is counted
// the same way as one that does not, and nothing on the request hot path has to
// know the event stream exists.
type phaseTracker struct {
	phase     string
	start     time.Time
	requester *http.Requester
	baseSent  int64
	findings  atomic.Int64
	stop      chan struct{}
	stopped   chan struct{}

	// mu guards the outcome ledger. Marks arrive from goroutines the phase does
	// not own — a deadline cancel func, an executor's worker teardown, a deferred
	// writer shutdown — while the phase goroutine is reading them in finish.
	mu         sync.Mutex
	reasons    map[string]struct{}
	limits     map[string]struct{}
	errs       int
	firstErr   string
	skipped    bool
	persist    database.PersistenceOutcome
	hasPersist bool
	unacked    int64
	counters   []phaseCounter
}

// phaseCounter is one additional request counter a phase contributes, with the
// value it held when it was registered. The delta is what counts: a counter whose
// owner was already in use before the phase began must only contribute what
// happened inside the phase.
type phaseCounter struct {
	read func() int64
	base int64
}

// beginPhase emits phase.started and starts the progress heartbeat. The returned
// tracker is always non-nil so the caller's finish call needs no guard; when the
// stream is off it still records the phase's outcome and simply emits nothing.
func (r *Runner) beginPhase(ctx context.Context, phase string, requester *http.Requester) *phaseTracker {
	t := &phaseTracker{
		phase:     phase,
		start:     time.Now(),
		requester: requester,
		reasons:   make(map[string]struct{}),
		limits:    make(map[string]struct{}),
	}
	if !scanevents.On() {
		return t
	}
	t.baseSent = requester.RequestsSent()
	scanevents.Emit(scanevents.Event{Type: scanevents.TypePhaseStarted, Phase: phase})

	t.stop = make(chan struct{})
	t.stopped = make(chan struct{})
	go t.heartbeat(ctx)
	return t
}

func (t *phaseTracker) heartbeat(ctx context.Context) {
	defer close(t.stopped)
	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			scanevents.Emit(scanevents.Event{
				Type:         scanevents.TypePhaseProgress,
				Phase:        t.phase,
				RequestsSent: scanevents.Int64(t.sentSoFar()),
				Findings:     scanevents.Int64(t.findings.Load()),
			})
		case <-t.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (t *phaseTracker) sentSoFar() int64 {
	var total int64
	if t.requester != nil {
		total = t.requester.RequestsSent() - t.baseSent
	}
	t.mu.Lock()
	for _, c := range t.counters {
		total += c.read() - c.base
	}
	t.mu.Unlock()
	return total
}

// addCounter registers an additional request counter with the running phase, read
// as a delta from its value right now.
//
// The tracker's primary figure is a delta on the SHARED requester, which is the
// right reading for every phase that dispatches through it. Two do not: discovery
// runs deparos, which owns its own HTTP client, and a rate-limit-overridden probe
// builds a phase-local requester. Both reported ≈0 requests for phases that sent
// the bulk of a scan's traffic. A counter added here is summed into every
// phase.progress and phase.finished line for the rest of the phase.
//
// Safe to call concurrently with the heartbeat that reads them.
func (t *phaseTracker) addCounter(f func() int64) {
	if t == nil || f == nil {
		return
	}
	base := f()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.counters = append(t.counters, phaseCounter{read: f, base: base})
}

// recordFinding counts a finding against the running phase, so phase.finished
// reports what the phase actually produced rather than a scan-wide total.
func (t *phaseTracker) recordFinding() {
	if t == nil {
		return
	}
	t.findings.Add(1)
}

// addCode inserts code into *set, allocating the set on first use and ignoring
// an empty code. Caller holds t.mu.
//
// The sets are lazily allocated because beginPhase is not the only way a tracker
// comes into existence — a bare &phaseTracker{} is a valid, nil-safe one — so
// every writer has to tolerate a nil map.
func addCode(set *map[string]struct{}, code string) {
	if code == "" {
		return
	}
	if *set == nil {
		*set = make(map[string]struct{})
	}
	(*set)[code] = struct{}{}
}

// markPartial records a reason the phase did not cover everything it was given.
// Idempotent per code: the same reason arriving from two places (a deadline that
// fired AND the skipped-target count it produced) is one reason, not two.
func (t *phaseTracker) markPartial(code string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	addCode(&t.reasons, code)
}

// noteLimit records that a configured bound was reached. Separate from a reason
// on purpose: a target that used its whole time budget behaved exactly as
// configured, and folding that into "partial" would mark every properly
// time-boxed scan as degraded.
func (t *phaseTracker) noteLimit(code string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	addCode(&t.limits, code)
}

// markSkipped records that the phase never ran, with the reason it was skipped.
func (t *phaseTracker) markSkipped(code string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.skipped = true
	addCode(&t.reasons, code)
}

// addPersistence folds a writer-shutdown outcome into the phase, and marks the
// phase partial when the writer could not account for every write it accepted.
// Several writers per phase merge into one figure (see PersistenceOutcome.Merge).
func (t *phaseTracker) addPersistence(o database.PersistenceOutcome) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.persist.Merge(o)
	t.hasPersist = true
	notClean := !o.Clean()
	t.mu.Unlock()
	if notClean {
		t.markPartial(database.ReasonPersistence)
	}
}

// noteExecution folds one Execute call's self-report into the phase. A phase can
// run several (dynamic assessment runs one executor per feedback round), so the
// marks accumulate and the un-acknowledged count sums.
func (t *phaseTracker) noteExecution(rep core.ExecutionReport) {
	if t == nil {
		return
	}
	if rep.StoppedEarly {
		t.markPartial(database.ReasonInputIncomplete)
	}
	if rep.DrainStalled {
		t.markPartial(database.ReasonDrainStalled)
	}
	if rep.WorkersAbandoned {
		t.markPartial(database.ReasonWorkersAbandoned)
	}
	if rep.DeferredFlushSkipped {
		t.markPartial(database.ReasonDeferredFlushSkipped)
	}
	if rep.Unacked > 0 {
		t.mu.Lock()
		t.unacked += rep.Unacked
		t.mu.Unlock()
	}
}

// finish closes out the phase: it always computes the phase's outcome, and emits
// phase.finished only when a stream is attached.
//
// status mapping: completed → "completed", partial → "curtailed", failed →
// "failed", skipped → "completed" (with its reason, since a skipped phase is not
// a degraded one). A phase whose own deadline fired now reports "curtailed"
// rather than "completed" — before, only the OUTER context was consulted, so a
// per-phase max_duration that fired inside a healthy scan was invisible.
func (t *phaseTracker) finish(ctx context.Context, err error) database.PhaseOutcome {
	if t == nil {
		return database.PhaseOutcome{}
	}
	// recordError, not noteError: an error that reaches finish is the one the
	// CALLER is returning, so it rides out on scan.finished. Emitting a non-fatal
	// `error` event for it too would contradict that event's contract, and the
	// arms that log-and-continue have already called noteError themselves.
	t.recordError(err)
	// The context the phase ran under explains a curtailment the phase itself
	// cannot see: the total scan budget, or an operator's Ctrl-C.
	if ctx != nil && ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.markPartial(database.ReasonScanBudget)
		} else {
			t.markPartial(database.ReasonCancelled)
		}
	}

	out := t.outcome()

	if t.stop == nil {
		return out
	}
	close(t.stop)
	<-t.stopped

	status := scanevents.StatusCompleted
	switch out.State {
	case database.PhaseFailed:
		status = scanevents.StatusFailed
	case database.PhasePartial:
		status = scanevents.StatusCurtailed
	}
	ev := scanevents.Event{
		Type:         scanevents.TypePhaseFinished,
		Phase:        t.phase,
		Status:       status,
		DurationMS:   out.DurationMS,
		RequestsSent: scanevents.Int64(t.sentSoFar()),
		Findings:     scanevents.Int64(t.findings.Load()),
		Reasons:      out.Reasons,
		Limits:       out.Limits,
	}
	if out.Message != "" {
		ev.Message = out.Message
	}
	scanevents.Emit(ev)
	return out
}

// outcome snapshots the ledger. Split out of finish so the outcome can be read
// without the emission side effects (and so the lock is held for exactly as long
// as the copy takes).
func (t *phaseTracker) outcome() database.PhaseOutcome {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := database.PhaseOutcome{
		Phase:       t.phase,
		Reasons:     database.SortedCodes(t.reasons),
		Limits:      database.SortedCodes(t.limits),
		Errors:      t.errs,
		Message:     t.firstErr,
		Unprocessed: t.unacked,
		DurationMS:  time.Since(t.start).Milliseconds(),
	}
	out.State = database.ResolvePhaseState(out.Errors, out.Reasons, t.skipped)
	if t.hasPersist {
		p := t.persist
		out.Persistence = &p
	}
	return out
}

// attachEventObserver routes every finding the output writer emits into the
// machine event stream, and counts it against the phase that produced it. One
// call, one seam: the runner has ~six OnResult callbacks and the writer is the
// only thing all of them reach.
func (r *Runner) attachEventObserver() {
	if !scanevents.On() {
		return
	}
	sw, ok := r.output.(*output.StandardWriter)
	if !ok {
		return
	}
	prior := sw.OnEvent
	sw.OnEvent = func(ev *output.ResultEvent) {
		if prior != nil {
			prior(ev)
		}
		r.currentPhase.Load().recordFinding()
		emitFindingEvent(ev)
	}
}

// noteError reports a phase failure the scan SURVIVED. Most phases log and carry
// on, so their error never reaches the caller and never reaches phase.finished's
// status either — from the stream alone the phase looked fine. An `error` event
// is non-fatal by construction; a failure that ends the run rides on
// scan.finished instead.
//
// A method on the tracker rather than a free function taking a name: the tracker
// owns the CANONICAL phase id, and the eight call sites sit next to
// scanLogger.Error calls whose component labels are the short tags
// ("heuristics", "harvest", "respider"). Hand-typing the label at each site had
// already produced three phases that reported one spelling on phase.started and
// another on error, which silently breaks a consumer correlating the two.
func (t *phaseTracker) noteError(err error) {
	if t == nil || err == nil {
		return
	}
	// Record BEFORE the stream check. The outcome ledger is what the scan row and
	// the console banner read, and it has to be right whether or not --events was
	// passed — a phase that failed on a plain CLI run used to leave no structured
	// trace at all because this method bailed out here first.
	t.recordError(err)
	if !scanevents.On() {
		return
	}
	scanevents.Emit(scanevents.Event{
		Type:    scanevents.TypeError,
		Phase:   t.phase,
		Message: err.Error(),
	})
}

// recordError folds a phase failure into the ledger: the count, and the first
// error's text as the outcome's message.
//
// First rather than last, because the first failure in a phase is normally the
// cause and the rest are consequences of it (one unreachable host producing a
// failure per module), and because the message is bounded — keeping the latest
// would mean the stored explanation changes every time a downstream error
// arrives.
func (t *phaseTracker) recordError(err error) {
	if t == nil || err == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.errs++
	if t.firstErr == "" {
		t.firstErr = database.TruncateOutcomeMessage(err.Error())
	}
}

// emitBlockEvent mirrors the operator's [waf-block-detected] stderr line onto
// the machine stream. Both hang off the same notifier, so a consumer never has
// to scrape a rendered session log to recover a block — which is what it had to
// do before, at the cost of an N+1 subprocess walk per sweep.
func emitBlockEvent(n http.BlockNotice) {
	if !scanevents.On() {
		return
	}
	vendor := n.WAFType
	if vendor == "" || vendor == "generic" {
		vendor = "unknown"
	}
	scanevents.Emit(scanevents.Event{
		Type:       scanevents.TypeWAFBlock,
		Host:       n.Host,
		Vendor:     vendor,
		StatusCode: n.Status,
		Detail:     "edge is filtering scan traffic — results for this host may be incomplete",
	})
}

// emitPacingEvent mirrors [waf-pacing-armed] onto the machine stream, spelling
// out the concurrency drop so a consumer can attribute a slowdown to the pacing
// decision rather than to the target.
func emitPacingEvent(host, vendor string, from, to int) {
	if !scanevents.On() {
		return
	}
	if vendor == "" {
		vendor = "unknown"
	}
	scanevents.Emit(scanevents.Event{
		Type:            scanevents.TypeWAFPacing,
		Host:            host,
		Vendor:          vendor,
		ConcurrencyFrom: from,
		ConcurrencyTo:   to,
		Detail:          "proactive pacing: host is behind a CDN/WAF edge",
	})
}

// emitFindingEvent reports a finding as it is discovered. Deliberately a
// metadata line, not the finding: the stream is a progress channel, and the
// evidence lives in the database the consumer already has a handle to (the path
// is on scan.started). Carrying request/response bytes here would make the
// stream large enough that flushing per line stops being cheap.
func emitFindingEvent(result *output.ResultEvent) {
	if result == nil || !scanevents.On() {
		return
	}
	scanevents.Emit(scanevents.Event{
		Type:       scanevents.TypeFindingNew,
		Severity:   strings.ToLower(result.Info.Severity.String()),
		Confidence: strings.ToLower(result.Info.Confidence.String()),
		ModuleID:   result.ModuleID,
		URL:        result.URL,
		Host:       result.Host,
	})
}

// knownIssueScanEdge builds the pacing/detection hooks handed to the
// known-issue-scan phase. Both are backed by objects the rest of the scan
// already shares: the requester (whose block notifier and host-limiter feedback
// fire as a side effect of every probe) and the host limiter itself.
//
// Returns a zero Edge when there is no requester — the phase then behaves as it
// did before, which is the correct degradation for a caller that never built the
// shared infrastructure (a test, or an API path constructing the config by hand).
func (r *Runner) knownIssueScanEdge(infra *phaseInfra) knownissuescan.Edge {
	if infra == nil || infra.httpRequester == nil {
		return knownissuescan.Edge{}
	}
	requester := infra.httpRequester
	edge := knownissuescan.Edge{
		Probe: func(ctx context.Context, rawURL string) (bool, error) {
			return probeEdgeThroughRequester(ctx, requester, rawURL)
		},
	}
	if infra.hostLimiter != nil {
		limiter := infra.hostLimiter
		edge.HostLimit = limiter.CurrentLimit
	}
	return edge
}

// probeEdgeThroughRequester sends one GET to rawURL on the shared requester and
// reports whether the edge answered with a block.
//
// The classification is not done here: it is done inside the requester, by the
// same detector every other phase's traffic passes through, and its side effects
// (the one-time-per-host operator notice, the waf.block event, the limiter's
// WAF-auto-arm feedback) all fire from there. This function only needs to know
// whether the notifier considered the host blocked, which it learns by watching
// the requester's own classification via the response status and the block
// detector's verdict on the returned chain.
func probeEdgeThroughRequester(ctx context.Context, requester *http.Requester, rawURL string) (bool, error) {
	rr, err := httpmsg.GetRawRequestFromURL(rawURL)
	if err != nil {
		return false, err
	}
	chain, _, err := requester.ExecuteContext(ctx, rr, http.Options{})
	if err != nil {
		return false, err
	}
	return http.IsBlockedResponse(chain), nil
}
