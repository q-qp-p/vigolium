package runner

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/database"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/tlsprobe"
	"go.uber.org/zap"
)

// probePassiveTags selects the passive modules the probe phase runs.
//
// "fingerprint" is what makes the phase answer "what is this host running":
// those modules publish into the scan's TechRegistry, which is in turn the
// host-scoped signal in surface_scoring. Without them a probe would record a
// status code and nothing else — which is what `run discover` does today, since
// discovery.passive_module_tags has no default and the phase therefore runs
// ZERO passive modules.
//
// The set is deliberately narrow. "light" would have been the obvious pick and
// is wrong: 110 of the 117 passive modules carry it, so it is the whole
// registry under another name, and running all of it across thousands of hosts
// buries the sweep's actual output in findings. A probe is a triage pass; the
// modules that say "this is worth a real scan" earn their place, the rest do
// not.
var probePassiveTags = []string{"fingerprint"}

// probePhaseName is the canonical phase id, shared by the pace lookups and the
// NativePhase const so a rename cannot leave one of them behind.
const probePhaseName = string(PhaseProbe)

// probeExtraPassiveModuleIDs are passive modules the probe runs by ID because
// their tags do not describe them as fingerprinting. surface_scoring is tagged
// "behavior-analysis, light" — accurate, but it is precisely the per-record
// 0-100 ranking a sweep exists to produce, so it is named directly rather than
// by widening probePassiveTags into something that would drag in half the
// registry with it.
var probeExtraPassiveModuleIDs = []string{"surface-scoring"}

// runProbePhase sweeps the CLI target list: one request per target, passive
// modules only, no content discovery and no fuzzing.
//
// It is a sibling of the discovery phase rather than a mode of it, because the
// two differ in the thing that dominates their cost. Discovery builds a
// DeparosDiscoverySource that crawls and (on a discovery-only run) brute-forces
// paths per target; the probe issues exactly one request per target and is done.
// Pointing `run discover` at a few hundred hosts therefore spends its budget on
// the first handful — the probe spends one request each and reaches all of them.
func (r *Runner) runProbePhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	if len(r.options.Targets) == 0 {
		r.printPhaseStart("Probe", "sweep targets for liveness, technology, and attack surface")
		r.printPhaseDetail(terminal.Orange("no targets to probe — pass -t/--target or -T/--target-file"))
		return nil
	}

	r.printPhaseStart("Probe", "sweep targets for liveness, technology, and attack surface")

	pace := r.probePace()

	// The phase budget has to start HERE, not inside the executor.
	//
	// MaxDuration reaches the executor as ExecutorConfig.MaxDuration, whose clock
	// starts in Execute - which runs after the DNS prefetch barrier below. A
	// sweep of a large list of dead hostnames could therefore spend an unbounded
	// stretch resolving before the budget that was supposed to cap the phase had
	// begun counting. Wrapping the phase context makes the number mean what it
	// says: every stage of the probe, prefetch included. phaseDeadline keeps the
	// earlier deadline, so an outer scan-wide cap still wins.
	if pace.MaxDuration > 0 {
		var phaseCancel context.CancelFunc
		ctx, phaseCancel = r.trackedPhaseDeadline(ctx, pace.MaxDuration)
		defer phaseCancel()
	}

	sharedRequester := infra.httpRequester
	infra, releasePace := r.probePaceInfra(infra, pace)
	defer releasePace()
	// A phase-local requester is traffic the tracker knows nothing about:
	// beginPhase baselined the SHARED requester, which a paced probe never touches,
	// so phase.finished reported ≈0 requests for a full sweep.
	if local := infra.httpRequester; local != nil && local != sharedRequester {
		r.currentPhase.Load().addCounter(local.RequestsSent)
	}
	r.printPhaseDetail(fmt.Sprintf("Speed: concurrency=%s, rate-limit=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", pace.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", pace.RateLimit)),
		terminal.HiBlue(fmt.Sprintf("%d", pace.MaxPerHost))))

	passive := probePassiveModules()
	r.printPhaseDetail(fmt.Sprintf("Analysis: %s passive modules (tech fingerprinting + surface scoring), %s, redirects=%s",
		terminal.HiTeal(fmt.Sprintf("%d", len(passive))),
		terminal.HiTeal("no fuzzing"),
		terminal.HiTeal(r.probeRedirectDesc())))
	// Where the two outputs land. Stated because both are columns on the record
	// rather than findings, so an operator reading a "0 findings" summary would
	// otherwise conclude the sweep produced nothing.
	r.printPhaseDetail(fmt.Sprintf("Output: per-record %s and %s on each http_record row",
		terminal.HiTeal("surface_score"),
		terminal.HiTeal("technology")))
	// Proactive edge pacing is off by default here (one request per host has no
	// burst to pre-empt). Stated rather than assumed: it is a safety default
	// being turned off, and an operator who wants it back needs to know it went.
	if r.options.NoWafPacing {
		r.printPhaseDetail(fmt.Sprintf("Pacing: %s %s",
			terminal.HiTeal("proactive WAF-edge pre-arm off"),
			terminal.Gray("(reactive back-off after a real block still applies; re-enable with --no-waf-pacing=false)")))
	}
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	r.printVerboseTargets(r.options.Targets)

	// DNS prefetch, as its own bounded stage ahead of the HTTP sweep.
	//
	// On a sweep DNS is part of the ANSWER, not incidental metadata: "where does
	// this name point, and does it share infrastructure with the others" is half
	// of what a host list is being asked. The normal write-path resolver is
	// background/best-effort — correct there, because a blocking lookup would
	// stall the record writer for a full DNS timeout per dead host — but it means
	// the first record for each host is written before its answer arrives, which
	// on a one-request-per-host sweep is EVERY record. Resolving up front is what
	// makes the columns populated rather than empty.
	//
	// It is a separate stage rather than work folded into the request because
	// resolution and fetching have different natural concurrencies and different
	// failure modes: a host that does not resolve never needs a socket.
	// Scheme resolution runs FIRST so every stage below operates on the endpoint
	// the sweep will actually contact. Resolving it afterwards would prefetch
	// DNS and TLS for :80 and then send the request to :443.
	sweepTargets, unreachable := applyResolvedSchemes(r.options.Targets,
		r.resolveProbeSchemes(ctx, pace.Concurrency))
	r.prefetchProbeTargets(ctx, pace.Concurrency, infra.scanUUID, sweepTargets)

	// A dedicated writer so the phase's rows are flushed and counted on its own
	// boundary, mirroring the discovery phase. Closed before the processed-count
	// update so that count reflects rows that actually landed.
	var probeRecordWriter *database.RecordWriter
	if r.repository != nil {
		probeRecordWriter = database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
	}

	authWalls := newAuthWallCollector()

	executorCfg := core.ExecutorConfig{
		Workers:       pace.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		RecordWriter:  probeRecordWriter,
		ScanUUID:      infra.scanUUID,
		ProjectUUID:   r.options.ProjectUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTrafficVerbose("probe"),
		// Label the rows so a sweep's output is separable from a real scan's in
		// the same project: `vigolium traffic --source probe`.
		RecordSource: database.RecordSourceProbe,
		// Every followed hop becomes its own row, chained by parent_uuid. On a
		// sweep this is the point rather than a detail: a host list is mostly
		// redirects, and "example.com answered 301 to www.example.com which
		// answered 200" is the finding.
		RecordRedirectChain: r.options.RecordRedirectChain,
		// The probe sends its own request per target and never re-injects, so
		// there is no feedback loop to drain.
		DisableFeedback: true,
		// A host list is exactly where login walls cluster: an estate's apps sit
		// behind one IdP, so a sweep bounces off the same wall hundreds of times.
		// Collected and reported once per wall below.
		OnAuthWall: authWalls.Observe,
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	// The CLI target list directly — no deparos source, which is the whole
	// difference from the discovery phase. Schemeless entries carry the scheme
	// the prefetch stage resolved, and endpoints nothing answered on are absent
	// (counted back into "attempted" below).
	src := source.NewTargetSource(sweepTargets, nil)

	executor := core.NewExecutor(executorCfg, src, nil, passive)
	_, err := executor.Execute(ctx)
	r.currentPhase.Load().noteExecution(executor.Report())
	r.shutdownWriters("probe", probeRecordWriter)
	if err != nil {
		return err
	}

	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("Probe: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	// Responded(), not Processed(): the executor's processed counter ticks once
	// per item it took off the queue, including the ones whose fetch failed, so
	// on a sweep of a stale host list it would report every dead host as a target
	// that answered. Both are printed when they disagree, because "700 attempted,
	// 300 answered" is itself the result of a liveness sweep.
	answered := executor.Responded()
	// Endpoints the prefetch stage found closed on every candidate port never
	// reached the executor, so its counter cannot see them. They were still
	// attempted — a TCP connect is an attempt, and a shorter one than the
	// request would have been — and they did not respond, which is exactly the
	// bucket the summary's second number names.
	attempted := executor.Processed() + int64(unreachable)
	summary := fmt.Sprintf("completed — %s of %s targets answered in %s",
		terminal.Orange(fmt.Sprintf("%d", answered)),
		terminal.HiTeal(fmt.Sprintf("%d", len(r.options.Targets))),
		terminal.HiPurple(fmtDuration(elapsed)))
	if attempted > answered {
		summary += terminal.Gray(fmt.Sprintf(" (%d attempted, %d did not respond)",
			attempted, attempted-answered))
	}
	r.printPhaseComplete("Probe", summary)
	r.reportAuthWalls("Probe", authWalls)
	zap.L().Info("Probe: completed",
		zap.Int64("answered", answered),
		zap.Int64("processed", attempted),
		zap.Int("targets", len(r.options.Targets)))

	if !r.options.Silent {
		r.printPhaseFeedback("Probe", fmt.Sprintf("rank the sweep with %s",
			terminal.HiCyan("vigolium traffic --source probe --sort surface_score")))
	}
	return nil
}

// probePace resolves the phase's speed dials.
//
// The three dials come from r.options (already fully resolved from the CLI) and
// are displaced ONLY by an explicit per-phase override. ResolvePhase cannot be
// used for them: it merges the per-phase section over the COMMON scanning_pace
// values and returns the result, so its Concurrency is non-zero even when no
// probe override exists — applying that would overwrite whatever -c the operator
// typed with the config file's common default. Reading the section directly is
// also what makes `--concurrency probe=200` work, since the pace flag writes the
// qualified value there.
//
// MaxDuration has no CLI equivalent on this phase, so it takes the merged value:
// a common scanning_pace.max_duration should bound the sweep exactly as it
// bounds every other phase.
func (r *Runner) probePace() config.ResolvedPhasePace {
	out := config.ResolvedPhasePace{
		Concurrency: r.options.Concurrency,
		RateLimit:   r.options.RateLimit,
		MaxPerHost:  r.options.MaxPerHost,
	}
	if r.settings == nil {
		return out
	}
	out.MaxDuration = r.settings.ScanningPace.ResolvePhase(probePhaseName).MaxDuration
	section := r.settings.ScanningPace.Section(probePhaseName)
	if section == nil {
		return out
	}
	if section.Concurrency > 0 {
		out.Concurrency = section.Concurrency
	}
	if section.RateLimit > 0 {
		out.RateLimit = section.RateLimit
	}
	if section.MaxPerHost > 0 {
		out.MaxPerHost = section.MaxPerHost
	}
	return out
}

// probePaceInfra resolves the infrastructure the sweep actually runs on,
// honouring the phase's rate-limit and per-host dials.
//
// Those two dials had no effect before this: the shared infrastructure is built
// ONCE per run from the global options, and only Concurrency travels separately
// (to ExecutorConfig.Workers). RateLimit and MaxPerHost live inside the
// requester's services, so `--rate-limit probe=5` reached the phase header and
// stopped there - the printed number was a promise the sweep did not keep.
//
// An override gets its OWN services copy and its own requester rather than
// mutating infra's. One phaseInfra is shared by every phase in a run, so writing
// the probe's limiter into it would silently re-pace the scan that follows. The
// common no-override path returns infra untouched, so no run that does not ask
// for phase-local pacing pays for a second transport.
func (r *Runner) probePaceInfra(infra *phaseInfra, pace config.ResolvedPhasePace) (*phaseInfra, func()) {
	noop := func() {}
	// A displaced value is exactly what probePace() returns when the phase
	// section overrode the global one, so no extra plumbing is needed to detect it.
	if pace.RateLimit == r.options.RateLimit && pace.MaxPerHost == r.options.MaxPerHost {
		return infra, noop
	}

	// Shallow copy: HostErrors, Notifier and DedupManager are deliberately shared
	// with the rest of the run - they accumulate cross-phase knowledge, and
	// forking them would make the sweep forget what earlier phases learned.
	local := *infra.svc
	local.RateLimiter = buildScanRateLimiter(pace.RateLimit)

	var ownedLimiter *hostlimit.HostRateLimiter
	if pace.MaxPerHost != r.options.MaxPerHost && pace.MaxPerHost > 0 {
		ownedLimiter = newHostLimiter(pace.MaxPerHost, r.settings, r.options.NoWafPacing)
		local.HostLimiter = ownedLimiter
	}

	// Built after the limiter: NewRequester reads HostLimiter.CeilingPerHost() to
	// size its connection pool, so constructing it first would size the pool from
	// the limiter the phase is replacing.
	requester, err := vighttp.NewRequester(r.options, &local)
	if err != nil {
		zap.L().Warn("Probe: phase-local pacing unavailable, using scan-wide limits",
			zap.Error(err))
		if ownedLimiter != nil {
			_ = ownedLimiter.Close()
		}
		return infra, noop
	}

	// A derived phaseInfra rather than a loose pair of components: the phase runs
	// on ONE infra object, and the caller cannot accidentally pass the forked
	// services alongside the original requester. Everything else is carried over
	// by value and stays owned by the original, which is why nothing here closes
	// it - only the two members this function created are released below.
	paced := *infra
	paced.svc = &local
	paced.httpRequester = requester
	if ownedLimiter != nil {
		paced.hostLimiter = ownedLimiter
	}

	return &paced, func() {
		requester.CloseIdleConnections()
		if ownedLimiter != nil {
			_ = ownedLimiter.Close()
		}
	}
}

// probeRedirectDesc renders the effective redirect policy for the phase header.
// It is shown unconditionally because "did this sweep follow the 301 or record
// it" changes what every row in the output means.
func (r *Runner) probeRedirectDesc() string {
	// ResolveRedirectMode is what NewRequester resolves the live policy with,
	// including the legacy DisableRedirects/FollowHostRedirects pair. Re-deriving
	// the default here would print "any" for a scan the requester is actually
	// running as same-host or off — and this line exists precisely because the
	// redirect policy changes what every row in the output means.
	mode := vighttp.ResolveRedirectMode(r.options)
	if r.options.RecordRedirectChain {
		return mode + " (hops recorded)"
	}
	return mode
}

// probePassiveModules resolves the phase's passive module set: everything tagged
// for fingerprinting, plus the explicitly named extras. No dedup needed —
// GetPassiveModulesByIDs builds a set from the ids and walks the registry once,
// so a repeated id cannot yield a repeated module.
func probePassiveModules() []modules.PassiveModule {
	return modules.GetPassiveModulesByIDs(
		append(modules.ResolveModuleTags(probePassiveTags), probeExtraPassiveModuleIDs...))
}

// probeDNSConcurrency bounds the prefetch stage. Resolution is cheaper and more
// parallel than an HTTP round trip, so it runs wider than the request
// concurrency — but nowhere near unbounded: the pure-Go resolver still costs a
// goroutine and a socket per lookup, and a local recursive resolver starts
// dropping UDP under load, which presents as multi-second timeouts rather than
// as an error. Capped so a huge target list cannot turn the prefetch into the
// slowest part of the sweep.
const (
	probeDNSConcurrencyFactor = 4
	probeDNSConcurrencyMax    = 128
)

// hostObservationSaveTimeout bounds the one write that persists the stage's
// observations. It runs on a context detached from the phase's, so that a
// cancelled sweep still keeps what it already resolved - which means it needs a
// bound of its own or a wedged database could outlive the scan that was told to
// stop.
const hostObservationSaveTimeout = 30 * time.Second

// sweepEndpoint is one distinct endpoint to prefetch: a hostname, plus the port
// and scheme the sweep will contact it on.
type sweepEndpoint struct {
	host  string
	port  int
	https bool
}

// prefetchProbeTargets resolves DNS for every target hostname — and, under
// --tls-probe, completes a TLS handshake against every HTTPS endpoint — before
// the sweep sends its first request.
//
// This stage is a barrier: nothing is fetched until it finishes, so its duration
// is the sweep's time to first result. That makes its concurrency load-bearing,
// and it used to be a fiction — the worker pool below scales to 128, but every
// lookup was charged against a 16-slot semaphore shared with the background
// write-path resolver, so the stage ran at an eighth of its stated width. It now
// charges dnsSweepSem, which is sized for exactly this caller.
//
// One pass over the target list rather than a stage each, because both are
// per-host facts keyed the same way and both feed the same serialization-time
// attachment. Splitting them would walk the list twice and pay two goroutine
// pools to answer two questions about the same endpoint.
//
// Best-effort by construction: a DNS failure leaves that record's DNS fields
// empty ("did not resolve"), and a failed handshake is itself reported
// (ProbeStatus false) rather than dropped — "this host does not speak TLS" is an
// answer a sweep wants. Honours ctx so a cancelled scan stops prefetching
// instead of walking the whole list.
func (r *Runner) prefetchProbeTargets(ctx context.Context, requestConcurrency int, scanUUID string, sweepTargets []string) {
	targets := distinctSweepEndpoints(sweepTargets)
	if len(targets) == 0 {
		return
	}
	tlsProbe := r.options.TLSProbe

	start := time.Now()
	var resolved, tlsOK, attempted atomic.Int64

	// Observations are collected here, at the point of observation, rather than
	// re-read from the process caches at emit time.
	//
	// That re-read is what made a large sweep lose its own work: the DNS and TLS
	// caches hold 8192 entries each and evict in insertion order, so past that
	// size the hosts resolved FIRST had their answers dropped before the export
	// that wanted them - resolved successfully, then silently absent from the
	// output. Capturing the answer while it is in hand and persisting it makes
	// the output independent of what a bounded cache happens to still hold.
	var obsMu sync.Mutex
	observations := make([]database.HostObservationInput, 0, len(targets))

	complete := sweepFanOut(ctx, requestConcurrency, targets, func(t sweepEndpoint) {
		attempted.Add(1)
		obs := database.HostObservationInput{Hostname: t.host, Port: t.port}
		obs.A, obs.AAAA, obs.CNAME = database.ResolveHostnameNow(ctx, t.host)
		if len(obs.A)+len(obs.AAAA) > 0 {
			resolved.Add(1)
		}
		// Complete means the lookup ran to an answer, not that the answer was
		// positive: a host that genuinely resolves to nothing is a complete
		// observation, and only a cancelled stage is not.
		obs.Complete = ctx.Err() == nil

		// Only HTTPS endpoints are handshaked: a TLS probe against a plaintext
		// port is a guaranteed timeout, and on a large sweep those timeouts
		// would dominate the stage.
		if tlsProbe && t.https {
			if info := tlsprobe.Probe(ctx, t.host, t.port, tlsprobe.DefaultTimeout); info != nil {
				if info.ProbeStatus {
					tlsOK.Add(1)
				}
				// Stored even on a failed handshake: "this endpoint does not
				// speak TLS" is an answer a sweep wants, and it is exactly the
				// one that cannot be re-derived later.
				obs.TLS = info
			}
		}

		if obs.Empty() {
			return
		}
		obsMu.Lock()
		observations = append(observations, obs)
		obsMu.Unlock()
	})
	cancelled := !complete

	// Persisted on a context detached from the phase's, so a cancelled or
	// budget-exhausted sweep still keeps the observations it already paid for.
	// The rows it writes are marked incomplete, which is what tells a later
	// reader the stage did not finish.
	stored := 0
	if r.repository != nil && len(observations) > 0 {
		saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(ctx), hostObservationSaveTimeout)
		if err := r.repository.SaveHostObservations(saveCtx, r.options.ProjectUUID, scanUUID, observations); err != nil {
			zap.L().Warn("Probe: failed to persist host observations", zap.Error(err))
		} else {
			stored = len(observations)
		}
		saveCancel()
	}

	detail := fmt.Sprintf("DNS: resolved %s of %s hostname(s)",
		terminal.Orange(fmt.Sprintf("%d", resolved.Load())),
		terminal.HiTeal(fmt.Sprintf("%d", len(targets))))
	// A cut-short prefetch is stated rather than left to be inferred from a
	// low resolved count: the records for the endpoints never reached carry no
	// DNS at all, and "the stage ran out of budget" is a different fact about
	// the output than "those hosts do not resolve".
	if cancelled {
		detail += terminal.Gray(fmt.Sprintf(" (stopped early — %d of %d endpoints reached)",
			attempted.Load(), len(targets)))
	}
	if tlsProbe {
		detail += fmt.Sprintf(" | TLS: %s handshake(s) completed",
			terminal.Orange(fmt.Sprintf("%d", tlsOK.Load())))
	}
	// Stated because it is what makes the sweep's DNS/TLS output survive: the
	// process caches these were read from hold 8192 entries, so without the
	// stored rows a bigger sweep would emit facts for its last hosts and nothing
	// for its first.
	if stored > 0 {
		detail += fmt.Sprintf(" | stored %s endpoint observation(s)",
			terminal.Orange(fmt.Sprintf("%d", stored)))
	}
	r.printPhaseDetail(detail + " in " + terminal.HiPurple(fmtDuration(time.Since(start))))
}

// sweepFanOut runs fn over items on a bounded worker pool, stopping early if
// ctx is cancelled. Reports whether every item was dispatched.
//
// One helper because the probe has two barrier stages with identical shapes —
// resolve a scheme per target, then resolve DNS/TLS per endpoint — and the
// concurrency policy (probeDNSConcurrencyFactor/Max) is meant to be decided in
// one place. Two hand-rolled copies of the same pool is how the two stages come
// to run at different widths for no stated reason.
func sweepFanOut[T any](ctx context.Context, requestConcurrency int, items []T, fn func(T)) (complete bool) {
	if len(items) == 0 {
		return true
	}
	workers := min(max(requestConcurrency, 1)*probeDNSConcurrencyFactor, probeDNSConcurrencyMax)
	workers = min(workers, len(items))

	queue := make(chan T)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range queue {
				fn(it)
			}
		}()
	}

	complete = true
	for _, it := range items {
		select {
		case <-ctx.Done():
			complete = false
		default:
		}
		if !complete {
			break
		}
		select {
		case <-ctx.Done():
			complete = false
		case queue <- it:
		}
	}
	close(queue)
	wg.Wait()
	return complete
}

// resolveProbeSchemes decides, for every schemeless target, which scheme the
// sweep contacts it over — and which are not worth contacting at all.
//
// A schemeless line used to mean http and nothing else, so every https-only
// host in a target list was reported dead. See resolveSweepScheme for the
// rules; this is the stage that runs them concurrently and reports the result.
//
// Nothing here is silent. A sweep that quietly changed which port it probed
// would be harder to trust than one that got it wrong consistently, so the
// counts go in the phase header next to DNS.
//
// The resolution is PROBE-LOCAL: it produces the phase's own target list and
// deliberately does not rewrite Options.Targets, so a probe riding along inside
// a full scan does not re-point the scope matcher (already built) or the phases
// after it, which keep the http guess. Hoisting it to a runner-level stage
// ahead of scope construction would let every phase benefit and is the right
// eventual shape; it is a larger move than this change, which is why the
// narrower version lives here.
func (r *Runner) resolveProbeSchemes(ctx context.Context, requestConcurrency int) map[string]sweepScheme {
	if len(r.options.TargetsSchemeAssumed) == 0 {
		return nil
	}

	// Only targets whose scheme this process guessed. An explicit http:// or
	// https:// is the operator's instruction, not a default to be tested.
	// Deduped because a list may repeat a name, and a repeat must not connect
	// twice.
	var work []string
	seen := make(map[string]struct{}, len(r.options.TargetsSchemeAssumed))
	for _, raw := range r.options.Targets {
		if _, assumed := r.options.TargetsSchemeAssumed[raw]; !assumed {
			continue
		}
		if _, dup := seen[raw]; dup {
			continue
		}
		seen[raw] = struct{}{}
		work = append(work, raw)
	}
	if len(work) == 0 {
		return nil
	}

	start := time.Now()
	var mu sync.Mutex
	out := make(map[string]sweepScheme, len(work))

	sweepFanOut(ctx, requestConcurrency, work, func(target string) {
		host, port, rest, ok := splitSweepTarget(target)
		if !ok {
			return
		}
		res := resolveSweepScheme(ctx, host, port, rest)
		mu.Lock()
		out[target] = res
		mu.Unlock()
	})

	var https, dead int
	for _, res := range out {
		switch {
		case !res.reachable:
			dead++
		case strings.HasPrefix(res.url, "https://"):
			https++
		}
	}
	// Only worth a line when it changed something. On a list of explicit URLs
	// this stage does nothing and should say nothing.
	if https == 0 && dead == 0 {
		return out
	}
	detail := fmt.Sprintf("Scheme: resolved %s schemeless target(s)",
		terminal.HiTeal(fmt.Sprintf("%d", len(out))))
	if https > 0 {
		detail += fmt.Sprintf(" | %s over https", terminal.Orange(fmt.Sprintf("%d", https)))
	}
	if dead > 0 {
		detail += terminal.Gray(fmt.Sprintf(" | %d no open port (skipped, not requested)", dead))
	}
	r.printPhaseDetail(detail + " in " + terminal.HiPurple(fmtDuration(time.Since(start))))
	return out
}

// distinctSweepEndpoints reduces the CLI target list to one entry per
// scheme+host:port, preserving order. A sweep routinely carries several URLs on
// one host; resolving or handshaking it once per URL would multiply the stage's
// cost for an answer that cannot differ.
//
// Parsing goes through hostPortScheme (port_sweep.go) rather than a second URL
// parser: that one prefixes a missing scheme before parsing, and without the
// prefix a schemeless `example.com:8443` parses as Scheme="example.com" with no
// port — so the endpoint would be resolved and handshaked on 443 while the
// port-sweep phase read the same line as 8443. One parser, one answer.
//
// The scheme comes from the target rather than from its port. Deriving it
// ("anything but 80 is TLS") inverted both mixed-port forms: http://host:8080
// was handed a TLS handshake, which is the guaranteed timeout this stage skips
// plaintext ports to avoid, and https://host:80 was never handshaked at all. It
// is part of the dedup key for the same reason — a host offering both schemes on
// one port is two endpoints, and letting the first one seen answer for both
// would drop whichever came second.
// Takes the already-resolved sweep list rather than Options.Targets: the
// endpoints to prefetch are the ones the sweep will contact, schemes settled
// and unreachable entries already dropped.
func distinctSweepEndpoints(targets []string) []sweepEndpoint {
	out := make([]sweepEndpoint, 0, len(targets))
	seen := make(map[sweepEndpoint]struct{}, len(targets))
	for _, raw := range targets {
		host, portStr, https := hostPortScheme(raw)
		if host == "" {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 {
			continue
		}
		ep := sweepEndpoint{host: host, port: port, https: https}
		if _, dup := seen[ep]; dup {
			continue
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
	}
	return out
}
