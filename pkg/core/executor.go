package core

import (
	"context"
	"errors"
	"fmt"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sourcegraph/conc"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/storagesig"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// Tiered response buffer pools reduce GC pressure across response sizes.
// Three tiers cover the common response size distribution:
//   - small:  responses up to 1 MiB  (most responses)
//   - medium: responses up to 4 MiB  (large pages, API responses)
//   - large:  responses up to 16 MiB (very large payloads)
//
// Responses exceeding 16 MiB are allocated directly and not pooled.
const (
	poolTierSmall  = 1 << 20  // 1 MiB
	poolTierMedium = 4 << 20  // 4 MiB
	poolTierLarge  = 16 << 20 // 16 MiB
)

// Bounds on the post-EOF drain's poll interval. The drain starts at
// drainPollMin and doubles up to drainPollMax, so a phase whose workers have
// already finished notices immediately instead of waiting out a fixed tick,
// while a long drain settles onto a cheap interval. See the drain loop in
// Execute.
const (
	drainPollMin = time.Millisecond
	drainPollMax = 50 * time.Millisecond
)

var (
	smallResponsePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 32*1024) // 32 KiB initial cap
			return &b
		},
	}
	mediumResponsePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 1<<20) // 1 MiB initial cap
			return &b
		},
	}
	largeResponsePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 4<<20) // 4 MiB initial cap
			return &b
		},
	}
)

func getResponseBuffer(n int) []byte {
	var pool *sync.Pool
	switch {
	case n <= poolTierSmall:
		pool = &smallResponsePool
	case n <= poolTierMedium:
		pool = &mediumResponsePool
	case n <= poolTierLarge:
		pool = &largeResponsePool
	default:
		return make([]byte, n) // Too large for any pool
	}
	bp := pool.Get().(*[]byte)
	b := *bp
	if cap(b) >= n {
		return b[:n]
	}
	return make([]byte, n)
}

func putResponseBuffer(buf []byte) {
	c := cap(buf)
	buf = buf[:0]
	switch {
	case c <= poolTierSmall:
		smallResponsePool.Put(&buf)
	case c <= poolTierMedium:
		mediumResponsePool.Put(&buf)
	case c <= poolTierLarge:
		largeResponsePool.Put(&buf)
		// c > poolTierLarge: let GC collect it
	}
}

// responseBufferGuard records that something still reachable may read the work
// item's pooled response buffer after processItem returns, so the buffer must NOT
// go back to the pool.
//
// The case it exists for: a module that exceeds its per-module timeout (or is
// caught by phase cancellation) keeps running — a goroutine cannot be killed —
// and its scan closure still holds the item, whose response is built over the
// pooled buffer. Its wrapper meanwhile returns, processItem finishes, and the
// deferred putResponseBuffer hands that buffer to the next item, which overwrites
// it underneath the abandoned module. The module then reads another request's
// response and can report a finding against it.
//
// Giving up pooling for such an item is the whole fix: the buffer is simply left
// for the GC, which is correct however long the abandoned goroutine runs. This
// costs one allocation on a path that has already lost a module call, and nothing
// at all on the normal path.
type responseBufferGuard struct {
	escaped atomic.Bool
}

type responseBufferGuardKey struct{}

// withResponseBufferGuard attaches g to ctx for the lifetime of one work item.
//
// Carried in the context rather than as a parameter because the two abandonment
// points sit at the bottom of the active and passive dispatch fan-outs: reaching
// them explicitly means threading a guard through runActiveStage,
// runActivePer{Host,Request,InsertionPoint} and the runPassivePer*Filtered
// helpers, about six signatures, all of which already carry this context. The
// cost of the context value is ~50 bytes and ~40ns per item, against a per-item
// baseline of a network round trip plus a record conversion — so the explicit
// form buys clarity, not speed. If a third consumer of this flag ever appears,
// prefer the parameter.
func withResponseBufferGuard(ctx context.Context, g *responseBufferGuard) context.Context {
	return context.WithValue(ctx, responseBufferGuardKey{}, g)
}

// markResponseBufferEscaped flags the current item's pooled buffer as unsafe to
// recycle. A no-op when no guard is attached (an executor path that does not own
// a pooled buffer, or a unit test calling a wrapper directly).
func markResponseBufferEscaped(ctx context.Context) {
	if g, ok := ctx.Value(responseBufferGuardKey{}).(*responseBufferGuard); ok && g != nil {
		g.escaped.Store(true)
	}
}

// moduleFindingTracker tracks finding count and one-time warning for a single module.
type moduleFindingTracker struct {
	count  atomic.Int64
	warned sync.Once
}

// findingAdmission coordinates the first cap decision for one post-hook
// root-cause identity. Duplicate emissions wait for ready before using allowed,
// so they cannot race ahead and persist a finding that the owner is dropping.
type findingAdmission struct {
	ready   chan struct{}
	allowed bool
}

// FindingAdmission is the state behind the per-module finding cap: how many
// findings each module has had admitted, and which root-cause identities have
// already been admitted.
//
// It is a separate type so it can OUTLIVE one Executor. The dynamic-assessment
// phase builds a fresh executor per feedback round, so this state used to reset
// between rounds: a cap documented as holding "for the remainder of the scan"
// actually restarted every round, and a root cause re-found in round 2 re-fired
// every callback and notification for a finding already reported in round 1.
// Sharing one admission across the phase's rounds is what makes the documented
// contract true (triage C7: per dynamic-assessment phase, shared across rounds;
// other phases are uncapped).
//
// The zero value is ready to use, so an Executor built without a shared one gets
// its own by construction and a literal &Executor{cfg: …} in a test still works.
// Safe for concurrent use: both fields are sync.Maps.
type FindingAdmission struct {
	// counts is module ID → *moduleFindingTracker.
	counts sync.Map
	// ids tracks final post-hook root-cause identities and their admission
	// decisions. Repeated evidence is still persisted so the repository can merge
	// it, but only the first distinct finding consumes caps, stats, callbacks and
	// notifications.
	ids sync.Map
}

// NewFindingAdmission returns admission state a caller can share across several
// executors — one per dynamic-assessment phase, covering all of its rounds.
func NewFindingAdmission() *FindingAdmission { return &FindingAdmission{} }

// admission returns the state the cap decisions read: the caller's shared one
// when configured, otherwise this executor's own.
func (e *Executor) admission() *FindingAdmission {
	if e.cfg.FindingAdmission != nil {
		return e.cfg.FindingAdmission
	}
	return &e.caches.admission
}

// HookRunner transforms requests before scanning and filters results after scanning.
type HookRunner interface {
	RunPreHooks(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error)
	RunPostHooks(result *output.ResultEvent) (*output.ResultEvent, error)
}

// OASTFlusher is implemented by the OAST service to allow the executor to flush
// pending interactions after scanning completes.
type OASTFlusher interface {
	Flush()
	Close()
}

// ExecutorConfig configures the Executor behavior.
type ExecutorConfig struct {
	Workers       int
	OnResult      func(*output.ResultEvent)
	OnCandidate   func(*output.ResultEvent)
	OnObservation func(*output.ResultEvent)
	OnTraffic     func(method, url string, statusCode int, contentType string) // Optional: called for each processed item
	// OnAuthWall is called once per item whose redirect chain the transport
	// refused to follow into a login / SSO wall (http.StoppedAtAuthWall). It
	// carries the target that bounced and the wall it bounced to.
	//
	// The executor only reports; the phase decides what to do. That split is
	// deliberate: the wall host is a scan-wide fact (it feeds the fuzz-target
	// exclusion the spidering phase already maintains) and the executor has no
	// business owning scan-wide state, while re-deriving it later from stored
	// records would mean re-parsing every 3xx in the corpus.
	OnAuthWall    func(target, wall string)
	Services      *services.Services
	HTTPRequester *http.Requester
	Repository    *database.Repository    // Optional: database storage
	RecordWriter  *database.RecordWriter  // Optional: batched record writer (preferred over Repository.SaveRecord)
	FindingWriter *database.FindingWriter // Optional: batched finding writer (preferred over Repository.SaveFinding)
	ScanUUID      string
	// ProjectUUID owns every record and finding this executor writes. An empty
	// value is silently coerced to the DEFAULT project by the repository (see
	// database.defaultProjectUUID), so a config carrying a Repository/
	// RecordWriter/FindingWriter MUST set it or its output lands in a project
	// nobody is reading. Enforced by TestExecutorConfigAlwaysSetsProjectUUID.
	ProjectUUID       string
	Hooks             HookRunner           // Optional: pre/post hooks
	ScopeMatcher      *config.ScopeMatcher // Optional: scope filtering
	ScopeOnIngest     bool                 // When true, skip both save and scan for out-of-scope items
	StaticFileMatcher *config.ScopeMatcher // Optional: always-on static file filtering (independent of ScopeMatcher)
	FollowSubdomains  bool                 // When true, subdomain_harvest adds discovered subdomains to scope and feeds them (needs ScopeMatcher + feedback)
	SkipBaseline      bool                 // When true, skip HTTP fetch if response already attached (Phase 3 DB source)
	// RecordRedirectChain persists each followed redirect hop as its own record,
	// chained through parent_uuid, and re-pairs the final response with the
	// request that actually produced it. Off by default: it multiplies row
	// counts on every redirecting URL, and only a host-sweep style phase wants
	// the intermediate hops. See saveRedirectHops.
	RecordRedirectChain bool
	// RecordSource is the http_records.source label this executor stamps. Empty
	// means "scanner", which is what every phase used before the label became
	// configurable — so a phase that says nothing is unchanged.
	RecordSource         string
	OASTProvider         modkit.OASTProvider // Optional: OAST callback URL generator for blind vuln detection
	OASTService          OASTFlusher         // Optional: OAST service to flush after scanning
	PauseCtrl            *PauseController    // Optional: cooperative pause/resume controller
	MaxFindingsPerModule int                 // When > 0, suppress findings after this many per module
	// FindingAdmission optionally shares the per-module cap and the
	// already-admitted identity set with other executors. nil = executor-local,
	// which is right for a phase that runs exactly one Execute. The
	// dynamic-assessment phase passes ONE admission to every feedback round, so
	// the cap spans the phase and a root cause re-found in a later round does not
	// re-fire its callbacks. See FindingAdmission.
	FindingAdmission      *FindingAdmission
	MaxDuration           time.Duration                                                                                                       // When > 0, cancel execution after this duration
	FeedbackDrainTimeout  time.Duration                                                                                                       // Idle timeout for draining feedback after source EOF (default: 100ms)
	FeedbackDrainMaxStall time.Duration                                                                                                       // Hard cap on draining with workers in-flight but making no progress (0 = 2x active module timeout). Guards against a module that ignores cancellation.
	WorkerExitGrace       time.Duration                                                                                                       // Grace for worker goroutines to exit after the item channel is closed (0 = default 60s, capped at FeedbackDrainMaxStall). Kept short and separate from the drain-stall cap so shutdown stays responsive.
	IPCacheSize           int                                                                                                                 // LRU cache size for parsed insertion points (default: 4096)
	IPCache               *InsertionPointCache                                                                                                // Optional: shared IP cache (if nil, a new one is created)
	ParallelPassive       bool                                                                                                                // When true, run passive per-request modules concurrently
	PassiveModuleTimeout  time.Duration                                                                                                       // Timeout per passive module call (default: 5s). 0 uses default.
	ActiveModuleTimeout   time.Duration                                                                                                       // Timeout per active module call (default: 300s). 0 uses default. Modules may raise via TimeoutHinter.
	AdaptiveWorkers       bool                                                                                                                // When true, dynamically scale worker count based on queue depth
	MinWorkers            int                                                                                                                 // Floor for adaptive scaling (default: 2)
	MaxWorkers            int                                                                                                                 // Ceiling for adaptive scaling (default: Workers*4)
	ActiveTaskLimit       int                                                                                                                 // Max concurrent active module tasks across host/request/IP scopes
	OnStatus              func(processed, total, findings, distinctModules, activeCount, passiveCount, timedOut int64, elapsed time.Duration) // Optional: periodic status callback
	StatusInterval        time.Duration                                                                                                       // Interval for OnStatus callback (default: 30s)
	// ModuleTimeouts, when non-nil, is an externally-owned counter the executor
	// increments on each active-module timeout (instead of its own private one).
	// A multi-round phase passes one shared counter so the timed-out total in the
	// status line accumulates across the per-round executors it creates.
	ModuleTimeouts *atomic.Int64
	// FirstStatusInterval, when > 0 and shorter than StatusInterval, fires the
	// very first status tick after this duration instead of waiting a full
	// StatusInterval. Useful for long-cadence status (e.g., 2m) where users
	// shouldn't have to stare at silence before the first line appears.
	FirstStatusInterval time.Duration
	// DisableFeedback drops every URL discovered by passive modules instead of
	// re-injecting it into the scan. With this flag the executor scans exactly
	// the items the input source delivers and nothing more — matching the
	// shallow per-request semantics of `vigolium scan-request`. Used by
	// scan-on-receive's default mode to avoid the cascade of new HTTP records
	// that link extractors and redirect followers would otherwise generate.
	DisableFeedback bool
	// TechFilterDisabled bypasses the tech-stack allowlist gate (see modules.TechAware).
	// Set by --no-tech-filter and automatically by --intensity=deep so deep scans
	// run every module regardless of detected stack.
	TechFilterDisabled bool
	// OnTechDetected fires once per (host, tag) when a passive fingerprint
	// module first publishes a stack detection.
	OnTechDetected func(host, tag string)
	// DeepScan mirrors --intensity=deep into ScanContext so modules can unlock
	// heavier probing (e.g. dashboard_exposure's full mount-path sweep).
	DeepScan bool
	// ContentClassByHost seeds the per-host content-class registry from the
	// heuristics root probe (host → modkit.ContentClass string). It is the
	// fallback consulted by the content-class gate when a record's own
	// Content-Type is indeterminate. Honors the same TechFilterDisabled switch.
	ContentClassByHost map[string]string
}

// DefaultExecutorConfig returns sensible defaults.
func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{
		Workers: goruntime.NumCPU(),
	}
}

// SuggestWorkerCount returns a heuristic worker count for rescans.
// It scales with the number of active modules but caps at maxWorkers.
// The floor is 2 to ensure at least minimal parallelism.
func SuggestWorkerCount(moduleCount, maxWorkers int) int {
	suggested := moduleCount * 2
	if suggested < 2 {
		suggested = 2
	}
	if suggested > maxWorkers {
		suggested = maxWorkers
	}
	return suggested
}

// Executor orchestrates scanning with worker pool.
type Executor struct {
	cfg            ExecutorConfig
	source         source.InputSource
	activeModules  []modules.ActiveModule
	passiveModules []modules.PassiveModule
	httpClient     *http.Requester
	scanCtx        *modules.ScanContext
	hooks          HookRunner // Optional: pre/post hooks

	// Grouped modules for efficient routing
	perHostActive     []modules.ActiveModule
	perRequestActive  []modules.ActiveModule
	perIPActive       []modules.ActiveModule
	perHostPassive    []modules.PassiveModule
	perRequestPassive []modules.PassiveModule

	running       atomic.Bool
	results       atomic.Bool
	statsTracker  *stats.Tracker
	moduleMetrics *stats.ModuleMetrics

	// moduleTimeouts counts active-module invocations that hit the per-module
	// timeout and were skipped. Surfaced via the OnStatus callback so the status
	// line can show how many modules are timing out without flooding stderr with
	// a WARN per skip (those are logged at debug level instead). This is the
	// executor's own tally; a multi-round phase can instead supply a shared
	// counter via ExecutorConfig.ModuleTimeouts so the total accumulates across
	// rounds — see recordModuleTimeout / timedOutCount, which pick the right one.
	moduleTimeouts atomic.Int64

	// suppressedFindings counts candidate findings that were dropped by the
	// body-differential safety net (the payload-vs-baseline re-confirmation could
	// not establish a real, reproducible difference). Surfaced via
	// SuppressedFindings() so a quiet target doesn't look identical to a
	// confirmed-clean one — re-confirmation never truncates silently.
	suppressedFindings atomic.Int64

	// stored and storeFailed count what became of each item's PRIMARY record:
	// stored is one that is in the database when the item is done with (newly
	// written, or matched to the row it came from), storeFailed is one whose
	// write returned an error. Redirect hops and finding evidence are not
	// counted — the question these answer is "how many of my inputs are in the
	// store", and a chain is one input.
	//
	// They exist because neither Processed() nor Responded() can answer it, and
	// `vigolium ingest` reported Processed() as "records ingested": against a
	// host that no longer resolves that printed a full count over an empty
	// table. Attempted, answered and stored are three different numbers and the
	// only honest one for an ingest is the third.
	stored      atomic.Int64
	storeFailed atomic.Int64

	// responded counts input items for which an HTTP response was actually
	// received - one per item, not per redirect hop or retry.
	//
	// It exists because Processed() cannot answer that question: the worker
	// increments its stats tracker after processItem returns, and processItem
	// returns early on a transport failure, a dropped storage-metadata probe, or
	// a pre-hook rejection. On a normal scan the difference is noise; on a host
	// sweep, where dead hosts are a large fraction of the input, reporting
	// Processed() as "targets answered" reports every unreachable host as a
	// success. An HTTP error status is an answer; a connection failure is not.
	responded atomic.Int64

	// Database storage (optional)
	repo          *database.Repository
	recordWriter  *database.RecordWriter  // batched record writer (preferred over repo.SaveRecord)
	findingWriter *database.FindingWriter // batched finding writer (preferred over repo.SaveFinding)
	scanUUID      string
	projectUUID   string

	// corroboration collects database-error leaks observed in any active module's
	// 5xx probe response (via the requester response observer), emitted at phase end.
	corroboration *probeCorroboration

	// caches groups the per-scan lookup/dedup bookkeeping; pool groups the
	// worker-pool concurrency state. Both are split out of Executor to keep
	// this struct focused on orchestration rather than implementation state.
	caches scanCaches
	pool   workerPool

	// storageHosts records hosts observed to front object storage (a response
	// carried a storage backend signal) so the static-file carve-out keeps
	// sibling static assets on the same host. Key: host → struct{}. Bounded LRU
	// (not an unbounded sync.Map) so a long-lived executor can't accumulate one
	// entry per distinct storage-fronting host for the process lifetime.
	storageHosts *lru.Cache[string, struct{}]

	// report records whether this Execute call covered its whole input. Written
	// only by the Execute goroutine (the drain loop and the shutdown sequence all
	// run there), read by Report() after Execute returns — so the return itself is
	// the synchronisation. unacked is the exception: workers write it, so it is
	// atomic and lives outside the struct.
	report  ExecutionReport
	unacked atomic.Int64
}

// ExecutionReport says whether one Execute call processed its whole input, and
// what it gave up on if not.
//
// Execute returns (bool, error) where the bool is "produced findings" and the
// error is nil on every one of these paths: a cancelled feed, an abandoned
// drain, abandoned workers, a skipped deferred flush. Each of those silently
// reduces coverage, and the caller had no way to learn about any of them — a
// scan whose workers were abandoned mid-flight reported exactly what a clean one
// did. This is that missing channel.
type ExecutionReport struct {
	// StoppedEarly — the input source was not read to EOF (cancelled, deadline,
	// or a paused scan that was stopped while waiting).
	StoppedEarly bool
	// DrainStalled — the feedback drain was abandoned with workers still in
	// flight and making no progress.
	DrainStalled bool
	// WorkersAbandoned — one or more workers did not exit within the shutdown
	// grace and were leaked.
	WorkersAbandoned bool
	// DeferredFlushSkipped — the end-of-run passive flush was skipped because a
	// worker was abandoned, so deferred findings (secret detection, anomaly
	// ranking) may be incomplete.
	DeferredFlushSkipped bool
	// Unacked counts work items a worker dequeued but deliberately did NOT
	// acknowledge, because the context was already cancelled when it got them.
	// Not acknowledging is what keeps the durable cursor behind them so a later
	// run re-serves them; this number is how many that was.
	Unacked int64
}

// Clean reports whether the run covered its whole input with nothing abandoned.
//
// A convenience for callers and tests that want the one-line question. The
// runner's own consumer (phaseTracker.noteExecution) deliberately does not use
// it: each flag maps to a distinct outcome reason code, so it has to read them
// individually.
func (r ExecutionReport) Clean() bool {
	return !r.StoppedEarly && !r.DrainStalled && !r.WorkersAbandoned &&
		!r.DeferredFlushSkipped && r.Unacked == 0
}

// Report returns this executor's coverage self-report. Call it after Execute has
// returned; before that the fields are still being written.
func (e *Executor) Report() ExecutionReport {
	rep := e.report
	rep.Unacked = e.unacked.Load()
	return rep
}

// markStorageHost records that host fronts object storage.
func (e *Executor) markStorageHost(host string) {
	if host != "" {
		e.storageHosts.Add(host, struct{}{})
	}
}

// isLearnedStorageHost reports whether host was previously seen fronting
// object storage this scan.
func (e *Executor) isLearnedStorageHost(host string) bool {
	if host == "" {
		return false
	}
	return e.storageHosts.Contains(host)
}

// staticStorageCandidate reports whether a static-file request looks like an
// object-storage asset worth keeping (recorded metadata-only) rather than
// dropping: a /obj/<bucket>/<object> path shape, or a host already learned to
// front object storage.
func (e *Executor) staticStorageCandidate(rr *httpmsg.HttpRequestResponse) bool {
	if rr == nil || rr.Request() == nil {
		return false
	}
	if storagesig.LooksLikeStorageObjectPath(rr.Request().Path()) {
		return true
	}
	return rr.Service() != nil && e.isLearnedStorageHost(rr.Service().Host())
}

// perHostClaimCacheSize bounds each per-host claim LRU. With ~31 per-host
// modules this covers roughly 500 distinct hosts before the oldest claims
// evict — large enough that re-firing is rare during a single host's scan
// window, small enough that the maps can't grow unbounded over a multi-day
// server run.
const perHostClaimCacheSize = 16384

// hostClaimKey identifies a (module, origin) per-host claim, where origin is the
// canonical scheme://host:port identity (see originKeyFromItem) rather than a
// bare hostname — so the same hostname exposed on multiple ports/schemes doesn't
// collapse into one claim and suppress a ScanPerHost module on the other origins.
// Using a struct key instead of a "moduleID:origin" string avoids allocating a
// fresh string on every request for every per-host module (the claim is checked
// per request but only won once per pair) — the struct is hashed/compared in
// place by the LRU's map.
type hostClaimKey struct {
	moduleID string
	origin   string
}

// scanCaches groups the Executor's per-scan lookup and dedup state. Every field
// is safe for concurrent use (bounded LRU / sharded map / sync.Map).
type scanCaches struct {
	// ipCache is an insertion-point cache keyed by request SHA-256 hash, bounded
	// by both entry count and retained bytes. Avoids redundant AnalyzeRequest()
	// calls for repeated/retried requests.
	ipCache *InsertionPointCache

	// requestUUIDs tracks the database record UUID for each HttpRequestResponse
	// (for linking findings). Key: request hash, value: database record UUID.
	requestUUIDs *shardedMap

	// admission holds the per-module finding cap and the set of already-admitted
	// root-cause identities. Executor-local unless the caller supplies a shared
	// one through ExecutorConfig.FindingAdmission — see FindingAdmission.
	admission FindingAdmission

	// perHostActiveClaimed / perHostPassiveClaimed ensure per-host modules run
	// exactly once per (module, host) pair even with concurrent workers.
	// Key: hostClaimKey{moduleID, origin} → struct{}. Bounded LRUs rather than
	// unbounded sync.Maps: in a long-lived scan-on-receive executor the (module,
	// host) key space grows with every distinct host ingested, so an unbounded
	// map leaks for the process lifetime. The LRU caps that growth and, by
	// evicting the least-recently-claimed pairs, lets per-host modules re-fire
	// for a host whose claim has aged out — restoring coverage on hosts seen long
	// ago.
	perHostActiveClaimed  *lru.Cache[hostClaimKey, struct{}]
	perHostPassiveClaimed *lru.Cache[hostClaimKey, struct{}]

	// moduleTechReq is a per-module required-tech cache. Populated lazily by
	// passesTechFilter since module tags are immutable for the scan's lifetime.
	// Stored pre-normalized (lowercased, trimmed) so the registry lookup can skip
	// re-normalizing on each call. Key: module ID → []string (nil = always-runs).
	moduleTechReq sync.Map

	// moduleContentClassReq is the analogous per-module required-content-class
	// cache for passesContentClassFilter. Key: module ID → []string (nil = runs
	// on any content type).
	moduleContentClassReq sync.Map
}

// workerPool groups the Executor's worker-pool concurrency state.
type workerPool struct {
	// inFlight counts workers currently processing items. Used by the feedback
	// drain loop to wait for all workers to complete.
	inFlight atomic.Int64

	// Adaptive worker scaling: current count plus the lower/upper bounds.
	activeWorkers atomic.Int32
	minWorkers    int
	maxWorkers    int

	// feedbackCh lets modules inject discovered requests back into the pipeline;
	// feeder wraps it to track drop metrics. activeTaskSem bounds concurrent
	// active-module tasks.
	feedbackCh    chan *work.WorkItem
	feeder        *executorFeeder
	activeTaskSem chan struct{}
	// passiveTaskSem bounds concurrent parallel-passive goroutines GLOBALLY across
	// all record workers. Without it, ParallelPassive spawns one goroutine per
	// eligible passive module for every in-flight record (workers × modules), which
	// can reach thousands; this caps the fan-out to a fixed budget.
	passiveTaskSem chan struct{}
}

// NewExecutor creates a new Executor with the given configuration.
func NewExecutor(
	cfg ExecutorConfig,
	src source.InputSource,
	activeModules []modules.ActiveModule,
	passiveModules []modules.PassiveModule,
) *Executor {
	if cfg.Workers <= 0 {
		cfg.Workers = goruntime.NumCPU()
	}

	// Create ScanContext from Services
	var scanCtx *modules.ScanContext
	if cfg.Services != nil && cfg.Services.DedupManager != nil {
		scanCtx = &modules.ScanContext{
			DedupManager: cfg.Services.DedupManager,
		}
	}

	var ipCache *InsertionPointCache
	if cfg.IPCache != nil {
		ipCache = cfg.IPCache
	} else {
		ipCacheSize := cfg.IPCacheSize
		if ipCacheSize <= 0 {
			// Auto-size based on input source count for better cache utilization.
			// This is an entry cap only — retained bytes are bounded separately by
			// the cache itself (ipCacheMaxBytes), since entry size varies by four
			// orders of magnitude between a short GET and a large nested body.
			total := getKnownTotal(src)
			switch {
			case total > 0 && total <= 500:
				ipCacheSize = int(total) + 100
			case total > 500 && total <= 50000:
				ipCacheSize = int(total / 2)
			case total > 50000:
				ipCacheSize = 25000
			default:
				ipCacheSize = 4096
			}
		}
		ipCache = NewInsertionPointCache(ipCacheSize)
	}

	// Bounded LRUs for the per-host run-once claims (size <= 0 is the only error
	// lru.New returns, and perHostClaimCacheSize is a positive constant, so the
	// ignored error is provably nil).
	perHostActiveClaimed, _ := lru.New[hostClaimKey, struct{}](perHostClaimCacheSize)
	perHostPassiveClaimed, _ := lru.New[hostClaimKey, struct{}](perHostClaimCacheSize)
	storageHosts, _ := lru.New[string, struct{}](perHostClaimCacheSize)

	e := &Executor{
		cfg:            cfg,
		source:         src,
		activeModules:  activeModules,
		passiveModules: passiveModules,
		httpClient:     cfg.HTTPRequester,
		scanCtx:        scanCtx,
		hooks:          cfg.Hooks,
		repo:           cfg.Repository,
		recordWriter:   cfg.RecordWriter,
		findingWriter:  cfg.FindingWriter,
		scanUUID:       cfg.ScanUUID,
		projectUUID:    cfg.ProjectUUID,
		corroboration:  newProbeCorroboration(),
		storageHosts:   storageHosts,
		caches: scanCaches{
			requestUUIDs:          newShardedMap(cfg.Workers),
			ipCache:               ipCache,
			perHostActiveClaimed:  perHostActiveClaimed,
			perHostPassiveClaimed: perHostPassiveClaimed,
		},
		pool: workerPool{
			feedbackCh: make(chan *work.WorkItem, cfg.Workers*16),
		},
	}

	activeTaskLimit := cfg.ActiveTaskLimit
	if activeTaskLimit <= 0 {
		activeTaskLimit = cfg.Workers * 8
		if activeTaskLimit < 32 {
			activeTaskLimit = 32
		}
	}
	e.pool.activeTaskSem = make(chan struct{}, activeTaskLimit)

	// Global budget for parallel-passive goroutines. Passive work is CPU-bound, so
	// the bound only needs to keep cores busy — sized like the active budget so the
	// fan-out is capped to hundreds instead of workers × registered-modules.
	passiveTaskLimit := cfg.Workers * 8
	if passiveTaskLimit < 64 {
		passiveTaskLimit = 64
	}
	e.pool.passiveTaskSem = make(chan struct{}, passiveTaskLimit)

	// Wire risk/surface score updaters, remarks and technology annotators,
	// record-response rewriter, and request UUID resolver into ScanContext
	if e.scanCtx != nil && cfg.Repository != nil {
		e.scanCtx.RiskScoreUpdater = &repoRiskScoreUpdater{repo: cfg.Repository}
		e.scanCtx.SurfaceScoreUpdater = &repoSurfaceScoreUpdater{repo: cfg.Repository}
		e.scanCtx.RemarksAnnotator = &repoRemarksAnnotator{repo: cfg.Repository}
		e.scanCtx.TechAnnotator = &repoTechnologyAnnotator{repo: cfg.Repository}
		e.scanCtx.RecordRewriter = &repoRecordResponseRewriter{repo: cfg.Repository}
		e.scanCtx.ArtifactWriter = &repoDerivedArtifactWriter{repo: cfg.Repository}
		e.scanCtx.RequestUUIDResolver = e
	}

	// Expose a read-only scope check so modules can tell a scan-target host from a
	// third-party one (e.g. js-beautify only skips vendor scripts that are not the
	// target). Independent of Repository (works for stateless scans too).
	if e.scanCtx != nil && cfg.ScopeMatcher != nil {
		e.scanCtx.Scope = &executorScopeChecker{matcher: cfg.ScopeMatcher}
	}

	// Wire OAST provider into ScanContext
	if cfg.OASTProvider != nil {
		if e.scanCtx == nil {
			e.scanCtx = &modules.ScanContext{}
		}
		e.scanCtx.OASTProvider = cfg.OASTProvider
	}

	// Wire feedback feeder and cross-module finding dedup into ScanContext
	if e.scanCtx == nil {
		e.scanCtx = &modules.ScanContext{}
	}
	if cfg.DisableFeedback {
		// Shallow mode: modules can still call Feed() but it's a no-op. The
		// feedback channel is still allocated (cheap) but stays empty, so the
		// drain loop exits as soon as in-flight workers finish.
		e.scanCtx.RequestFeeder = nopFeederInstance
	} else {
		e.pool.feeder = &executorFeeder{ch: e.pool.feedbackCh}
		e.scanCtx.RequestFeeder = e.pool.feeder
	}
	// Wire scope expander + follow-subdomains toggle (subdomain_harvest feed-back).
	// Requires a real scope matcher and live feedback; otherwise the module stays
	// recon-only because ShouldFollowSubdomains() sees no expander/feeder.
	if cfg.FollowSubdomains && cfg.ScopeMatcher != nil && !cfg.DisableFeedback {
		e.scanCtx.ScopeExpander = &executorScopeExpander{matcher: cfg.ScopeMatcher}
		e.scanCtx.FollowSubdomains = true
	}
	e.scanCtx.DeepScan = cfg.DeepScan
	e.scanCtx.ParamFindings = &modkit.ParameterFindingRegistry{}
	e.scanCtx.TechStack = modkit.NewTechRegistry()
	e.scanCtx.TechStack.OnDetect = cfg.OnTechDetected
	e.scanCtx.WAFStack = modkit.NewWAFRegistry()
	e.scanCtx.ContentClass = modkit.NewContentClassRegistry()
	for host, class := range cfg.ContentClassByHost {
		e.scanCtx.ContentClass.Set(host, modkit.ContentClass(class))
	}

	// Wire insertion point provider for module reuse of cached IPs
	e.scanCtx.InsertionPoints = &executorIPProvider{cache: e.caches.ipCache}

	// Pre-group modules by scan type
	e.perHostActive = filterActiveModulesByScanScope(activeModules, modules.ScanScopeHost)
	e.perRequestActive = filterActiveModulesByScanScope(activeModules, modules.ScanScopeRequest)
	e.perIPActive = filterActiveModulesByScanScope(activeModules, modules.ScanScopeInsertionPoint)
	e.perHostPassive = filterPassiveModulesByScanScope(passiveModules, modules.ScanScopeHost)
	e.perRequestPassive = filterPassiveModulesByScanScope(passiveModules, modules.ScanScopeRequest)

	// Sort active modules by priority within each scope group.
	// Higher priority (lower number) modules are spawned first,
	// getting earlier access to rate-limit slots.
	sortActiveByPriority(e.perHostActive)
	sortActiveByPriority(e.perRequestActive)
	sortActiveByPriority(e.perIPActive)

	// Always create stats tracker for counting processed items.
	// Periodic printing is only started when ShowStats is enabled (see Execute).
	total := getKnownTotal(src)
	e.statsTracker = stats.New(total, false)
	e.moduleMetrics = &stats.ModuleMetrics{}

	return e
}

// Processed returns the number of items processed by the executor.
func (e *Executor) Processed() int64 {
	if e.statsTracker != nil {
		return e.statsTracker.Processed()
	}
	return 0
}

// ModuleMetrics returns a point-in-time snapshot of per-module performance metrics.
func (e *Executor) ModuleMetrics() map[string]stats.ModuleStatsSnapshot {
	if e.moduleMetrics != nil {
		return e.moduleMetrics.Snapshot()
	}
	return nil
}

// FeedbackDropped returns the number of feedback items dropped due to channel capacity.
func (e *Executor) FeedbackDropped() int64 {
	if e.pool.feeder != nil {
		return e.pool.feeder.Dropped()
	}
	return 0
}

// SuppressedFindings returns the number of candidate findings dropped by the
// body-differential safety net because a real payload-vs-baseline difference
// could not be re-confirmed.
func (e *Executor) SuppressedFindings() int64 {
	return e.suppressedFindings.Load()
}

// Responded returns how many input items produced an HTTP response, which is
// always <= Processed(). Use this, not Processed(), to report how many targets
// answered: Processed() counts attempts, including the ones that never reached
// a server. See the responded field for why the two differ.
// Stored returns the number of input items whose primary record is in the
// database when this executor finished with them. Use this, not Processed(),
// to report how many records a run PERSISTED: Processed() counts attempts, and
// an attempt that never reached a host, or whose write failed, stores nothing.
func (e *Executor) Stored() int64 {
	return e.stored.Load()
}

// StoreFailed returns the number of input items whose primary record could not
// be written. Distinct from an item that was never stored because it got no
// response (Processed() minus Responded()) or because a filter dropped it: this
// one reached the database and the database refused it.
func (e *Executor) StoreFailed() int64 {
	return e.storeFailed.Load()
}

func (e *Executor) Responded() int64 {
	return e.responded.Load()
}

// InFlight returns the number of worker goroutines currently processing items.
// Zero means the executor is quiescent (all workers idle, no items in flight).
// Exposed for status reporting — callers typically combine this with source-level
// idle signals to distinguish "still doing work" from "waiting for input."
func (e *Executor) InFlight() int64 {
	return e.pool.inFlight.Load()
}

// ConsideredModuleCount returns the number of distinct modules whose CanProcess
// has been evaluated at least once during this scan. Reaches parity with the
// total enabled-module count once every module has been seen — including those
// whose CanProcess always rejects the input shape (e.g., POST-only modules in
// a GET-only scan). Use this for "modules scanned X/Y" status displays.
func (e *Executor) ConsideredModuleCount() int64 {
	if e.moduleMetrics == nil {
		return 0
	}
	return e.moduleMetrics.ConsideredCount()
}

// Execute runs the scan. Blocks until all inputs are processed or context is cancelled.
func (e *Executor) Execute(ctx context.Context) (bool, error) {
	if !e.running.CompareAndSwap(false, true) {
		return false, fmt.Errorf("executor already running")
	}
	defer e.running.Store(false)

	// Fresh report per run. An executor is normally single-use (dynamic
	// assessment builds one per feedback round), but a reused one must not
	// inherit a previous run's abandonment.
	e.report = ExecutionReport{}
	e.unacked.Store(0)

	// Observe server-error probe responses so a leaked database error surfaced by
	// ANY module's probe is corroborated even when the sending module didn't check
	// for it. Installed for this run only; cleared on return so a later phase's
	// traffic on the shared requester isn't observed into a stale collector.
	if e.httpClient != nil {
		e.httpClient.SetResponseObserver(e.observeProbeResponse)
		defer e.httpClient.SetResponseObserver(nil)
	}

	// Give this execution its own cancellation scope, ALWAYS — not only when a
	// phase timeout is configured. Background loops below (the status callback)
	// used to exit on the caller's ctx alone, so with MaxDuration == 0 a normal
	// EOF return left them running: dynamic assessment builds one executor per
	// round against a phase-long context, so each finished round leaked a ticker
	// goroutine that kept firing OnStatus — reporting a completed executor's
	// metrics, and reading the database — until the whole phase ended.
	execCtx, cancelExec := context.WithCancel(ctx)
	defer cancelExec()
	ctx = execCtx

	// Enforce per-phase timeout when configured
	if e.cfg.MaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.cfg.MaxDuration)
		defer cancel()
	}

	// Start periodic stats printing only when ShowStats is enabled
	if e.cfg.Services != nil && e.cfg.Services.Options != nil &&
		e.cfg.Services.Options.ShowStats && !e.cfg.Services.Options.Silent {
		e.statsTracker.Start(ctx)
		defer e.statsTracker.Stop()
	}

	// Start periodic status callback when configured
	if e.cfg.OnStatus != nil {
		statusInterval := e.cfg.StatusInterval
		if statusInterval <= 0 {
			statusInterval = 30 * time.Second
		}
		statusStart := time.Now()
		statusTicker := time.NewTicker(statusInterval)
		activeCount := int64(len(e.activeModules))
		passiveCount := int64(len(e.passiveModules))

		// Optional early-tick: fire a single status before the regular cadence
		// kicks in. Helpful for long StatusInterval (e.g. 2m) where the user
		// would otherwise wait the full interval to see anything.
		var firstTickCh <-chan time.Time
		if e.cfg.FirstStatusInterval > 0 && e.cfg.FirstStatusInterval < statusInterval {
			firstTickCh = time.NewTimer(e.cfg.FirstStatusInterval).C
		}

		fireStatus := func() {
			e.cfg.OnStatus(
				e.statsTracker.Processed(),
				e.statsTracker.Total(),
				e.statsTracker.Findings(),
				e.moduleMetrics.DistinctCount(),
				activeCount,
				passiveCount,
				e.timedOutCount(),
				time.Since(statusStart),
			)
		}

		statusDone := make(chan struct{})
		go func() {
			defer close(statusDone)
			defer statusTicker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-firstTickCh:
					fireStatus()
					firstTickCh = nil // one-shot
				case <-statusTicker.C:
					fireStatus()
				}
			}
		}()
		// Join before returning, so no status line can be emitted after Execute
		// has handed back its result. cancelExec runs first (defers are LIFO
		// relative to this one being registered later), releasing the loop.
		defer func() {
			cancelExec()
			<-statusDone
		}()
	}

	var wg conc.WaitGroup
	itemCh := make(chan *work.WorkItem, e.cfg.Workers*2)

	e.pool.activeWorkers.Store(int32(e.cfg.Workers))
	for i := 0; i < e.cfg.Workers; i++ {
		workerID := i
		wg.Go(func() {
			e.worker(ctx, workerID, itemCh)
			e.pool.activeWorkers.Add(-1)
		})
	}

	// Start adaptive worker controller if enabled
	var controllerCancel context.CancelFunc
	if e.cfg.AdaptiveWorkers {
		e.pool.minWorkers = e.cfg.MinWorkers
		if e.pool.minWorkers <= 0 {
			e.pool.minWorkers = 2
		}
		e.pool.maxWorkers = e.cfg.MaxWorkers
		if e.pool.maxWorkers <= 0 {
			e.pool.maxWorkers = e.cfg.Workers * 4
		}
		var controllerCtx context.Context
		controllerCtx, controllerCancel = context.WithCancel(ctx)
		go e.workerController(controllerCtx, itemCh, &wg)
	}

	e.report.StoppedEarly = !e.feedItems(ctx, itemCh)

	// After source EOF, drain remaining feedback items from in-flight workers.
	// Wait until all workers finish (inFlight == 0) and the feedback channel is empty.
	// When FeedbackDrainTimeout is configured, require the executor to remain idle
	// for that duration before completing the drain.
	// Backing-off poll rather than a fixed tick; see drainPollMin/drainPollMax.
	drainDelay := drainPollMin
	drainTimer := time.NewTimer(drainDelay)
	defer drainTimer.Stop()
	idleTimeout := e.cfg.FeedbackDrainTimeout
	// stallTimeout bounds the drain when workers stay in-flight but make no
	// forward progress. The idle branch below only fires once inFlight hits 0, so
	// a module that ignores cancellation would otherwise pin inFlight > 0 and hang
	// the drain forever. lastProgress is reset whenever a feedback item arrives or
	// an in-flight item completes (inFlight decreases), so a healthy long-running
	// drain is never truncated — only a genuine no-progress stall trips the cap.
	stallTimeout := e.feedbackDrainMaxStall()
	var idleSince time.Time
	lastProgress := time.Now()
	prevInFlight := e.pool.inFlight.Load()
drainLoop:
	for {
		select {
		case <-ctx.Done():
			break drainLoop
		case fb := <-e.pool.feedbackCh:
			idleSince = time.Time{}
			lastProgress = time.Now()
			if !e.sendItem(ctx, fb, itemCh) {
				break drainLoop
			}
		case <-drainTimer.C:
			// Monotonic backoff. Resetting the delay whenever feedback arrives
			// looks like "poll tightly again while there is work", but it is the
			// opposite of what the drain wants: a busy drain would knock the
			// interval back to 1ms on every item and settle near 500 wakeups a
			// second, where the fixed tick it replaced did 20. The fast-finish
			// win is entirely in the first few ticks, which monotonic backoff
			// already gives.
			drainDelay = min(drainDelay*2, drainPollMax)
			drainTimer.Reset(drainDelay)
			cur := e.pool.inFlight.Load()
			if cur < prevInFlight {
				lastProgress = time.Now() // a worker completed an item
			}
			prevInFlight = cur
			if cur != 0 || len(e.pool.feedbackCh) != 0 {
				idleSince = time.Time{}
				if stallTimeout > 0 && time.Since(lastProgress) >= stallTimeout {
					zap.L().Warn("feedback drain abandoned: workers still in flight but no progress within stall timeout (a module may be ignoring cancellation)",
						zap.Int64("in_flight", cur),
						zap.Int("feedback_queued", len(e.pool.feedbackCh)),
						zap.Duration("stall_timeout", stallTimeout))
					e.report.DrainStalled = true
					break drainLoop
				}
				continue
			}
			if idleTimeout <= 0 {
				break drainLoop
			}
			if idleSince.IsZero() {
				idleSince = time.Now()
				continue
			}
			if time.Since(idleSince) >= idleTimeout {
				break drainLoop
			}
		}
	}

	// Stop the adaptive worker controller before closing the channel
	if controllerCancel != nil {
		controllerCancel()
	}

	close(itemCh)

	// Bound the wait for workers to exit. Healthy workers return immediately once
	// itemCh is closed; only a worker stuck in a code path that ignores
	// cancellation lingers. Without a bound, that single worker would hang Wait()
	// — and the whole scan — forever (the drain stall cap above only breaks the
	// drain loop; this is where an unresponsive worker would otherwise re-block).
	// We run Wait() in a goroutine and forward any captured panic so conc's
	// re-panic semantics are preserved on the normal path; on timeout we log
	// loudly and proceed, leaking the stuck goroutine rather than hanging.
	waitDone := make(chan struct{})
	var waitPanic atomic.Value
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Never silently swallow a worker panic. Log it here so it stays
				// visible even when the main goroutine has already abandoned the
				// wait (the timeout branch below never reads waitPanic); also stash
				// it so the normal path re-raises it with conc's semantics.
				zap.L().Error("recovered panic while waiting for scan workers to exit",
					zap.Any("panic", r))
				waitPanic.Store(r)
			}
			close(waitDone)
		}()
		wg.Wait()
	}()
	exitGrace := e.workerExitGrace()
	workersExited := true
	select {
	case <-waitDone:
		if r := waitPanic.Load(); r != nil {
			panic(r)
		}
	case <-time.After(exitGrace):
		workersExited = false
		e.report.WorkersAbandoned = true
		zap.L().Warn("abandoning scan worker(s) that did not exit within the shutdown grace to avoid hanging the scan; leaking goroutine(s)",
			zap.Int64("in_flight", e.pool.inFlight.Load()),
			zap.Duration("worker_exit_grace", exitGrace))
	}

	// Passive-module flush must only run once every worker has exited. Flusher /
	// BatchFlusher modules aggregate cross-request state that a worker mutates
	// from ScanPerRequest; if we abandoned a still-running worker above, flushing
	// here would race that worker on the module's buffer and the result pipeline.
	// In that (pathological, already-degraded) case we skip the flush rather than
	// risk corrupted findings — deferred findings may be incomplete.
	if workersExited {
		// Flush passive modules that buffer data (e.g., anomaly ranking)
		for _, pm := range e.passiveModules {
			if flusher, ok := pm.(modules.Flusher); ok {
				flusher.Flush(e.scanCtx)
			}
		}

		// Flush batch passive modules that produce deferred findings (e.g., secret detection)
		for _, pm := range e.passiveModules {
			if bf, ok := pm.(modules.BatchFlusher); ok {
				results, err := bf.FlushFindings(e.scanCtx)
				if err != nil {
					zap.L().Warn("BatchFlusher error",
						zap.String("module", pm.ID()),
						zap.Error(err))
					continue
				}
				for _, r := range results {
					r.ModuleType = database.ModuleTypePassive
					r.FindingSource = database.FindingSourceDynamicAssessment
					// Deferred batch findings carry their own request; no baseline
					// item is in scope here, so take the standard parse/save path.
					// The per-module cap is enforced once inside emitResult →
					// admitFinding; do NOT pre-check moduleFindingAllowed here or each
					// finding would consume the cap twice (a cap of 15 admits ~7).
					e.emitResult(ctx, r, nil, nil)
				}
			}
		}
		// Emit corroboration observations harvested from probe traffic. Same
		// workers-exited guard as the passive flush: the observer runs on request
		// goroutines, so draining before they exit could race a live append.
		e.drainProbeCorroboration(ctx)
	} else {
		e.report.DeferredFlushSkipped = true
		zap.L().Warn("skipping passive-module flush after abandoning workers; deferred findings (e.g. secret detection, anomaly ranking) may be incomplete")
	}

	// Flush OAST service: wait for grace period to catch late callbacks
	if e.cfg.OASTService != nil {
		e.cfg.OASTService.Flush()
	}

	e.logInsertionPointCacheStats()

	return e.results.Load(), nil
}

// logInsertionPointCacheStats reports the insertion-point cache's behaviour once
// the scan is done. Byte evictions and size rejections are the interesting
// signals: they mean the byte budget, not the entry cap, was the binding limit —
// i.e. this scan's requests were heavy enough to re-derive insertion points that
// a larger budget would have kept.
func (e *Executor) logInsertionPointCacheStats() {
	s := e.caches.ipCache.Stats()
	if s.Hits == 0 && s.Misses == 0 {
		return
	}

	zap.L().Debug("Insertion-point cache",
		zap.Int("entries", s.Entries),
		zap.Int64("retained_mib", s.RetainedBytes>>20),
		zap.Int64("hits", s.Hits),
		zap.Int64("misses", s.Misses),
		zap.Int64("byte_evictions", s.Evictions),
		zap.Int64("size_rejections", s.Rejected))
}

// feedItems pumps the input source into itemCh. It returns whether the source
// was EXHAUSTED — true only on io.EOF. Every other way out (cancellation, a
// deadline, a stop while paused, a blocked send) means items were left unread,
// which is the one fact the caller needs to know and could not previously learn:
// the function returned nothing, so a cancelled feed and a fully consumed one
// were the same event.
func (e *Executor) feedItems(ctx context.Context, itemCh chan<- *work.WorkItem) (exhausted bool) {
	// Sources report per-item failures by returning a non-EOF error from Next();
	// we log and skip the bad item, then keep reading. This must NOT abort the
	// feed: e.g. TargetSource advances its cursor before validating a URL, so a
	// malformed entry returns an error but the next call yields the next valid
	// target — bailing out here would silently drop the rest of the input.
	// Exhaustion is signalled by io.EOF (a source that can't make progress, like
	// a FileSource whose parse failed, reports its error once and then EOFs).
	//
	// The only hazard is a source that returns the same error on every call
	// without ever yielding an item or EOF; an unconditional retry would peg a
	// CPU. We guard against that with a small backoff once errors arrive
	// back-to-back with no item in between — a spin guard only, never a reason
	// to drop input. A source that interleaves errors with items resets the
	// streak and never pays the cost.
	const spinGuardThreshold = 4
	consecutiveErrors := 0
	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		// Drain any pending feedback items (non-blocking) before pulling from source
		e.drainFeedback(ctx, itemCh)

		// Block feeding while paused
		if e.cfg.PauseCtrl != nil {
			if !e.cfg.PauseCtrl.WaitIfPaused(ctx) {
				return false
			}
		}

		item, err := e.source.Next(ctx)
		if err != nil {
			if source.IsEOF(err) {
				return true
			}
			if ctx.Err() != nil {
				return false
			}
			consecutiveErrors++
			zap.L().Warn("Error reading from source",
				zap.Error(err),
				zap.Int("consecutive_errors", consecutiveErrors))
			// Spin guard: only sleep once errors come back-to-back with no item
			// in between (a source stuck returning the same error). This never
			// fires for sources that keep making progress between errors.
			if consecutiveErrors >= spinGuardThreshold {
				select {
				case <-ctx.Done():
					return false
				case <-time.After(50 * time.Millisecond):
				}
			}
			continue
		}
		consecutiveErrors = 0

		if !e.sendItem(ctx, item, itemCh) {
			return false
		}
	}
}

// drainFeedback non-blocking drains all pending feedback items into itemCh.
func (e *Executor) drainFeedback(ctx context.Context, itemCh chan<- *work.WorkItem) {
	for {
		select {
		case fb := <-e.pool.feedbackCh:
			if !e.sendItem(ctx, fb, itemCh) {
				return
			}
		default:
			return
		}
	}
}

// sendItem applies scope/static filters and sends the item to itemCh.
// Returns false if context is cancelled.
func (e *Executor) sendItem(ctx context.Context, item *work.WorkItem, itemCh chan<- *work.WorkItem) bool {
	// Always filter static files before HTTP fetch — EXCEPT object-storage
	// assets, which are kept and recorded metadata-only (HEAD, body stripped)
	// so the CDN traversal modules can probe storage-fronted static URLs.
	if e.cfg.StaticFileMatcher != nil &&
		e.cfg.StaticFileMatcher.IsStaticFile(item.Request.Request().Path()) {
		if e.staticStorageCandidate(item.Request) {
			item.StaticMeta = true
		} else {
			item.Complete()
			return true
		}
	}

	// Pre-request scope check (host/path only — avoids HTTP call)
	if e.cfg.ScopeMatcher != nil && item.Request.Service() != nil {
		if !e.cfg.ScopeMatcher.InScopeRequest(
			item.Request.Service().Host(),
			item.Request.Request().Path(), "", "") {
			item.Complete()
			return true
		}
	}

	// Per-module filtering via CanProcess() replaces global ShouldSkip
	if e.cfg.Services != nil && e.cfg.Services.HostErrors != nil &&
		e.cfg.Services.HostErrors.Check(item.Request.ID()) {
		item.Complete()
		return true
	}

	select {
	case <-ctx.Done():
		return false
	case itemCh <- item:
		return true
	}
}

func (e *Executor) worker(ctx context.Context, _ int, itemCh <-chan *work.WorkItem) {
	for {
		// Block if paused, abort if context cancelled
		if e.cfg.PauseCtrl != nil {
			if !e.cfg.PauseCtrl.WaitIfPaused(ctx) {
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case item, ok := <-itemCh:
			if !ok {
				return
			}
			e.pool.inFlight.Add(1)
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.AcquireWorker()
			}
			panicked := e.processItem(ctx, item)
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.ReleaseWorker()
			}
			e.pool.inFlight.Add(-1)
			e.finishItem(ctx, item, panicked)
			if e.statsTracker != nil {
				e.statsTracker.Increment()
			}
		}
	}
}

// finishItem acknowledges an item only if it was actually processed.
//
// The worker's select can win a dequeue in the same instant the context is
// cancelled, and processItem's first act is to bail out on a cancelled context —
// so the item came off the queue, did no work, and was then acknowledged anyway.
// For a DB-backed source an ack is a durable cursor advance: the scan's cursor
// moved past records nothing ever looked at, and because a curtailed scan still
// recorded "completed", the next scan-on-receive run inherited that cursor and
// skipped them permanently. Withholding the ack is what makes those records get
// re-served.
//
// force is for a recovered panic: a poison item that keeps failing must still be
// acknowledged, or it comes back every run and the cursor never moves past it.
func (e *Executor) finishItem(ctx context.Context, item *work.WorkItem, force bool) {
	if !force && ctx.Err() != nil {
		e.unacked.Add(1)
		return
	}
	item.Complete()
}

// workerController monitors queue depth and scales workers up or down.
// Only active when AdaptiveWorkers is enabled.
func (e *Executor) workerController(ctx context.Context, itemCh chan *work.WorkItem, wg *conc.WaitGroup) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	nextID := e.cfg.Workers // start IDs after initial workers

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			queueDepth := len(itemCh)
			queueCap := cap(itemCh)
			active := int(e.pool.activeWorkers.Load())

			// Scale up: queue > 75% full and we have headroom
			if queueDepth > queueCap*3/4 && active < e.pool.maxWorkers {
				workerID := nextID
				nextID++
				e.pool.activeWorkers.Add(1)
				wg.Go(func() {
					e.worker(ctx, workerID, itemCh)
					e.pool.activeWorkers.Add(-1)
				})
				zap.L().Debug("Adaptive scaling: spawned worker",
					zap.Int("worker_id", workerID),
					zap.Int("active_workers", int(e.pool.activeWorkers.Load())))
			}

			// Note: scaling down is handled naturally — when itemCh is closed,
			// excess workers exit on their own. We don't preemptively kill workers
			// to avoid complexity of per-worker cancellation and potential data loss.
		}
	}
}

// processItem runs one work item through the fetch, passive and active stages.
// It returns whether a panic was recovered, which the caller needs in order to
// acknowledge the item anyway: a poison item that is never acknowledged is
// re-served on every subsequent run and freezes the cursor behind it.
func (e *Executor) processItem(ctx context.Context, item *work.WorkItem) (panicked bool) {
	// Registered first so it unwinds LAST, after the buffer-return defer below.
	defer e.recoverFromPanicInto("processItem", &panicked)

	// Bail out early if context is cancelled (graceful shutdown)
	select {
	case <-ctx.Done():
		return false
	default:
	}

	// Track pooled response buffer for deferred return.
	// Must be declared before the panic-recovery defer so it runs first (LIFO).
	//
	// guard withholds the buffer from the pool when a module call was abandoned
	// (per-module timeout or phase cancellation) and may still be reading it. See
	// responseBufferGuard.
	var pooledBuf []byte
	var guard responseBufferGuard
	ctx = withResponseBufferGuard(ctx, &guard)
	defer func() {
		if pooledBuf != nil && !guard.escaped.Load() {
			putResponseBuffer(pooledBuf)
		}
	}()

	req := item.Request
	enableModules := item.EnableModules

	zap.L().Debug("Processing item",
		zap.String("url", req.Target()),
		zap.Strings("enable_modules", enableModules))

	// Check context before expensive HTTP fetch
	select {
	case <-ctx.Done():
		return
	default:
	}

	var fetched baselineFetch
	var ok bool
	if item.StaticMeta {
		// Object-storage metadata items record the URL + headers (status,
		// content-type, content-length), never the (large/binary) object body:
		// a HEAD, falling back to a ranged GET for origins that reject HEAD.
		fetched, ok = e.fetchStaticMetaResponse(ctx, req)
	} else {
		fetched, ok = e.fetchBaseline(ctx, req)
	}
	if !ok {
		return
	}
	// Counted here rather than at the end of processItem: this is the exact point
	// where a server answered, and every later return in this function is a
	// policy decision about an answer we already have.
	e.responded.Add(1)
	// pooledBuf is ASSIGNED, never redeclared: the deferred putResponseBuffer
	// above closes over the outer variable, and a `:=` here would shadow it and
	// leak the buffer on every item.
	var httpResp *httpmsg.HttpResponse
	req, httpResp, pooledBuf = fetched.req, fetched.resp, fetched.pooledBuf
	redirectHops := fetched.hops

	// Learn object-storage-backed hosts from any storage-signalled response so
	// the static-file carve-out keeps sibling assets on the same host.
	if req.Service() != nil && storagesig.ResponseHasStorageSignal(httpResp) {
		e.markStorageHost(req.Service().Host())
	}

	// Static metadata items: keep only genuine storage assets, body stripped.
	if item.StaticMeta {
		if !storagesig.ResponseHasStorageSignal(httpResp) &&
			!storagesig.LooksLikeStorageObjectPath(req.Request().Path()) {
			return // storage hint did not pan out; drop without recording
		}
		httpResp.TruncateBody(0)
	}

	// Notify traffic callback
	if e.cfg.OnTraffic != nil {
		ct := getHeaderValue(httpResp.Headers(), "Content-Type")
		e.cfg.OnTraffic(req.Request().Method(), req.Target(), httpResp.StatusCode(), ct)
	}

	// Report a chain the transport stopped at an authentication wall. Read off
	// the stored 3xx rather than signalled out of CheckRedirect: the policy can
	// only answer with ErrUseLastResponse, and — decisively — the request
	// clusterer replays cached responses WITHOUT running CheckRedirect at all,
	// so anything recorded inside the policy would be missing on every cache
	// hit. Re-deriving is uniform across live and replayed responses.
	//
	// Status first: everything after it allocates (a header scan and a URL
	// rebuild), and the overwhelming majority of items are not redirects.
	if e.cfg.OnAuthWall != nil && httpmsg.IsRedirectStatus(httpResp.StatusCode()) {
		if wall, ok := http.StoppedAtAuthWall(req.Target(), httpResp.StatusCode(),
			getHeaderValue(httpResp.Headers(), "Location")); ok {
			e.cfg.OnAuthWall(req.Target(), wall)
		}
	}

	req, ok = e.applyPreHooks(req)
	if !ok {
		return
	}

	// Body size enforcement — truncate oversized bodies but defer drop/skip
	// decisions until after passive modules run (they are read-only).
	var bodySizeAction config.BodySizeAction
	if e.cfg.ScopeMatcher != nil {
		reqBodyLen := len(req.Request().Body())
		respBodyLen := len(httpResp.Body())
		var maxReq, maxResp int
		bodySizeAction, maxReq, maxResp = e.cfg.ScopeMatcher.CheckBodySize(reqBodyLen, respBodyLen)

		if bodySizeAction != config.BodySizeOK {
			if reqBodyLen > maxReq {
				req.Request().TruncateBody(maxReq)
				zap.L().Debug("Request body truncated",
					zap.String("url", req.Target()),
					zap.Int("original", reqBodyLen),
					zap.Int("truncated_to", maxReq))
			}
			if respBodyLen > maxResp {
				httpResp.TruncateBody(maxResp)
				zap.L().Debug("Response body truncated",
					zap.String("url", req.Target()),
					zap.Int("original", respBodyLen),
					zap.Int("truncated_to", maxResp))
			}
		}
	}

	// Module filter setup (needed by passive modules below)
	var filter moduleFilter
	if len(enableModules) == 0 {
		filter = allModulesFilter
	} else {
		filter = newModuleFilter(enableModules)
	}

	// Pre-register requestUUIDs for DB-sourced items so passive module
	// findings can link to the existing http_record instead of creating
	// duplicate "finding" records.
	if item.RecordUUID != "" && e.repo != nil {
		e.caches.requestUUIDs.Store(req.Request().ID(), item.RecordUUID)
	}

	// Pre-compute scope status before passive modules so scope-aware
	// passive modules can be skipped for out-of-scope items.
	inScope := true
	if e.cfg.ScopeMatcher != nil && req.Service() != nil {
		inScope = e.cfg.ScopeMatcher.InScopeBytes(
			req.Service().Host(),
			req.Request().Path(),
			httpResp.StatusCode(),
			getHeaderValue(req.Request().Headers(), "Content-Type"),
			getHeaderValue(httpResp.Headers(), "Content-Type"),
			req.Request().Raw(),
			httpResp.Body(),
		)
	}

	e.runPassiveStage(ctx, req, &filter, inScope)

	// Body size gate — drop/skip only affects active modules
	if bodySizeAction == config.BodySizeDrop {
		zap.L().Debug("Body size exceeded, dropping item (active scan skipped)",
			zap.String("url", req.Target()))
		return
	}
	if bodySizeAction == config.BodySizeSkipScan {
		e.saveToDatabase(ctx, item, req, redirectHops)
		return
	}
	skipActive := bodySizeAction == config.BodySizePassiveOnly

	if !e.persistAndCheckScope(ctx, item, req, inScope, redirectHops) {
		return
	}

	elig := computeEligibility(req)

	if !skipActive {
		e.runActiveStage(ctx, req, &filter, &elig)
	}
	return false
}

// fetchStaticMetaResponse fetches headers-only metadata for an object-storage
// static asset: a HEAD request, falling back to a ranged GET (Range: bytes=0-0)
// when the origin rejects HEAD (405/501). The full object body is never
// downloaded; callers still strip whatever minimal body returns.
func (e *Executor) fetchStaticMetaResponse(ctx context.Context, base *httpmsg.HttpRequestResponse) (baselineFetch, bool) {
	out, ok := e.fetchBaseline(ctx, staticMetaProbe(base, "HEAD", ""))
	if !ok || headRejectedStatus(out.resp.StatusCode()) {
		// Release the HEAD buffer before retrying with a ranged GET.
		//
		// This release needs no responseBufferGuard check, unlike processItem's:
		// the HEAD response never leaves this function — no module has run
		// against it and no record has been written from it — so nothing can
		// still be reading it. Any future code that hands this response to a
		// module or a writer before this point must take the guard into account.
		if out.pooledBuf != nil {
			putResponseBuffer(out.pooledBuf)
		}
		out, ok = e.fetchBaseline(ctx, staticMetaProbe(base, "GET", "bytes=0-0"))
	}
	// The point of a static-meta probe is one metadata row per object, not a
	// chain. Dropped explicitly rather than by a return value the caller happens
	// not to read — the hops are still WALKED above, which is the cost of saying
	// it here instead of in fetchBaseline.
	out.hops = nil
	return out, ok
}

// staticMetaProbe builds a header-only probe request from base: a method
// override plus an optional Range header. Returns base unchanged on parse error.
func staticMetaProbe(base *httpmsg.HttpRequestResponse, method, rangeHdr string) *httpmsg.HttpRequestResponse {
	raw := base.Request().Raw()
	if m, err := httpmsg.SetMethod(raw, method); err == nil {
		raw = m
	}
	if rangeHdr != "" {
		if h, err := httpmsg.AddHeader(raw, "Range", rangeHdr); err == nil {
			raw = h
		}
	}
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return base
	}
	return req.WithService(base.Service())
}

// headRejectedStatus reports whether a status indicates the origin refused the
// HEAD method, so a ranged GET retry is warranted.
func headRejectedStatus(status int) bool {
	return status == 405 || status == 501
}

// baselineFetch is the outcome of fetching (or reusing) the response the rest
// of processItem scans.
type baselineFetch struct {
	req       *httpmsg.HttpRequestResponse
	resp      *httpmsg.HttpResponse
	pooledBuf []byte
	// hops are the intermediate redirect responses, oldest first, when
	// RecordRedirectChain is on and the request was redirected. Each is a
	// complete request/response pair ready to be written as its own record.
	hops []*httpmsg.HttpRequestResponse
}

func (e *Executor) fetchBaseline(ctx context.Context, req *httpmsg.HttpRequestResponse) (baselineFetch, bool) {
	if e.cfg.SkipBaseline && req.Response() != nil {
		return baselineFetch{req: req, resp: req.Response()}, true
	}

	// Bind the phase context so a cancelled scan / phase deadline / Ctrl-C aborts
	// the baseline fetch in flight. The context-less Execute would otherwise fall
	// back to context.Background() and keep hitting the target after the phase
	// asked every worker to stop.
	opts := http.Options{
		// The request clusterer serves repeats from a SNAPSHOT of the response,
		// reconstructed as a fresh single-response chain — so the redirect
		// linkage (resp.Request.Response) is gone and the hops would silently
		// vanish for every request after the first. Clustering is a
		// within-500ms duplicate-suppression optimization; hop recording is
		// evidence. When both are asked for, evidence wins.
		//
		// It costs nothing where this matters: a host sweep sends one request
		// per target, so there are no duplicates for the cache to collapse.
		NoClustering: e.cfg.RecordRedirectChain,
	}
	respChain, elapsed, err := e.httpClient.WithContext(ctx).Execute(req, opts)
	if err != nil {
		zap.L().Debug("Failed to fetch baseline response, skipping item",
			zap.String("url", req.Target()),
			zap.Error(err))
		return baselineFetch{}, false
	}

	if blockErr := infra.GetBlockDetectionValidator().Validate(respChain); blockErr != nil {
		respChain.Close()
		zap.L().Debug("Block detected, skipping item",
			zap.String("url", req.Target()),
			zap.Error(blockErr))
		if e.statsTracker != nil {
			e.statsTracker.IncrementBlocked()
		}
		return baselineFetch{}, false
	}

	// Compose headers+body directly into one pooled buffer. Using
	// FullResponseBytes() here would allocate a throwaway full-size copy that we
	// then copy *again* into the pooled buffer — two full-size allocations per
	// record on the hot path. HeadersBytes()/BodyBytes() alias the chain's own
	// buffers (valid until Close()), so a single splice into the pool suffices.
	headers := respChain.HeadersBytes()
	body := respChain.BodyBytes()
	rawResponseCopy := getResponseBuffer(len(headers) + len(body))
	copy(rawResponseCopy, headers)
	copy(rawResponseCopy[len(headers):], body)

	// elapsed is the requester's measurement of this send, so this is the one
	// place in the native-scan path that can populate response_time_ms at all.
	// Every other construction site rebuilds a response from stored bytes and
	// correctly leaves the duration at zero ("not measured").
	httpResp := httpmsg.NewHttpResponseWithDuration(rawResponseCopy, elapsed)
	out := baselineFetch{req: req.WithResponse(httpResp), resp: httpResp, pooledBuf: rawResponseCopy}

	// Redirect handling, in the only window where the chain is still intact and
	// the final response has already been copied out of it. Order matters twice
	// over: FinalRequestOf must run before RedirectChainHops (which rewinds the
	// chain), and both must run before Close (which reclaims the buffers).
	//
	// The re-pairing is UNCONDITIONAL. It used to be gated on
	// RecordRedirectChain — off for every phase but the probe — which left the
	// default path pairing the ORIGINAL request with the FINAL response: one
	// row whose URL named the target and whose body came from wherever the
	// chain ended. A scan of a host that 302s elsewhere filed the destination's
	// page, its technology and every passive finding under the target's own
	// URL, and the target's owner could not reproduce a line of it.
	//
	// Two things made that defensible before and no longer do. The record's
	// identity does change for a redirected target — but a row that misnames
	// its own origin has no identity worth preserving, and Target now carries
	// the submitted line, so nothing is lost by moving the URL to where the
	// bytes came from. And scope is matched on this request: leaving it at the
	// original host meant an out-of-scope destination was ingested and scanned
	// under an in-scope name.
	// ChainRelocated, not WasRedirected: the clusterer's reconstructed chain has
	// no resp.Request.Response, so the linkage test reports "not redirected" for
	// every cache hit — and clustering is ON for every phase that does not
	// record hops, which is all of them but the probe. It keeps the final hop's
	// request, so the destination URL survives; comparing it is what makes the
	// re-pairing work on the default path rather than only under --record-
	// redirect-chain.
	// URL() is memoized on the request, so this costs a map/pointer read rather
	// than a parse. An error here means the request URL never parsed, in which
	// case there is nothing to compare against and the linkage test decides.
	requestedURL, _ := req.Request().URL()
	relocated, linked := http.ChainRelocated(respChain, requestedURL.URL)
	if relocated {
		if finalReq := http.FinalRequestOf(respChain, httpResp); finalReq != nil {
			out.req = finalReq
		}
	}
	// The intermediate URLs are not lost by the swap: with hop recording on they
	// become their own records, and with it off they are dropped, which is the
	// setting's whole purpose — the terminal row still names its submitted
	// Target. Hop recording needs the real linkage rather than just a changed
	// URL, which is the second value ChainRelocated returns.
	if e.cfg.RecordRedirectChain && linked {
		out.hops = http.RedirectChainHops(respChain)
	}
	respChain.Close()

	return out, true
}

func (e *Executor) applyPreHooks(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, bool) {
	if e.hooks == nil {
		return req, true
	}

	hooked, err := e.hooks.RunPreHooks(req)
	if err != nil {
		zap.L().Debug("Pre-hook error, skipping item",
			zap.String("url", req.Target()), zap.Error(err))
		return nil, false
	}
	if hooked == nil {
		zap.L().Debug("Pre-hook filtered out item",
			zap.String("url", req.Target()))
		return nil, false
	}
	return hooked, true
}

func (e *Executor) runPassiveStage(ctx context.Context, req *httpmsg.HttpRequestResponse, filter *moduleFilter, inScope bool) {
	eligiblePerHost := e.filterEligiblePassive(e.perHostPassive, req, filter)
	eligiblePerRequest := e.filterEligiblePassive(e.perRequestPassive, req, filter)
	if !inScope {
		eligiblePerHost = filterNonScopeAware(eligiblePerHost)
		eligiblePerRequest = filterNonScopeAware(eligiblePerRequest)
	}
	e.runPassivePerHostFiltered(ctx, req, eligiblePerHost)
	e.runPassivePerRequestFiltered(ctx, req, eligiblePerRequest)
}

func (e *Executor) persistAndCheckScope(ctx context.Context, item *work.WorkItem, req *httpmsg.HttpRequestResponse, inScope bool, redirectHops []*httpmsg.HttpRequestResponse) bool {
	if e.cfg.ScopeMatcher != nil {
		if req.Service() == nil {
			return false
		}

		if !inScope && e.cfg.ScopeOnIngest {
			return false
		}

		e.saveToDatabase(ctx, item, req, redirectHops)
		return inScope
	}

	e.saveToDatabase(ctx, item, req, redirectHops)
	return true
}

func (e *Executor) runActiveStage(ctx context.Context, req *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility) {
	// One context-bound requester clone per item, handed to every active-module
	// task below — they all run under the same PHASE ctx. Binding the context once
	// here keeps that work off the hottest fan-out loop; runActiveWithTimeout still
	// takes a second shallow clone per call to attach that call's abandon flag,
	// which is the minimum needed to carry per-call state into a module that takes
	// a *http.Requester.
	// Bound to the phase context, NOT any per-module timeout, so the shared request
	// clusterer isn't poisoned by one module's timeout (see runActiveWithTimeout).
	var reqClient *http.Requester
	if e.httpClient != nil {
		reqClient = e.httpClient.WithContext(ctx)
	}

	// conc.WaitGroup automatically catches panics per goroutine and re-panics
	// on Wait(), which is caught by processItem's top-level panic recovery.
	var g conc.WaitGroup
	e.runActivePerHost(ctx, reqClient, req, filter, elig, &g)
	e.runActivePerRequest(ctx, reqClient, req, filter, elig, &g)
	e.runActivePerInsertionPoint(ctx, reqClient, req, filter, elig, &g)
	g.Wait()
}

// saveToDatabase stores the request/response record in the database if enabled.
func (e *Executor) saveToDatabase(ctx context.Context, item *work.WorkItem, req *httpmsg.HttpRequestResponse, redirectHops []*httpmsg.HttpRequestResponse) {
	if e.repo == nil {
		return
	}
	if item.RecordUUID != "" {
		// Item maps to an existing DB record — reuse its UUID (skip insert) so
		// findings link to it instead of creating a duplicate record. Counted as
		// stored: the question Stored() answers is "is this input in the store",
		// and for a record that CAME from the store the answer is yes.
		e.stored.Add(1)
		e.caches.requestUUIDs.Store(req.Request().ID(), item.RecordUUID)

		// Backfill the response for records stored as request-only stubs (e.g.
		// endpoints synthesized from a discovered OpenAPI/Swagger spec). The
		// executor just fetched a real baseline to scan the endpoint; persist it
		// so the route shows its actual status/body instead of staying at
		// status 0 with an empty response in the traffic view. item.Request is
		// the untouched stub (fetchBaseline returns a copy via
		// WithResponse), so a nil response there marks a stub even though req now
		// carries one. The repo update is a no-op once the record has a response.
		if item.Request != nil && item.Request.Response() == nil && req.Response() != nil {
			if err := e.repo.BackfillRecordResponse(ctx, item.RecordUUID, req); err != nil {
				zap.L().Debug("Failed to backfill stub record response",
					zap.String("uuid", item.RecordUUID), zap.Error(err))
			}
		}
		return
	}

	// Redirect hops first, oldest to newest, so each one's parent already exists
	// by the time its child is written. The last hop's UUID becomes the final
	// record's parent, giving the whole chain one walkable parent_uuid spine.
	//
	// Guarded on len: only a chain-recording phase has hops, and req.Target()
	// rebuilds the URL string, so the unguarded call cost one allocation per
	// saved record across every phase to shape a nil slice.
	target := item.Target
	var parentUUID, rootUUID string
	if len(redirectHops) > 0 {
		parentUUID, rootUUID = e.saveRedirectHops(ctx,
			http.ShapeRedirectChain(redirectHops, req.Target()), target)
	}

	recordUUID, err := e.writeRecord(ctx, req, e.recordSource(), database.RecordLineage{
		ParentUUID: parentUUID,
		RootUUID:   rootUUID,
		Target:     target,
		// The terminal row is truncated when it is itself a 3xx: the transport
		// handed back a redirect as the final response, which means it stopped
		// rather than arrived — the follow cap, the mode's host rule, or the
		// authentication gate. Without the flag that row is indistinguishable
		// from a chain that legitimately ended at a redirect whose destination
		// never answered.
		ChainTruncated: req.Response() != nil && httpmsg.IsRedirectStatus(req.Response().StatusCode()),
	})
	if err != nil {
		e.storeFailed.Add(1)
		zap.L().Debug("Failed to save record to database", zap.Error(err))
		return
	}
	e.stored.Add(1)
	e.caches.requestUUIDs.Store(req.Request().ID(), recordUUID)
}

// saveRedirectHops persists each intermediate redirect response as its own
// record, chained through parent_uuid, and returns the UUID of the LAST hop —
// the parent the final record should point at. Returns "" when there are no
// hops, or when the first write fails.
//
// A hop that fails to write ends the chain rather than aborting the item: the
// final response is the one that carries the evidence, and losing an
// intermediate 301 must not cost the 200 behind it. The chain simply stops at
// the last hop that did persist, which reads correctly as a shorter chain
// rather than as a wrong one.
// It also returns the chain's ROOT uuid — the first hop's — which every row
// carries so "which chain is this" is answerable from a single record instead
// of by walking parent_uuid back to a row the storage cap may have dropped.
func (e *Executor) saveRedirectHops(ctx context.Context, rows []http.ChainRow, target string) (parentUUID, rootUUID string) {
	for _, row := range rows {
		if row.RR == nil || row.RR.Request() == nil {
			continue
		}
		hopUUID, err := e.writeRecord(ctx, row.RR, e.recordSource(), database.RecordLineage{
			ParentUUID:     parentUUID,
			RootUUID:       rootUUID,
			Target:         target,
			ChainTruncated: row.Truncated,
		})
		if err != nil {
			zap.L().Debug("Failed to save redirect hop record",
				zap.String("url", row.RR.Target()), zap.Error(err))
			break
		}
		if rootUUID == "" {
			rootUUID = hopUUID
		}
		parentUUID = hopUUID
	}
	return parentUUID, rootUUID
}

// writeRecord persists one request/response pair, preferring the batched writer
// for throughput and falling back to an individual insert. lineage places the
// row in its redirect chain and names the target it came from; a zero value
// means a standalone record.
//
// The single owner of "which persistence path does this executor use" — finding
// evidence (emitResult) goes through it too, so a change to that choice has one
// place to land.
func (e *Executor) writeRecord(ctx context.Context, req *httpmsg.HttpRequestResponse, source string, lineage database.RecordLineage) (string, error) {
	if e.recordWriter != nil {
		return e.recordWriter.WriteWithLineage(ctx, req, source, e.projectUUID, lineage)
	}
	return e.repo.SaveRecordWithLineage(ctx, req, source, e.projectUUID, lineage)
}

// recordSource is the http_records.source label this executor stamps on the
// records it owns. Finding evidence carries its own record kind instead.
func (e *Executor) recordSource() string {
	if e.cfg.RecordSource == "" {
		return database.RecordSourceScanner
	}
	return e.cfg.RecordSource
}

// filterEligiblePassive pre-filters passive modules by CanProcess and module filter,
// computing eligibility once per request instead of per-module in each run method.
func (e *Executor) filterEligiblePassive(mods []modules.PassiveModule, item *httpmsg.HttpRequestResponse, filter *moduleFilter) []modules.PassiveModule {
	if len(mods) == 0 {
		return nil
	}
	eligible := make([]modules.PassiveModule, 0, len(mods))
	for _, m := range mods {
		if !filter.allows(m.ID()) {
			continue
		}
		if !e.passesTechFilter(m, item) {
			continue
		}
		if !e.passesContentClassFilter(m, item) {
			continue
		}
		// Mark considered before CanProcess so modules that always reject this
		// input shape still count toward the "modules scanned" status counter.
		e.moduleMetrics.MarkConsidered(m.ID())
		if m.CanProcess(item) {
			eligible = append(eligible, m)
		}
	}
	return eligible
}

// defaultPassiveModuleTimeout limits how long a single passive module can take per request.
const defaultPassiveModuleTimeout = 5 * time.Second

// defaultActiveModuleTimeout limits how long a single active module can take per
// (record / insertion-point) call. Active modules run multi-probe injection so this
// is much higher than the passive default; modules that legitimately need longer
// (e.g. diffscan behavioral timing analysis) opt in via modules.TimeoutHinter.
const defaultActiveModuleTimeout = 300 * time.Second

// moduleDeadlineGrace is how far before the hard per-module watchdog a contextual
// module's handed context is cancelled. It gives a deadline-aware module (one that
// checks its context between insertion points) a window to unwind its loop and
// return the findings it has already confirmed, so the executor collects them via
// the result channel instead of the hard timeout discarding everything.
const moduleDeadlineGrace = 15 * time.Second

const (
	// timeoutScaleRefPoints is the insertion-point count that maps a whole-request
	// module to the base per-module timeout (1x). A ScanPerRequest module loops
	// over every insertion point in a single call, so a browser-captured request
	// (many cookies + headers → 20+ points) legitimately needs proportionally
	// longer than a bare URL, or it exceeds the base timeout mid-loop.
	timeoutScaleRefPoints = 10
	// maxModuleTimeoutScale caps how far the per-module timeout may stretch for a
	// high-insertion-point request, so a pathological request can't wedge a phase.
	maxModuleTimeoutScale = 5
)

// scaleModuleTimeout stretches the base per-module timeout in proportion to the
// number of insertion points a whole-request module must cover, capped at
// maxModuleTimeoutScale x. Returns base unchanged when workUnits is at or below
// the reference (the common small-request case) or when base is non-positive.
func scaleModuleTimeout(base time.Duration, workUnits int) time.Duration {
	if base <= 0 || workUnits <= timeoutScaleRefPoints {
		return base
	}
	scale := min(float64(workUnits)/float64(timeoutScaleRefPoints), maxModuleTimeoutScale)
	return time.Duration(float64(base) * scale)
}

// passiveModuleTimeout returns the effective passive module timeout.
func (e *Executor) passiveModuleTimeout() time.Duration {
	if e.cfg.PassiveModuleTimeout > 0 {
		return e.cfg.PassiveModuleTimeout
	}
	return defaultPassiveModuleTimeout
}

// activeModuleTimeout returns the effective active module timeout.
func (e *Executor) activeModuleTimeout() time.Duration {
	if e.cfg.ActiveModuleTimeout > 0 {
		return e.cfg.ActiveModuleTimeout
	}
	return defaultActiveModuleTimeout
}

// maxModuleTimeout returns the longest a single module call can legitimately
// run: the larger of the base active/passive timeouts and the largest
// TimeoutHint any registered module advertises (both scan wrappers raise their
// per-call timeout to the hint via modules.TimeoutHinter). The active
// contribution is the scaled ceiling (activeModuleTimeout x maxModuleTimeoutScale)
// because whole-request modules stretch their per-call timeout up to that scale
// via scaleModuleTimeout — so a legitimately long, high-insertion-point scan
// still running during the post-EOF drain is not mistaken for a wedged worker.
// The drain stall cap is derived from this.
func (e *Executor) maxModuleTimeout() time.Duration {
	maxT := e.activeModuleTimeout() * maxModuleTimeoutScale
	if pt := e.passiveModuleTimeout(); pt > maxT {
		maxT = pt
	}
	consider := func(m modules.Module) {
		if hinter, ok := m.(modules.TimeoutHinter); ok {
			if hint := hinter.TimeoutHint(); hint > maxT {
				maxT = hint
			}
		}
	}
	for _, m := range e.activeModules {
		consider(m)
	}
	for _, m := range e.passiveModules {
		consider(m)
	}
	return maxT
}

// feedbackDrainMaxStall returns the hard cap on how long the post-EOF feedback
// drain will wait while workers are still in flight but making no forward
// progress. The idle-detection branch in the drain loop only fires once
// inFlight reaches 0, so without this bound a module that ignores context
// cancellation (and never returns) would hang the drain — and the whole scan —
// indefinitely. Defaults to twice the longest legitimate module call
// (maxModuleTimeout, which includes per-module TimeoutHints) so a slow-but-not-
// wedged module isn't abandoned, while a truly stuck worker still trips the cap.
func (e *Executor) feedbackDrainMaxStall() time.Duration {
	if e.cfg.FeedbackDrainMaxStall > 0 {
		return e.cfg.FeedbackDrainMaxStall
	}
	return 2 * e.maxModuleTimeout()
}

// workerExitGraceDefault bounds how long Execute waits for worker goroutines to
// exit after the item channel is closed. It is deliberately short and fixed,
// unlike the drain-stall cap: by the time workers are joined the drain loop has
// already ended, so on a clean scan inFlight is 0 and this wait returns at once,
// while on cancellation a worker returns as soon as it observes ctx.Done. Only a
// worker wedged in inline passive code that ignores cancellation lingers — and
// inline passive modules are bounded and short — so a minute of grace is ample.
const workerExitGraceDefault = 60 * time.Second

// workerExitGrace returns the bounded wait for worker goroutines to exit after
// the item channel is closed. It is decoupled from feedbackDrainMaxStall so a
// stuck worker (or a scan cancelled by Ctrl-C / --scanning-max-duration) doesn't
// inherit that cap's up-to-50-minute worst case, which is sized for a
// legitimately slow module still running mid-drain, not for shutdown. It never
// exceeds the drain-stall cap, so an operator who tightens FeedbackDrainMaxStall
// also tightens shutdown.
func (e *Executor) workerExitGrace() time.Duration {
	grace := workerExitGraceDefault
	if e.cfg.WorkerExitGrace > 0 {
		grace = e.cfg.WorkerExitGrace
	}
	if stall := e.feedbackDrainMaxStall(); stall < grace {
		grace = stall
	}
	return grace
}

// timerPool recycles the watchdog timers used by the per-module timeout wrappers
// so each module call doesn't allocate a fresh runtime timer — these wrappers run
// on the hottest per-module dispatch loop (every active and passive call). A
// timer taken from the pool is always Reset before use and Stopped/drained before
// being returned, so a recycled timer never carries a stale fire.
var timerPool = sync.Pool{
	New: func() any {
		t := time.NewTimer(time.Hour)
		t.Stop()
		return t
	},
}

// acquireTimer returns a pooled timer armed to fire after d.
func acquireTimer(d time.Duration) *time.Timer {
	t := timerPool.Get().(*time.Timer)
	t.Reset(d)
	return t
}

// releaseTimer stops t and returns it to the pool, draining a pending fire so the
// next Reset starts clean.
func releaseTimer(t *time.Timer) {
	if !t.Stop() {
		// Already fired (or was already stopped): drain a queued value if the
		// select didn't consume it. The non-blocking default handles the case
		// where the firing value was already received.
		select {
		case <-t.C:
		default:
		}
	}
	timerPool.Put(t)
}

// callGuard sets up the per-module timeout guard shared by the active and passive
// wrappers: a cancel-only child context plus a pooled watchdog timer armed for
// timeout. It returns the child context to hand the scan function, the timer's
// fire channel (the genuine per-call timeout — selected separately from
// ctx.Done(), which is parent cancellation), and a stop func the caller defers to
// cancel the context and return the timer to the pool. The common non-contextual
// case (the hottest per-module dispatch loop) hands back the parent ctx unchanged
// and relies solely on the pooled watchdog timer, avoiding any per-call context
// allocation; only contextual modules pay for a child context, and it carries a
// soft deadline (a grace before the watchdog) so a deadline-aware module can return
// its already-confirmed findings before the hard timeout discards them. The child
// context is intentionally NOT bound into the requester — that is phase-context-bound
// in runActiveStage — so one module's timeout never cancels a request the clusterer
// shares with others.
func callGuard(ctx context.Context, timeout time.Duration, needCancel bool) (callCtx context.Context, timeoutC <-chan time.Time, stop func()) {
	t := acquireTimer(timeout)
	if !needCancel {
		// Non-contextual module: its scanFn ignores the handed context (it runs
		// against the phase-bound requester / e.scanCtx), so the WithCancel child
		// would never be observed. Skip that per-call heap allocation; the pooled
		// timer still enforces the per-module timeout via timeoutC.
		return ctx, t.C, func() { releaseTimer(t) }
	}
	// Contextual module: give its handed context a soft deadline a short grace
	// before the hard watchdog (timeoutC) fires. A deadline-aware module checks
	// this context between insertion points and returns the findings it has
	// already confirmed, so the executor collects them via the result channel
	// instead of the hard timeout discarding everything. The context stays
	// unbound from the requester (that is phase-context-bound), so this deadline
	// only gates the module's own loop, never a request the clusterer shares.
	soft := timeout - moduleDeadlineGrace
	if soft <= 0 {
		soft = timeout / 2
	}
	callCtx, cancel := context.WithTimeout(ctx, soft)
	return callCtx, t.C, func() {
		cancel()
		releaseTimer(t)
	}
}

// moduleCallResult carries a module scan function's return across the watchdog
// goroutine. Shared by the active and passive wrappers so they can use one
// channel pool.
type moduleCallResult struct {
	events []*output.ResultEvent
	err    error
}

// moduleResultChanPool recycles the 1-slot result channels used by the per-module
// timeout wrappers — the single highest-frequency allocation site in the
// dispatch loop (one per active and passive module call). A channel is returned
// to the pool ONLY on the normal completion path, where the watchdog goroutine
// has finished sending and will never touch it again; on the timeout / parent-
// cancel paths the abandoned goroutine still owns the channel (it sends when the
// slow scanFn eventually returns), so those channels are left for the GC.
var moduleResultChanPool = sync.Pool{
	New: func() any { return make(chan moduleCallResult, 1) },
}

// recordPassiveResult records the module's timing/metrics and normalizes its
// return: on error it logs at debug and drops the events (returns nil), otherwise
// it returns the events. Shared by the inline and watchdog-goroutine completion
// paths of runPassiveWithTimeout.
func (e *Executor) recordPassiveResult(module modules.PassiveModule, start time.Time, events []*output.ResultEvent, err error) []*output.ResultEvent {
	e.moduleMetrics.Record(module.ID(), time.Since(start), len(events), err)
	if err != nil {
		zap.L().Debug("Passive module error",
			zap.String("module", module.ID()),
			zap.Error(err))
		return nil
	}
	return events
}

// runPassiveWithTimeout executes a passive module scan function with a timeout guard.
func (e *Executor) runPassiveWithTimeout(
	ctx context.Context,
	scanFn func(context.Context) ([]*output.ResultEvent, error),
	module modules.PassiveModule,
	item *httpmsg.HttpRequestResponse,
) []*output.ResultEvent {
	// Fast exit when the scan/phase context is already cancelled: skip the
	// watchdog goroutine + pooled timer + result channel entirely. During
	// shutdown or after a phase deadline, many modules are still dispatched and
	// would each otherwise spawn a doomed goroutine.
	if ctx.Err() != nil {
		return nil
	}

	// Only contextual passive modules observe the handed context.
	_, isContextual := module.(modules.ContextualPassiveModule)

	timeout := e.passiveModuleTimeout()
	// Allow modules to override with a per-module timeout hint
	hintedTimeout := false
	if hinter, ok := module.(modules.TimeoutHinter); ok {
		if hint := hinter.TimeoutHint(); hint > 0 {
			timeout = hint
			hintedTimeout = true
		}
	}

	// Fast inline path for the common case: a non-contextual passive module with
	// no explicit timeout hint. Passive modules send no traffic (no network I/O
	// to block on), read a size-capped body, and Go's regexp is RE2 (linear-time,
	// no catastrophic backtracking) — so their runtime is bounded and short, and
	// the per-call watchdog goroutine + pooled timer + result channel are pure
	// overhead on the single highest-frequency call in the dispatch loop. Running
	// inline is also safer against a module panic (it unwinds to the worker's
	// recoverFromPanic instead of crashing an unrecovered raw goroutine). Modules
	// that observe the context or ask for a specific timeout keep the enforced
	// goroutine path below; the end-of-scan drain-stall cap remains the backstop.
	runInline := !isContextual && !hintedTimeout
	if runInline {
		start := time.Now()
		events, err := scanFn(ctx)
		return e.recordPassiveResult(module, start, events, err)
	}

	// Enforced-timeout path: contextual modules need a cancellable child (see
	// callGuard); hinted modules asked for their timeout to be enforced.
	callCtx, timeoutC, stop := callGuard(ctx, timeout, isContextual)
	defer stop()

	start := time.Now()
	ch := moduleResultChanPool.Get().(chan moduleCallResult)
	go func() {
		// runScanFnGuarded recovers a module panic into an error: this goroutine
		// is outside processItem's recover and the conc.WaitGroup boundary, so an
		// unrecovered panic here would crash the process.
		events, err := e.runScanFnGuarded(callCtx, module.ID(), scanFn)
		ch <- moduleCallResult{events, err}
	}()

	select {
	case r := <-ch:
		moduleResultChanPool.Put(ch) // goroutine done; channel drained and safe to reuse
		return e.recordPassiveResult(module, start, r.events, r.err)
	case <-timeoutC:
		// The scan goroutine is still running and still holds item, whose response
		// is built over the item's pooled buffer. Withhold that buffer from the
		// pool so this abandoned call cannot be fed another request's bytes.
		markResponseBufferEscaped(ctx)
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		zap.L().Warn("Passive module timed out — skipping",
			zap.String("module", module.ID()),
			zap.String("url", item.Target()),
			zap.Duration("timeout", timeout))
		return nil
	case <-ctx.Done():
		// Parent cancellation (scan shutdown / phase deadline) — not a per-module
		// timeout, so stay quiet; the scan is ending.
		markResponseBufferEscaped(ctx)
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		return nil
	}
}

// runActiveWithTimeout executes an active module scan function under a timeout
// derived from the phase context. It returns the module's results and whether
// the call completed within the bound. When the per-module timeout fires OR the
// phase deadline (ctx) is reached, it returns (nil, false) immediately so the
// worker stops blocking on g.Wait() and the phase ends on time. The scan function
// receives callCtx for explicit use. The executor also hands the module a
// requester bound to the PHASE context (http.Requester.WithContext), so
// context-less Execute calls abort in-flight requests on scan shutdown / phase
// deadline. It deliberately is NOT bound to callCtx: the request clusterer
// shares one in-flight request across modules, so a single module's per-module
// timeout must not cancel a request other modules deduped onto. The per-module
// timeout is still enforced here — a timed-out call returns (nil, false) and the
// caller skips processResults — it just doesn't sever the shared socket early.
// releaseSlot frees the active-task semaphore slot goActiveTask acquired for this
// call. runActiveWithTimeout owns it and MUST call it exactly once: from the
// background scan goroutine's defer (so the slot is held for as long as the real
// work runs, even past a per-module timeout) or directly on the pre-spawn early
// return. Releasing it when the wrapper merely *gives up waiting* would let the
// executor admit replacement work while abandoned scans still hold connections,
// so the active-task cap would understate true concurrency (a hot/slow target
// could then be hit far harder than --concurrency allows).
// workUnits estimates how much a whole-request/host module must cover in one call
// (its insertion-point count) so the per-module timeout can scale with it; pass 0
// to leave the base timeout untouched (per-insertion-point calls, which are already
// bounded and processed incrementally).
func (e *Executor) runActiveWithTimeout(
	ctx context.Context,
	scanFn func(context.Context, *http.Requester) ([]*output.ResultEvent, error),
	module modules.Module,
	item *httpmsg.HttpRequestResponse,
	reqClient *http.Requester,
	releaseSlot func(),
	workUnits int,
) ([]*output.ResultEvent, bool) {
	// Fast exit when the scan/phase context is already cancelled: skip the
	// watchdog goroutine + pooled timer + result channel entirely (mirrors the
	// <-ctx.Done() arm below). Avoids spawning doomed goroutines for the many
	// modules still dispatched during shutdown or after a phase deadline. No
	// background goroutine is spawned here, so release the slot directly.
	if ctx.Err() != nil {
		releaseSlot()
		return nil, false
	}

	// Scale the timeout with the request's insertion-point count for whole-request
	// modules that loop over every point in a single call (workUnits 0, or at/below
	// the reference count, leaves it unchanged): without this a request with many
	// cookies/headers exceeds the base timeout mid-loop and its already-confirmed
	// findings are discarded (capped at maxModuleTimeoutScale x).
	timeout := scaleModuleTimeout(e.activeModuleTimeout(), workUnits)
	// Allow modules to override with a per-module timeout hint (e.g. diffscan
	// timing analysis legitimately needs longer than the global default).
	if hinter, ok := module.(modules.TimeoutHinter); ok {
		if hint := hinter.TimeoutHint(); hint > timeout {
			timeout = hint
		}
	}

	// Only contextual active modules observe the handed context, so only they
	// need a cancellable child (see callGuard).
	_, needCancel := module.(modules.ContextualActiveModule)
	callCtx, timeoutC, stop := callGuard(ctx, timeout, needCancel)
	defer stop()

	// Abandon signal: set the moment this wrapper stops waiting, on every path. A
	// module that outlives its timeout keeps running (a goroutine cannot be
	// killed) and used to keep issuing requests whose results are discarded by
	// definition — stealing per-host concurrency from live work and holding its
	// active-task slot until it finally unwound. Once set, its next Execute
	// returns ErrRequestAbandoned immediately, so it unwinds promptly and stops
	// generating load. In-flight requests are untouched, so a request the
	// clusterer shares with other modules is never severed.
	//
	// Deferring the set is correct on all three exits: on the normal path the
	// scan goroutine has already delivered its result, and on the timeout /
	// parent-cancel paths flagging it is precisely the intent.
	if reqClient != nil {
		var abandoned atomic.Bool
		defer abandoned.Store(true)
		reqClient = reqClient.WithAbandonFlag(&abandoned)
	}

	start := time.Now()
	ch := moduleResultChanPool.Get().(chan moduleCallResult)
	go func() {
		// Hold the active-task slot for the whole life of the real work. On the
		// normal path this fires just as the wrapper receives the result; on the
		// timeout / parent-cancel paths the wrapper has already returned but this
		// abandoned goroutine keeps the slot until scanFn actually unwinds, so the
		// executor's concurrency cap keeps reflecting genuinely in-flight scans.
		defer releaseSlot()
		// runScanFnGuarded recovers a module panic into an error: this goroutine
		// is outside processItem's recover and the conc.WaitGroup boundary, so an
		// unrecovered panic here would crash the process.
		events, err := e.runScanFnGuarded(callCtx, module.ID(), func(c context.Context) ([]*output.ResultEvent, error) {
			return scanFn(c, reqClient)
		})
		ch <- moduleCallResult{events, err}
	}()

	select {
	case r := <-ch:
		moduleResultChanPool.Put(ch) // goroutine done; channel drained and safe to reuse
		e.moduleMetrics.Record(module.ID(), time.Since(start), len(r.events), r.err)
		if r.err != nil {
			if isLevelDBClosed(r.err) {
				zap.L().Debug("Active module error (shutdown)",
					zap.String("module", module.ID()),
					zap.Error(r.err))
			} else {
				zap.L().Warn("Active module error",
					zap.String("module", module.ID()),
					zap.Error(r.err))
			}
			return nil, true
		}
		return r.events, true
	case <-timeoutC:
		// The scan goroutine outlives this wrapper and still holds item, whose
		// response is built over the item's pooled buffer — keep that buffer out of
		// the pool so the abandoned module cannot be handed another request's bytes.
		markResponseBufferEscaped(ctx)
		// Genuine per-module timeout. Count it only when the parent is still alive,
		// so cancelling a scan with many modules in flight doesn't inflate the
		// status-line count with modules that were merely interrupted at the same
		// instant.
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		if ctx.Err() == nil {
			e.recordModuleTimeout()
		}
		// Logged at debug level: a per-skip WARN floods stderr on slow targets.
		// The running count is surfaced in the status line via OnStatus instead.
		zap.L().Debug("Active module timed out — skipping",
			zap.String("module", module.ID()),
			zap.String("url", item.Target()),
			zap.Duration("timeout", timeout))
		return nil, false
	case <-ctx.Done():
		// Parent cancellation (Ctrl-C, --scanning-max-duration, phase deadline) —
		// an interruption, not a timed-out module, so it is not counted.
		markResponseBufferEscaped(ctx)
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		return nil, false
	}
}

// recordModuleTimeout increments the active-module timeout counter — the shared
// phase counter when one was supplied via ExecutorConfig.ModuleTimeouts (so the
// total accumulates across a multi-round phase's per-round executors), otherwise
// this executor's own tally.
func (e *Executor) recordModuleTimeout() {
	if e.cfg.ModuleTimeouts != nil {
		e.cfg.ModuleTimeouts.Add(1)
		return
	}
	e.moduleTimeouts.Add(1)
}

// timedOutCount returns the active-module timeout total reported in the status
// line: the shared phase counter when present, else this executor's own tally.
func (e *Executor) timedOutCount() int64 {
	if e.cfg.ModuleTimeouts != nil {
		return e.cfg.ModuleTimeouts.Load()
	}
	return e.moduleTimeouts.Load()
}

// isLevelDBClosed returns true if the error is caused by a closed LevelDB instance,
// which happens during shutdown when the dedup manager is closed before workers finish.
//
// The typed sentinel (errors.Is) is the primary check and survives any future
// change to goleveldb's error message, but we keep a string fallback because the
// error reaches us through module/storage call chains that may format it with %v
// (non-wrapping), which defeats errors.Is. Matching both is strictly more robust
// than either alone.
func isLevelDBClosed(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, leveldb.ErrClosed) || strings.Contains(err.Error(), "leveldb: closed")
}

// moduleFilter provides O(1) module-enable lookups via a map.
type moduleFilter struct {
	all bool
	set map[string]struct{}
}

// allModulesFilter is a pre-allocated filter that allows all modules,
// avoiding a new moduleFilter allocation on the common path.
var allModulesFilter = moduleFilter{all: true}

// newModuleFilter builds a filter from the enableModules slice.
// Empty slice or "all" sentinel means all modules are enabled.
func newModuleFilter(enableModules []string) moduleFilter {
	if len(enableModules) == 0 {
		return moduleFilter{all: true}
	}
	set := make(map[string]struct{}, len(enableModules))
	for _, id := range enableModules {
		if id == "all" {
			return moduleFilter{all: true}
		}
		set[id] = struct{}{}
	}
	return moduleFilter{set: set}
}

// allows returns true if the module should run.
func (f *moduleFilter) allows(moduleID string) bool {
	if f.all {
		return true
	}
	_, ok := f.set[moduleID]
	return ok
}

// getKnownTotal returns the total count from source if known, otherwise 0.
func getKnownTotal(src source.InputSource) int64 {
	return source.GetTotal(src)
}

// getHeaderValue extracts the first matching header value by name (case-insensitive).
func getHeaderValue(headers []httpmsg.HttpHeader, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// ResolveRequestUUID resolves a request hash to its database record UUID.
// Implements modkit.RequestUUIDResolver.
func (e *Executor) ResolveRequestUUID(requestHash string) string {
	val, _ := e.caches.requestUUIDs.Load(requestHash)
	return val
}
