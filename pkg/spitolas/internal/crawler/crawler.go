package crawler

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/authsig"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/condition"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/fragment"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/mab"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/metrics"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// Crawler is the main web crawler engine.
type Crawler struct {
	config      *config.Config
	graph       *state.Graph
	candidates  *action.UnfiredFragmentCandidates
	browserPool *browser.Pool
	// browser is the single browser instance the crawler operates on. The pool
	// is used to construct it (and remains owned by the pool), but Pool.Get()
	// uses round-robin, which would silently switch browsers between calls —
	// so we cache one reference here and use it for the entire crawl session.
	browser     *browser.Browser
	extractor   *action.CandidateElementExtractor
	comparator  *state.Comparator
	formHandler *form.Handler
	fragManager *fragment.Manager

	// Conditions
	crawlConditions []*condition.Condition
	waitConditions  []*condition.WaitCondition

	// Invariants - conditions that must always hold
	invariants []*condition.Condition

	// Invariant checker (optional) - structured invariant management
	invariantChecker *condition.InvariantChecker

	// Form input cache - stores successful form inputs per action
	// Uses DetectedInput for Go extension metadata (value rotation, etc.)
	formCache map[string][]*form.DetectedInput

	// Form trainer (optional) - for reproducible form testing
	formTrainer *form.FormTrainer

	// ND Cluster manager (optional) - for near-duplicate state clustering
	clusterMgr *state.NDClusterManager

	// Contains currentState, initialState, onURLSet
	// Reference to graph is shared (GLOBAL)
	stateMachine *state.StateMachine

	// NEW instance created on each reset()
	crawlPath *state.CrawlPath

	session *CrawlSession

	// Used to generate action combinations with different form input values.
	eventableConditions *condition.EventableConditionChecker

	// Used to determine if we need to add final reload edge when crawl finishes.
	resetCalled bool

	// Metrics collector for benchmark tracking (optional)
	metricsCollector *metrics.Collector

	// MAB policy for adaptive action selection (optional, used when strategy=adaptive)
	// RLCRAWLER PARITY: Exp3.1 Multi-Armed Bandit algorithm
	mabPolicy *mab.MABExp3Policy

	// Writer for network traffic capture output
	writer network.Writer

	// adoptedHost is an off-host redirect target that the start URL bounced to
	// and that did NOT look like a login/SSO wall. When set, isInScope treats it
	// as in-scope (alongside the configured target host) so the crawl can follow
	// an app that simply relocated to another domain. Only ever set under the
	// default host-scope rule — an explicit CrawlScope is never widened.
	adoptedHost string

	// wallHosts are hosts classified as a login/SSO wall. isInScope denies them
	// ahead of the configured scope rule, so they are out of scope no matter what
	// the operator's scope mode would otherwise say.
	//
	// The denial has to override the scope rule rather than defer to it, because
	// the case that motivated it is one the scope rule gets wrong by design: an
	// organization's IdP usually shares the target's registrable domain (or its
	// brand keyword), so every mode short of "strict" admits it. Without this the
	// wall classification was advisory only — the crawler would identify the wall,
	// log "supply --auth", and then spend the whole crawl budget interacting with
	// the identity provider's login page: seeding from its robots.txt, filling and
	// submitting its form, and re-entering the OAuth flow each time the reset loop
	// sent the browser back to the start URL.
	//
	// Guarded by wallHostsMu; read on the hot in-scope path from crawl goroutines.
	// hasWallHosts mirrors "the map is non-empty" so that path can skip the lock
	// entirely on the overwhelming majority of crawls, which never see a wall.
	wallHostsMu  sync.RWMutex
	wallHosts    map[string]bool
	hasWallHosts atomic.Bool

	// startWalled records that the START URL's landing was a wall, which ends the
	// crawl — a different question from "is this host denied" (hasWallHosts), and
	// asked at different call sites.
	//
	// Denying the host alone is not enough to stop the crawl: with the landing out
	// of scope the main loop resets, navigates back to the start URL, is
	// redirected to the same wall, and goes out of scope again — an oscillation
	// that ran until the time budget expired, re-entering the OAuth flow (and
	// re-arming the provider's CAPTCHA) on every lap. There is nothing reachable
	// to crawl, so the honest move is to stop and hand the remaining budget back
	// to the phases that can use it.
	startWalled atomic.Bool

	// observedLoginHosts reports the hosts seen serving an authentication endpoint
	// so far. Set from the network capture in crawlWithBrowser, which is the only
	// component that sees individual redirect hops — Chrome collapses server
	// redirects into one history entry, so the crawler cannot name the chain from
	// the landing page alone. nil until the capture is wired.
	observedLoginHosts func() []string

	// primedFrames dedups iframe-source priming across the whole crawl so a frame
	// that recurs in many states (a persistent header/captcha iframe) is fetched
	// once, not once per state. Guarded by primedFramesMu.
	primedFramesMu sync.Mutex
	primedFrames   map[string]bool

	// submittedForms dedups GET-form submit priming across the whole crawl so the
	// same synthesized submit URL (e.g. a search box present on every catalog page
	// → /catalog?searchTerm=a) is fetched once, not once per state. submittedPostForms
	// is the POST-form counterpart, keyed by (action + field-name) signature so the
	// same JS-driven form (e.g. a stock-check present on every product page) is only
	// triggered once. Both guarded by submittedFormsMu; both capped by
	// config.SubmitFormMaxVariants (shared budget).
	submittedFormsMu   sync.Mutex
	submittedForms     map[string]bool
	submittedPostForms map[string]bool

	// primedLinks dedups parameterized-anchor priming across the whole crawl (each
	// URL fetched once) and primedLinkShapes caps how many distinct value-variants
	// of one endpoint shape are primed (mirrors the capture's MaxParamValueVariants
	// so priming never fetches more than the capture would keep). Guarded by
	// primedLinksMu.
	primedLinksMu    sync.Mutex
	primedLinks      map[string]bool
	primedLinkShapes map[string]int

	// loginCTAPrimed marks that the one-shot login-CTA drive has already run, so a
	// crawl that revisits the landing does not re-enter the auth flow repeatedly.
	loginCTAPrimed bool

	// loginCredHosts single-flights the common-credential login pass per host, so
	// a login form reachable from many states is only sprayed once. Guarded by
	// loginCredMu.
	loginCredMu    sync.Mutex
	loginCredHosts map[string]bool

	// selfRegisterHosts single-flights the self-registration pass per host.
	// Registering is a write, so it must happen at most once regardless of how
	// many states expose the signup form. Guarded by selfRegisterMu.
	selfRegisterMu    sync.Mutex
	selfRegisterHosts map[string]bool

	// speculativeScript is the link-discovery script with the crawl's cap already
	// substituted. Rendered once: the cap is fixed for the crawl and the script is
	// several KB, so rebuilding it per state would re-ship the same bytes on the
	// hottest path.
	speculativeScript string

	// failedActions collects actions that errored mid-crawl so the retry sweep can
	// re-attempt them after the queue drains. Guarded by failedActionsMu.
	failedActionsMu sync.Mutex
	failedActions   []failedAction

	mu      sync.Mutex
	stats   Stats
	running bool
	// harvestedAuth is a JWT/Bearer token read from the app's client storage after
	// a confirmed default-credential login, carried forward so token-based SPAs are
	// scanned authenticated (guarded by mu). Empty when no login succeeded.
	harvestedAuth string

	// authOps installs credentials on a page (zero value: the page's own
	// methods). credentialHeadersWithdrawn is set once the crawl leaves the
	// credential scope; later pages do not get the headers back (guarded by mu).
	authOps                    pageAuthOps
	credentialHeadersWithdrawn bool
}

// browserCountClampWarn makes the browser_count clamp warn once per process
// rather than once per target crawl.
var browserCountClampWarn sync.Once

// Stats holds crawl statistics.
type Stats struct {
	StatesDiscovered    int
	StatesDuplicate     int
	ActionsExecuted     int
	ActionsFailed       int
	ConsecutiveFailures int // Current streak of consecutive failures
	// FormsSubmitted counts form submissions dispatched by every mechanism
	// (see submitMechanisms); written only by countSubmitDispatched.
	// FormSubmitsPrevented counts submissions the interaction policy refused at
	// a dispatch point. FormSubmitsUncertain counts POST forms whose outcome
	// could not be attributed, so no fallback was sent.
	FormsSubmitted       int
	FormSubmitsPrevented int
	FormSubmitsUncertain int
	BacktrackCount       int
	InvariantFails       int
	StartTime            time.Time
	EndTime              time.Time

	// Start-redirect observations (default host-scope rule only).
	// OffHostLanding is true when the start URL redirected the browser to a host
	// outside the target's scope. LandingURL is that post-redirect URL.
	// LandingIsLogin marks it as an apparent login/SSO wall (crawl can't proceed
	// unauthenticated). HostAdopted marks a non-login landing whose host was
	// pulled into scope so the crawl continued.
	OffHostLanding bool
	LandingURL     string
	LandingIsLogin bool
	HostAdopted    bool

	// WallHosts are the hosts denied as login/SSO walls during the crawl — the
	// landing host plus every redirect hop that looked like an authentication
	// endpoint. The caller feeds these into the scan-wide fuzz exclusion, so a
	// later phase never brute-forces the identity provider. Reporting the whole
	// chain rather than just the landing matters: an OAuth bounce routinely
	// crosses two hosts (an authorize endpoint on one, the login form on
	// another), and excluding only the last one leaves the first a fuzz target.
	WallHosts []string

	// LoginCTADriven is true when the one-shot login-CTA priming found and clicked
	// a login call-to-action on the landing, driving the OAuth/SAML/SSO flow.
	// LoginCTAText is the CTA's visible label (for logging).
	LoginCTADriven bool
	LoginCTAText   string

	// Common-credential login pass (only runs at --intensity deep, against a
	// confirmed local login form). LoginCredsTried counts credential pairs
	// submitted across the crawl; LoginCredsSucceeded counts forms where a pair
	// authenticated; LoginCredsURL is the last login form the pass ran against.
	LoginCredsTried     int
	LoginCredsSucceeded int
	LoginCredsURL       string

	// Frontier seeding from robots.txt / sitemap.xml. SeedURLsDiscovered counts
	// in-scope locations those files declared; SeedURLsCrawled counts how many of
	// them were additionally browsed into states (the rest are recorded only).
	SeedURLsDiscovered int
	SeedURLsCrawled    int

	// SpeculativeLinksFetched counts URL-like strings scraped from comments and
	// inline script that were fetched and recorded.
	SpeculativeLinksFetched int

	// Self-registration. SelfRegistered is true when a signup form was completed
	// and the app accepted it; SelfRegisterIdentity is the identity created, which
	// the login pass then reuses.
	SelfRegistered       bool
	SelfRegisterIdentity string

	// FollowUpPassesRun counts extra sweeps run after the first pass drained.
	// ActionsRetried / ActionsRecovered count the end-of-crawl retry sweep and how
	// many of those retries then succeeded.
	FollowUpPassesRun int
	ActionsRetried    int
	ActionsRecovered  int

	// AuthState is the authentication outcome: AuthNotRequested,
	// AuthConfigured, AuthApplied or AuthFailed (see page_auth.go).
	// CredentialOriginsDenied counts hosts the operator's credential headers
	// were kept from (outside the operator scope); CredentialHostsDenied names
	// them — hosts only, never header values.
	AuthState               string
	CredentialOriginsDenied int
	CredentialHostsDenied   []string

	// AuxFetchesDenied counts URLs an in-page primer (iframe, GET-form, anchor,
	// seed, speculative) wanted to fetch but the operator scope (or a denied
	// login wall) did not admit — see admissibleFetchURLs.
	AuxFetchesDenied int

	// WaitConditionsFailed counts readiness (wait) conditions that timed out;
	// WaitConditionFailures holds up to maxWaitConditionFailures of their
	// distinct selectors.
	WaitConditionsFailed  int
	WaitConditionFailures []string
}

// New creates a new crawler.
func New(cfg *config.Config) (*Crawler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	candidatesConfig := &action.UnfiredFragmentCandidatesConfig{
		MaxRepeat:             action.DefaultMaxRepeat,
		SkipExploredActions:   true,
		ApplyNonSelAdvantage:  false,
		RestoreConnectedEdges: false,
	}

	c := &Crawler{
		config:              cfg,
		graph:               state.NewGraph(),
		candidates:          action.NewUnfiredFragmentCandidates(candidatesConfig, nil), // StateProvider set after graph init
		extractor:           action.NewCandidateElementExtractor(cfg),
		comparator:          state.NewComparator(cfg),
		formHandler:         form.NewHandler(cfg),
		fragManager:         fragment.NewManager(),
		crawlConditions:     make([]*condition.Condition, 0),
		waitConditions:      make([]*condition.WaitCondition, 0),
		invariants:          make([]*condition.Condition, 0),
		formCache:           make(map[string][]*form.DetectedInput),
		eventableConditions: condition.NewEventableConditionChecker(),
		writer:              network.NopWriter{}, // Default no-op; override with SetWriter()
		stats:               Stats{},
		loginCredHosts:      make(map[string]bool),
		selfRegisterHosts:   make(map[string]bool),
		wallHosts:           make(map[string]bool),
		speculativeScript:   renderSpeculativeScript(cfg.SpeculativeMaxLinks),
		// NOTE: stateMachine, crawlPath, session initialized in initializeIndexState()
	}

	// Attach a per-crawl fill context so form values become response-aware:
	// identity values (email/username/password) stay consistent across a
	// register→login flow, on-page examples are preferred, and email/username are
	// derived from the target. The login-credential pass reads back the same
	// context to reuse an identity registered earlier in the crawl.
	c.formHandler.SetFillContext(form.NewFillContext(cfg.URL))

	// Convert config conditions
	for _, cc := range cfg.CrawlConditions {
		c.crawlConditions = append(c.crawlConditions, condition.NewFromConfig(cc))
	}

	for _, wc := range cfg.WaitConditions {
		c.waitConditions = append(c.waitConditions, condition.NewWaitConditionFromConfig(wc))
	}

	c.stats.AuthState = c.initialAuthState()

	// Initialize MAB policy if strategy is adaptive
	// RLCRAWLER PARITY: Use DefaultK=100 for Exp3.1 algorithm
	if cfg.CrawlStrategy == config.CrawlStrategyAdaptive {
		c.mabPolicy = mab.NewMABExp3Policy(mab.DefaultK)
		c.candidates.SetMABPolicy(c.mabPolicy)
		zap.L().Debug("MAB Exp3.1 policy initialized",
			zap.Int("K", mab.DefaultK),
			zap.String("strategy", string(cfg.CrawlStrategy)))
	}

	return c, nil
}

// SetWriter sets the network traffic writer used during crawling.
// Must be called before Run().
func (c *Crawler) SetWriter(w network.Writer) {
	c.writer = w
}

// AddInvariant adds an invariant condition that must always hold.
func (c *Crawler) AddInvariant(inv *condition.Condition) {
	c.invariants = append(c.invariants, inv)
}

// SetInvariantChecker sets the invariant checker for structured invariant management.
func (c *Crawler) SetInvariantChecker(checker *condition.InvariantChecker) {
	c.invariantChecker = checker
}

// SetFormTrainer sets the form trainer for reproducible form testing.
func (c *Crawler) SetFormTrainer(trainer *form.FormTrainer) {
	c.formTrainer = trainer
}

// GetFormTrainer returns the form trainer.
func (c *Crawler) GetFormTrainer() *form.FormTrainer {
	return c.formTrainer
}

// SetMetricsCollector sets the metrics collector for benchmark tracking.
func (c *Crawler) SetMetricsCollector(collector *metrics.Collector) {
	c.metricsCollector = collector
}

// GetMetricsCollector returns the metrics collector.
func (c *Crawler) GetMetricsCollector() *metrics.Collector {
	return c.metricsCollector
}

// SetClusterManager sets the ND cluster manager for near-duplicate state clustering.
func (c *Crawler) SetClusterManager(mgr *state.NDClusterManager) {
	c.clusterMgr = mgr
}

// GetClusterManager returns the ND cluster manager.
func (c *Crawler) GetClusterManager() *state.NDClusterManager {
	return c.clusterMgr
}

// AddEventableCondition adds an eventable condition for form-to-element linking.
// This enables generating multiple action variants with different form input values.
func (c *Crawler) AddEventableCondition(ec *condition.EventableCondition) {
	c.eventableConditions.Add(ec)
}

// GetEventableConditions returns the eventable condition checker.
func (c *Crawler) GetEventableConditions() *condition.EventableConditionChecker {
	return c.eventableConditions
}

// Run starts the crawl.
func (c *Crawler) Run(ctx context.Context) (*Result, error) {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil, fmt.Errorf("crawler is already running")
	}
	c.running = true
	c.stats.StartTime = time.Now()
	c.mu.Unlock()

	zap.L().Debug("Crawler starting",
		zap.String("url", c.config.URL.String()),
		zap.Int("max_states", c.config.MaxStates),
		zap.Int("max_depth", c.config.MaxDepth),
		zap.String("strategy", string(c.config.CrawlStrategy)))

	defer func() {
		c.mu.Lock()
		c.running = false
		c.stats.EndTime = time.Now()
		c.mu.Unlock()
	}()

	// The single-threaded crawler pins exactly one browser for the entire crawl
	// (see the Pool.Get() note below), so launching the configured BrowserCount>1
	// only burns startup time and memory without adding any crawl throughput. Cap
	// it to one; multi-browser scheduling is not implemented in this crawler.
	if c.config.BrowserCount > 1 {
		browserCountClampWarn.Do(func() {
			zap.L().Warn("Spidering: browser_count > 1 requested, but the crawler is single-threaded — launching 1 browser",
				zap.Int("configured", c.config.BrowserCount))
		})
		c.config.BrowserCount = 1
	}

	// Create browser pool FIRST (needed for browser-level capture)
	pool, err := browser.NewPoolWithContext(ctx, c.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create browser pool: %w", err)
	}
	c.browserPool = pool
	zap.L().Debug("Browser pool created", zap.Int("size", c.config.BrowserCount))
	defer func() {
		if err := pool.Close(); err != nil {
			zap.L().Warn("Browser pool close failed", zap.Error(err))
		}
	}()

	// Bind the crawl context to every page the pool creates so the deadline /
	// cancellation reaches rod's per-operation timeouts. Without this the
	// max-duration is only honored at Go-level loop boundaries, while in-flight
	// browser work (navigation, WaitStable, clicks, form fills, the per-page
	// priming steps) runs to its own fixed rod timeouts — the spider overshoots
	// the deadline by however long the current browser operation takes to wind
	// down. Must run before initializeIndexState creates the first page.
	pool.SetCrawlContext(ctx)

	// Create traffic capture with the configured writer
	capture := network.New(c.writer, c.config.NoColor, c.config.Silent, c.config.Verbose, c.config.IncludeResponseBody, c.config.IncludeResponseHeaders, c.config.URL.Hostname(), "spider")
	// Keep several distinct query-value variants per endpoint shape (category/
	// filter/tab/search links) instead of collapsing them to one representative.
	capture.SetMaxParamValueVariants(c.config.MaxParamValueVariants)
	capture.SetMaxBodyBytes(c.config.MaxCaptureBodyBytes)
	// Keep out-of-scope subresources (a login page's CAPTCHA widget, analytics
	// beacons) out of the live log — they are dropped before storage anyway.
	capture.ScopeFilter = c.config.ScopeFilter
	// A finished crawl is not failed over a flush error: the capture close
	// error is the writer's drop tally, which the caller reads from the
	// writer's receipt. Logged so it is never silent.
	defer func() {
		if err := capture.Close(); err != nil {
			zap.L().Warn("Traffic capture closed with lost records", zap.Error(err))
		}
	}()

	// Start capture at BROWSER level (captures ALL pages).
	// Pin one browser for the entire crawl — Pool.Get() round-robins, so calling
	// it from each helper would silently rotate to a different browser whose
	// CurrentPage is nil. This Crawler is single-threaded and not designed to fan
	// out across multiple browsers.
	br := pool.Get()
	if br == nil {
		return nil, fmt.Errorf("browser pool returned nil browser")
	}
	c.browser = br
	zap.L().Debug("Starting network capture",
		zap.Bool("include_body", c.config.IncludeResponseBody),
		zap.Bool("include_headers", c.config.IncludeResponseHeaders))
	if err := capture.Start(br.RodBrowser()); err != nil {
		return nil, fmt.Errorf("failed to start traffic capture: %w", err)
	}
	zap.L().Debug("Traffic capture enabled")

	return c.crawlWithBrowser(ctx, br, capture)
}

// RunOnBrowser crawls this seed using a browser + capture owned by an external
// SpiderSession instead of creating (and tearing down) its own pool/capture. This
// is how one browser context is reused across several same-host seeds so cookies,
// local storage, and capture-level dedup persist between them. The session owns
// the pool/capture lifecycle; this method only rebinds the seed's deadline onto
// the shared browser and runs the crawl.
func (c *Crawler) RunOnBrowser(ctx context.Context, br *browser.Browser, capture *network.Capture) (*Result, error) {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil, fmt.Errorf("crawler is already running")
	}
	c.running = true
	c.stats.StartTime = time.Now()
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.running = false
		c.stats.EndTime = time.Now()
		c.mu.Unlock()
	}()

	if br == nil {
		return nil, fmt.Errorf("RunOnBrowser: nil browser")
	}
	c.browserPool = nil // session owns the pool; never close it from here
	// Rebind THIS seed's deadline/cancellation onto every page the shared browser
	// creates, exactly as Run does via pool.SetCrawlContext for a fresh pool.
	br.SetCrawlContext(ctx)

	zap.L().Debug("Crawler starting on shared browser",
		zap.String("url", c.config.URL.String()),
		zap.Int("max_states", c.config.MaxStates),
		zap.String("strategy", string(c.config.CrawlStrategy)))

	return c.crawlWithBrowser(ctx, br, capture)
}

// crawlWithBrowser runs the seed-level crawl once the browser and capture are
// ready: it pins the browser, initializes the index state, runs the main loop,
// and builds the result. It is the shared body of Run (own pool/capture) and
// RunOnBrowser (session-owned pool/capture).
func (c *Crawler) crawlWithBrowser(ctx context.Context, br *browser.Browser, capture *network.Capture) (*Result, error) {
	if br == nil {
		return nil, fmt.Errorf("browser pool returned nil browser")
	}
	c.browser = br
	// Upload fixtures are generated on demand into a run-owned directory; hold
	// it for the crawl so the last crawl out removes it.
	form.RetainGeneratedFiles()
	defer form.ReleaseGeneratedFiles()
	// Both entry points funnel through here with the capture in hand, so this is
	// the one place the wiring cannot be missed. Setting it on the Config instead
	// silently failed on the multi-seed SpiderSession path, which rebuilds a fresh
	// Config per seed and never carried the hook across.
	if capture != nil {
		c.observedLoginHosts = capture.LoginHostsSeen
	}

	if c.eventableConditions != nil && c.eventableConditions.Count() > 0 {
		c.extractor.SetFormHandler(&formHandlerAdapter{checker: c.eventableConditions})
	}

	// Initialize
	if err := c.initializeIndexState(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize: %w", err)
	}

	// If the start URL bounced off-host and we adopted the landing host into
	// scope (evaluateStartRedirect, called during init), re-point the capture's
	// cross-origin log filter at it. Otherwise it keeps keying on the original
	// target host and suppresses every adopted-host line from stderr — the run
	// looks silent even though records are being written.
	if c.adoptedHost != "" {
		capture.SetTargetHost(c.adoptedHost)
	}

	// Seed the frontier from the host's own route declarations before the loop
	// starts. This belongs here rather than in index-state initialization: every
	// step there operates on the landing page, whereas this navigates to other
	// locations and folds each into the graph — a frontier-level operation, and a
	// sibling of the follow-up/retry passes below. Running it after
	// initializeIndexState also means scope adoption is already decided, so seeds
	// filter against the final boundary and land under the retargeted capture.
	if page := br.CurrentPage(); page != nil {
		c.seedFrontier(ctx, page)
	}

	// Main crawl loop
	if err := c.crawlLoop(ctx); err != nil {
		zap.L().Debug("Crawl loop ended", zap.Error(err))
	}

	// Re-walk for actions that only became available partway through the pass
	// (an authenticated menu, a section unlocked by an earlier action), then
	// re-attempt the actions that failed on transient page conditions. Both are
	// no-ops when the crawl stopped on its budget rather than by draining.
	c.runFollowUpPasses(ctx)
	c.retryFailedActions(ctx)

	// The map of what was reached and how is written by the caller
	// (WriteGraphDump) once the capture has drained, so the graph's manifest can
	// carry the final capture receipt.

	// Log final MAB summary
	c.logMABFinalSummary()

	return c.buildResult(ctx), nil
}

// logMABFinalSummary logs comprehensive MAB policy state at end of crawl.
func (c *Crawler) logMABFinalSummary() {
	if c.mabPolicy == nil {
		return
	}

	k, r, gThr, eta, globalR := c.mabPolicy.GetGlobalParams()
	stateCount := c.mabPolicy.GetStateCount()
	actionCount := c.mabPolicy.GetActionCount()

	zap.L().Debug("=== MAB FINAL SUMMARY ===",
		zap.Int("K", k),
		zap.Int("round", r),
		zap.Float64("G_thr", gThr),
		zap.Float64("eta", eta),
		zap.Float64("global_R", globalR),
		zap.Int("total_states", stateCount),
		zap.Int("total_actions", actionCount))
}

// initializeIndexState loads the initial page and captures the index state.
func (c *Crawler) initializeIndexState(ctx context.Context) error {
	zap.L().Debug("Initializing index state")

	br := c.browser
	if br == nil {
		return fmt.Errorf("no browser available")
	}

	page, err := br.NewPage()
	if err != nil {
		return err
	}

	// Set as current page so executeActionDFS can access it
	br.SetCurrentPage(page)

	// Seed operator-supplied authentication (cookies + extra headers) before the
	// first navigation so the crawl explores authenticated rather than only the
	// unauthenticated shell. A failure is recorded in Stats.AuthState; with
	// RequireAuth it fails the crawl instead of letting it run anonymously.
	if err := c.seedPageAuth(page); err != nil {
		return err
	}

	// Navigate to target URL
	url := c.config.URL.String()
	if c.config.BasicAuthUser != "" {
		url = c.config.GetBasicAuthURL()
	}

	zap.L().Debug("Navigating to target", zap.String("url", c.config.URL.String()))
	zap.L().Debug("Navigation URL prepared", zap.String("url", url))

	// Retry the very first navigation a few times. A transient transport error
	// (e.g. net::ERR_CONNECTION_RESET, common on the first connect through an
	// intercepting proxy like Burp) can fail an otherwise-reachable target, and
	// aborting here kills the whole spidering run for that target. Retrying rules
	// out a one-off browser/network hiccup before we give up.
	navErr := navigateWithRetry(ctx, url, initNavRetryBackoff, func() error {
		return page.NavigateCtx(ctx, url)
	})
	if navErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to navigate: %w%s", navErr, certRejectedHint(navErr))
	}

	// Check wait conditions
	c.checkWaitConditions(ctx, page)

	// NOTE: no explicit WaitStable here — NavigateCtx already waited for the DOM
	// to stabilize (WaitStable(DOMStableTime)) as part of the navigation above, so
	// repeating it only doubled the settle. The heavier SPA settle below picks up
	// anything still in flight.

	// Let a heavy SPA finish its bootstrap XHR chain (config/i18n/content/feature
	// flags) before we snapshot the page and extract clickables — otherwise we
	// capture a half-rendered shell whose login CTA and data calls have not landed
	// yet. Then clear any cookie-consent overlay so it neither blocks the real
	// content from rendering nor masks the elements we extract/click, and scroll
	// the page so content/assets that only load as sections enter the viewport are
	// requested and captured.
	c.settleSPA(ctx, page)
	c.dismissConsentOverlays(ctx, page)
	c.scrollToLoadContent(ctx, page)

	// Decide what to do about an off-host start redirect (SSO wall vs. relocated
	// app) BEFORE any priming or extraction, so an adopted host is in scope by the
	// time the crawl loop follows links — and so a denied login wall is known
	// before anything below touches the page.
	//
	// Position is load-bearing. The two priming steps that follow fetch up to
	// several hundred URLs apiece from the page's OWN origin, which on a walled
	// start is the identity provider's. Classifying after them left the single
	// largest burst of IdP traffic in this function ungated, and made the guard
	// positional: any helper added above the classification would be silently
	// unguarded again.
	landingURL, _ := page.URL()
	c.evaluateStartRedirect(page, landingURL)
	walled := c.startWalled.Load()

	if !walled {
		// Prime service-worker assets: fetch the files a PWA service worker would
		// pre-cache (e.g. Angular's lazy webpack chunks listed in ngsw.json) so the
		// network capture records them. A short headless visit never runs the
		// worker's precache, so these are otherwise missed.
		c.primeServiceWorkerAssets(ctx, page)

		// Prime iframe sources: fetch the same-origin <iframe>/<frame> URLs present
		// in the rendered DOM (including frames injected client-side after first
		// paint) so the page they point at — and any reflected query parameters on
		// it — is recorded and scanned even when the served HTML never linked it.
		c.primeIframeAssets(ctx, page)
	}

	// Capture index state
	zap.L().Debug("Capturing index state")
	indexState, err := c.captureState(ctx, page, 0)
	if err != nil {
		return fmt.Errorf("failed to capture index state: %w", err)
	}
	zap.L().Debug("Index state captured",
		zap.String("state_id", indexState.ID),
		zap.String("url", indexState.URL),
		zap.Int("dom_size", len(indexState.StrippedDOM)))

	// Add to graph
	c.graph.AddState(indexState)
	c.candidates.RecordStateCreation(indexState.ID)
	c.stats.StatesDiscovered++

	// RLCRAWLER PARITY: Register index state with MAB policy
	if c.mabPolicy != nil {
		c.mabPolicy.AddState(indexState.ID)
	}

	c.stateMachine = state.NewStateMachine(c.graph, indexState)

	c.session = NewCrawlSession(c.config, indexState)

	c.crawlPath = state.NewCrawlPath(indexState.ID)

	zap.L().Debug("Index state captured", zap.String("state", indexState.Name))

	// The landing is a denied login wall. Stop here rather than running the rest
	// of this function against it: everything below interacts with the page —
	// extracting and firing actions, filling and submitting its forms, priming
	// its anchors, harvesting its inline URLs — and the page belongs to somebody
	// else's identity provider. The index state and the redirect chain that got us
	// here are already recorded, which is the only part worth keeping.
	if walled {
		zap.L().Info("Spidering: landing is a login wall — skipping page interaction",
			zap.String("landing", landingURL))
		return nil
	}

	// Extract fragments
	c.extractFragments(page, indexState)

	// Extract initial actions (check crawl conditions first)
	if c.shouldCrawl(page) {
		c.extractor.SetCurrentState(indexState.ID)
		actions, err := c.extractor.Extract(ctx, page)
		if err != nil {
			zap.L().Debug("Failed to extract actions", zap.Error(err))
		} else {
			c.candidates.AddActions(actions, indexState.ID)
			added := len(actions)
			zap.L().Debug("Extracted actions from index state", zap.Int("count", added))
		}

		// NOTE: Frame extraction is already handled by c.extractor.Extract() which
		// recursively processes frames with correct framePath. No separate call needed.
	}

	// Drive the login CTA once. An unauthenticated visit to many enterprise apps
	// bounces to a portal landing whose "Log on" button kicks off an OAuth/SAML/SSO
	// navigation chain (… /oauth2/authorize → /idp/login → SAML → vendor login). The
	// normal state machine may never click it — it triggers a full cross-origin
	// navigation away from the landing — so the entire flow, and every URL it
	// touches, is missed. Clicking it here lets the network capture record the chain
	// and the destination login page's own XHRs; we then return to the landing so
	// the loop resumes from a known state.
	//
	// Runs BEFORE form-filling: a cookie-consent preference form (OneTrust et al.)
	// can carry dozens of controls that the form filler spends the element timeout
	// on apiece, which would otherwise burn the whole spider budget before the
	// login CTA is ever driven.
	c.primeLoginCTA(ctx, page, indexState.URL)

	// Fill forms if present.
	if c.config.FormFillEnabled {
		zap.L().Debug("Form filling enabled, detecting forms")
		c.fillFormsIfPresent(page, "")
	}

	// Submit GET forms (search/filter boxes) so their result URLs — e.g.
	// /catalog?searchTerm=a — are requested and captured. The interaction crawl
	// only submits a form when its submit control happens to be clicked, which the
	// bounded action budget frequently never selects; this makes it deterministic.
	// The forms were just filled above, so submitGetForms skips its own fill.
	c.submitGetForms(ctx, page, true)

	// Trigger POST forms (a JS-driven stock check → /catalog/product/stock, a
	// newsletter subscribe, etc.) so their endpoints are exercised and captured.
	// GET-form synthesis above already re-filled the forms, so skip a repeat fill.
	c.submitPostForms(ctx, page, true)

	// Fetch same-origin parameterized <a href> links (e.g. React-rendered
	// /catalog?category=Books filter links) so they are captured even when the
	// interaction budget never clicks them.
	c.primeAnchorLinks(ctx, page)

	// Scrape URL-like strings out of the rendered document's comments and inline
	// script — locations reachable by no click.
	c.harvestSpeculativeLinks(ctx, page)

	// If the landing itself is a login form, try common credentials (deep
	// intensity only, confirmed-login-gated) so the crawl can proceed
	// authenticated. Runs after form-filling so the fixed-identity fill has
	// already seeded the fill context that this pass reuses.
	c.attemptLoginCredentials(ctx, page)

	// Complete a public signup form, if the app has one and the operator opted
	// in, so the crawl continues as an authenticated user. Runs after the
	// credential pass so an existing-account login is preferred over creating a
	// new one; the identity it registers is reused by later login attempts.
	c.attemptSelfRegistration(ctx, page)

	return nil
}

// initNavAttempts is the total number of times the initial target navigation is
// attempted (1 initial try + 2 retries) before the crawl gives up on a target.
const initNavAttempts = 3

// initNavRetryBackoff is the pause between initial-navigation attempts.
const initNavRetryBackoff = 2 * time.Second

// navigateWithRetry calls navFn up to initNavAttempts times, pausing backoff
// between attempts, to ride out transient navigation failures (connection
// resets, proxy hiccups). Context cancellation aborts immediately and is never
// retried; the navigation error is returned only after every attempt fails. The
// navigation itself is injected so the retry policy can be unit-tested without a
// browser. url is used for logging only.
// certRejectedHint names the way out when navigation failed on a certificate:
// the browser only verifies TLS when spidering.browser_compat.ignore_tls_errors
// was turned off, so a self-signed local app needs it back on.
func certRejectedHint(err error) string {
	if err == nil || !strings.Contains(err.Error(), "ERR_CERT_") {
		return ""
	}
	return " (certificate rejected — re-run with --browser-insecure, or set spidering.browser_compat.ignore_tls_errors: true, if this is a local test app)"
}

func navigateWithRetry(ctx context.Context, url string, backoff time.Duration, navFn func() error) error {
	var lastErr error
	for attempt := 1; attempt <= initNavAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := navFn()
		if err == nil {
			if attempt > 1 {
				zap.L().Info("Initial navigation succeeded on retry",
					zap.String("url", url), zap.Int("attempt", attempt))
			}
			return nil
		}
		// A cancelled/expired context surfaces as a navigation error; don't
		// retry it — the run is over.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		lastErr = err
		if attempt < initNavAttempts {
			zap.L().Warn("Initial navigation failed, retrying",
				zap.String("url", url),
				zap.Int("attempt", attempt),
				zap.Int("max_attempts", initNavAttempts),
				zap.Error(err))
			if sleepErr := sleepWithContext(ctx, backoff); sleepErr != nil {
				return sleepErr
			}
		}
	}
	return lastErr
}

// crawlLoop is the main crawl loop.
//  1. Poll a STATE (not action) from the queue
//  2. Call execute(state) which:
//     a. If not at state, reset() to index (adds reload edge) then reachFromHome()
//     b. crawlThroughActions() - DFS through all actions from current state
//  3. TaskDone(state) - re-add state to queue if it still has actions
func (c *Crawler) crawlLoop(ctx context.Context) error {
	iteration := 0
	for {
		iteration++
		// Log queue stats every iteration for debugging
		stats := c.candidates.Stats()
		isEmpty := c.candidates.IsEmpty()
		zap.L().Debug("CrawlLoop iteration",
			zap.Int("iteration", iteration),
			zap.Int("pending_states", stats.TotalPending),
			zap.Int("total_seen", stats.TotalSeen))

		// Check termination conditions
		if c.shouldTerminate(ctx) {
			zap.L().Debug("Termination condition met")
			c.addFinalReloadEdge()
			return nil
		}

		// Check if queue is empty
		if isEmpty {
			zap.L().Debug("No more states to crawl")
			c.addFinalReloadEdge()
			return nil
		}

		// Poll a STATE (not action) from the queue based on crawl strategy
		stateID := c.candidates.PollStateByPriority(c.config.CrawlStrategy)
		if stateID == "" {
			zap.L().Debug("No more states with pending actions")
			c.addFinalReloadEdge()
			return nil
		}

		zap.L().Debug("Processing state", zap.String("state_id", stateID))

		// Get the state to crawl
		crawlTask, ok := c.graph.GetState(stateID)
		if !ok {
			zap.L().Warn("State not found, skipping", zap.String("state_id", stateID))
			continue
		}

		c.execute(ctx, crawlTask)

		zap.L().Debug("Execute completed for state", zap.String("state_id", stateID))

		c.candidates.TaskDone(stateID)

		// Log MAB summary every 5 iterations for debugging
		if c.mabPolicy != nil && iteration%5 == 0 {
			c.logMABSummary()
		}
	}
}

// logMABSummary logs a summary of MAB policy state for debugging.
func (c *Crawler) logMABSummary() {
	if c.mabPolicy == nil {
		return
	}

	k, r, gThr, eta, globalR := c.mabPolicy.GetGlobalParams()
	stateCount := c.mabPolicy.GetStateCount()
	actionCount := c.mabPolicy.GetActionCount()

	zap.L().Debug("MAB Summary",
		zap.Int("K", k),
		zap.Int("round", r),
		zap.Float64("G_thr", gThr),
		zap.Float64("eta", eta),
		zap.Float64("global_R", globalR),
		zap.Int("states_tracked", stateCount),
		zap.Int("actions_tracked", actionCount))
}

// execute crawls all actions from a target state.
//  1. If at crawlTask state -> setBTStatus(true, -1) + crawlThroughActions() (NO EARLY RETURN!)
//  2. ALWAYS: reset() + reachFromHome() + crawlThroughActions()
func (c *Crawler) execute(ctx context.Context, crawlTask *state.State) {
	zap.L().Debug("Execute task for state",
		zap.String("state", crawlTask.Name),
		zap.String("state_id", crawlTask.ID))

	currentState := c.stateMachine.GetCurrentState()

	if currentState != nil && currentState.ID == crawlTask.ID {
		zap.L().Debug("Already at target state, crawling through actions first")
		c.crawlPath.MarkSuccess()
		func() {
			defer func() {
				if r := recover(); r != nil {
					zap.L().Error("crawlThroughActions panicked in same-state block, recovering",
						zap.Any("panic", r))
				}
			}()
			c.crawlThroughActions(ctx)
		}()
		zap.L().Debug("crawlThroughActions completed (same state)")
	}

	//       reset(crawlTask.getId());
	//       reachFromHome(crawlTask);
	//       crawlThroughActions();

	if c.shouldTerminate(ctx) {
		return
	}

	currentStateName := "none"
	if currentState != nil {
		currentStateName = currentState.Name
	}
	zap.L().Debug("Resetting the crawler and going to state",
		zap.String("current_state", currentStateName),
		zap.String("target_state", crawlTask.Name))

	if err := c.reset(ctx, crawlTask.ID); err != nil {
		zap.L().Debug("Reset failed", zap.Error(err))
		c.crawlPath.MarkFailed()
		return
	}
	zap.L().Debug("Reset completed")

	if c.shouldTerminate(ctx) {
		return
	}

	zap.L().Debug("Reaching target state from home", zap.String("target", crawlTask.Name))
	if err := c.reachFromHome(ctx, crawlTask); err != nil {
		zap.L().Debug("State unreachable, removing from candidate actions",
			zap.String("state", crawlTask.Name), zap.Error(err))
		c.candidates.PurgeState(crawlTask.ID)
		return
	}

	if c.shouldTerminate(ctx) {
		return
	}

	c.crawlThroughActions(ctx)
	zap.L().Debug("crawlThroughActions completed")
}

// reset navigates to the index URL and creates a NEW StateMachine.
// 1. browser.handlePopups() - FIRST THING!
// 2. Save crawlPath to session
// 3. Get onURLSet + previousState from OLD StateMachine
// 4. Create NEW StateMachine BEFORE navigate
// 5. Create NEW CrawlPath
// 6. Navigate to URL
// 7. checkOnURLState() using NEW StateMachine
// 8. crawlDepth.set(0) - LAST THING!
func (c *Crawler) reset(ctx context.Context, nextTarget string) error {
	br := c.browser
	if br == nil {
		return fmt.Errorf("crawler browser not initialized")
	}
	page := br.CurrentPage()
	if page != nil {
		_ = page.HandlePopups()
	}

	if c.crawlPath != nil {
		c.crawlPath.Close()
		c.session.AddCrawlPath(c.crawlPath.ImmutableCopy())
	}

	var onURLSet []*state.State
	var previousState *state.State
	if c.stateMachine != nil {
		onURLSet = c.stateMachine.GetOnURLSet()
		previousState = c.stateMachine.GetCurrentState()
	} else {
		onURLSet = make([]*state.State, 0)
	}

	indexState := c.graph.GetIndexState()
	c.stateMachine = state.NewStateMachineWithOnURLSet(c.graph, indexState, onURLSet)
	zap.L().Debug("Reset: created NEW StateMachine BEFORE navigate",
		zap.String("initial_state", indexState.Name),
		zap.Int("onURLSet_size", c.stateMachine.OnURLSetSize()))

	c.crawlPath = state.NewCrawlPath(nextTarget)

	resetURL := c.config.URL.String()
	if c.config.BasicAuthUser != "" {
		resetURL = c.config.GetBasicAuthURL()
	}

	// Reuse br/page from Step 1, or create a new page on the same browser.
	if page == nil {
		var err error
		page, err = br.NewPage()
		if err != nil {
			return err
		}
		br.SetCurrentPage(page)
		// Extra headers are set per-page in CDP, so a freshly created reset page
		// needs them re-applied (cookies persist in the browser jar). The outcome
		// lands in Stats.AuthState.
		_ = c.applyPageAuth(page)
	}

	if err := page.NavigateCtx(ctx, resetURL); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("reset navigation failed: %w", err)
	}

	// Wait for page to stabilize
	if err := page.WaitStable(c.config.WaitAfterReload); err != nil {
		if ctxErr := sleepWithContext(ctx, c.config.WaitAfterReload); ctxErr != nil {
			return ctxErr
		}
	}
	c.checkWaitConditions(ctx, page)

	c.checkOnURLState(ctx, page, previousState, resetURL)

	// Go uses newState.Depth for maxDepth check instead of a per-crawler counter.

	c.resetCalled = true
	c.stats.BacktrackCount++
	return nil
}

// reachFromHome navigates from current state to target state.
// 1. Try shortest path from CURRENT state to target
// 2. If fails, try from each onURLSet state
// 3. Navigate to onURL state, then follow path
func (c *Crawler) reachFromHome(ctx context.Context, target *state.State) error {
	zap.L().Debug("Reaching target state", zap.String("target", target.Name))

	indexState := c.graph.GetIndexState()
	if indexState == nil {
		return fmt.Errorf("no index state")
	}

	br := c.browser
	if br == nil {
		return fmt.Errorf("crawler browser not initialized")
	}
	page := br.CurrentPage()
	if page == nil {
		return fmt.Errorf("no current page on crawler browser")
	}

	alreadyTried := make(map[string]bool)

	currentState := c.stateMachine.GetCurrentState()
	if currentState != nil {
		alreadyTried[currentState.ID] = true
		path := c.graph.ShortestPath(currentState.ID, target.ID)
		if path != nil {
			zap.L().Debug("Path found from current state",
				zap.String("from", currentState.Name),
				zap.Int("path_length", len(path)))
			err := c.followPath(ctx, path, target)
			if err == nil {
				reachedState := c.stateMachine.GetCurrentState()
				if reachedState.ID != target.ID {
					zap.L().Debug("Tried reaching target but reached near-duplicate",
						zap.String("target", target.Name),
						zap.String("reached", reachedState.Name))
					c.crawlPath.SetBacktrackSuccess(false)
					c.crawlPath.SetReachedNearDup(reachedState.ID)
					c.candidates.StateUpdated(target.ID)
				} else {
					zap.L().Debug("Reached the correct target", zap.String("target", target.Name))
					c.crawlPath.SetBacktrackSuccess(true)
				}
				return nil
			}
			zap.L().Debug("Path from current state failed, resetting before trying onURLSet",
				zap.String("from", currentState.Name),
				zap.Error(err))
			c.crawlPath.SetBacktrackSuccess(false)
			_ = c.reset(ctx, target.ID) // CRITICAL: Reset on first path failure!
		}
	}

	onURLStates := c.stateMachine.GetOnURLSetSlice()
	for _, onURLState := range onURLStates {
		if c.shouldTerminate(ctx) {
			return ctx.Err()
		}
		if alreadyTried[onURLState.ID] {
			zap.L().Debug("Skipping already tried onURL state", zap.String("state", onURLState.Name))
			continue
		}
		alreadyTried[onURLState.ID] = true

		// Find path from this onURL state to target
		path := c.graph.ShortestPath(onURLState.ID, target.ID)
		if path == nil {
			zap.L().Debug("No path from onURL state to target",
				zap.String("from", onURLState.Name),
				zap.String("to", target.Name))
			continue
		}

		zap.L().Debug("Trying path from onURL state",
			zap.String("from", onURLState.Name),
			zap.String("to", target.Name),
			zap.Int("path_length", len(path)))

		if err := page.NavigateCtx(ctx, onURLState.URL); err != nil {
			zap.L().Debug("Failed to navigate to onURL state",
				zap.String("state", onURLState.Name),
				zap.Error(err))
			if c.shouldTerminate(ctx) {
				return ctx.Err()
			}
			continue
		}
		if err := page.WaitStable(c.config.WaitAfterReload); err != nil {
			if ctxErr := sleepWithContext(ctx, c.config.WaitAfterReload); ctxErr != nil {
				return ctxErr
			}
		}
		c.checkWaitConditions(ctx, page)
		c.stateMachine.SetCurrentState(onURLState)

		// Follow path from onURL to target
		err := c.followPath(ctx, path, target)
		if err == nil {
			reachedState := c.stateMachine.GetCurrentState()
			if reachedState.ID != target.ID {
				zap.L().Debug("Tried reaching target but reached near-duplicate",
					zap.String("from", onURLState.Name),
					zap.String("target", target.Name),
					zap.String("reached", reachedState.Name))
				c.crawlPath.SetBacktrackSuccess(false)
				c.crawlPath.SetReachedNearDup(reachedState.ID)
				c.candidates.StateUpdated(target.ID)
			} else {
				zap.L().Debug("Reached the correct target",
					zap.String("from", onURLState.Name),
					zap.String("target", target.Name))
				c.crawlPath.SetBacktrackSuccess(true)
			}
			return nil
		}

		zap.L().Debug("Path from onURL state failed, resetting",
			zap.String("from", onURLState.Name),
			zap.Error(err))
		c.crawlPath.SetBacktrackSuccess(false)
		_ = c.reset(ctx, target.ID)
	}

	return fmt.Errorf("cannot reach state %s from any starting point", target.Name)
}

// followPath executes actions along a path to reach the target state.
func (c *Crawler) followPath(ctx context.Context, path []*action.Eventable, target *state.State) error {
	br := c.browser
	if br == nil {
		return fmt.Errorf("crawler browser not initialized")
	}
	page := br.CurrentPage()
	if page == nil {
		return fmt.Errorf("no current page on crawler browser")
	}

	for _, edge := range path {
		if c.shouldTerminate(ctx) {
			return ctx.Err()
		}
		// Check crawl conditions
		if !c.shouldCrawl(page) {
			return fmt.Errorf("crawl condition not met during path follow")
		}

		zap.L().Debug("Following edge", zap.String("source", edge.SourceStateID), zap.String("target", edge.TargetStateID))

		// Skip if edge has no identification
		if edge.Identification == nil {
			return fmt.Errorf("edge has no identification")
		}

		if c.config.FormFillEnabled {
			if !c.candidates.ShouldDisableInputForPath(edge) {
				// Try to get cached input from candidates
				cachedInputs := c.candidates.GetInput(edge)
				if len(cachedInputs) > 0 {
					// Use cached form inputs
					zap.L().Debug("Used cached form input for backtracking", zap.Int64("eventable_id", edge.ID))
					c.fillFormsWithInputs(page, cachedInputs)
				} else {
					// eventable.RelatedFormInputs with DOM-detected inputs
					zap.L().Debug("No cached input, using getInputElements", zap.Int64("eventable_id", edge.ID))
					handled := c.handleInputElements(page, edge)
					// Cache the handled inputs for future backtracking
					if len(handled) > 0 {
						c.candidates.MapInput(edge, handled)
					}
				}
			}
			// If shouldDisableInput is true, skip form filling entirely
		}

		// Execute the event based on EventType
		// CRITICAL: Check How to determine if selector is XPath or CSS
		selector := edge.GetSelector()
		isXPath := edge.Identification != nil && edge.Identification.How == action.HowXPath
		switch edge.EventType {
		case action.EventTypeClick:
			var err error
			if isXPath {
				// Use XPath-based element finding
				elem, findErr := page.ElementX(selector)
				if findErr != nil {
					return fmt.Errorf("click failed during path follow (XPath): %w", findErr)
				}
				err = elem.Click()
			} else {
				err = page.Click(selector)
			}
			if err != nil {
				return fmt.Errorf("click failed during path follow: %w", err)
			}
		case action.EventTypeReload:
			// Reload events just navigate, already handled
			continue
		default:
			// Default to click for other event types
			var err error
			if isXPath {
				elem, findErr := page.ElementX(selector)
				if findErr != nil {
					return fmt.Errorf("action failed during path follow (XPath): %w", findErr)
				}
				err = elem.Click()
			} else {
				err = page.Click(selector)
			}
			if err != nil {
				return fmt.Errorf("action failed during path follow: %w", err)
			}
		}

		// Wait for state change
		if err := page.WaitStable(c.config.DOMStableTime); err != nil {
			if ctxErr := sleepWithContext(ctx, c.config.DOMStableTime); ctxErr != nil {
				return ctxErr
			}
		}

		// If ChangeState returns false, the path is invalid (edge no longer exists).
		targetState, ok := c.graph.GetState(edge.TargetStateID)
		if !ok {
			return fmt.Errorf("target state %s not found in graph during path follow", edge.TargetStateID)
		}
		if !c.stateMachine.ChangeState(targetState) {
			return fmt.Errorf("could not switch states during path follow: %s -> %s", edge.SourceStateID, edge.TargetStateID)
		}

		// crawlpath.add(clickable);
		if c.crawlPath != nil {
			c.crawlPath.Add(edge)
		}
	}

	// Verify we reached the target
	currentState := c.stateMachine.GetCurrentState()
	if currentState == nil || currentState.ID != target.ID {
		currentName := "nil"
		if currentState != nil {
			currentName = currentState.Name
		}
		return fmt.Errorf("path didn't reach target state %s, at %s", target.Name, currentName)
	}

	return nil
}

// DUPLICATE_EVENT_SEED is used to encode equivalentAccess in eventable IDs.
const DUPLICATE_EVENT_SEED = 100000

// crawlThroughActions crawls through all actions for current state using DFS.
//  1. afterBacktrack=true for first poll
//  2. Poll action with afterBacktrack parameter
//  3. Check allConditionsSatisfied(browser) BEFORE firing
//  4. If wasExplored(): eventableId = equivalentAccess * DUPLICATE_EVENT_SEED + eventableId
//  5. On success: fragmentManager.recordAccess(), inspectNewState()
//  6. On failure: setDirectAccess(true), disableInputsForAction(), re-add action if disableInputsForAction returns true
//  7. afterBacktrack=false for subsequent polls
//  8. Check crawlerNotInScope() after each action
func (c *Crawler) crawlThroughActions(ctx context.Context) {
	afterBacktrack := true

	for {
		if c.shouldTerminate(ctx) {
			return
		}

		// Poll action for current state only
		currentState := c.stateMachine.GetCurrentState()
		if currentState == nil {
			return
		}

		act := c.candidates.PollByMode(currentState.ID, c.config.CrawlStrategy, afterBacktrack)
		if act == nil {
			// No more actions for current state, exit DFS
			zap.L().Debug("No more actions for state", zap.String("state", currentState.Name))
			return
		}

		element := act.GetCandidateElement()

		page := c.browser.CurrentPage()
		if page == nil {
			zap.L().Debug("No current page available, exiting crawl loop")
			return
		}
		if !c.checkAllConditionsSatisfied(page, element) {
			zap.L().Debug("Element not clicked because not all crawl conditions were satisfied",
				zap.String("xpath", element.GetIdentification().Value))
			afterBacktrack = false
			continue
		}

		//   long eventableId = getEventableId();
		//   if (element.wasExplored()) {
		//       eventableId = (long) (element.getEquivalentAccess()) * DUPLICATE_EVENT_SEED + eventableId;
		//   }
		eventableID := action.NextEventableID()
		if element.WasExplored() {
			eventableID = int64(element.GetEquivalentAccess())*DUPLICATE_EVENT_SEED + eventableID
			zap.L().Debug("Duplicate access for element",
				zap.String("xpath", element.GetIdentification().Value),
				zap.Int64("seed_id", eventableID))
		}

		sourceStateID := currentState.ID

		// This allows us to use eventable.getRelatedFormInputs() in fireEventWithInputs
		eventable := action.NewEventableFromCandidateCrawlActionWithID(act, eventableID)
		eventable.SourceStateID = sourceStateID

		// Execute the action with eventable (for proper form input handling)
		newActionsCount, filledFormInputs, err := c.executeActionWithEventable(ctx, act, eventable)

		targetStateID := sourceStateID
		if newState := c.stateMachine.GetCurrentState(); newState != nil {
			targetStateID = newState.ID
		}
		eventable.TargetStateID = targetStateID

		if err != nil {
			// A policy-denied action is consumed, not failed: re-queueing or
			// retrying it would only be denied again, and counting it toward
			// ConsecutiveFailures could end a crawl that is working as configured.
			if errors.Is(err, ErrActionNotPermitted) {
				c.candidates.MarkExecuted(act)
				if c.mabPolicy != nil {
					c.mabPolicy.RemoveAction(sourceStateID, element.GetIdentification().Value)
				}
				afterBacktrack = false
				continue
			}
			// RLCRAWLER PARITY: Skip MAB update entirely when crawl condition not met
			// Action was not actually executed, so we shouldn't update MAB or count as failure
			if errors.Is(err, ErrCrawlConditionNotMet) {
				zap.L().Debug("Action skipped (crawl condition not met)",
					zap.String("state", sourceStateID))
				// Don't count as failure, don't update MAB, just continue
				afterBacktrack = false
				continue
			}

			//   LOG.info("Could not fire event. Putting back the actions on the todo list and disabling input next time");
			//   LOG.info("Recording direct access to the action to avoid picking in the same state again");
			//   element.setDirectAccess(true);
			//   if (action != null) {
			//       boolean added = candidateActionCache.disableInputsForAction(action);
			//       if (added) {
			//           List<CandidateCrawlAction> actions = new ArrayList<>();
			//           actions.add(action);
			//           candidateActionCache.addActions(actions, stateMachine.getCurrentState());
			//       }
			//   }
			zap.L().Debug("Could not fire event. Putting back on todo list and disabling input next time",
				zap.Error(err))
			zap.L().Debug("Recording direct access to avoid picking in the same state again")
			element.SetDirectAccess(true)
			added := c.candidates.DisableInputsForAction(act)
			if added {
				c.candidates.ReAddAction(act, currentState.ID)
			} else {
				// The normal path has run out of re-queues for this action, so it
				// is about to be dropped for good. Hand it to the retry sweep
				// instead: most of these failed on a transient page condition that
				// will not still be true at the end of the crawl.
				c.recordFailedAction(act, currentState.ID)
			}
			c.stats.ActionsFailed++
			c.stats.ConsecutiveFailures++
			// Record failed action to metrics (only when benchmark mode)
			if c.metricsCollector != nil {
				c.recordMetrics(act, false, false, false, 0)
			}
			// RLCRAWLER PARITY: Update MAB with zero reward for failed actions
			// This allows MAB to learn that certain actions are unreliable
			if c.mabPolicy != nil {
				actionID := element.GetIdentification().Value
				rewardEnv := 0.0
				reward := mab.TransformReward(rewardEnv)
				c.mabPolicy.Update(sourceStateID, actionID, reward)
				// Spitolas ADAPTATION: Remove executed action from MAB (click-once semantics)
				c.mabPolicy.RemoveAction(sourceStateID, actionID)
				zap.L().Debug("MAB updated for failed action",
					zap.String("state", sourceStateID),
					zap.String("action", actionID),
					zap.Float64("reward", reward))
			}
			// It's set to false AFTER the if-else block (line 1323)
			// But since we continue here, we need to set it too
			afterBacktrack = false
			continue
		}

		if len(filledFormInputs) > 0 {
			c.candidates.MapInput(eventable, filledFormInputs)
		}

		if c.fragManager != nil {
			c.fragManager.RecordElementAccess(element, currentState.ID)
		}

		// ONLY when DOM actually changed. NOT here unconditionally.

		c.candidates.MarkExecuted(act)
		c.stats.ActionsExecuted++
		c.stats.ConsecutiveFailures = 0 // Reset on success

		// Record successful action to metrics (only when benchmark mode)
		if c.metricsCollector != nil {
			isFormSubmit := act.GetEventType() == action.EventTypeEnter
			c.recordMetrics(act, true, newActionsCount > 0, isFormSubmit, newActionsCount)
		}

		// RLCRAWLER PARITY: Update MAB policy with coverage-based reward
		// reward_env = newActionsCount, transformed via 1-exp(-reward_env)
		if c.mabPolicy != nil {
			actionID := element.GetIdentification().Value
			rewardEnv := float64(newActionsCount)
			reward := mab.TransformReward(rewardEnv)
			reset := c.mabPolicy.Update(sourceStateID, actionID, reward)
			// Spitolas ADAPTATION: Remove executed action from MAB (click-once semantics)
			c.mabPolicy.RemoveAction(sourceStateID, actionID)
			zap.L().Debug("MAB policy updated",
				zap.String("state", sourceStateID),
				zap.String("action", actionID),
				zap.Float64("reward_env", rewardEnv),
				zap.Float64("reward", reward),
				zap.Bool("round_reset", reset))
			if reset {
				zap.L().Debug("MAB round reset",
					zap.Int("new_round", c.mabPolicy.GetRound()))
			}
		}

		afterBacktrack = false

		//   if (!interrupted && crawlerNotInScope()) {
		//       throw new CrawlerLeftDomainException(browser.getCurrentUrl());
		//   }
		// Note: Go doesn't throw exceptions, we just return to let reset handle it
		if page != nil && !c.isInScope(page) {
			zap.L().Warn("Crawler left domain scope during action crawl")
			return // Let the main loop handle reset
		}

		// After action, currentState may have changed (if new state discovered)
		// Continue DFS from the new current state
	}
}

// checkAllConditionsSatisfied checks if all conditions are satisfied for an element.
func (c *Crawler) checkAllConditionsSatisfied(page *browser.Page, element *action.CandidateElement) bool {
	// Check page-level crawl conditions first
	if !c.shouldCrawl(page) {
		return false
	}

	//   public boolean allConditionsSatisfied(EmbeddedBrowser browser) {
	//       return eventableCondition == null || eventableCondition.checkCondition(browser);
	//   }
	eventableCondition := element.GetEventableCondition()
	if eventableCondition == nil {
		return true
	}

	// If we have an eventable condition checker, use it
	if c.eventableConditions != nil {
		// Get element XPath for condition check
		elementXPath := ""
		if element.GetIdentification() != nil {
			elementXPath = element.GetIdentification().Value
		}
		// Check all conditions for this element
		return c.eventableConditions.Check(elementXPath, page)
	}

	// If no specific condition or checker, assume satisfied
	return true
}

// executeActionWithEventable executes an action with proper Eventable-based form handling.
// Returns (newActionsCount, filledFormInputs, error) where:
// - newActionsCount is the number of new actions discovered
// - filledFormInputs are the form inputs that were filled (for caching in candidates)
func (c *Crawler) executeActionWithEventable(ctx context.Context, crawlAction *action.CandidateCrawlAction, eventable *action.Eventable) (newActionsCount int, filledInputs []*action.FormInput, err error) {
	// CRITICAL: General panic recovery - catch all runtime panics during action execution.
	// Prevents entire crawl from crashing when an action encounters problems
	// (cross-origin frames, detached elements, nil pointer dereferences, etc.)
	defer func() {
		if r := recover(); r != nil {
			candidate := crawlAction.GetCandidateElement()
			identification := candidate.GetIdentification()
			xpath := ""
			if identification != nil {
				xpath = identification.Value
			}
			zap.L().Warn("PANIC in executeActionWithEventable - recovering",
				zap.String("xpath", xpath),
				zap.String("event_type", string(crawlAction.GetEventType())),
				zap.String("frame", candidate.RelatedFrame),
				zap.Any("panic", r),
				zap.Stack("stack"))

			// Convert panic to error, action will be marked as failed and may be retried
			newActionsCount = 0
			filledInputs = nil
			err = fmt.Errorf("action execution panicked: %v", r)
		}
	}()

	candidate := crawlAction.GetCandidateElement()
	eventType := crawlAction.GetEventType()
	identification := candidate.GetIdentification()

	// Get XPath from identification
	xpath := ""
	if identification != nil && identification.How == action.HowXPath {
		xpath = identification.Value
	}

	zap.L().Debug("Event xpath", zap.String("xpath", xpath))

	// The interaction policy is checked before anything is filled or clicked.
	if err := c.checkSubmitPermitted(candidate, eventType); err != nil {
		return 0, nil, err
	}

	if c.browser == nil {
		return 0, nil, fmt.Errorf("crawler browser not initialized")
	}
	page := c.browser.CurrentPage()
	if page == nil {
		return 0, nil, fmt.Errorf("no page available")
	}

	// Handle frame context if action is inside a frame
	targetPage := page
	if candidate.RelatedFrame != "" {
		zap.L().Debug("Navigating to frame", zap.String("frame_path", candidate.RelatedFrame))
		framePage, err := c.navigateToFrame(page, candidate.RelatedFrame)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to navigate to frame %s: %w", candidate.RelatedFrame, err)
		}
		targetPage = framePage
	}

	// Check crawl conditions
	if !c.shouldCrawl(targetPage) {
		zap.L().Warn("Crawl condition not met, skipping action")
		return 0, nil, ErrCrawlConditionNotMet
	}

	//   1. List<FormInput> available = getInputElements(event);  // merge related + DOM
	//   2. List<FormInput> handled = formHandler.handleFormElements(available);  // fill
	//   3. candidateActionCache.mapInput(event, handled);  // cache (done in caller)
	shouldDisableInputs := c.candidates.ShouldDisableInputForAction(crawlAction)
	if c.config.FormFillEnabled && !shouldDisableInputs {
		// 1. eventable.getRelatedFormInputs() (inputs linked from CandidateElement)
		// 2. formHandler.getFormInputs() (all inputs on current DOM)
		filledInputs = c.handleInputElements(targetPage, eventable)
	} else if shouldDisableInputs {
		zap.L().Debug("Form inputs disabled for this action (retry without inputs)")
	}

	// Execute the action using identification selector
	selector := ""
	useXPath := false
	if identification != nil {
		selector = identification.Value
		useXPath = identification.How == action.HowXPath
	}
	frameInfo := ""
	if candidate.RelatedFrame != "" {
		frameInfo = candidate.RelatedFrame
	}
	zap.L().Debug("Executing action",
		zap.String("type", string(eventType)),
		zap.String("selector", selector),
		zap.Bool("useXPath", useXPath),
		zap.String("frame", frameInfo),
		zap.String("tagName", candidate.TagName))

	// Helper to get element with proper selector type (XPath vs CSS)
	getElement := func() (*browser.Element, error) {
		if useXPath {
			return targetPage.ElementX(selector)
		}
		return targetPage.Element(selector)
	}

	switch eventType {
	case action.EventTypeClick:
		elem, err := getElement()
		if err != nil {
			zap.L().Debug("Click failed: element not found",
				zap.String("selector", selector),
				zap.Bool("useXPath", useXPath),
				zap.Error(err))
			// try to navigate directly to href for anchor elements (visitAnchorHrefIfPossible)
			if c.config.CrawlHiddenAnchors && strings.EqualFold(candidate.TagName, "a") && candidate.Href != "" {
				zap.L().Debug("Click failed on hidden anchor, navigating to href", zap.String("href", candidate.Href))
				if navErr := c.visitAnchorHref(page, candidate.Href); navErr != nil {
					return 0, nil, fmt.Errorf("click failed and href navigation failed: %w", navErr)
				}
			} else {
				return 0, nil, fmt.Errorf("click failed: element not found: %w", err)
			}
		} else if err := elem.Click(); err != nil {
			zap.L().Debug("Click action failed",
				zap.String("selector", selector),
				zap.Error(err))
			if c.config.CrawlHiddenAnchors && strings.EqualFold(candidate.TagName, "a") && candidate.Href != "" {
				zap.L().Debug("Click failed on hidden anchor, navigating to href", zap.String("href", candidate.Href))
				if navErr := c.visitAnchorHref(page, candidate.Href); navErr != nil {
					return 0, nil, fmt.Errorf("click failed and href navigation failed: %w", navErr)
				}
			} else {
				return 0, nil, fmt.Errorf("click failed: %w", err)
			}
		} else if submitLikeCandidate(candidate) {
			c.countSubmitDispatched(submitMechClick, 1)
		}
	case action.EventTypeHover:
		elem, err := getElement()
		if err != nil {
			return 0, nil, fmt.Errorf("hover failed: element not found: %w", err)
		}
		if err := elem.Hover(); err != nil {
			return 0, nil, fmt.Errorf("hover failed: %w", err)
		}
	case action.EventTypeEnter:
		// Enter key event - typically used for form submission
		elem, err := getElement()
		if err != nil {
			return 0, nil, fmt.Errorf("enter failed: element not found: %w", err)
		}
		if err := elem.Click(); err != nil {
			return 0, nil, fmt.Errorf("enter failed: %w", err)
		}
		c.countSubmitDispatched(submitMechEnter, 1)
	default:
		return 0, nil, fmt.Errorf("unknown event type: %s", eventType)
	}

	// Wait after action
	zap.L().Debug("Waiting after action", zap.Duration("wait_time", c.config.WaitAfterEvent))
	if err := sleepWithContext(ctx, c.config.WaitAfterEvent); err != nil {
		return 0, nil, err
	}

	_ = page.HandlePopups()

	// This is CRITICAL for target="_blank" and window.open() links
	if err := c.browser.CloseOtherWindows(); err != nil {
		// Log but don't fail the crawl - this is a cleanup operation
		zap.L().Warn("Failed to close other windows, continuing crawl", zap.Error(err))
	}

	// Wait for potential state change
	zap.L().Debug("Waiting for DOM stability after action")
	if err := page.WaitStable(c.config.DOMStableTime); err != nil {
		if ctxErr := sleepWithContext(ctx, c.config.DOMStableTime); ctxErr != nil {
			return 0, nil, ctxErr
		}
	}

	zap.L().Debug("Inspecting new state after action")
	newActionsCount = c.inspectNewState(ctx, page, eventable)

	return newActionsCount, filledInputs, nil
}

// inspectNewState checks if the DOM changed after an action and handles new/clone states.
// Returns the number of new actions discovered (for MAB reward and metrics).
// The eventable parameter is the FIRED eventable with correct ID (including DUPLICATE_EVENT_SEED).
func (c *Crawler) inspectNewState(ctx context.Context, page *browser.Page, eventable *action.Eventable) int {
	_ = page.HandlePopups()

	currentState := c.stateMachine.GetCurrentState()

	// This MUST be checked before capturing state to prevent out-of-scope states
	if !c.isInScope(page) {
		zap.L().Warn("Browser left crawl scope, going back")
		// Go back to previous state
		if err := page.NavigateBack(); err != nil {
			zap.L().Debug("Failed to navigate back", zap.Error(err))
			// If back fails, navigate to current state URL
			if currentState != nil {
				if err := page.Navigate(currentState.URL); err != nil {
					zap.L().Debug("Failed to navigate to current state", zap.Error(err))
				}
			}
		}
		// NavigateBack() already waits for navigation to complete, no need for additional WaitStable()
		return 0 // Don't capture out-of-scope state
	}

	// Wait out an in-progress render before snapshotting. The snapshot decides
	// whether this is a new state at all, so a half-rendered DOM here compares as
	// a duplicate of the state we came from and the route is discarded — the
	// settle that runs further down would never be reached. Gated on cheap
	// signals, so a click that changed nothing costs nothing.
	settled := c.settleBeforeCapture(ctx, page, currentState.URL)

	// Capture current DOM state
	zap.L().Debug("Capturing DOM state for comparison")
	newState, err := c.captureState(ctx, page, currentState.Depth+1)
	if err != nil {
		zap.L().Debug("Failed to capture state", zap.Error(err))
		return 0
	}
	zap.L().Debug("State captured",
		zap.String("state_id", newState.ID),
		zap.Int("dom_size", len(newState.StrippedDOM)))

	// Check if this is the same as current state (DOM unchanged)
	comparison := c.comparator.Compare(currentState, newState)
	comparisonStr := "different"
	if comparison == state.ResultDuplicate {
		comparisonStr = "duplicate"
	}
	zap.L().Debug("DOM comparison result",
		zap.String("current_state", currentState.ID),
		zap.String("new_state", newState.ID),
		zap.String("result", comparisonStr))

	if comparison == state.ResultDuplicate {
		zap.L().Debug("DOM unchanged after action")
		return 0
	}

	if eventable.ID <= 0 {
		zap.L().Warn("Adding Eventable to Crawlpath has id less than zero", zap.Int64("id", eventable.ID))
	}
	c.crawlPath.Add(eventable)

	// This handles: AddState (putIfAbsent), AddEdge, and ChangeState all in one call.
	existingState, isClone, graphEdge := c.stateMachine.SwitchToStateAndCheckIfClone(newState, eventable)
	if isClone {
		// Clone state detected
		zap.L().Debug("State already exists (clone detected)",
			zap.String("state", existingState.Name),
			zap.String("state_id", existingState.ID))

		// When addEdge detects a duplicate, it sets eventable.ID = -1 and returns
		// the pre-existing graph edge. We must fix the crawlPath by replacing the
		// clone edge with that real graph edge.
		//
		// The edge comes back from the state machine rather than being searched
		// for: this branch is the common case in a crawl (revisiting a known
		// state), and scanning c.graph.AllEdges() to re-find an edge AddEdge just
		// returned costs a full materialization of every edge in the graph plus an
		// Equals per edge, growing with the graph on every duplicate transition.
		if eventable.ID == -1 {
			zap.L().Debug("Removing Clone Edge from crawlPath")
			c.crawlPath.RemoveLast()

			replacement := eventable // fallback: re-add the original eventable
			if graphEdge != nil && graphEdge != eventable {
				replacement = graphEdge
				zap.L().Debug("CrawlPath fixed with existing graph edge", zap.Int64("edge_id", graphEdge.ID))
			} else {
				zap.L().Debug("Crawlpath could not be fixed with graph, using removed eventable")
			}
			c.crawlPath.Add(replacement)
		}

		c.candidates.RediscoveredState(existingState.ID)
		if c.graph.RestoreState(existingState.ID) {
			zap.L().Debug("Restored expired state and its incoming edges", zap.String("state_id", existingState.ID))
		}

		c.stats.StatesDuplicate++
		return 0
	}

	// New state discovered!
	zap.L().Debug("New state discovered", zap.String("state", newState.Name), zap.Int("depth", newState.Depth))
	c.candidates.RecordStateCreation(newState.ID)

	// Harvest iframe sources mounted in this newly reached state — a click/form
	// (e.g. opening a registration step) can inject a frame whose URL the served
	// HTML never contained. Deduped across the crawl so a recurring frame is
	// fetched once.
	c.primeIframeAssets(ctx, page)

	// A login form can surface anywhere mid-crawl (a "Sign in" link, a gated
	// section). If this newly reached state is a confirmed local login form, try
	// common credentials once per host (when the policy permits) so the crawl can
	// continue into the now-unlocked area.
	c.attemptLoginCredentials(ctx, page)

	// RLCRAWLER PARITY: Register new state with MAB policy
	if c.mabPolicy != nil {
		c.mabPolicy.AddState(newState.ID)
	}
	c.stats.StatesDiscovered++
	zap.L().Debug("Current state updated to new state", zap.String("state_id", newState.ID))

	// Let this newly reached state settle and (if it has content below the fold)
	// scroll to trigger lazy loads BEFORE extracting its fragments/actions, so a
	// deep SPA route contributes its lazy content and data fetches instead of just
	// its above-the-fold shell. The pre-snapshot settle above already quiesced the
	// page on a navigating action, so this skips its own wait in that case.
	c.settleNewState(ctx, page, settled)

	// Extract fragments
	c.extractFragments(page, newState)

	// Check max depth
	if c.config.MaxDepth > 0 && newState.Depth >= c.config.MaxDepth {
		zap.L().Debug("Max depth reached, not extracting actions",
			zap.Int("depth", newState.Depth),
			zap.Int("max_depth", c.config.MaxDepth))
		return 0
	}

	// Extract actions from new state (if crawl conditions allow)
	if !c.shouldCrawl(page) {
		zap.L().Debug("Crawl conditions not met, skipping action extraction")
		return 0
	}

	zap.L().Debug("Extracting actions from new state")
	c.extractor.SetCurrentState(newState.ID)
	actions, err := c.extractor.Extract(ctx, page)
	if err != nil {
		zap.L().Debug("Failed to extract actions", zap.Error(err))
		return 0
	}

	c.candidates.AddActions(actions, newState.ID)
	added := len(actions)
	zap.L().Debug("Extracted actions from state", zap.Int("count", added), zap.String("state", newState.Name))

	// NOTE: Frame extraction is already handled by c.extractor.Extract() which
	// recursively processes frames with correct framePath. No separate call needed.

	// Submit any GET forms this newly reached state introduced (a per-route search
	// or filter box), deduped across the crawl so a form present on every page is
	// only fetched once. This state's forms weren't pre-filled, so submitGetForms
	// fills them.
	c.submitGetForms(ctx, page, false)

	// Trigger any POST forms this state introduced (a per-route stock/quote/action
	// form), deduped across the crawl. submitGetForms above just filled the page's
	// forms, so skip a repeat fill.
	c.submitPostForms(ctx, page, true)

	// Fetch any parameterized <a href> links this state introduced (client-rendered
	// category/filter/pagination links), deduped + per-shape capped across the crawl.
	c.primeAnchorLinks(ctx, page)

	// Scrape this state's own comments and inline script for URL-like strings. A
	// route reached mid-crawl frequently injects its own config/endpoint block
	// (a per-section API base, a feature-flagged admin path) that the landing
	// page never carried.
	c.harvestSpeculativeLinks(ctx, page)

	return added
}

// checkOnURLState checks DOM after URL reload and handles state changes.
// 1. newState = stateMachine.newStateFor(browser)
// 2. clone = stateFlowGraph.putIfAbsent(newState)
// 3. if (clone == null): setCurrentState(newState), add to onURLSet
// 4. else: setCurrentState(clone), add clone to onURLSet if not index
// 5. Always try to add reload edge (graph handles duplicate)
func (c *Crawler) checkOnURLState(ctx context.Context, page *browser.Page, previousState *state.State, resetURL string) {
	// Same reason as inspectNewState: this DOM read mints a state identity, so it
	// must not be taken while the reloaded page is still rendering. This path
	// always follows an explicit navigation, so there is no URL to compare
	// against — passing none makes the busy probe the sole gate, which is what
	// keeps a once-per-crawl-loop-iteration call from settling unconditionally.
	c.settleBeforeCapture(ctx, page, "")

	var combinedDOM string
	var err error
	if c.config.CrawlFrames {
		combinedDOM, err = page.HTMLWithFramesFiltered(true, c.config.ExcludeFrames)
	} else {
		combinedDOM, err = page.HTML()
	}
	if err != nil {
		zap.L().Debug("checkOnURLState: failed to get DOM", zap.Error(err))
		return
	}

	// Strip DOM for comparison via the comparator so this state's identity uses
	// the exact same stripping + volatile-content normalization as every other
	// state (otherwise a clock/nonce here would still mint a fresh state, and a
	// config-customized strip set would be ignored on this path).
	strippedDOM := c.comparator.PrepareForComparison(combinedDOM)
	currentURL, _ := page.URL()

	newState := state.New(currentURL, combinedDOM, strippedDOM, 1)

	// checkOnURLState does NOT use switchToStateAndCheckIfClone — it's a direct putIfAbsent.
	isNew := c.graph.AddState(newState)

	if isNew {
		// NEW STATE discovered after URL reload!
		c.candidates.RecordStateCreation(newState.ID)

		// RLCRAWLER PARITY: Register new state with MAB policy
		if c.mabPolicy != nil {
			c.mabPolicy.AddState(newState.ID)
		}

		c.stateMachine.SetCurrentState(newState)

		c.stateMachine.AddToOnURLSet(newState)

		newState.SetOnURL(true)

		zap.L().Debug("checkOnURLState: NEW state discovered after reload", zap.String("state", newState.Name))

		c.extractor.SetCurrentState(newState.ID)
		actions, err := c.extractor.Extract(ctx, page)
		if err == nil && len(actions) > 0 {
			c.candidates.AddActions(actions, newState.ID)
			zap.L().Debug("Extracted actions from new onURL state",
				zap.Int("count", len(actions)),
				zap.String("state", newState.Name))
		}

		c.stats.StatesDiscovered++
	} else {
		// EXISTING STATE (clone)
		existingState, _ := c.graph.GetState(newState.ID)
		if existingState == nil {
			existingState = newState
		}

		c.stateMachine.SetCurrentState(existingState)

		//                         if (!onURLSet.contains(clone)) onURLSet.add(clone)
		if existingState.Name != "index" {
			c.stateMachine.AddToOnURLSet(existingState)
			zap.L().Debug("checkOnURLState: index has changed to", zap.String("state", existingState.Name))
		}
	}

	// Graph.AddEdge() handles duplicate detection via Eventable.Equals()
	if previousState != nil {
		currentState := c.stateMachine.GetCurrentState()
		if currentState != nil {
			c.graph.AddEdge(previousState.ID, currentState.ID, action.NewReloadEventable(resetURL))
			zap.L().Debug("Added reload edge",
				zap.String("from", previousState.Name),
				zap.String("to", currentState.Name))
		}
	}
}

// addFinalReloadEdge adds a reload edge from current state to index when crawl finishes.
// If reset() was called at least once, all intermediate states already have reload edges.
// The final leaf state does NOT get a reload edge because the crawl just terminates.
func (c *Crawler) addFinalReloadEdge() {
	// This handles simple DFS crawls (like SimpleInputSite: index → state, end).
	// For complex crawls where reset() was called, reload edges are already added during processing.
	if c.resetCalled {
		return
	}

	indexState := c.graph.GetIndexState()
	currentState := c.stateMachine.GetCurrentState()
	if indexState == nil || currentState == nil {
		return
	}
	// Only add if we're not already at index
	if currentState.ID == indexState.ID {
		return
	}
	resetURL := c.config.URL.String()
	c.graph.AddEdge(currentState.ID, indexState.ID, action.NewReloadEventable(resetURL))
	zap.L().Debug("Added final reload edge", zap.String("from", currentState.Name), zap.String("to", indexState.Name))
}

// captureState captures the current page state.
// into the DOM so that state changes within iframes are detected.
func (c *Crawler) captureState(ctx context.Context, page *browser.Page, depth int) (*state.State, error) {
	url, err := page.URL()
	if err != nil {
		return nil, err
	}

	// Respects CrawlFrames and ExcludeFrames configuration
	zap.L().Debug("Retrieving HTML",
		zap.Bool("crawl_frames", c.config.CrawlFrames),
		zap.Int("exclude_frames_count", len(c.config.ExcludeFrames)))
	html, err := page.HTMLWithFramesFiltered(c.config.CrawlFrames, c.config.ExcludeFrames)
	if err != nil {
		return nil, err
	}

	rawSize := len(html)
	zap.L().Debug("HTML retrieved", zap.Int("size_bytes", rawSize))

	// Create state (stripping is done internally)
	s := c.comparator.CreateState(url, html, depth)

	strippedSize := len(s.StrippedDOM)
	zap.L().Debug("State created",
		zap.String("state_id", s.ID),
		zap.String("state_name", s.Name),
		zap.String("url", s.URL),
		zap.Int("depth", s.Depth),
		zap.Int("raw_size", rawSize),
		zap.Int("stripped_size", strippedSize))

	return s, nil
}

// shouldTerminate checks if crawl should terminate.
func (c *Crawler) shouldTerminate(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		zap.L().Debug("Context cancelled, terminating")
		return true
	default:
	}

	// The start URL lands on a denied login wall: nothing in scope is reachable,
	// so keep the remaining budget instead of oscillating against the provider.
	if c.startWalled.Load() {
		return true
	}

	// Check max duration. This is a backstop: the caller normally enforces the
	// budget via a context deadline (which also propagates into browser ops via
	// the bound page context), but checking elapsed time here makes MaxDuration
	// meaningful even when the caller passes a context without a deadline, and
	// guarantees the loop stops promptly at the boundary regardless.
	if c.config.MaxDuration > 0 {
		c.mu.Lock()
		start := c.stats.StartTime
		c.mu.Unlock()
		if !start.IsZero() {
			if elapsed := time.Since(start); elapsed >= c.config.MaxDuration {
				zap.L().Debug("Max duration reached, terminating",
					zap.Duration("elapsed", elapsed),
					zap.Duration("max", c.config.MaxDuration))
				return true
			}
		}
	}

	// Check max states
	if c.config.MaxStates > 0 {
		currentStates := c.graph.StateCount()
		if currentStates >= c.config.MaxStates {
			zap.L().Debug("Max states reached",
				zap.Int("current", currentStates),
				zap.Int("max", c.config.MaxStates))
			return true
		}
		zap.L().Debug("State count check",
			zap.Int("current", currentStates),
			zap.Int("max", c.config.MaxStates))
	}

	// Check max consecutive failures
	if c.config.MaxConsecutiveFails > 0 {
		c.mu.Lock()
		consecutiveFails := c.stats.ConsecutiveFailures
		c.mu.Unlock()
		if consecutiveFails >= c.config.MaxConsecutiveFails {
			zap.L().Debug("Max consecutive failures reached",
				zap.Int("current", consecutiveFails),
				zap.Int("max", c.config.MaxConsecutiveFails))
			return true
		}
	}

	return false
}

// sleepWithContext sleeps for duration d but returns early if ctx is cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// isInScope checks if the current page URL is within the crawl scope.
// Returns true if in scope, false if out of scope.
func (c *Crawler) isInScope(page *browser.Page) bool {
	currentURL, err := page.URL()
	if err != nil {
		return false // Can't determine, assume out of scope
	}
	return c.inScopeURL(currentURL)
}

// inScopeURL is the scope decision itself, separated from reading the URL out
// of a live page so it can be exercised without a browser.
func (c *Crawler) inScopeURL(currentURL string) bool {
	// Parsed once and shared by both branches. The wall check used to add a parse
	// of its own on top of the default branch's two (this URL, then a needless
	// re-parse of c.config.URL, which is already a *url.URL).
	u, err := url.Parse(currentURL)
	if err != nil {
		return false // Can't determine, assume out of scope
	}

	// A denied login/SSO wall is out of scope ahead of every other rule,
	// including an explicit operator CrawlScope. See wallHosts.
	if c.isWallHost(u.Hostname()) {
		return false
	}

	if c.config.CrawlScope != nil {
		return c.config.CrawlScope(currentURL)
	}

	// Default: the target host, its subdomains, or an adopted relocation host.
	return c.isTargetHost(u.Hostname())
}

// denyRedirectChainWalls denies every off-target host observed serving an
// authentication endpoint, so an SSO bounce is excluded end to end rather than
// only at the host the browser came to rest on.
//
// The target's own hosts are never denied: a login page on the application
// under test is a legitimate crawl and scan surface. Only somebody else's
// identity provider is excluded, and only once the landing has already been
// classified as a wall — so an ordinary app that happens to serve /login on a
// sibling host is untouched.
func (c *Crawler) denyRedirectChainWalls() {
	if c.observedLoginHosts == nil {
		return
	}
	for _, host := range c.observedLoginHosts() {
		if c.isTargetHost(host) {
			continue
		}
		c.denyWallHost(host)
	}
}

// isTargetHost reports whether host belongs to the target under test (the
// configured target host, one of its subdomains, or an adopted relocation
// host) — the hosts a wall denial must never remove from scope.
func (c *Crawler) isTargetHost(host string) bool {
	host = strings.ToLower(host)
	if host == "" {
		return false
	}
	if c.config != nil && c.config.URL != nil {
		if sameOrSubdomain(host, strings.ToLower(c.config.URL.Hostname())) {
			return true
		}
	}
	return c.adoptedHost != "" && sameOrSubdomain(host, c.adoptedHost)
}

// denyWallHost marks host as a login/SSO wall, putting it out of scope for the
// rest of the crawl. Idempotent and safe for concurrent use.
func (c *Crawler) denyWallHost(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	c.wallHostsMu.Lock()
	defer c.wallHostsMu.Unlock()
	// Lazily allocated despite New initializing it: a Crawler is also built by
	// struct literal in tests, and a nil-map write here would panic rather than
	// fail.
	if c.wallHosts == nil {
		c.wallHosts = make(map[string]bool)
	}
	if c.wallHosts[host] {
		return
	}
	c.wallHosts[host] = true
	c.hasWallHosts.Store(true)
	zap.L().Info("Spidering: login/SSO wall host denied for the rest of the crawl",
		zap.String("host", host))
}

// isWallHost reports whether host has been denied as a login/SSO wall.
//
// The hasWallHosts gate keeps the common case free: a crawl that never hits a
// wall — nearly all of them — answers with one atomic load and never takes the
// lock, and this runs on the per-navigation scope path. Mirrors the hasDynamic
// gate ScopeMatcher.hostInScope uses for the same reason.
func (c *Crawler) isWallHost(host string) bool {
	if !c.hasWallHosts.Load() || host == "" {
		return false
	}
	c.wallHostsMu.RLock()
	defer c.wallHostsMu.RUnlock()
	return c.wallHosts[strings.ToLower(host)]
}

// wallHostList returns the denied wall hosts, sorted for stable reporting.
func (c *Crawler) wallHostList() []string {
	c.wallHostsMu.RLock()
	defer c.wallHostsMu.RUnlock()
	if len(c.wallHosts) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(c.wallHosts))
}

// sameOrSubdomain reports whether host equals base or is a subdomain of it.
func sameOrSubdomain(host, base string) bool {
	if host == "" || base == "" {
		return false
	}
	return host == base || strings.HasSuffix(host, "."+base)
}

// evaluateStartRedirect inspects the index (start) page after the browser has
// followed any initial redirects. When the start URL bounced to a different
// host (a common SSO/login pattern), the default same-host scope would trap the
// crawler on the landing page and yield almost nothing. If that landing is NOT
// a login/SSO wall, we adopt its host into scope so the crawl can proceed
// against the relocated app; login walls are left out of scope (nothing useful
// to crawl unauthenticated) but recorded so the caller can advise on auth.
//
// Only applies under the default host-scope rule — an explicit CrawlScope is
// the operator's own boundary and is never widened here.
func (c *Crawler) evaluateStartRedirect(page *browser.Page, landingURL string) {
	if landingURL == "" {
		return
	}

	landing, err := url.Parse(landingURL)
	if err != nil {
		return
	}
	landHost := strings.ToLower(landing.Hostname())
	tgtHost := strings.ToLower(c.config.URL.Hostname())
	if landHost == "" || tgtHost == "" || sameOrSubdomain(landHost, tgtHost) {
		return // no off-host redirect
	}

	c.stats.OffHostLanding = true
	c.stats.LandingURL = landingURL

	// Whatever the landing turns out to be, the operator's credential headers
	// stop here unless the operator scope admits the new host.
	c.withdrawCredentialHeaders(page, landingURL, landHost)

	// Login/SSO-wall detection runs regardless of scope mode so the caller still
	// gets the "supply --auth" advice and the SSO host is excluded from fuzzing —
	// even under an explicit operator scope.
	if c.landingLooksLikeLogin(page, landing) {
		c.stats.LandingIsLogin = true
		// Deny the wall itself and every authentication hop the browser passed
		// through on the way here. Denial (not just classification) is what stops
		// the crawl: without it the configured scope rule usually still admits
		// these hosts and the crawler spends its budget on the IdP.
		c.denyWallHost(landHost)
		c.denyRedirectChainWalls()
		c.stats.WallHosts = c.wallHostList()
		c.startWalled.Store(true)
		zap.L().Warn("Spidering: start URL redirected to an off-host login wall — stopping the crawl",
			zap.String("target", c.config.URL.String()),
			zap.String("landing", landingURL),
			zap.Strings("denied_hosts", c.stats.WallHosts))
		return
	}

	// Non-login off-host landing: adopt it so the crawl can continue — but ONLY
	// under the default host-scope rule. An explicit CrawlScope is the operator's
	// own boundary and is never widened; if the relocated host is genuinely in
	// scope the CrawlScope filter already admits it, so no adoption is needed.
	if c.config.CrawlScope != nil {
		return
	}
	c.adoptedHost = landHost
	c.stats.HostAdopted = true
	zap.L().Info("Spidering: adopting off-host redirect target into scope",
		zap.String("target", c.config.URL.String()),
		zap.String("landing", landingURL),
		zap.String("adopted_host", landHost))
}

// landingLooksLikeLogin classifies an off-host start-redirect landing as a
// login/SSO wall. A URL that matches a known identity-provider host or a
// login/authorize path is treated as a wall outright; otherwise a visible
// password field on the rendered page is the strongest remaining signal.
func (c *Crawler) landingLooksLikeLogin(page *browser.Page, landing *url.URL) bool {
	if looksLikeLoginURL(landing) {
		return true
	}
	if page == nil {
		return false
	}
	// A visible password field is the strongest remaining login signal. Eval
	// runs a JS expression and returns the value by-value; treat any error or
	// non-true result as "not a login page" so a flaky probe never blocks a
	// crawl we'd otherwise proceed with.
	val, err := page.Eval(`(function(){return !!document.querySelector('input[type=password]')})()`)
	if err != nil {
		return false
	}
	hasPassword, _ := val.(bool)
	return hasPassword
}

// looksLikeLoginURL reports whether u points at an authentication endpoint,
// based on its host and path/query alone (no page load required). The
// signature tables live in pkg/authsig so other phases (e.g. the
// targeted re-spider candidate screen) share one source of truth.
func looksLikeLoginURL(u *url.URL) bool {
	return authsig.LooksLikeLoginURL(u)
}

// visitAnchorHref navigates directly to an anchor's href URL.
// Used when crawlHiddenAnchors is enabled and clicking a hidden anchor fails.
func (c *Crawler) visitAnchorHref(page *browser.Page, href string) error {
	// Resolve relative URL against current page URL
	currentURL, err := page.URL()
	if err != nil {
		return fmt.Errorf("failed to get current URL: %w", err)
	}

	// Parse and resolve the href
	baseURL, err := url.Parse(currentURL)
	if err != nil {
		return fmt.Errorf("failed to parse current URL: %w", err)
	}

	hrefURL, err := url.Parse(href)
	if err != nil {
		return fmt.Errorf("failed to parse href: %w", err)
	}

	// Resolve relative URL
	resolvedURL := baseURL.ResolveReference(hrefURL)

	zap.L().Debug("Navigating to anchor href", zap.String("url", resolvedURL.String()))
	return page.Navigate(resolvedURL.String())
}

// shouldCrawl checks if page should be crawled based on conditions.
func (c *Crawler) shouldCrawl(page *browser.Page) bool {
	if len(c.crawlConditions) == 0 {
		return true
	}

	for _, cond := range c.crawlConditions {
		if !cond.Check(page) {
			return false
		}
	}

	return true
}

// maxWaitConditionFailures caps the failing selectors kept in Stats.
const maxWaitConditionFailures = 5

// checkWaitConditions applies wait conditions to the page and returns how many
// timed out. Each timeout is counted in Stats.WaitConditionsFailed (with the
// selector, up to maxWaitConditionFailures distinct ones) so a run that never
// met a readiness condition says so instead of reading as an empty site. A
// condition whose URL does not match, or a cancelled crawl, is not a failure.
func (c *Crawler) checkWaitConditions(ctx context.Context, page *browser.Page) int {
	failed := 0
	for _, wc := range c.waitConditions {
		if wc.Wait(ctx, page) != condition.WaitTimeout {
			continue
		}
		failed++
		c.recordWaitConditionFailure(wc.Selector)
	}
	return failed
}

// recordWaitConditionFailure counts one timed-out readiness condition.
func (c *Crawler) recordWaitConditionFailure(selector string) {
	zap.L().Warn("Wait condition timed out", zap.String("selector", selector))
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.WaitConditionsFailed++
	if len(c.stats.WaitConditionFailures) < maxWaitConditionFailures && !slices.Contains(c.stats.WaitConditionFailures, selector) {
		c.stats.WaitConditionFailures = append(c.stats.WaitConditionFailures, selector)
	}
}

// getInputElements merges related form inputs with DOM-detected inputs.
//  1. Start with eventable.getRelatedFormInputs() (inputs linked to this action)
//  2. Add the inputs detected on the current DOM that belong to the action's
//     own form (see mergeActionInputs) — an action never edits a form it
//     cannot submit
//  3. Remove duplicates (based on Identification)
//  4. Order by FormFillOrder (NORMAL, DOM, VISUAL) - not implemented yet
//
// Returns DetectedInput for Go extension (value rotation, detection metadata).
func (c *Crawler) getInputElements(page *browser.Page, eventable *action.Eventable) []*form.DetectedInput {
	// Step 1: Start with related inputs from eventable
	related := make([]*form.DetectedInput, 0)
	for _, actionInput := range eventable.GetRelatedFormInputs() {
		if detected := form.FromFormInput(actionInput); detected != nil {
			related = append(related, detected)
		}
	}

	// Step 2: Merge with the DOM inputs of the action's own form. The owning
	// form is resolved in the same page evaluation as the inputs, so both sides
	// of the comparison come from one DOM snapshot.
	actionXPath := ""
	if id := eventable.Identification; id != nil && id.How == action.HowXPath {
		actionXPath = id.Value
	}
	domInputs, actionForm, _ := c.formHandler.DetectInputsForAction(page, actionXPath)
	formInputs, excluded := c.mergeActionInputs(related, domInputs, actionForm)

	zap.L().Debug("Changing related inputs",
		zap.Int64("eventable_id", eventable.ID),
		zap.Int("existing", len(related)),
		zap.Int("merged", len(formInputs)-len(related)),
		zap.Int("excluded_other_forms", excluded),
		zap.String("action_form", actionForm),
		zap.Int("total", len(formInputs)))

	// TODO: Step 3 - Order by FormFillOrder (VISUAL ordering)
	// For now, use DOM order (default)

	return formInputs
}

// mergeActionInputs appends to related every DOM input the action could submit
// and returns the merged list plus how many DOM inputs were left out because
// they belong to a different form.
//
// When the action sits inside a form (actionForm != ""), only that form's
// controls are merged: clicking form A's submit button must not edit form B,
// nor the orphan controls around it. When the action is outside any form — a
// plain link, or an SPA "form" built from orphan inputs and a script-driven
// button — every DOM input is merged, as before form scoping existed: there is
// no owning form to scope by, and SPA login/registration flows depend on it.
func (c *Crawler) mergeActionInputs(related, dom []*form.DetectedInput, actionForm string) ([]*form.DetectedInput, int) {
	merged := related
	excluded := 0
	for _, domInput := range dom {
		if actionForm != "" && domInput.FormKey != actionForm {
			excluded++
			continue
		}
		exists := false
		for _, existing := range merged {
			if c.detectedInputEquals(existing, domInput) {
				exists = true
				break
			}
		}
		if !exists {
			merged = append(merged, domInput)
		}
	}
	return merged, excluded
}

// detectedInputEquals checks if two detected inputs are equal based on Identification.
func (c *Crawler) detectedInputEquals(a, b *form.DetectedInput) bool {
	if a == nil || b == nil || a.FormInput == nil || b.FormInput == nil {
		return false
	}

	// Compare by Identification first
	if a.Identification != nil && b.Identification != nil {
		return a.Identification.How == b.Identification.How &&
			a.Identification.Value == b.Identification.Value
	}

	// Fallback: compare by ID or Name (from DetectedInput metadata)
	if a.ID != "" && a.ID == b.ID {
		return true
	}
	if a.Name != "" && a.Name == b.Name {
		return true
	}

	return false
}

// handleInputElements fills form inputs and returns the handled list.
//  1. List<FormInput> formInputs = getInputElements(eventable);
//  2. return formHandler.handleFormElements(formInputs);
//
// Returns action.FormInput (used in candidates cache).
func (c *Crawler) handleInputElements(page *browser.Page, eventable *action.Eventable) []*action.FormInput {
	formInputs := c.getInputElements(page, eventable)
	return c.formHandler.HandleFormElements(page, formInputs)
}

// fillFormsIfPresent detects and fills forms on the page.
// If actionID is provided, caches the form inputs for reuse.
func (c *Crawler) fillFormsIfPresent(page *browser.Page, actionID string) []*action.FormInput {
	// Check if we have cached inputs for this action
	if actionID != "" {
		if cached, ok := c.formCache[actionID]; ok && len(cached) > 0 {
			zap.L().Debug("Using cached form inputs for action", zap.String("action_id", actionID))
			result := c.formHandler.FillInputs(page, cached)
			if result.HasErrors() {
				zap.L().Debug("Form fill had failures", zap.Int("failed", result.Failed), zap.Int("total", len(cached)))
			}
			// Return as action.FormInput
			return form.ToFormInputs(cached)
		}
	}

	inputs, err := c.formHandler.DetectInputs(page)
	if err != nil {
		return nil
	}

	if len(inputs) > 0 {
		// The trainer keys values by page origin and owning form, so a value
		// learned on one origin is never replayed into another's form.
		origin := ""
		if c.formTrainer != nil {
			if u, uerr := page.URL(); uerr == nil {
				origin = httpmsg.OriginFromURL(u)
			}
		}

		// Form trainer replay mode: use trained inputs
		if c.formTrainer != nil && c.formTrainer.GetMode() == form.FillReplay {
			for _, input := range inputs {
				inputType := ""
				if input.FormInput != nil {
					inputType = string(input.Type)
				}
				trained := c.formTrainer.MatchInput(input.XPath, input.ID, input.Name, inputType, origin, input.FormKey)
				if trained != nil && trained.Value != "" {
					input.SetValues([]string{trained.Value})
				}
			}
		}

		zap.L().Debug("Found form inputs, filling...", zap.Int("count", len(inputs)))

		// This returns list with XPath-based identification for backtracking
		handled := c.formHandler.HandleFormElements(page, inputs)

		// Check if we have failures by comparing handled vs inputs
		if len(handled) < len(inputs) {
			zap.L().Debug("Normal form fill had failures, trying pairwise",
				zap.Int("handled", len(handled)),
				zap.Int("total", len(inputs)))
			success, worked := c.formHandler.FillInputsPairwise(page, inputs)
			if success && len(worked) > 0 {
				zap.L().Debug("Pairwise form fill succeeded", zap.Int("worked", len(worked)))
				// Update inputs with worked inputs for caching
				inputs = worked
				handled = form.ToFormInputs(worked)
			} else {
				zap.L().Debug("Pairwise form fill also failed")
			}
		}

		// Form trainer training mode: record inputs from DetectedInput (has metadata)
		if c.formTrainer != nil && (c.formTrainer.GetMode() == form.FillTraining || c.formTrainer.GetMode() == form.FillXPathTraining) {
			for _, input := range inputs {
				value := ""
				values := input.GetValues()
				if len(values) > 0 {
					value = values[0]
				}
				inputType := ""
				if input.FormInput != nil {
					inputType = string(input.Type)
				}
				c.formTrainer.RecordInput(&form.TrainedInput{
					XPath:   input.XPath,
					Type:    inputType,
					Name:    input.Name,
					ID:      input.ID,
					Value:   value,
					Values:  values,
					Origin:  origin,
					FormKey: input.FormKey,
				})
			}
		}

		// Cache the DetectedInput for this action (has metadata for value rotation)
		if actionID != "" {
			c.formCache[actionID] = inputs
		}

		return handled
	}

	return nil
}

// fillFormsWithInputs fills forms using cached action.FormInput data.
func (c *Crawler) fillFormsWithInputs(page *browser.Page, inputs []*action.FormInput) {
	for _, formInput := range inputs {
		if formInput.Identification == nil {
			continue
		}

		selector := formInput.Identification.Value
		if selector == "" {
			continue
		}

		// Get value to fill
		var value string
		if len(formInput.InputValues) > 0 {
			value = formInput.InputValues[0].Value
		}

		if value == "" {
			continue
		}

		// Fill the input by finding element based on selector type
		var elem *browser.Element
		var err error
		isXPath := formInput.Identification.How == action.HowXPath
		if isXPath {
			elem, err = page.ElementX(selector)
		} else {
			elem, err = page.Element(selector)
		}
		if err != nil {
			zap.L().Debug("Failed to find cached form input element",
				zap.String("selector", selector),
				zap.Bool("is_xpath", isXPath),
				zap.Error(err))
			continue
		}
		if err := elem.Input(value); err != nil {
			zap.L().Debug("Failed to fill cached form input",
				zap.String("selector", selector),
				zap.Error(err))
		} else {
			zap.L().Debug("Filled cached form input",
				zap.String("selector", selector),
				zap.String("value", value))
		}
	}
}

// navigateToFrame navigates to a specific frame by its path (e.g., "frame1.frame2").
// Returns the Page object for the target frame.
func (c *Crawler) navigateToFrame(page *browser.Page, framePath string) (*browser.Page, error) {
	if framePath == "" {
		return page, nil
	}

	// Split frame path into segments
	segments := strings.Split(framePath, ".")
	currentPage := page

	for _, segment := range segments {
		frameInfos, err := currentPage.FramesWithInfo()
		if err != nil {
			return nil, fmt.Errorf("failed to get frames: %w", err)
		}

		found := false
		for _, fi := range frameInfos {
			// Get frame identifier (FramesWithInfo already uses id before name)
			frameID := fi.ID
			if frameID == "" {
				frameID = fmt.Sprintf("frame%d", fi.Index)
			}
			if frameID == segment {
				currentPage = fi.Page
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("frame %q not found", segment)
		}
	}

	return currentPage, nil
}

// extractFragments extracts fragments from the page.
// Uses the configured fragmentation mode: landmark (default, fast) or vips.
func (c *Crawler) extractFragments(page *browser.Page, s *state.State) {
	var frags []*fragment.Fragment
	var err error

	switch c.config.FragmentationMode {
	case config.FragmentationVIPS:
		vips := fragment.NewVIPS().
			WithPDoC(c.config.VIPSPDoC).
			WithIterations(c.config.VIPSIterations)
		frags, err = vips.Extract(page)
	default: // config.FragmentationLandmark or empty
		extractor := fragment.NewExtractor()
		frags, err = extractor.Extract(page)
	}

	if err != nil {
		zap.L().Debug("Failed to extract fragments", zap.Error(err))
		return
	}

	c.fragManager.AddFragments(s.ID, frags)
	zap.L().Debug("Extracted fragments from state", zap.Int("count", len(frags)), zap.String("state", s.Name), zap.String("mode", string(c.config.FragmentationMode)))
}

// buildResult builds the crawl result.
func (c *Crawler) buildResult(ctx context.Context) *Result {
	if c.crawlPath != nil {
		c.crawlPath.Close()
		c.session.AddCrawlPath(c.crawlPath.ImmutableCopy())
	}
	if c.session != nil {
		c.session.MarkEnd()
	}

	res := &Result{
		Config:    c.config,
		Graph:     c.graph,
		Fragments: c.fragManager.GetStats(),
		Session:   c.session,
	}

	// Harvest the browser session (cookies + UA) while the browser is still
	// alive — buildResult runs before the deferred pool.Close() in Run. Failures
	// are non-fatal: the crawl already succeeded, we just can't carry the session.
	if c.browser != nil {
		res.BrowserUserAgent = c.browser.UserAgent()
		if cookies, err := c.browser.HarvestCookies(); err != nil {
			zap.L().Debug("Failed to harvest browser cookies for session carry-forward", zap.Error(err))
		} else {
			res.HarvestedCookies = cookies
		}
	}
	// Carry a token-auth session credential harvested during a confirmed login spray.
	c.mu.Lock()
	res.HarvestedAuthorization = c.harvestedAuth
	c.mu.Unlock()

	// Confirm DOM-based XSS on reflected client routes the crawl visited. Runs last
	// (it navigates the browser) and only after a cheap no-navigation prefilter finds
	// a reflected parameter, so it never spins up navigations blindly. Skips entirely
	// when ctx is already cancelled and budgets itself from the remaining parent
	// deadline, so it can't keep hitting the target after the operator stops the scan.
	res.DOMXssFindings = c.probeDOMXSS(ctx)

	// Stamp the end time only now, after every post-pass, and copy stats into the
	// immutable Result under the lock. The outer Run/RunOnBrowser defer also sets
	// EndTime, but it runs after this Result is built and copies c.stats by value,
	// so without stamping here Result.Stats.EndTime stays zero and Result.Duration()
	// underflows to a huge negative value.
	c.mu.Lock()
	c.stats.EndTime = time.Now()
	res.Stats = c.stats
	c.mu.Unlock()

	return res
}

// Stats returns current statistics.
func (c *Crawler) GetStats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// IsRunning returns true if crawler is running.
func (c *Crawler) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// Graph returns the state graph.
func (c *Crawler) Graph() *state.Graph {
	return c.graph
}

// formHandlerAdapter adapts EventableConditionChecker to action.FormHandler interface.
type formHandlerAdapter struct {
	checker *condition.EventableConditionChecker
}

// GetCandidateElementsForInputs implements action.FormHandler.
func (a *formHandlerAdapter) GetCandidateElementsForInputs(elementXPath string, baseCandidate *action.CandidateElement) []*action.CandidateElement {
	if a.checker == nil || a.checker.Count() == 0 {
		return []*action.CandidateElement{baseCandidate}
	}
	return a.checker.GetCandidateElementsForInputs(elementXPath, baseCandidate)
}

// GetFormInputs implements action.FormHandler.
// Returns all form inputs from the EventableConditions.
func (a *formHandlerAdapter) GetFormInputs() []*action.FormInput {
	if a.checker == nil {
		return nil
	}
	return a.checker.GetFormInputs()
}

// HandleFormElements implements action.FormHandler.
// This is a no-op in this adapter as form filling is handled elsewhere.
func (a *formHandlerAdapter) HandleFormElements(formInputs []*action.FormInput) []*action.FormInput {
	return formInputs
}

// recordMetrics records step metrics to the metrics collector.
// Called only when metricsCollector is set (benchmark mode).
func (c *Crawler) recordMetrics(crawlAction *action.CandidateCrawlAction, succeeded, stateDiscovered, formSubmitted bool, newActionsCount int) {
	// Get action ID from identification
	actionID := ""
	if crawlAction != nil && crawlAction.GetCandidateElement() != nil {
		ident := crawlAction.GetCandidateElement().GetIdentification()
		if ident != nil {
			actionID = ident.Value
		}
	}

	// Build step context
	ctx := &metrics.StepContext{
		ActionID:        actionID,
		ActionSucceeded: succeeded,
		StateDiscovered: stateDiscovered,
		FormSubmitted:   formSubmitted,
	}

	// Set reward based on new actions discovered
	ctx.RewardEnv = float64(newActionsCount)

	// Extract links from current page for link coverage
	if c.browser != nil {
		if page := c.browser.CurrentPage(); page != nil {
			links := c.extractLinksFromPage(page)
			ctx.NewLinks = links
		}
	}

	// Record to collector
	if err := c.metricsCollector.OnStepComplete(ctx); err != nil {
		zap.L().Warn("Failed to record metrics", zap.Error(err))
	}
}

// extractLinksFromPage extracts all links from the current page for metrics tracking.
func (c *Crawler) extractLinksFromPage(page *browser.Page) []string {
	if page == nil {
		return nil
	}

	// Use the page's current URL as base
	baseURL, err := page.URL()
	if err != nil || baseURL == "" {
		return nil
	}

	// Extract all anchor hrefs as JSON array
	result, err := page.Eval(`(() => {
		const links = [];
		const anchors = document.querySelectorAll('a[href]');
		for (const a of anchors) {
			const href = a.getAttribute('href');
			if (href && !href.startsWith('javascript:') && !href.startsWith('#')) {
				try {
					const url = new URL(href, window.location.href);
					links.push(url.href);
				} catch (e) {
					// Invalid URL, skip
				}
			}
		}
		return JSON.stringify(links);
	})()`)
	if err != nil {
		return nil
	}

	// Parse result as JSON string
	jsonStr, ok := result.(string)
	if !ok || jsonStr == "" || jsonStr == "<nil>" {
		return nil
	}

	// Parse JSON array
	var links []string
	if err := parseJSONLinks(jsonStr, &links); err != nil {
		return nil
	}

	return links
}

// parseJSONLinks parses a JSON array string into a slice of strings.
func parseJSONLinks(jsonStr string, links *[]string) error {
	// Simple JSON array parsing (avoid importing encoding/json for this)
	// Format: ["url1", "url2", ...]
	if len(jsonStr) < 2 || jsonStr[0] != '[' || jsonStr[len(jsonStr)-1] != ']' {
		return fmt.Errorf("invalid JSON array")
	}

	// Empty array
	if jsonStr == "[]" {
		return nil
	}

	// Remove brackets
	inner := jsonStr[1 : len(jsonStr)-1]

	// Split by comma (simple approach, doesn't handle escaped quotes)
	inQuote := false
	start := 0
	for i := 0; i < len(inner); i++ {
		if inner[i] == '"' {
			inQuote = !inQuote
		} else if inner[i] == ',' && !inQuote {
			s := strings.TrimSpace(inner[start:i])
			if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
				*links = append(*links, s[1:len(s)-1])
			}
			start = i + 1
		}
	}

	// Last element
	s := strings.TrimSpace(inner[start:])
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		*links = append(*links, s[1:len(s)-1])
	}

	return nil
}
