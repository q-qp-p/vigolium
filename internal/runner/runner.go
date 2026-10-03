package runner

import (
	"context"
	stderrors "errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/wsdl"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/notify"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/useragent"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// maxFeedbackRounds limits re-scanning of newly discovered URLs in the dynamic-assessment phase.
const maxFeedbackRounds = 1

// secretScanBatchSize is the number of records per batch when scanning response bodies for secrets.
const secretScanBatchSize = 500

// Runner is a client for running the enumeration process.
type Runner struct {
	output            output.Writer
	options           *types.Options
	settings          *config.Settings
	inputSource       source.InputSource
	dedupManager      *dedup.Manager
	repository        *database.Repository // Optional: database storage
	heuristicsResults map[string]*HeuristicsResult
	spidering         spideringOutcome // cross-phase signals captured after Spidering (drives Discovery auto-fuzz)
	// browserSessions holds WAF/bot-cleared sessions harvested by the spidering
	// browser, keyed by lowercased hostname. Populated after Spidering (when
	// Options.CarryBrowserSession is on) and consumed by Discovery
	// (buildDeparosConfig) and the shared scan requester so later phases inherit
	// the cleared session. Nil when spidering did not run or carrying is disabled.
	browserSessions   map[string]httpmsg.CarriedSession
	autoFuzzDiscovery bool                 // set by runDiscoveryPhase when low-yield/SSO auto-enables FUZZ fuzzing
	scanLogger        *database.ScanLogger // Optional: structured scan logging
	teeWriter         *teeWriter           // Optional: captures stderr for trace logging
	sessionLogFile    *os.File             // Optional: runtime.log handle for verbose file-only writes
	sessionLogMu      sync.Mutex           // serializes concurrent writes to sessionLogFile
	sharedInfra       *SharedInfra         // Optional: pre-built infrastructure for reuse across rescans

	ctx       context.Context       // cancellable context for graceful shutdown
	cancel    context.CancelFunc    // cancels ctx to signal workers to stop
	done      chan struct{}         // closed when RunNativeScan finishes
	pauseCtrl *core.PauseController // cooperative pause/resume for workers

	closeOnce sync.Once   // guards one-time resource release (Close/Discard may race)
	finalized atomic.Bool // set once RunNativeScan has written the terminal scan status

	// currentPhase is the outcome ledger and event tracker for the phase running
	// right now, or nil between phases. Findings arrive on worker goroutines that
	// know nothing about phases, so the phase they belong to is read from here
	// rather than threaded through every module callback. Atomic because the
	// phase loop swaps it while those workers are still draining.
	currentPhase atomic.Pointer[phaseTracker]

	// scanOutcome collects the per-phase outcomes this scan produced, which the
	// finalizer persists on the scan row and the terminal banner reads. Reset at
	// the top of RunNativeScan; see scanOutcome.
	scanOutcome scanOutcome
}

// Finalized reports whether RunNativeScan already wrote the scan's terminal
// status. The API server uses this so its safety-net CompleteScan only runs when
// the runner never reached its finalizer (e.g. infrastructure setup failed),
// avoiding a second write that would clobber the runner's truthful outcome.
func (r *Runner) Finalized() bool {
	return r.finalized.Load()
}

// spideringOutcome captures cross-phase signals from the Spidering phase that
// later phases consult. Currently it drives the Discovery phase's low-yield
// auto-fuzz decision: when spidering finds little (or bounces off-host to an
// SSO/login wall), Discovery auto-enables FUZZ fuzzing on the original target.
type spideringOutcome struct {
	ran      bool     // spidering actually executed (vs skipped / not in plan)
	records  int      // total records saved across all spidered targets
	lost     int      // records the capture admitted but failed to persist
	complete bool     // every capture receipt was complete (nothing lost, drains finished)
	sawSSO   bool     // at least one target redirected off-host to a login wall
	ssoHosts []string // the off-host login/SSO hosts (excluded from fuzzing scope)
}

// phaseInfra holds shared resources across all scan phases.
type phaseInfra struct {
	svc           *services.Services
	httpRequester *http.Requester
	scopeMatcher  *config.ScopeMatcher
	hostLimiter   *hostlimit.HostRateLimiter
	notifier      *notify.Manager
	hookChain     *jsext.HookChain
	jsEngine      *jsext.Engine
	scanUUID      string

	// borrowedInfra marks this phaseInfra as holding components OWNED by a
	// SharedInfra (reused across rescans) rather than built for this phase. A
	// borrower must not close them: the shared limiter would be stopped — and its
	// shard maps nilled — out from under the next rescan that borrows the same
	// instance, and a second Close on it is a "close of closed channel" panic.
	borrowedInfra bool

	// Multi-session support for IDOR/BOLA testing
	compareSessions []compareSession

	// assessmentHeaders carries the primary session's credential headers for the
	// phases that assess (dynamic-assessment, known-issue-scan) WITHOUT putting
	// them on httpRequester, which discovery and spidering share. It is set only
	// under session.use_in_discovery: false, whose documented meaning is "keep the
	// credentials out of discovery" — not "do not authenticate at all", which is
	// what happened before: the headers were resolved, dropped on the floor, and
	// the assessment ran anonymously against an authenticated-only app.
	// Empty under use_in_discovery: true, where the headers are already on the
	// shared requester and on r.options.Headers.
	assessmentHeaders []string

	// authFailureReason records that session initialization failed and the scan is
	// continuing without it (an explicitly configured auth with --auth-best-effort,
	// or a DB-sourced session), as the outcome code naming WHY — a login that was
	// cancelled, one that outlived the login budget, or any other failure. The
	// assessment phases report it so a wall of 401s is attributable instead of
	// looking like an unauthenticated app.
	//
	// Non-empty IS the "auth unavailable" fact: authFailureReason() always
	// classifies a failure into some code, so a separate bool would only be
	// another name for this field being set.
	authFailureReason string
}

// compareSession pairs a named session with its dedicated HTTP requester.
type compareSession struct {
	Name     string
	Client   *http.Requester
	Hostname string // hostname this session is associated with (empty = all hosts)
}

// Close releases infrastructure resources this phase OWNS. Components borrowed
// from a SharedInfra are left alone; their owner closes them.
func (p *phaseInfra) Close() {
	if p.borrowedInfra {
		return
	}
	// Return idle sockets before dropping the requester. This phase owns it
	// (borrowedInfra is false), so nothing else is still reading through its
	// transport. Compare-session requesters are separate owners with their own
	// pools and are released alongside it.
	p.httpRequester.CloseIdleConnections()
	for _, cs := range p.compareSessions {
		cs.Client.CloseIdleConnections()
	}
	if p.hostLimiter != nil {
		_ = p.hostLimiter.Close()
	}
	if p.notifier != nil {
		p.notifier.Close()
	}
}

// SharedInfra holds reusable infrastructure components that can be shared across
// multiple scan runs (e.g., rescans in agent swarm mode). This avoids rebuilding
// expensive resources like HTTP requesters and scope matchers for each rescan.
type SharedInfra struct {
	HTTPRequester *http.Requester
	ScopeMatcher  *config.ScopeMatcher
	HostLimiter   *hostlimit.HostRateLimiter
	Services      *services.Services
	JSEngine      *jsext.Engine
	HookChain     *jsext.HookChain
}

// Close releases resources held by SharedInfra.
func (s *SharedInfra) Close() {
	// The shared requester outlives individual scans (that is the point of
	// SharedInfra), so its pool is only released when the sharer itself is done.
	s.HTTPRequester.CloseIdleConnections()
	if s.HostLimiter != nil {
		_ = s.HostLimiter.Close()
	}
}

// effectiveRateLimit is the single source of truth for the scan's global
// requests-per-second cap: whatever is on Options, clamped to a non-negative
// value. Both the limiter that enforces the cap and every surface that reports it
// (the Speed banner line, the config snapshot) must read it from here.
//
// They used to disagree. The limiter was built from Options.RateLimit while the
// banner and the snapshot printed settings.ScanningPace.RateLimit, so a scan
// could advertise one rate and run at another — most visibly when a scanning
// profile set a pace the CLI flag had already overridden.
func effectiveRateLimit(opts *types.Options) int {
	if opts == nil || opts.RateLimit < 0 {
		return 0
	}
	return opts.RateLimit
}

// buildScanRateLimiter returns a global requests-per-second token bucket for the
// scan, or nil when no explicit --rate-limit was set (perSec <= 0) so default
// scans keep their current throughput. Burst equals the rate so a fresh scan can
// send up to one second's worth immediately, then settles to the steady cap.
func buildScanRateLimiter(perSec int) *rate.Limiter {
	if perSec <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Limit(perSec), perSec)
}

// BuildSharedInfra creates a SharedInfra from the given options and settings.
// It extracts the reusable portions of buildInfrastructure.
func BuildSharedInfra(opts *types.Options, settings *config.Settings, repo *database.Repository) (*SharedInfra, error) {
	infra := &SharedInfra{}

	svc := &services.Services{
		Options:     opts,
		RateLimiter: buildScanRateLimiter(effectiveRateLimit(opts)),
	}

	if opts.ShouldUseHostError() {
		cache := hosterrors.New(
			opts.MaxHostError,
			hosterrors.DefaultMaxHostsCount,
			[]string{},
		)
		cache.SetVerbose(opts.Verbose)
		svc.HostErrors = cache
	}

	maxPerHost := opts.MaxPerHost
	if opts.MaxPerHostExplicitlySet {
		// An explicit -c/--max-per-host wins outright; otherwise newHostLimiter
		// falls back to the common scanning_pace value.
		maxPerHost = max(maxPerHost, 1)
	} else {
		maxPerHost = 0
	}
	hostLimiter := newHostLimiter(maxPerHost, settings, opts.NoWafPacing)
	svc.HostLimiter = hostLimiter
	infra.HostLimiter = hostLimiter
	infra.Services = svc

	var errs []error

	httpRequester, err := http.NewRequester(opts, svc)
	if err != nil {
		zap.L().Warn("Failed to create HTTP requester for SharedInfra", zap.Error(err))
		errs = append(errs, fmt.Errorf("could not create http requester: %w", err))
	} else {
		infra.HTTPRequester = httpRequester
	}

	if settings != nil {
		infra.ScopeMatcher = config.NewScopeMatcher(settings.Scope, opts.Targets...)
	}

	if settings != nil && settings.DynamicAssessment.Extensions.Enabled {
		jsEngineOpts := &jsext.EngineOptions{
			ScanUUID:   opts.ScanUUID,
			Repository: repo,
			LLMClient:  extensionLLMClient(settings),
		}
		if settings != nil {
			scopeCfg := settings.Scope
			jsEngineOpts.ScopeConfig = &scopeCfg
			jsEngineOpts.ScopeMatcher = config.NewScopeMatcher(settings.Scope, opts.Targets...)
		}
		jsEngine, jsErr := jsext.NewEngine(&settings.DynamicAssessment.Extensions, httpRequester, jsEngineOpts)
		if jsErr != nil {
			zap.L().Warn("Failed to initialize JS extensions for SharedInfra", zap.Error(jsErr))
			errs = append(errs, fmt.Errorf("could not create js engine: %w", jsErr))
		} else {
			infra.JSEngine = jsEngine
			preHooks := jsEngine.PreHooks()
			postHooks := jsEngine.PostHooks()
			if len(preHooks) > 0 || len(postHooks) > 0 {
				infra.HookChain = jsext.NewHookChain(preHooks, postHooks)
			}
		}
	}

	if len(errs) > 0 {
		return infra, fmt.Errorf("partial SharedInfra (%d failures): %w", len(errs), stderrors.Join(errs...))
	}
	return infra, nil
}

// SetSharedInfra allows the runner to reuse pre-built infrastructure instead of building fresh.
func (r *Runner) SetSharedInfra(infra *SharedInfra) {
	r.sharedInfra = infra
}

// New creates a new client for running the enumeration process.
func New(options *types.Options) (*Runner, error) {
	// Ahead of the input source, which is built from the same slice.
	normalizeTargetSchemes(options)

	inputSource, err := source.NewInputSource(source.SourceConfig{
		Targets:               options.Targets,
		FilePaths:             options.TargetsFilePaths,
		Format:                options.InputFileMode,
		UseStdin:              options.Stdin,
		SkipFormatValidation:  options.SkipFormatValidation,
		FormatUseRequiredOnly: options.FormatUseRequiredOnly,
		BufferSize:            100,
		EnableModules:         options.Modules,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create input source")
	}

	// Configure spec-format options on the file parser. FirstFileSource unwraps a
	// MultiSource so the override lands when targets/-t are combined with a file,
	// and covers a content-sniffed .wsdl (resolved parser type, not the format
	// string). The -t target is the OpenAPI BaseURL / WSDL endpoint host override.
	if fs := source.FirstFileSource(inputSource); fs != nil {
		switch parser := fs.Format().(type) {
		case *openapi.Format:
			oaOpts := openapi.Options{
				BaseURL:              options.OpenAPIBaseURL,
				UseSpecServers:       options.OpenAPIUseSpecServers,
				Headers:              parseHeaders(options.SpecHeaders),
				Variables:            parseVariables(options.OpenAPIVariables),
				DefaultFallbackValue: options.OpenAPIDefaultParam,
			}
			// Load field type defaults from config
			if cfg, err := config.LoadSettings(options.ConfigPath); err == nil {
				oaOpts.FieldTypeDefaults = cfg.MutationStrategy.FieldTypeDefaults.ToMap()
			}
			parser.SetOpenAPIOptions(oaOpts)
		case *wsdl.Format:
			parser.SetWSDLOptions(wsdl.Options{
				EndpointURL: options.OpenAPIBaseURL,
				Headers:     parseHeaders(options.SpecHeaders),
				Variables:   parseVariables(options.OpenAPIVariables),
			})
		}
	}

	return NewWithInputSource(options, inputSource)
}

// parseHeaders parses header strings in "Name: Value" format.
func parseHeaders(headers []string) map[string]string {
	result := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// parseVariables parses variable strings in "key=value" format.
func parseVariables(variables []string) map[string]string {
	result := make(map[string]string)
	for _, v := range variables {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// NewWithInputSource creates a new Runner with a custom InputSource.
// Used by server mode to provide queue-based input.
func NewWithInputSource(options *types.Options, inputSource source.InputSource) (*Runner, error) {
	normalizeTargetSchemes(options)

	if err := network.Init(options); err != nil {
		return nil, errors.Wrap(err, "failed to initialize network")
	}

	outputWriter, err := output.NewStandardWriter(options)
	if err != nil {
		// No Runner is returned, so nothing will ever call releaseResources for
		// this attempt: hand back both references here or a bad -o path leaks
		// the shared dialer and strands this run's scratch until it ages out.
		network.Close()
		return nil, errors.Wrap(err, "could not create output file")
	}

	setupUserAgents()

	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{
		options:      options,
		inputSource:  inputSource,
		output:       outputWriter,
		dedupManager: dedup.NewManager(),
		ctx:          ctx,
		cancel:       cancel,
		done:         make(chan struct{}),
		pauseCtrl:    core.NewPauseController(),
	}, nil
}

// setupUserAgentsOnce guards the one-time write to the package-global
// useragent.UserAgents slice. Every runner construction called it, racing the
// shared global against concurrent request setup; the picked set is effectively
// constant, so initialize it exactly once.
var setupUserAgentsOnce sync.Once

// setupUserAgents initializes global user agents for HTTP requests (once).
func setupUserAgents() {
	setupUserAgentsOnce.Do(func() {
		filters := []useragent.Filter{useragent.Windows}
		userAgents, err := useragent.PickWithFilters(30, filters...)
		if err != nil {
			zap.L().Error("Error picking user agent", zap.Error(err))
			userAgents = []*useragent.UserAgent{
				{
					Raw:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
					Tags: []string{"Chrome"},
				},
			}
		}
		useragent.UserAgents = userAgents
	})
}

// Close cancels the run, waits (bounded) for RunNativeScan to finish, then
// releases resources. Safe to call concurrently and repeatedly — a stop handler
// and the background-completion path can both call it, so the resource release
// (which decrements the process-global network dialer refcount) is guarded by
// sync.Once to avoid a double teardown of the shared dialer.
func (r *Runner) Close() {
	// Resume if paused — workers must unblock before they can see context cancellation
	if r.pauseCtrl != nil && r.pauseCtrl.IsPaused() {
		r.pauseCtrl.Resume()
	}

	// Signal cancellation to all workers first
	if r.cancel != nil {
		r.cancel()
	}

	// Wait for RunNativeScan to finish (with configurable timeout)
	if r.done != nil {
		shutdownTimeout := r.options.ShutdownTimeout
		if shutdownTimeout <= 0 {
			shutdownTimeout = 30 * time.Second
		}
		select {
		case <-r.done:
		case <-time.After(shutdownTimeout):
			zap.L().Warn("Graceful shutdown timed out, forcing cleanup",
				zap.Duration("timeout", shutdownTimeout))
		}
	}

	r.closeOnce.Do(r.releaseResources)
}

// Discard releases a runner's resources without waiting for RunNativeScan.
// Used when a scan is rejected (queue full / project busy) before it ever
// starts: r.done is never closed in that case, so a normal Close would block for
// the full shutdown timeout. Shares closeOnce with Close so the network refcount
// is released exactly once.
func (r *Runner) Discard() {
	if r.cancel != nil {
		r.cancel()
	}
	r.closeOnce.Do(r.releaseResources)
}

// releaseResources frees the runner's owned resources. Runs at most once.
func (r *Runner) releaseResources() {
	if r.output != nil {
		r.output.Close()
	}

	if r.dedupManager != nil {
		r.dedupManager.Close()
	}

	if r.inputSource != nil {
		_ = r.inputSource.Close()
	}

	network.Close()

	// Scratch is NOT released here. It is held for the life of the process by
	// pkg/cli.Execute, so commands that never build a runner get the same
	// cleanup and a server does not tear the directory down between scans.
}

// SetRepository sets the database repository for storing scan results
func (r *Runner) SetRepository(repo *database.Repository) {
	r.repository = repo
}

// SetSettings sets the configuration settings for notifications and other YAML-based config
func (r *Runner) SetSettings(s *config.Settings) {
	r.settings = s
}

// Pause suspends scan processing. Workers finish their current item then block.
// writeSessionLog appends a plain-text line to runtime.log (ANSI stripped,
// timestamped) without routing it through stderr. No-op when session log
// persistence is disabled. Safe for concurrent use.
func (r *Runner) writeSessionLog(line string) {
	r.sessionLogMu.Lock()
	f := r.sessionLogFile
	r.sessionLogMu.Unlock()
	if f == nil {
		return
	}
	plain := terminal.StripANSI(line)
	if !strings.HasSuffix(plain, "\n") {
		plain += "\n"
	}
	ts := time.Now().Format("15:04:05")
	_, _ = f.WriteString("[" + ts + "] " + plain)
}

func (r *Runner) Pause() {
	if r.pauseCtrl != nil {
		r.pauseCtrl.Pause()
		if r.scanLogger != nil {
			r.scanLogger.Info("", "scan paused")
		}
	}
}

// Resume unblocks paused workers and continues scan processing.
func (r *Runner) Resume() {
	if r.pauseCtrl != nil {
		r.pauseCtrl.Resume()
		if r.scanLogger != nil {
			r.scanLogger.Info("", "scan resumed")
		}
	}
}

// IsPaused returns whether the scan is currently paused.
func (r *Runner) IsPaused() bool {
	if r.pauseCtrl != nil {
		return r.pauseCtrl.IsPaused()
	}
	return false
}

// ScanLogger returns the scan logger (may be nil if no repository is set).
func (r *Runner) ScanLogger() *database.ScanLogger {
	return r.scanLogger
}
