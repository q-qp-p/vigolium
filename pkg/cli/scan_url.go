package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/scratch"

	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// scan-url flags
var (
	scanURLMethod    string
	scanURLBody      string
	scanURLHeaders   []string
	scanURLNoPassive bool
)

// Phase enable flags (shared by scan-url and scan-request)
var (
	scanPhaseDiscover        bool
	scanPhaseSpider          bool
	scanPhaseExternalHarvest bool
	scanPhaseKnownIssueScan  bool
)

// registerPhaseFlags adds --discover, --spider, --external-harvest, and --known-issue-scan
// flags to the given FlagSet. Called from both scan-url and scan-request init().
func registerPhaseFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&scanPhaseDiscover, "discover", false, "Run content discovery before scanning")
	flags.BoolVar(&scanPhaseSpider, "spider", false, "Run browser-based spidering before scanning")
	flags.BoolVar(&scanPhaseExternalHarvest, "external-harvest", false, "Run external intelligence harvesting before scanning")
	flags.BoolVar(&scanPhaseKnownIssueScan, "known-issue-scan", false, "Run known issue scan (Nuclei + native secret scanning)")
}

// hasPhaseFlags returns true if any phase flag is set.
func hasPhaseFlags() bool {
	return scanPhaseDiscover || scanPhaseSpider || scanPhaseExternalHarvest || scanPhaseKnownIssueScan
}

var scanURLCmd = &cobra.Command{
	Use:   "scan-url [url]",
	Short: "Scan a single URL for vulnerabilities",
	Long: `Run active and passive scanner modules against a single URL.
Accepts a URL as argument or reads from stdin (auto-detects raw HTTP, curl, or URLs).
Designed for quick, targeted scans and AI agent integration.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScanURLCmd,
}

func init() {
	rootCmd.AddCommand(scanURLCmd)
	flags := scanURLCmd.Flags()

	flags.StringVar(&scanURLMethod, "method", "GET", "HTTP method")
	flags.StringVar(&scanURLBody, "body", "", "Request body")
	flags.StringArrayVarP(&scanURLHeaders, "header", "H", nil, "Custom header (repeatable, e.g. -H 'Cookie: x=1'). Commas are literal — repeat -H for multiple headers.")
	flags.BoolVar(&scanURLNoPassive, "no-passive", false, "Skip passive modules")
	flags.StringArrayVarP(&globalTargets, "target", "t", nil, "Target URL to scan (repeatable; alternative to the positional URL argument). Commas are literal.")
	registerScanModuleFlags(flags)
	registerModuleSelectionFlags(flags)
	registerHTTPClientFlags(flags)
	registerPhaseFlags(flags)
	registerLightweightScanIOFlags(flags)
}

// hasFileOutputFormat reports whether --format requests a file-materialized
// format (jsonl/html/report/pdf/fs/sqlite) as opposed to the default console
// view. The lightweight commands route to the Runner for these so the export
// tail (finishStatelessExport / finishFSExport / maybeGenerateReports /
// finishScanJSONLExport) runs — otherwise `--format fs` or `--format sqlite`
// would be silently dropped on the fast in-memory direct path. Plain --json /
// --ci-output-format leave globalFormat at "console" and keep the fast direct
// path, preserving the JSON shape AI agents consume.
// The predicate itself is wantsFileOutput, shared with the agentic -S path — an
// unlisted format routed down the direct path is neither validated nor written,
// so the command reports success and produces nothing. That is exactly how
// `sarif` behaved before this became a predicate.
func hasFileOutputFormat() bool {
	return wantsFileOutput(parseFormats(globalFormat))
}

// validateGlobalFormats validates the raw --format string (rejecting unknown
// formats and enforcing sqlite-requires-stateless) before the lightweight
// scan-url/scan-request commands do any network work. It reuses
// reconcileOutputFormats against a throwaway options value so the direct path
// enforces exactly the same rules as the full `scan` runner path — previously an
// unknown format (or fs/sqlite) could slip through unvalidated on the direct path.
func validateGlobalFormats() error {
	probe := types.DefaultOptions()
	probe.OutputFormats = parseFormats(globalFormat)
	return reconcileOutputFormats(probe)
}

// needsRunnerScan reports whether the request must run through the full
// native-scan Runner rather than the lightweight in-memory direct path. That is
// required whenever a phase is enabled, results are persisted/exported to a file
// (-o), the run is stateless (-S), phases are skipped (--skip), findings are
// printed as Markdown (--print-finding), traffic is printed (--print-traffic /
// --print-traffic-tree) — all of which render from the DB — or a file output
// format is requested; none of which the direct path implements.
//
// --events is on the list for the same reason: the event stream is emitted by
// the scan phases, which only run under the Runner. On the direct path the flag
// parsed and then described nothing.
func needsRunnerScan() bool {
	return hasPhaseFlags() ||
		globalStateless ||
		scanOpts.Output != "" ||
		len(globalSkipPhases) > 0 ||
		scanPrintFinding ||
		hasPrintTrafficFlags() ||
		strings.TrimSpace(scanOpts.Events) != "" ||
		hasFileOutputFormat()
}

// dispatchSingleScan routes one parsed request to either the Runner-backed scan
// (when output/persistence/phase flags are in play) or the fast direct path.
//
// ctx reaches only the direct path, which is not an oversight: the Runner path
// installs its own shutdown handler (scanSignalCoordinator), which closes the
// runner and reports the interrupt on the event stream, so a cancellation
// context there would be a second, slower answer to the same signal. The
// caller's loop still checks ctx between inputs, so an interrupt stops the
// batch on both paths.
func dispatchSingleScan(ctx context.Context, rr *httpmsg.HttpRequestResponse, target, method string) error {
	if needsRunnerScan() {
		return runRunnerScan(rr, target)
	}
	return runScanWithRR(ctx, rr, target, method)
}

// lightweightScanContext is the ONE cancellation context for a scan-url /
// scan-request invocation.
//
// It used to be installed per request, inside the direct scan: a multi-target
// run registered one signal channel and leaked one goroutine per target, and
// only the request in flight ever saw the interrupt — the loop went straight on
// to the next one. Installed here, a single Ctrl-C stops the batch and the
// remaining targets are reported as not scanned.
func lightweightScanContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), scanShutdownSignals...)
}

// runDirectScanBatch scans every input on the direct path.
//
// Under -j with more than one input the results become the `items` of one
// envelope, because two top-level objects on stdout are not a document the
// --json contract describes. Every other mode keeps per-input dispatch (the
// human renderer and --ci-output-format are line protocols where that is
// correct), and all of them stop early on an interrupt.
func runDirectScanBatch(ctx context.Context, cmd *cobra.Command, inputs []scanInput) error {
	results, notScanned, err := scanInputs(ctx, inputs,
		func(ctx context.Context, in scanInput) (*scanResult, error) {
			return executeDirectScan(ctx, in.rr, in.target, in.method)
		})
	if writeErr := writeDirectScanBatch(commandPathWithoutRoot(cmd), results, notScanned); writeErr != nil {
		return writeErr
	}
	return err
}

// dispatchScanInputs runs every input through the mode-appropriate path,
// stopping at the first sign of an interrupt.
//
// The cancellation rule is scanInputs', not a second copy of it: these inputs
// publish their own output as they go, so only the error is carried back — but
// "stop at a cancelled context, keep the last error" has to mean the same thing
// on both paths or a Ctrl-C behaves differently depending on which one ran.
func dispatchScanInputs(ctx context.Context, inputs []scanInput) error {
	_, _, err := scanInputs(ctx, inputs,
		func(ctx context.Context, in scanInput) (*scanResult, error) {
			return nil, dispatchSingleScan(ctx, in.rr, in.target, in.method)
		})
	return err
}

// directBatchJSON reports whether several direct-path results must be folded
// into one envelope. The Runner path writes its own output and --ci-output-format
// is a line protocol, so neither qualifies.
func directBatchJSON(inputs []scanInput) bool {
	return len(inputs) > 1 && globalJSON && !globalCIOutput && !needsRunnerScan()
}

func runScanURLCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	if err := resetFailOnGate(); err != nil {
		return err
	}
	if err := validateModuleSelectionFlags(scanURLNoPassive); err != nil {
		return err
	}
	// Validate --format before any network activity so an unknown format (or
	// fs/sqlite) fails fast instead of being silently ignored on the direct path.
	if err := validateGlobalFormats(); err != nil {
		return err
	}
	if err := validateEventsFlag(scanOpts.Events); err != nil {
		return asUsageError(err)
	}
	// Validated here, not only in runRunnerScan: without -S/-o this command takes
	// the direct in-memory path, which never reaches the Runner — so a check
	// there alone let `scan-url --keep-db-on-error` exit 0 having done nothing
	// with the flag, which is the shape of control this plan exists to remove.
	if err := validateKeepDBOnError(globalStateless); err != nil {
		return err
	}

	inputs, err := scanURLInputs(args)
	if err != nil {
		return err
	}

	ctx, stop := lightweightScanContext()
	defer stop()

	if directBatchJSON(inputs) {
		return withFailOnGate(runDirectScanBatch(ctx, cmd, inputs))
	}
	return withFailOnGate(dispatchScanInputs(ctx, inputs))
}

// scanURLInputs resolves the command's inputs: the positional URL argument
// and/or repeatable -t/--target flags, else the parsed stdin stream.
//
// The positional arg is kept for the original single-URL ergonomics; -t lets the
// command match `vigolium scan`'s muscle memory and pass several URLs at once.
// Resolved up front, as a list, so the batch paths above can report what they
// did not get to.
func scanURLInputs(args []string) ([]scanInput, error) {
	targets := append([]string{}, args...)
	targets = append(targets, globalTargets...)

	if len(targets) > 0 {
		inputs := make([]scanInput, 0, len(targets))
		for _, target := range targets {
			rr, err := buildRequestFromFlags(target, scanURLMethod, scanURLBody, scanURLHeaders)
			if err != nil {
				return nil, fmt.Errorf("failed to build request: %w", err)
			}
			inputs = append(inputs, scanInput{rr: rr, target: target, method: scanURLMethod})
		}
		return inputs, nil
	}

	// No args — try reading from stdin
	if !fileutil.HasStdin() {
		return nil, fmt.Errorf("no URL argument provided and no stdin input detected")
	}

	raw, err := readStdin()
	if err != nil {
		return nil, fmt.Errorf("failed to read stdin: %w", err)
	}

	content := strings.TrimSpace(string(raw))
	if content == "" {
		return nil, fmt.Errorf("empty stdin input")
	}

	detected := detect.DetectStdinFormat(content)
	items, err := detect.ParseStdinContent(content, detected)
	if err != nil {
		return nil, err
	}

	inputs := make([]scanInput, 0, len(items))
	for _, rr := range items {
		inputs = append(inputs, scanInput{rr: rr, target: rr.Target(), method: rr.Request().Method()})
	}
	return inputs, nil
}

// --- Shared helpers used by both scan-url and scan-request ---

// scanResult is the JSON output struct for scan-url and scan-request.
type scanResult struct {
	Target         string                `json:"target"`
	Method         string                `json:"method"`
	ScanDurationMs int64                 `json:"scan_duration_ms"`
	ModulesRun     int                   `json:"modules_run"`
	Findings       []*output.ResultEvent `json:"findings"`
	Candidates     []*output.ResultEvent `json:"candidates,omitempty"`
	Observations   []*output.ResultEvent `json:"observations,omitempty"`
	Errors         []string              `json:"errors,omitempty"`
	// Persisted states whether these findings also reached a database. The direct
	// path can run with no store at all, and a caller that reads the findings out
	// of this document and then expects `vigolium finding` to list them needs to
	// know which of those two runs it got.
	Persisted bool `json:"persisted"`
	// Interrupted states that the scan was cancelled (Ctrl-C, SIGTERM) before the
	// executor finished. The findings below are whatever had landed by then, which
	// is a different claim from "these are the findings".
	Interrupted bool `json:"interrupted,omitempty"`
}

// buildRequestFromFlags constructs an HttpRequestResponse from CLI flags.
func buildRequestFromFlags(target, method, body string, headers []string) (*httpmsg.HttpRequestResponse, error) {
	method = strings.ToUpper(method)

	// Simple case: GET with no body or custom headers
	if method == "GET" && body == "" && len(headers) == 0 {
		return httpmsg.GetRawRequestFromURL(target)
	}

	// Build raw HTTP request manually
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	path := u.RequestURI()
	host := u.Host

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&sb, "Host: %s\r\n", host)

	// Add custom headers
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			fmt.Fprintf(&sb, "%s: %s\r\n", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Add Content-Length if body is present
	if body != "" {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}

	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}

	rr, err := httpmsg.ParseRawRequestWithURL(sb.String(), target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}

	return rr, nil
}

// setupScanHTTPStack initializes the HTTP stack for scanning.
// Returns requester, services, and a cleanup function.
func setupScanHTTPStack() (*http.Requester, *services.Services, func(), error) {
	opts := types.DefaultOptions()
	opts.Concurrency = globalConcurrency
	opts.Timeout = globalTimeout
	opts.ProxyURL = globalProxy
	opts.Verbose = globalVerbose
	opts.Debug = globalDebug
	opts.DumpTraffic = globalDumpTraffic
	opts.MaxPerHost = globalMaxPerHost
	opts.NoWafPacing = globalNoWafPacing
	opts.MaxHostError = globalMaxHostError
	if globalNoClustering {
		opts.ClusterRequests = false
	}

	if err := network.Init(opts); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to initialize network: %w", err)
	}

	dedupMgr := dedup.NewManager()

	svc := &services.Services{
		Options:      opts,
		DedupManager: dedupMgr,
	}

	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost:    opts.MaxPerHost,
		MaxEntries:    1000,
		EvictAfter:    30 * time.Second,
		EvictInterval: 10 * time.Second,
		// Match the main scan/run path: throttle a host only once it returns
		// WAF/CDN blocks (reactive), plus proactive edge pre-arm unless
		// --no-waf-pacing disables it. Without this the default edge pacing AND its
		// disabling flag are both inert on the direct scan-url/scan-request path.
		WafAutoArm:    true,
		DisablePreArm: opts.NoWafPacing,
	})
	svc.HostLimiter = hostLimiter

	httpRequester, err := http.NewRequester(opts, svc)
	if err != nil {
		dedupMgr.Close()
		_ = hostLimiter.Close()
		return nil, nil, nil, fmt.Errorf("failed to create HTTP requester: %w", err)
	}

	cleanup := func() {
		dedupMgr.Close()
		_ = hostLimiter.Close()
	}

	return httpRequester, svc, cleanup, nil
}

// getFilteredModules returns active and passive modules based on CLI flags.
func getFilteredModules(moduleIDs []string, noPassive bool) ([]modules.ActiveModule, []modules.PassiveModule) {
	// Default selection from -m/--module-tag: resolved exact IDs apply to both
	// registries (["all"] and any exact ID already flow through unchanged; only an
	// empty result needs normalizing to "all").
	resolved := modules.ResolveModulePatterns(moduleIDs)
	activeIDs := resolved
	passiveIDs := resolved
	if len(resolved) == 0 {
		activeIDs = []string{"all"}
		passiveIDs = []string{"all"}
	}

	// Layer --module-id / --passive-only / --no-passive on top.
	applyModuleSelectionOverrides(&activeIDs, &passiveIDs, noPassive)

	// Note: this direct single-request path deliberately does not apply the config
	// enabled_modules allowlist or the intensity-tier ceiling — those narrow the
	// pipeline path in the runner's getModulesToExecute; a direct scan-url/-request
	// runs the resolved sentinel selection as-is.
	return selectModulesByIDs(activeIDs, passiveIDs)
}

// colorStreamingModuleType returns the module-type colored for the streaming
// finding line (active=BoldOrange / passive=BoldBlue). Mirrors the palette
// used by the server's formatFindingLine so the CLI and server console
// produce identical output.
func colorStreamingModuleType(t string) string {
	switch strings.ToLower(t) {
	case "active":
		return terminal.BoldOrange(t)
	case "passive":
		return terminal.BoldBlue(t)
	default:
		return t
	}
}

// streamingSeverityBracket renders the `[<symbol> <severity>]` field used by
// the streaming finding line. Symbol and text share a single color matching
// the severity palette (critical=magenta, high=orange, medium=yellow,
// low=green, suspect=cyan, info=blue).
func streamingSeverityBracket(s severity.Severity) string {
	sevStr := s.String()
	inner := ""
	switch s {
	case severity.Critical:
		inner = terminal.BoldMagenta("✖ " + sevStr)
	case severity.High:
		inner = terminal.BoldOrange("❖ " + sevStr)
	case severity.Medium:
		inner = terminal.BoldYellow("◆ " + sevStr)
	case severity.Low:
		inner = terminal.BoldGreen("• " + sevStr)
	case severity.Suspect:
		inner = terminal.BoldCyan("? " + sevStr)
	case severity.Info:
		inner = terminal.BoldBlue("◇ " + sevStr)
	default:
		inner = sevStr
	}
	return "[" + inner + "]"
}

// formatStreamingFindingLine renders a single finding as one line of console
// output for the `vigolium scan` / `vigolium scan-request` streaming view.
// Format (matching pkg/server/handlers_scan_url.go):
//
//	❯ scan-request │ [type] [module-id] [<sym> severity] METHOD URL[ [evidence]]
//
// METHOD is elided when the result has no request attached (typical for
// passive findings). The URL is truncated to fit the terminal width, and
// result.ExtractedResults + FuzzingParameter surface as a trailing cyan
// bracket.
func formatStreamingFindingLine(result *output.ResultEvent) string {
	prefix := terminal.Muted(terminal.SymbolChevron + " scan-request " + terminal.SymbolPipe)

	typeStr := result.ModuleType
	if typeStr == "" {
		typeStr = "?"
	}

	method := ""
	if result.Request != "" {
		if m, err := httpmsg.GetMethod([]byte(result.Request)); err == nil {
			method = m
		}
	}

	urlStr := result.Matched
	if urlStr == "" {
		urlStr = result.URL
	}

	suffix := ""
	if len(result.ExtractedResults) > 0 {
		suffix = " [" + output.EscapeOneLine(strings.Join(result.ExtractedResults, ",")) + "]"
	}
	if result.IsFuzzingResult && result.FuzzingParameter != "" {
		suffix += " [" + result.FuzzingParameter + "]"
	}

	// Visible-char accounting so the URL gets the remaining terminal width.
	// Hand-count the non-URL portion (ANSI escapes excluded).
	visibleLen := len("❯ scan-request │ ") +
		len("[") + len(typeStr) + len("] ") +
		len("[") + len(result.ModuleID) + len("] ") +
		len("[") + len("✖ ") + len(result.Info.Severity.String()) + len("] ")
	if method != "" {
		visibleLen += len(method) + 1
	}

	if termWidth := terminal.TerminalWidth(); termWidth > 0 {
		remaining := termWidth - visibleLen - len(suffix)
		if remaining > 20 && len(urlStr) > remaining {
			urlStr = terminal.Truncate(urlStr, remaining)
		}
	}

	var b strings.Builder
	b.WriteString(prefix)
	b.WriteString(" [")
	b.WriteString(colorStreamingModuleType(typeStr))
	b.WriteString("] [")
	b.WriteString(terminal.White(result.ModuleID))
	b.WriteString("] ")
	b.WriteString(streamingSeverityBracket(result.Info.Severity))
	if method != "" {
		b.WriteString(" ")
		b.WriteString(terminal.Bold(method))
	}
	b.WriteString(" ")
	b.WriteString(urlStr)
	if suffix != "" {
		b.WriteString(terminal.HiCyan(suffix))
	}
	b.WriteString("\n")
	return b.String()
}

// acquireDirectScanDB opens the store the direct path persists into, and decides
// whether failing to open it is fatal.
//
// It is fatal when the caller NAMED a store — `--db`, `VIGOLIUM_DB_PATH` (folded
// into globalDB by the root command), or `--config`. Scanning for minutes and
// then discarding every finding because the database the caller pinned could not
// be opened is exactly the silent data loss a pin exists to prevent, and the
// failure is reported before any request goes out rather than after.
//
// It is not fatal when no store was named: the direct path's whole point is that
// it can answer from memory, and a run with no -o and no --db did not ask for
// persistence. That case warns on stderr (unless --silent) and returns a nil
// repository, which the result's `persisted: false` then reports.
//
// open is a parameter rather than a direct getDB call so the three branches are
// testable without a database or a network.
func acquireDirectScanDB(open func() (*database.DB, error)) (*database.Repository, string, error) {
	db, dbErr := open()
	if dbErr != nil {
		if strings.TrimSpace(globalDB) != "" || strings.TrimSpace(globalConfig) != "" {
			return nil, "", fmt.Errorf("database unavailable: %w", dbErr)
		}
		if !globalSilent {
			fmt.Fprintf(os.Stderr, "%s database unavailable — results will not be persisted: %v\n",
				terminal.WarnPrefix(), dbErr)
		}
		return nil, "", nil
	}
	// getDB already ran EnsureSchemaCurrent on this handle, but that check covers
	// migrated columns only — a table or index added without a column migration
	// passes it. Bounded like the other two setup sites; a failure only warns
	// here because this path can still do useful work against a store it could
	// not migrate. nil settings because this function never loads them (the
	// handle came from getDB, which did) — that takes the minSetupTimeout floor,
	// the right order of magnitude for a check measured in microseconds.
	ctx, cancelSetup := setupContext(nil)
	defer cancelSetup()
	if schemaErr := db.EnsureSchemaReady(ctx); schemaErr != nil {
		zap.L().Warn("Failed to create schema", zap.Error(schemaErr))
	}
	// Resolve the active project so the executor stamps its records and findings
	// with it. Without this they fall through to the default project and become
	// invisible to every project-scoped read. A failure here is fatal rather than
	// a warning: continuing would file the whole scan into the default project —
	// the exact silent misfiling this resolution exists to prevent — and
	// `scan`/`ingest` both return it too.
	projectUUID, perr := resolveProjectUUID()
	if perr != nil {
		return nil, "", perr
	}
	return database.NewRepository(db), projectUUID, nil
}

// runScanWithRR executes one request on the direct path and writes its result.
//
// Split from executeDirectScan so the result is published on every exit: a
// cancelled or failed execution still has findings worth reporting, and under
// -j the document is what carries them. The error is returned after the write,
// so the exit code reports the failure without costing the output.
func runScanWithRR(ctx context.Context, rr *httpmsg.HttpRequestResponse, target, method string) error {
	result, execErr := executeDirectScan(ctx, rr, target, method)
	if result == nil {
		return execErr
	}
	if outErr := outputScanResult(result); outErr != nil {
		return outErr
	}
	return execErr
}

// executeDirectScan runs the lightweight in-memory scan: no Runner, no phases,
// one request through the executor. It returns the result it assembled together
// with the execution's own error, so the caller can publish the former and still
// report the latter.
func executeDirectScan(ctx context.Context, rr *httpmsg.HttpRequestResponse, target, method string) (*scanResult, error) {
	startTime := time.Now()
	resolvedModules := resolveModules()

	// Set up HTTP stack
	httpRequester, svc, cleanup, err := setupScanHTTPStack()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Warn once per host when the edge WAF/CDN starts filtering scan traffic.
	// The Runner-backed path wires this in RunNativeScan; this direct path builds
	// its own requester, so it needs the same hook to not silently miss it.
	if !globalSilent {
		httpRequester.SetBlockNotifier(func(n http.BlockNotice) {
			fmt.Fprint(os.Stderr, runner.FormatBlockNoticeLine(n))
		})
	}

	// Get modules
	active, passive := getFilteredModules(resolvedModules, scanURLNoPassive)

	// Storage. Acquired BEFORE any request goes out, so a pinned store that
	// cannot be opened fails the command instead of costing a whole scan.
	repo, scanProjectUUID, dbErr := acquireDirectScanDB(getDB)
	if dbErr != nil {
		return nil, dbErr
	}
	if repo != nil {
		defer closeDatabaseOnExit()
	}

	// Create source
	src := source.NewSingleSource(rr, resolvedModules)

	// Startup line so the user sees what's about to run rather than staring at
	// silence until the first module-level zap log fires.
	if !globalSilent {
		fmt.Fprintf(os.Stderr, "  %s Scanning %s %s with %s active + %s passive modules\n",
			terminal.InfoSymbol(),
			terminal.BoldCyan(method),
			terminal.Cyan(target),
			terminal.Orange(fmt.Sprintf("%d", len(active))),
			terminal.Orange(fmt.Sprintf("%d", len(passive))))
	}

	// Collect findings
	var mu sync.Mutex
	var findings []*output.ResultEvent
	var candidates []*output.ResultEvent
	var observations []*output.ResultEvent
	var scanErrors []string

	executorCfg := core.ExecutorConfig{
		Workers:              globalConcurrency,
		Services:             svc,
		HTTPRequester:        httpRequester,
		Repository:           repo,
		ScanUUID:             globalScanUUID,
		ProjectUUID:          scanProjectUUID,
		MaxFindingsPerModule: globalMaxFindingsPerModule,
		TechFilterDisabled:   globalNoTechFilter,
		OnResult: func(result *output.ResultEvent) {
			mu.Lock()
			findings = append(findings, result)
			mu.Unlock()
			if globalSilent || result == nil {
				return
			}
			// Per-finding stderr line so the user gets immediate feedback as
			// findings come in. Format:
			//   ◆ finding [severity] [type] [confidence] module-id — url
			// Severity is color-coded to match the canonical scheme used by
			// the results table renderer (format_screen.go). Optional [type]
			// and [confidence] brackets surface module class and signal
			// quality at a glance.
			fmt.Fprint(os.Stderr, formatStreamingFindingLine(result))
		},
		OnCandidate: func(result *output.ResultEvent) {
			mu.Lock()
			candidates = append(candidates, result)
			mu.Unlock()
		},
		OnObservation: func(result *output.ResultEvent) {
			mu.Lock()
			observations = append(observations, result)
			mu.Unlock()
		},
		StatusInterval: 30 * time.Second,
	}

	// Forward-declared so OnStatus can read the executor's considered-module
	// counter (which counts modules whose CanProcess was evaluated, fired or
	// not — so the X/Y can actually reach parity instead of stalling on the
	// "always-rejected" set forever).
	var scanExecutor *core.Executor

	// Periodic status line so the user can tell the scan is alive during long
	// runs (some modules can take minutes per insertion point).
	if !globalSilent {
		executorCfg.OnStatus = func(processed, total, findingsCount, distinctModules, activeCount, passiveCount, timedOut int64, elapsed time.Duration) {
			totalModules := activeCount + passiveCount
			scannedModules := distinctModules
			if scanExecutor != nil {
				scannedModules = scanExecutor.ConsideredModuleCount()
			}
			modulesStr := terminal.FormatModuleCount(scannedModules, totalModules, timedOut)
			fmt.Fprintf(os.Stderr, "  %s %s Modules: %s | Findings: %s | Elapsed: %s\n",
				terminal.InfoSymbol(),
				terminal.BoldCyan("[status]"),
				terminal.Yellow(modulesStr),
				terminal.Orange(fmt.Sprintf("%d", findingsCount)),
				terminal.Gray(elapsed.Round(time.Second).String()))
		}
	}

	// Verbose: log every HTTP request as it goes out, like burp-style debug.
	// Off by default so the console isn't flooded for typical scans.
	if globalVerbose && !globalSilent {
		executorCfg.OnTraffic = func(reqMethod, reqURL string, statusCode int, contentType string) {
			fmt.Fprintf(os.Stderr, "  %s [%s] %s %s\n",
				terminal.Muted(terminal.SymbolChevron+" scan-request "+terminal.SymbolPipe),
				terminal.Orange(fmt.Sprintf("%d", statusCode)),
				terminal.BoldCyan(reqMethod),
				terminal.Gray(reqURL))
		}
	}

	scanExecutor = core.NewExecutor(executorCfg, src, active, passive)
	executor := scanExecutor

	// The invocation's cancellation context arrives from the RunE, which installs
	// one signal handler for the whole command. This used to call signal.Notify
	// per request with a goroutine that outlived it, so a multi-target run left
	// one leaked goroutine and one registered channel per target, and only the
	// in-flight scan saw the interrupt.
	_, execErr := executor.Execute(ctx)
	if execErr != nil {
		scanErrors = append(scanErrors, execErr.Error())
	}

	duration := time.Since(startTime)

	result := &scanResult{
		Target:         target,
		Method:         method,
		ScanDurationMs: duration.Milliseconds(),
		ModulesRun:     len(active) + len(passive),
		Findings:       findings,
		Candidates:     candidates,
		Observations:   observations,
		Errors:         scanErrors,
		Persisted:      repo != nil,
		Interrupted:    ctx.Err() != nil,
	}
	if result.Findings == nil {
		result.Findings = make([]*output.ResultEvent, 0)
	}

	// In-memory --fail-on gate: the direct path holds findings in memory rather
	// than a database, so check severities here. The RunE converts the flag into
	// an exit code after output is written.
	failOnGateFromEvents(result.Findings, globalSilent)

	return result, execErr
}

// --- Phase mode: delegates to the Runner for full-pipeline phases ---

// buildPhaseOptions creates a *types.Options populated from global flags and phase flags.
func buildPhaseOptions(target string) (*types.Options, error) {
	opts := types.DefaultOptions()

	// Target
	opts.Targets = []string{target}

	// Modules — active from -m/--module-tag, passive = all, then --module-id /
	// --passive-only / --no-passive overrides.
	opts.Modules, opts.PassiveModules = resolveModuleSelection(scanURLNoPassive)
	opts.NoTechFilter = globalNoTechFilter

	// Global CLI flags
	opts.ScanUUID = globalScanUUID
	opts.Timeout = globalTimeout
	opts.Concurrency = globalConcurrency
	opts.MaxPerHost = globalMaxPerHost
	opts.NoWafPacing = globalNoWafPacing
	opts.MaxHostError = globalMaxHostError
	opts.Verbose = globalVerbose
	opts.Silent = globalSilent
	opts.Debug = globalDebug
	opts.DumpTraffic = globalDumpTraffic
	opts.JSONOutput = globalJSON
	opts.ProxyURL = globalProxy
	opts.ConfigPath = globalConfig
	opts.ScopeOriginMode = globalScopeOrigin
	opts.OutputFormats = parseFormats(globalFormat)
	// reconcileOutputFormats validates formats and sets DeferredJSONLExport, which
	// the post-scan jsonl export keys off of. Propagate its error rather than
	// discarding it: callers (runScanURLCmd/runScanRequestCmd) also pre-validate
	// via validateGlobalFormats, but this keeps buildPhaseOptions self-consistent.
	if rerr := reconcileOutputFormats(opts); rerr != nil {
		return nil, rerr
	}

	// Output / persistence flags (shared with `vigolium scan`).
	opts.Output = scanOpts.Output
	opts.Stateless = globalStateless
	opts.SkipPhases = globalSkipPhases
	opts.OmitResponse = scanOpts.OmitResponse
	// --events, so the lightweight commands emit the same machine event stream as
	// `vigolium scan`. Without this the flag parsed, validated and then described
	// nothing, because the Runner was handed an empty Events path.
	opts.Events = scanOpts.Events
	// A failed project resolution is fatal, not a fallback. The error was
	// discarded, so a scan whose project could not be resolved ran under the
	// zero-value ProjectUUID and filed every record and finding into the default
	// project — invisible to every project-scoped read, and silently merged with
	// another project's data. `scan` and `ingest` both return it.
	projectUUID, perr := resolveProjectUUID()
	if perr != nil {
		return nil, perr
	}
	opts.ProjectUUID = projectUUID

	// Phase flags
	opts.DiscoverEnabled = scanPhaseDiscover
	opts.SpideringEnabled = scanPhaseSpider
	opts.ExternalHarvestEnabled = scanPhaseExternalHarvest
	opts.KnownIssueScanEnabled = scanPhaseKnownIssueScan

	// Heuristics: not useful for single-target phase mode
	opts.HeuristicsCheck = "none"

	if globalNoClustering {
		opts.ClusterRequests = false
	}

	return opts, nil
}

// validateRunnerScanOutput rejects output-format / -o combinations the export
// tail cannot satisfy, mirroring the equivalent guards on `vigolium scan` so the
// lightweight commands fail the same way instead of silently producing nothing.
func validateRunnerScanOutput(opts *types.Options) error {
	if opts.Output == "" {
		// Derived from the same predicate `vigolium scan` uses, rather than a
		// hand-listed set spelled out twice (condition and error string) that a
		// new format has to be remembered in — which is how `sarif` reached here
		// able to be requested and unable to be written.
		for _, f := range opts.OutputFormats {
			if formatNeedsOutput(f) {
				return fmt.Errorf("--format %s requires -o/--output to specify the report file path", f)
			}
		}
		if len(opts.OutputFormats) > 1 {
			return fmt.Errorf("multiple --format values require -o/--output as a base path")
		}
	}
	return nil
}

// runRunnerScan scans a single parsed request (or, when phase flags are set, the
// target URL) through the full native-scan Runner so the lightweight scan-url /
// scan-request commands honor -o/--output, -S/--stateless, --skip, and file
// output formats (jsonl/html/...) exactly like `vigolium scan`. It mirrors
// executeNativeScan's stateless temp-DB lifecycle and post-scan export tail.
//
// With no phase flags the exact request (method/body/headers) is fed straight to
// the executor via a SingleSource, so scan-request's raw POST bodies survive. A
// phase flag (discover/spider/...) instead routes through runner.New, which
// crawls from the target URL like the full pipeline.
func runRunnerScan(rr *httpmsg.HttpRequestResponse, target string) (err error) {
	scanStart := time.Now()
	opts, err := buildPhaseOptions(target)
	if err != nil {
		return err
	}

	if err := validateRunnerScanOutput(opts); err != nil {
		return err
	}
	if err := validateEventsFlag(opts.Events); err != nil {
		return asUsageError(err)
	}
	if err := validateStdoutProtocol(opts); err != nil {
		return err
	}
	if err := validateKeepDBOnError(opts.Stateless); err != nil {
		return err
	}
	if opts.Stateless && globalDB != "" {
		return fmt.Errorf("--stateless and --db are mutually exclusive")
	}

	// One signal handler for the whole invocation — see executeNativeScan.
	signals := startScanSignals(scanStart)
	defer signals.stop()
	// See the same guard in scan.go: --json/--ci-output stream results to stdout,
	// so they are not discarded and the warning would be false.
	if opts.Stateless && opts.Output == "" && !opts.Silent && !globalJSON && !globalCIOutput {
		fmt.Fprintf(os.Stderr,
			"%s %s: no %s set — scan results will be discarded with the temporary database. "+
				"Pass %s %s and %s %s to persist results.\n",
			terminal.WarnPrefix(), terminal.BoldCyan("--stateless"), terminal.BoldCyan("-o/--output"),
			terminal.BoldCyan("--output"), terminal.BoldYellow("<path>"),
			terminal.BoldCyan("--format"), terminal.BoldYellow("jsonl|html"))
	}

	// Fatal, for the reason spelled out in runScanCmd: an explicit --config that
	// cannot be read means the scan would run under settings nobody chose.
	settings, err := clicommon.LoadSettings(opts.ConfigPath)
	if err != nil {
		return err
	}

	// Apply CLI overrides
	if opts.ScopeOriginMode != "" {
		settings.Scope.CLIOriginMode = opts.ScopeOriginMode
	}

	// Stateless mode: scan into a throwaway temp SQLite DB that is removed after
	// the run, so the main DB stays untouched (mirrors `vigolium scan -S`).
	var statelessDBPath string
	if opts.Stateless {
		tmpFile, tmpErr := scratch.CreateTemp("stateless-*.sqlite")
		if tmpErr != nil {
			return fmt.Errorf("failed to create temporary database: %w", tmpErr)
		}
		statelessDBPath = tmpFile.Name()
		_ = tmpFile.Close()
		// Registered first so it runs last, after the DB handle is closed. See
		// the same defer in executeNativeScan.
		defer func() { err = releaseStatelessDB(statelessDBPath, err) }()
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = statelessDBPath
	} else if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}
	applyGlobalExtFlagsToSettings(settings)

	// Validate database config
	if err := settings.Database.Validate(); err != nil {
		return fmt.Errorf("invalid database configuration: %w", err)
	}
	if err := settings.DynamicAssessment.Extensions.Validate(); err != nil {
		return fmt.Errorf("invalid extensions configuration: %w", err)
	}

	// Validate per-phase configs when enabled
	if opts.DiscoverEnabled {
		if err := settings.Discovery.Validate(); err != nil {
			return fmt.Errorf("invalid discovery configuration: %w", err)
		}
	}
	if opts.SpideringEnabled {
		if err := settings.Spidering.Validate(); err != nil {
			return fmt.Errorf("invalid spidering configuration: %w", err)
		}
	}
	if opts.ExternalHarvestEnabled {
		if err := settings.ExternalHarvester.Validate(); err != nil {
			return fmt.Errorf("invalid external harvester configuration: %w", err)
		}
	}
	if opts.KnownIssueScanEnabled {
		if err := settings.KnownIssueScan.Validate(); err != nil {
			return fmt.Errorf("invalid KnownIssueScan configuration: %w", err)
		}
	}

	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("scan requires a database; use --db <path> or configure vigolium-configs.yaml: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx, cancelSetup := setupContext(settings)
	defer cancelSetup()
	if err := db.EnsureSchemaReady(ctx); err != nil {
		return wrapSetupError(ctx, db.Driver(), "database schema setup", err)
	}
	repo := database.NewRepository(db)

	// Machine event stream (--events). Registered before the export defers so its
	// terminal scan.finished is the last line written — a consumer treats it as
	// end-of-stream.
	opts.ScanUUID = pinnedOrNewUUID(opts.ScanUUID)
	prepareTerminalEvent, emitTerminalEvent, evErr := beginScanEventStream(db, opts, settings, opts.ScanningStrategy, scanStart)
	if evErr != nil {
		return evErr
	}
	// Registered first so LIFO writes the line last; prepare, registered second,
	// gathers the totals before it while the database is still open. There is no
	// --db-isolate merge on this path, so both sit together here.
	defer func() { emitTerminalEvent(err) }()
	defer func() { prepareTerminalEvent(err) }()

	// Stateless + -o: suppress StandardWriter's live file output and materialize
	// every requested format from the temp DB post-scan (mirrors executeNativeScan).
	var statelessOutputPath string
	if opts.Stateless && opts.Output != "" {
		statelessOutputPath = opts.Output
		opts.Output = ""
	}
	// Export tail. Registered before the runner is closed; both read the DB after
	// the explicit scanRunner.Close() below flushes records, but before db.Close().
	defer func() { recordExportFailure(&err, finishStatelessExport(db, opts, statelessOutputPath, false)) }()
	defer func() {
		if skipDeferredJSONLExport(err, opts.Stateless, statelessOutputPath) {
			return
		}
		recordExportFailure(&err, finishScanJSONLExport(db, opts))
	}()

	// Build the Runner. No phase flags → scan the exact request via SingleSource;
	// a phase flag → crawl from the target URL via the standard input source.
	var scanRunner *runner.Runner
	if hasPhaseFlags() {
		scanRunner, err = runner.New(opts)
	} else {
		scanRunner, err = runner.NewWithInputSource(opts, source.NewSingleSource(rr, opts.Modules))
	}
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	if scanRunner == nil {
		return nil
	}
	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)

	// Close before the export defers read the DB so any buffered records land
	// first. A failed scan must abort visibly (non-zero, no success banner).
	scanErr := runNativeScanPass(scanRunner)
	if scanErr != nil {
		err = scanErr
		return err
	}

	// The same tail the full scan command runs, minus the upload — see
	// reportNativeScanSuccess for why that step stays behind.
	//
	// recordExportFailure, not a bare return: the summary and the gate still run
	// on an unwritable report (the findings exist and are worth showing), but the
	// run no longer exits 0 claiming to have written a file that is not there.
	recordExportFailure(&err, reportScanCompletion(db, settings, repo, opts, scanStart))
	return err
}

// outputScanResult writes the scan result as JSON or human-readable table.
func outputScanResult(result *scanResult) error {
	// CI output: one JSONL line per finding, nothing else
	if globalCIOutput {
		for _, f := range result.Findings {
			data, err := json.Marshal(f)
			if err != nil {
				return err
			}
			_, _ = os.Stdout.Write(data)
			_, _ = os.Stdout.Write([]byte("\n"))
		}
		return nil
	}

	if globalJSON {
		return writeAgentJSON(result)
	}

	// Human-readable output
	fmt.Fprintf(os.Stderr, "\n%s Native scan completed: %s (%s %s) in %s\n",
		terminal.SuccessSymbol(),
		terminal.Cyan(result.Target),
		result.Method,
		terminal.Gray(fmt.Sprintf("%d modules", result.ModulesRun)),
		(time.Duration(result.ScanDurationMs) * time.Millisecond).Round(time.Second))

	if len(result.Findings) == 0 {
		fmt.Fprintf(os.Stderr, "%s No findings.\n", terminal.InfoSymbol())
		return nil
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "SEVERITY", "MODULE", "TYPE", "MATCHED", "NAME")
	for _, f := range result.Findings {
		tbl.AddRow(
			clicommon.ColorSeverity(f.Info.Severity.String()),
			terminal.Cyan(f.ModuleID),
			colorModuleType(f.ModuleType),
			f.Matched,
			f.Info.Name,
		)
	}
	tbl.Print()

	if len(result.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s Errors:\n", terminal.WarningSymbol())
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
	}

	return nil
}
