package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vigolium/vigolium/internal/scratch"

	"github.com/dustin/go-humanize"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/memlimit"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/burpscope"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/wsdl"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

var scanOpts = types.DefaultOptions()

// scanReportSharedURL holds the --report-url flag value for native-scan HTML report rendering.
var scanReportSharedURL string

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a native scan — deterministic multi-phase vulnerability scanning",
	Long: `Run the native scan pipeline against one or more targets. Phases run in order:
ingestion → discovery → external-harvest → spidering → known-issue-scan → dynamic-assessment → extension.

Use --only / --skip to limit phases, --strategy or --scanning-profile for tuned presets, and --ext / --ext-dir to load custom JavaScript extensions.

Targets may be passed as positional URLs (vigolium scan https://a https://b), via
repeated -t/--target, or from -T/--target-file; the three combine and duplicates
are removed. A positional value is always treated as a target URL, never a file —
use -T or -i for files.`,
	Args: cobra.ArbitraryArgs,
	RunE: runScanCmd,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	flags := scanCmd.Flags()
	registerInputSourceFlags(flags)
	registerHTTPClientFlags(flags)
	registerScanModuleFlags(flags)
	registerModuleSelectionFlags(flags)
	registerScanPipelineFlags(flags)
	registerSpecFlags(flags)
	registerNativeScanFlags(flags, true)
	addFlagAliases(scanCmd, nativeScanFlagAliases)
}

// allKnownIssueScanSeverities is the full nuclei severity set. A known-issue-scan
// run launched in isolation widens to this so a focused single-phase run is
// exhaustive rather than limited to the balanced default (critical+high).
var allKnownIssueScanSeverities = []string{"critical", "high", "medium", "low", "info"}

// shouldWidenKnownIssueScanSeverities reports whether a known-issue-scan launched
// as the only phase (`vigolium run known-issue-scan` / `--only known-issue-scan`)
// should have its severity filter widened to all levels. Running a single phase on
// its own is normally meant to be an exhaustive sweep, so the balanced default of
// critical+high would silently drop medium/low/info findings. Returns false when
// the user explicitly set --known-issue-scan-severities (their choice wins), when
// any phase other than known-issue-scan is also selected, or when the configured
// set is already empty (= all) or already covers every level.
func shouldWidenKnownIssueScanSeverities(onlyPhase string, severitiesExplicit bool, configured []string) bool {
	if onlyPhase != string(runner.PhaseKnownIssueScan) || severitiesExplicit {
		return false
	}
	if len(configured) == 0 {
		return false // empty = already all severities
	}
	have := make(map[string]bool, len(configured))
	for _, s := range configured {
		have[strings.ToLower(strings.TrimSpace(s))] = true
	}
	for _, s := range allKnownIssueScanSeverities {
		if !have[s] {
			return true // missing at least one level → widen to all
		}
	}
	return false // already covers every level
}

// mergePositionalTargets combines positional target URLs with repeated --target
// values, preserving order (positional first) and removing duplicates and blanks.
// It normalizes the scheme here as well as in runner.NewWithInputSource, where
// every entry point is caught: doing it before the dedup is what collapses
// `example.com` and `http://example.com` into one target rather than two, and it
// is the spelling the banner goes on to print.
// The second return names the targets whose scheme this merge SUPPLIED, for
// Options.TargetsSchemeAssumed. Normalization is what destroys the distinction
// between "the operator typed http" and "we guessed http", and the probe sweep
// needs it to know which guesses it may test — so the merge that destroys it
// is the only place that can report it.
func mergePositionalTargets(positional, flagged []string) (targets []string, assumed map[string]struct{}) {
	seen := make(map[string]bool, len(positional)+len(flagged))
	out := make([]string, 0, len(positional)+len(flagged))
	for _, src := range [][]string{positional, flagged} {
		for _, t := range src {
			t, guessed := httpmsg.EnsureURLSchemeTracked(strings.TrimSpace(t), httpmsg.DefaultTargetScheme)
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
			if guessed {
				if assumed == nil {
					assumed = make(map[string]struct{})
				}
				assumed[t] = struct{}{}
			}
		}
	}
	return out, assumed
}

func runScanCmd(cmd *cobra.Command, args []string) (err error) {
	defer syncLogger()

	// --fail-on gate: validate up front, then convert a tripped gate into a
	// non-zero exit once the body has returned (so reports/JSON are written
	// first). evaluateFailOnGate sets the flag during reportNativeScanSuccess.
	// Under -P/--parallel the gate is a no-op here — each child process runs its
	// own runScanCmd and exits non-zero on its own findings.
	if gateErr := resetFailOnGate(); gateErr != nil {
		return gateErr
	}
	defer func() { err = withFailOnGate(err) }()

	// Copy global flags into scan options
	scanOpts.ScanUUID = globalScanUUID
	if err := validateModuleSelectionFlags(false); err != nil {
		return err
	}
	scanOpts.Modules, scanOpts.PassiveModules = resolveModuleSelection(false)
	// Positional URLs combine with repeated -t/--target (positional first),
	// de-duplicated. `run` passes nil here since its positional arg is a phase.
	var schemeAssumed map[string]struct{}
	scanOpts.Targets, schemeAssumed = mergePositionalTargets(args, globalTargets)
	scanOpts.MarkSchemeAssumed(schemeAssumed)
	scanOpts.TargetsFilePaths = globalTargetFiles
	scanOpts.InputFileMode = globalInputMode
	scanOpts.Timeout = globalTimeout
	scanOpts.Concurrency = globalConcurrency
	scanOpts.MaxPerHost = globalMaxPerHost
	scanOpts.NoWafPacing = globalNoWafPacing
	// globalChanged, not cmd.Flags().Changed: pflag marks a flag Changed when only
	// its PHASE-QUALIFIED form was typed, so `--concurrency known-issue-scan=5`
	// would read as an explicit global concurrency — which makes the runner refuse
	// to read the very per-phase value that flag just wrote.
	scanOpts.ConcurrencyExplicitlySet = concurrencyKnob.globalChanged()
	scanOpts.MaxPerHostExplicitlySet = maxPerHostKnob.globalChanged()
	// --rate-limit applies whether or not it was typed. It used to be copied only
	// under cmd.Flags().Changed, which left an unset flag meaning "no cap at all"
	// while its own help text advertised a default of 100 — silence resolving to
	// unlimited, i.e. the fail-OPEN direction on a safety knob, and a documented
	// default the code never applied. The no-cap case now requires asking for it
	// (--rate-limit 0); negative values are rejected by the flag parser.
	scanOpts.RateLimit = globalRateLimit
	scanOpts.MaxHostError = globalMaxHostError
	scanOpts.MaxFindingsPerModule = globalMaxFindingsPerModule
	scanOpts.Verbose = globalVerbose
	scanOpts.Silent = globalSilent
	scanOpts.Debug = globalDebug
	scanOpts.DumpTraffic = globalDumpTraffic
	scanOpts.JSONOutput = globalJSON
	scanOpts.ProxyURL = globalProxy
	scanOpts.ConfigPath = globalConfig
	// Targets and TargetsFilePaths are bound above, so both are readable here.
	scanOpts.Stdin = resolveStdinInput(
		fileutil.HasStdin(),
		cmd.Flags().Changed("input"), globalInput,
		len(scanOpts.Targets), len(scanOpts.TargetsFilePaths),
	)
	scanOpts.OnlyPhase = globalOnly
	scanOpts.SkipPhases = globalSkipPhases
	scanOpts.ScopeOriginMode = globalScopeOrigin
	scanOpts.NoTechFilter = globalNoTechFilter
	scanOpts.OutputFormats = parseFormats(globalFormat)
	// Validated here, before any network or database work: a typo in --events
	// should fail in milliseconds, not after a 15-minute crawl whose whole reason
	// for running was the stream it never produced.
	if err := validateEventsFlag(scanOpts.Events); err != nil {
		return asUsageError(err)
	}
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	scanOpts.ProjectUUID = projectUUID

	if err := reconcileOutputFormats(scanOpts); err != nil {
		return err
	}
	// After reconcileOutputFormats, so the --json → jsonl mapping it performs is
	// already visible: --events --json is the same stdout collision as
	// --events --format jsonl, and checking before the mapping would miss it.
	if err := validateStdoutProtocol(scanOpts); err != nil {
		return err
	}

	// Stateless mode validation. The db-isolate precedence runs BEFORE the flag
	// is copied into Options, so the copy below is already the resolved value and
	// there is never a second place to clear.
	scanOpts.Stateless = globalStateless
	scanOpts.SplitByHost = globalSplitByHost
	dbIsolateYieldsToStateless(scanOpts.Stateless)
	scanOpts.DBIsolate = globalDBIsolate
	scanOpts.Parallel = globalParallel
	scanOpts.Resume = globalResume

	// Bare `vigolium scan --resume` (no -T/-t/stdin to scan): auto-discover the
	// progress manifest in the working directory and relaunch the saved run from
	// it, so the operator can resume a fan-out without re-typing every flag. With
	// targets present this is skipped and --resume continues through the normal
	// path (which narrows the fan-out to the unscanned tail).
	if scanOpts.Resume && len(scanOpts.TargetsFilePaths) == 0 && len(scanOpts.Targets) == 0 && !scanOpts.Stdin {
		return resumeFromDiscoveredManifest(cmd)
	}

	// --split-by-host names each per-host output file after the target's hostname
	// (acme-<host>.jsonl with a base, or just <host>.jsonl when no -o is given), so
	// the host already disambiguates files and -o/--output is OPTIONAL in that mode.
	// Only true when the flag will actually take effect (the dispatch only takes the
	// split path for a stateless multi-target file scan), so file-based formats still
	// require -o everywhere else.
	splitByHostNaming := scanOpts.SplitByHost && scanOpts.Stateless && len(scanOpts.TargetsFilePaths) > 0

	// Supplying a fuzz wordlist and disabling fuzzing states two opposite
	// intents. Resolving it silently either way leaves the operator believing
	// the other one took effect, and the two outcomes differ by thousands of
	// requests per host — so it is an error rather than a precedence rule.
	if scanOpts.NoDiscoveryFuzz && scanOpts.FuzzWordlistPath != "" {
		return fmt.Errorf("--no-discovery-fuzz and --discovery-wordlist are mutually exclusive (--discovery-wordlist exists to turn discovery fuzzing on; drop one)")
	}
	if err := validateParallelScan(scanOpts); err != nil {
		return err
	}
	if err := validateKeepDBOnError(scanOpts.Stateless); err != nil {
		return err
	}
	if scanOpts.Stateless {
		if globalDB != "" {
			return fmt.Errorf("--stateless and --db are mutually exclusive")
		}
		// Not warned under --json/--ci-output: those stream every record and
		// finding to stdout as they are written, so the results are NOT
		// discarded — they have already left the process by the time the
		// temporary database goes away. Telling an operator piping that stream
		// that their output is being thrown away is worse than saying nothing.
		if scanOpts.Output == "" && !scanOpts.Silent && !splitByHostNaming && !globalJSON && !globalCIOutput {
			fmt.Fprintf(os.Stderr,
				"%s %s: no %s set — scan results will be discarded with the temporary database. "+
					"Pass %s %s and %s %s to persist results.\n",
				terminal.WarnPrefix(),
				terminal.BoldCyan("--stateless"),
				terminal.BoldCyan("-o/--output"),
				terminal.BoldCyan("--output"),
				terminal.BoldYellow("<path>"),
				terminal.BoldCyan("--format"),
				terminal.BoldYellow("jsonl|html"))
		}
	}

	// Load settings from config file. A failure here is fatal: only an EXPLICIT
	// --config reaches this branch (clicommon.LoadSettings degrades a discovered
	// one to defaults with a warning), and running a scan under settings the
	// operator did not choose — a different database, a different scope, a
	// different rate limit — is worse than not running it. The old branch printed
	// "Config file not found, using defaults", which was wrong twice: the file is
	// usually found and unparseable, and "using defaults" was the problem.
	settings, err := clicommon.LoadSettings(scanOpts.ConfigPath)
	if err != nil {
		return err
	}

	if scanOpts.ScopeOriginMode != "" {
		settings.Scope.CLIOriginMode = scanOpts.ScopeOriginMode
	}

	scanOpts.RateLimitExplicitlySet = rateLimitKnob.globalChanged()

	// Override OAST URL if --oast-url flag is set
	if scanOpts.OastURL != "" {
		settings.OAST.OastURL = scanOpts.OastURL
	}

	// Override SQLite path if --db flag is set
	if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}

	// Apply --ext / --ext-dir overrides before validation
	applyGlobalExtFlagsToSettings(settings)

	// Validate extensions config
	if err := settings.DynamicAssessment.Extensions.Validate(); err != nil {
		return fmt.Errorf("invalid extensions configuration: %w", err)
	}

	// Validate scanning strategy config
	if err := settings.ScanningStrategy.Validate(); err != nil {
		return fmt.Errorf("invalid scanning strategy configuration: %w", err)
	}

	// Resolve --intensity to scanning profile name.
	if cmd.Flags().Changed("intensity") {
		profileName, resolvedIntensity, intensityErr := agent.ResolveNativeScanIntensity(globalIntensity)
		if intensityErr != nil {
			return intensityErr
		}
		scanOpts.Intensity = resolvedIntensity
		if !cmd.Flags().Changed("scanning-profile") {
			globalScanningProfile = profileName
		}
	}

	// Determine scanning profile: CLI --scanning-profile > config scanning_strategy.scanning_profile
	profileName := globalScanningProfile
	if profileName == "" {
		profileName = settings.ScanningStrategy.ScanningProfile
	}

	// Load and apply scanning profile before strategy resolution
	if profileName != "" {
		profilePath := settings.ScanningStrategy.ResolveProfilePath(profileName)
		profile, profileErr := config.LoadProfile(profilePath)
		if profileErr != nil {
			return fmt.Errorf("failed to load scanning profile %q: %w", profileName, profileErr)
		}
		if err := config.ApplyProfile(settings, profile); err != nil {
			return fmt.Errorf("failed to apply scanning profile %q: %w", profileName, err)
		}
		scanOpts.ScanningProfile = profileName
		zap.L().Info("Applied scanning profile", zap.String("profile", profileName), zap.String("path", profilePath))
	}

	// Propagate --rate-limit into the scanning pace so the known-issue-scan /
	// nuclei limiter honors it. Only when the operator typed the flag: the flag's
	// default IS the applied default, and a config file that wants a different one
	// sets scanning_pace.rate_limit.
	//
	// This has to run AFTER ApplyProfile. It used to run before, so a profile
	// carrying its own scanning_pace.rate_limit overwrote the typed flag and
	// known-issue-scan quietly paced itself at the profile's rate while the native
	// scan honored the flag. A flag the operator typed outranks a profile.
	if scanOpts.RateLimitExplicitlySet {
		settings.ScanningPace.RateLimit = globalRateLimit
	}

	// Apply scanning strategy as baseline before per-phase overrides
	scanOpts.ScanningStrategy = globalStrategy
	strategyName := globalStrategy
	if strategyName == "" {
		strategyName = settings.ScanningStrategy.DefaultStrategy
	}
	if strategyName != "" {
		phases, ok := settings.ScanningStrategy.GetStrategy(strategyName)
		if !ok {
			return fmt.Errorf("unknown scanning strategy %q; valid names: %v", strategyName, settings.ScanningStrategy.StrategyNames())
		}
		scanOpts.DiscoverEnabled = phases.Discovery
		scanOpts.SpideringEnabled = phases.Spidering
		scanOpts.KnownIssueScanEnabled = phases.KnownIssueScan
		if !phases.DynamicAssessment {
			scanOpts.SkipDynamicAssessment = true
		}
		// --external-harvest is a per-phase override on top of the strategy
		// baseline: when explicitly set on the command line it wins, so the
		// harvest phase can be toggled on demand without switching strategies
		// (e.g. --intensity balanced --external-harvest). When the flag is not
		// set, the strategy's ExternalHarvesting value applies.
		if !cmd.Flags().Changed("external-harvest") {
			scanOpts.ExternalHarvestEnabled = phases.ExternalHarvesting
		}
		// A strategy is a narrowing request, so its pace ceiling applies before
		// the per-phase overrides below and before the pace validation. Without
		// this `lite` selected fewer modules and opened the crawl exactly as wide
		// as `balanced`.
		applyStrategyPace(settings, phases, scanOpts)
		zap.L().Debug("Applied scanning strategy",
			zap.String("strategy", strategyName),
			zap.Bool("external_harvest", scanOpts.ExternalHarvestEnabled))
	}

	// Resolve heuristics check level
	// Precedence: --skip-heuristics > --heuristics-check > config default > "basic"
	scanOpts.HeuristicsCheck = "basic"
	if settings.ScanningStrategy.HeuristicsCheck != "" {
		scanOpts.HeuristicsCheck = settings.ScanningStrategy.HeuristicsCheck
	}
	if globalHeuristicsCheck != "" {
		scanOpts.HeuristicsCheck = globalHeuristicsCheck
	}
	if globalSkipHeuristics {
		scanOpts.HeuristicsCheck = "none"
	}

	// A hand-picked module selection (--module-id / -m) implies a targeted,
	// low-noise scan, so auto-skip the broad known-issue-scan pass before phase
	// selection resolves it. Must run after the strategy sets KnownIssueScanEnabled
	// and before ApplyNativePhaseSelection consumes SkipPhases.
	autoSkipKnownIssueScanForModuleSelection(scanOpts)

	// Before ApplyNativePhaseSelection: it applies the probe phase's own
	// defaults, and needs to know whether --record-redirect-chain was typed.
	if err := applyProbeFlags(scanOpts, cmd); err != nil {
		return err
	}
	if err := runner.ApplyNativePhaseSelection(scanOpts, func() {
		settings.DynamicAssessment.Extensions.Enabled = true
	}); err != nil {
		return err
	}
	warnInertProbeFlags(scanOpts, cmd)
	if err := applyExportScope(scanOpts); err != nil {
		return err
	}
	if scanOpts.OnlyPhase != "" {
		zap.L().Info("Phase isolation active", zap.String("only", scanOpts.OnlyPhase))
	}
	if len(scanOpts.SkipPhases) > 0 {
		zap.L().Info("Phases skipped", zap.Strings("skip", scanOpts.SkipPhases))
	}

	// HTML's -o requirement is covered by the generic formatNeedsOutput loop
	// below; only the phase restriction is html-specific.
	if scanOpts.HasFormat("html") {
		if phases := runner.OnlyPhaseSet(scanOpts.OnlyPhase); len(phases) > 0 {
			for p := range phases {
				if p != "discovery" && p != "spidering" {
					return fmt.Errorf("--format html is only supported for discovery and spidering phases")
				}
			}
		}
	}

	for _, f := range scanOpts.OutputFormats {
		if formatNeedsOutput(f) && scanOpts.Output == "" && !splitByHostNaming {
			return fmt.Errorf("--format %s requires -o/--output to specify the output file path (or pass --split-by-host to name per-host files by hostname)", f)
		}
	}

	// Multi-format requires -o/--output for file-based formats — unless
	// --split-by-host supplies a per-host base from each target's hostname.
	if len(scanOpts.OutputFormats) > 1 && scanOpts.Output == "" && !splitByHostNaming {
		return fmt.Errorf("multiple --format values require -o/--output to specify the base output path (or pass --split-by-host to name per-host files by hostname)")
	}

	// A negative budget is an already-expired deadline, not "unlimited": every
	// consumer feeds it straight to context.WithTimeout, so the phase it governs
	// does nothing and reports no error. Reject it before any side effect rather
	// than silently running an empty scan. (Zero stays legal and means "default"
	// for these two phases — see docs/configuration.md.)
	for _, d := range []struct {
		flag  string
		value time.Duration
	}{
		{"discover-max-time", scanOpts.DiscoverMaxDuration},
		{"spider-max-time", scanOpts.SpideringMaxDuration},
		{"scanning-max-duration", globalScanningMaxDuration},
	} {
		if d.value < 0 {
			return fmt.Errorf("--%s must not be negative, got %s", d.flag, d.value)
		}
	}

	// Override scanning_pace.max_duration if --scanning-max-duration flag is set.
	// This value plays two roles: it seeds the per-phase base (each phase scales
	// it by its duration_factor) AND caps total wall-clock time for the whole
	// scan via Options.ScanMaxDuration, so the per-phase factors distribute time
	// within the total budget rather than stacking sequentially past it.
	if cmd.Flags().Changed("scanning-max-duration") && globalScanningMaxDuration > 0 {
		settings.ScanningPace.MaxDuration = globalScanningMaxDuration.String()
		scanOpts.ScanMaxDuration = globalScanningMaxDuration
	}

	// Per-phase pace qualifiers (`--rate-limit known-issue-scan=20`) land in the
	// matching scanning_pace section, so ResolvePhase stays the one place
	// per-phase pace is merged. Applied after the phase selection is settled so a
	// qualifier naming a phase this run skips can be reported.
	applyPhasePaceOverrides(settings, scanOpts)

	// Validate and apply scanning_pace centralized speed control
	if err := settings.ScanningPace.Validate(); err != nil {
		return fmt.Errorf("invalid scanning_pace configuration: %w", err)
	}

	// Apply scanning_pace common values (precedence 4 — lowest after built-in defaults)
	pace := &settings.ScanningPace
	if !scanOpts.ConcurrencyExplicitlySet && pace.Concurrency > 0 {
		scanOpts.Concurrency = pace.Concurrency
	}
	if !scanOpts.MaxPerHostExplicitlySet && pace.MaxPerHost > 0 {
		scanOpts.MaxPerHost = pace.MaxPerHost
	}
	// The rate limit follows the same rung as its two siblings. It used to be the
	// odd one out: only a typed flag reached scanOpts, so a config file that set
	// scanning_pace.rate_limit paced known-issue-scan while the native scan ran
	// at the flag default — one invocation, two different documented rates.
	if !scanOpts.RateLimitExplicitlySet && pace.RateLimit > 0 {
		scanOpts.RateLimit = pace.RateLimit
	}

	// Apply scanning_pace.discovery.max_duration (precedence 3) to scanOpts
	discoveryPace := pace.ResolvePhase("discovery")
	if !cmd.Flags().Changed("discover-max-time") && discoveryPace.MaxDuration > 0 {
		scanOpts.DiscoverMaxDuration = discoveryPace.MaxDuration
	}

	// Apply scanning_pace.spidering.max_duration to scanOpts
	spideringPace := pace.ResolvePhase("spidering")
	if !cmd.Flags().Changed("spider-max-time") && spideringPace.MaxDuration > 0 {
		scanOpts.SpideringMaxDuration = spideringPace.MaxDuration
	}

	// Validate per-phase configs when enabled (strategy + CLI flags are the only sources)
	if scanOpts.DiscoverEnabled {
		if err := settings.Discovery.Validate(); err != nil {
			return fmt.Errorf("invalid discovery configuration: %w", err)
		}
	}
	if scanOpts.KnownIssueScanEnabled {
		// Apply CLI overrides for KnownIssueScan config
		if cmd.Flags().Changed("known-issue-scan-tags") {
			settings.KnownIssueScan.Tags = scanOpts.KnownIssueScanTags
		}
		if cmd.Flags().Changed("known-issue-scan-exclude-tags") {
			settings.KnownIssueScan.ExcludeTags = scanOpts.KnownIssueScanExcludeTags
		}
		if cmd.Flags().Changed("known-issue-scan-severities") {
			settings.KnownIssueScan.Severities = scanOpts.KnownIssueScanSeverities
		}
		// When known-issue-scan is the only phase requested, treat it as a focused
		// full scan and widen severities to all levels (unless the user pinned them
		// with --known-issue-scan-severities). The balanced default ships
		// critical+high, which would silently drop medium/low/info on an isolated run.
		if shouldWidenKnownIssueScanSeverities(scanOpts.OnlyPhase, cmd.Flags().Changed("known-issue-scan-severities"), settings.KnownIssueScan.Severities) {
			prev := strings.Join(settings.KnownIssueScan.Severities, ",")
			settings.KnownIssueScan.Severities = append([]string(nil), allKnownIssueScanSeverities...)
			if !scanOpts.Silent {
				fmt.Fprintf(os.Stderr, "  %s %s\n",
					terminal.TipPrefix(),
					terminal.Gray(fmt.Sprintf("running only known-issue-scan — adjusted known_issue_scan.severities from %s to all severities (%s) for this scan",
						prev, strings.Join(allKnownIssueScanSeverities, ","))))
			}
		}
		if cmd.Flags().Changed("known-issue-scan-templates-dir") {
			settings.KnownIssueScan.TemplatesDir = scanOpts.KnownIssueScanTemplatesDir
		}
		if err := settings.KnownIssueScan.Validate(); err != nil {
			return fmt.Errorf("invalid known-issue-scan configuration: %w", err)
		}
	}
	if scanOpts.SpideringEnabled {
		// Apply CLI overrides for spidering config
		if cmd.Flags().Changed("browser-engine") {
			settings.Spidering.BrowserEngine = scanOpts.SpideringBrowserEngine
		}
		if cmd.Flags().Changed("browsers") {
			settings.Spidering.BrowserCount = scanOpts.SpideringBrowserCount
		}
		if cmd.Flags().Changed("headless") {
			settings.Spidering.Headless = scanOpts.SpideringHeadless
		}
		// --headed is sugar for --headless=false and wins ties: a user who
		// explicitly asks to see the window gets a visible browser even if
		// --headless was also passed.
		if cmd.Flags().Changed("headed") && scanOpts.SpideringHeaded {
			settings.Spidering.Headless = false
		}
		if cmd.Flags().Changed("no-cdp") {
			settings.Spidering.NoCDP = scanOpts.SpideringNoCDP
		}
		if cmd.Flags().Changed("no-forms") {
			settings.Spidering.NoForms = scanOpts.SpideringNoForms
		}
		if cmd.Flags().Changed("browser-insecure") {
			settings.Spidering.BrowserCompat.SetAll(scanOpts.SpideringBrowserInsecure)
		}
		if cmd.Flags().Changed("require-auth") {
			settings.Spidering.RequireAuth = scanOpts.SpideringRequireAuth
		}
		if err := settings.Spidering.Validate(); err != nil {
			return fmt.Errorf("invalid spidering configuration: %w", err)
		}
	}
	if scanNoCarryBrowserSession {
		scanOpts.CarryBrowserSession = false
	}
	if scanOpts.ExternalHarvestEnabled {
		if len(settings.ExternalHarvester.Sources) == 0 {
			defaults := config.DefaultExternalHarvesterConfig()
			settings.ExternalHarvester.Sources = defaults.Sources
		}
		if err := settings.ExternalHarvester.Validate(); err != nil {
			return fmt.Errorf("invalid external harvester configuration: %w", err)
		}
	}

	// A target file that yields no targets is a misconfiguration in every mode;
	// fail loudly rather than running a zero-target scan that reports "completed".
	// (The --split-by-host path re-checks this in runStatelessTargetFile; the
	// shared fall-through below otherwise has no such guard.)
	if len(scanOpts.TargetsFilePaths) > 0 {
		fileTargets, terr := readTargetFilesLines(scanOpts.TargetsFilePaths)
		if terr != nil {
			return terr
		}
		if len(fileTargets) == 0 {
			return fmt.Errorf("target file(s) %s contain no targets", strings.Join(scanOpts.TargetsFilePaths, ", "))
		}
	}

	// DB-isolate parallel fan-out (-P > 1 with --db-isolate): scan each target as
	// an isolated child that merges into --db, then export one unified output from
	// the merged DB. -P 1 / a single target falls through to the single-process
	// path below, which already scans the whole file into one scratch and merges.
	if scanOpts.DBIsolate && scanOpts.Parallel > 1 && len(scanOpts.TargetsFilePaths) > 0 {
		return runIsolatedTargetsParallel(cmd, settings, strategyName)
	}

	// Multi-target stateless with --split-by-host: iterate per line with a fresh
	// temp DB each time, writing one per-host output file per target. Without the
	// flag, fall through to a single shared pass so the whole target file scans
	// into one temp DB and exports to one unified output file (all formats).
	if scanOpts.Stateless && len(scanOpts.TargetsFilePaths) > 0 && scanOpts.SplitByHost {
		return runStatelessTargetFile(cmd, settings, strategyName)
	}

	return executeNativeScan(cmd, settings, strategyName)
}

// executeNativeScan runs one full native scan pass against the current
// scanOpts. In stateless mode it allocates a fresh temporary SQLite database
// and tears it down on return so callers can invoke it once per target.
func executeNativeScan(cmd *cobra.Command, settings *config.Settings, strategyName string) (err error) {
	// Wall-clock anchor for the whole scan pass, surfaced in the completion
	// summary. Captured before DB setup so it reflects total time, not just the
	// scanning legs.
	scanStart := time.Now()

	// Stateless mode: create a temporary SQLite database for this run only.
	var statelessDBPath string
	if scanOpts.Stateless {
		tmpFile, tmpErr := scratch.CreateTemp("stateless-*.sqlite")
		if tmpErr != nil {
			return fmt.Errorf("failed to create temporary database: %w", tmpErr)
		}
		statelessDBPath = tmpFile.Name()
		_ = tmpFile.Close()
		// Registered first, so it runs LAST (defers are LIFO) — after db.Close
		// and after the db-isolate merge. Removing or preserving a database that
		// still has an open handle would be the wrong order in both directions.
		defer func() { err = releaseStatelessDB(statelessDBPath, err) }()

		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = statelessDBPath
	}

	// One signal handler for the whole invocation, installed before any of the
	// setup below. The old one went in immediately before RunNativeScan, so a
	// Ctrl+C during a schema migration, a session login or target expansion was
	// not trapped by the scan at all.
	signals := startScanSignals(scanStart)
	defer signals.stop()

	// The terminal event is emitted HERE, before --db-isolate registers its
	// merge, so LIFO runs it after that merge has either landed or failed: the
	// stream's last word on the scan must include whether the results reached
	// the database the operator named. emitTerminalEvent is assigned later (the
	// emitter needs the open database and the pinned uuid), so the holder is
	// nil-checked rather than pre-filled.
	var emitTerminalEvent func(error)
	defer func() {
		if emitTerminalEvent != nil {
			emitTerminalEvent(err)
		}
	}()

	// DB-isolate mode: scan into a private temporary SQLite database, then merge
	// the results into the real --db (or default DB) once the scan finishes, so
	// many parallel scan processes can share one --db without contending on a
	// single SQLite writer. Registered before the DB opens so the merge runs
	// after db.Close() (defers are LIFO), once the scratch's writes are flushed.
	finish, dErr := dbIsolateBegin(settings, scanOpts.Silent)
	if dErr != nil {
		return dErr
	}
	defer func() { err = finish(err) }()

	if err := settings.Database.Validate(); err != nil {
		return fmt.Errorf("invalid database configuration: %w", err)
	}

	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("failed to create database connection: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx, cancelSetup := setupContext(settings)
	defer cancelSetup()
	if err := db.EnsureSchemaReady(ctx); err != nil {
		return wrapSetupError(ctx, db.Driver(), "database schema setup", err)
	}

	repo := database.NewRepository(db)
	zap.L().Debug("Database initialized successfully",
		zap.String("driver", db.Driver()))

	// Stateless + -o + default console format: capture the full verbose
	// console session (banner, scan summary, phase progress, result lines)
	// into the output file as a faithful transcript, instead of the minimal
	// per-record DB export. Started before printScanSummary so the banner is
	// included. Other --format values keep the post-scan DB export below.
	transcriptActive := scanOpts.Stateless && scanOpts.Output != "" &&
		!scanOpts.Silent && !globalJSON && !globalCIOutput &&
		len(scanOpts.OutputFormats) == 1 && scanOpts.OutputFormats[0] == "console"
	if transcriptActive {
		transcriptPath := scanOpts.Output
		tc, tErr := startTranscriptCapture(transcriptPath)
		if tErr != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to start transcript capture (%v); falling back to record export\n",
				terminal.WarnPrefix(), tErr)
			transcriptActive = false
		} else {
			defer func() {
				tc.Stop()
				fmt.Fprintf(os.Stderr, "%s Transcript written to %s\n",
					terminal.InfoSymbol(), terminal.Cyan(transcriptPath))
			}()
		}
	}

	// Pin the scan UUID before the banner so the config summary can show it and
	// the runner reuses the same identifier instead of minting its own.
	scanOpts.ScanUUID = pinnedOrNewUUID(scanOpts.ScanUUID)

	// Machine event stream (--events). Installed here, after the uuid is pinned
	// and the database is open, so scan.started can name both. The totals are
	// gathered as the OUTERMOST of the post-scan defers below — while the
	// database is still open — and the line itself is written by the holder
	// registered above, after the db-isolate merge.
	prepareTerminalEvent, emitEvents, evErr := beginScanEventStream(db, scanOpts, settings, strategyName, scanStart)
	if evErr != nil {
		return evErr
	}
	emitTerminalEvent = emitEvents
	defer func() { prepareTerminalEvent(err) }()
	// Print scan summary banner (after DB init so we can show HTTP record count)
	printScanSummary(scanOpts, settings, strategyName, repo, "")
	scanOpts.ScanConfigPrinted = true

	// For stateless mode with --output: suppress StandardWriter's live file
	// output and export the full database post-scan. This covers console
	// (default), jsonl, and report formats so -o always produces a populated
	// file even when the phase only ingests HTTP records (e.g. discovery) and
	// emits no findings for StandardWriter to write.
	var statelessOutputPath string
	if scanOpts.Stateless && scanOpts.Output != "" {
		statelessOutputPath = scanOpts.Output
		savedOutput := scanOpts.Output
		scanOpts.Output = "" // prevent StandardWriter from creating the output file
		defer func() { scanOpts.Output = savedOutput }()
	}
	// Defer stateless export so all exit paths are covered automatically. When
	// a transcript is being captured, skip the console export so it does not
	// truncate and clobber the transcript file at the same path.
	defer func() {
		recordExportFailure(&err, finishStatelessExport(db, scanOpts, statelessOutputPath, transcriptActive))
	}()
	// Persisted (non-stateless) --format jsonl emits the same project-scoped
	// unified envelope post-scan instead of StandardWriter's live nuclei stream
	// (suppressed via DeferredJSONLExport). No-ops for stateless and CI runs.
	defer func() {
		if skipDeferredJSONLExport(err, scanOpts.Stateless, statelessOutputPath) {
			return
		}
		recordExportFailure(&err, finishScanJSONLExport(db, scanOpts))
	}()

	// If -i was explicitly provided, use two-phase ingest-then-scan
	hasInputFile := globalInput != "" && globalInput != "-"
	if hasInputFile {
		return runScanWithIngest(settings, db, repo, scanStart)
	}

	// If no targets/input/stdin, fall back to scanning DB records
	hasTargets := len(scanOpts.Targets) > 0
	hasTargetFile := len(scanOpts.TargetsFilePaths) > 0
	hasStdin := scanOpts.Stdin
	if !hasTargets && !hasTargetFile && !hasStdin {
		return runDBScan(settings, db, repo, scanStart)
	}

	// Promote -T/--target-file lines into scanOpts.Targets so the phases that
	// seed from the CLI target list (spidering's crawl seeds, deparos content
	// discovery) actually receive them. Runs after the fan-out dispatch in
	// runNativeScan and after printScanSummary, both of which read
	// TargetsFilePaths, and before the stdin block so a -T list survives the
	// raw-stdin SliceSource branch too.
	if err := seedTargetsFromTargetFiles(scanOpts); err != nil {
		return err
	}

	// Smart stdin detection: peek at piped content to detect raw HTTP or curl
	// format. Skipped when -I names a specific non-list format — that is an
	// explicit instruction the detector must not overrule — but an explicit
	// -I urls still comes through here, because the point of this block is to
	// land a piped URL list in scanOpts.Targets rather than in a StdinSource
	// the target-seeded phases never see. (An unset -I defaults to "urls", so
	// the target-list test alone admits the auto-detect case too.)
	inputModeExplicit := cmd.Flags().Changed("input-mode")
	if hasStdin && source.IsTargetListFormat(scanOpts.InputFileMode) {
		raw, readErr := readStdin()
		if readErr != nil {
			return fmt.Errorf("failed to read stdin: %w", readErr)
		}
		content := strings.TrimSpace(string(raw))
		// An explicit -I urls pins the format; only an unset -I is auto-detected.
		if content != "" && !inputModeExplicit {
			detected := detect.DetectStdinFormat(content)
			if detected != detect.FormatURLs {
				// Raw HTTP or curl — parse eagerly and use SliceSource
				items, parseErr := detect.ParseStdinContent(content, detected)
				if parseErr != nil {
					return fmt.Errorf("failed to parse stdin as %s: %w", detected, parseErr)
				}
				inputSrc := source.NewSliceSource(items, scanOpts.Modules)
				scanOpts.Stdin = false

				scanRunner, runnerErr := runner.NewWithInputSource(scanOpts, inputSrc)
				if runnerErr != nil {
					return fmt.Errorf("failed to create scan runner: %w", runnerErr)
				}

				scanRunner.SetSettings(settings)
				if repo != nil {
					scanRunner.SetRepository(repo)
				}

				// Close before reporting (so any flush lands in the DB the reports
				// read) — matching the main runner.New path below.
				scanErr := runNativeScanPass(scanRunner)
				if scanErr != nil {
					return scanErr
				}
				recordExportFailure(&err, reportNativeScanSuccess(db, settings, repo, scanStart))
				return err
			}
		}
		// URLs — fall through to the runner.New() path below. Stdin is already
		// drained, so the lines are passed as targets rather than left to a
		// StdinSource (which would also leave the target-seeded phases empty).
		seedTargetsFromStdinLines(scanOpts, content)
		scanOpts.Stdin = false
	}

	// Returned, not zap.L().Fatal: Fatal calls os.Exit(1), which runs none of the
	// defers above — the event stream never writes its scan.finished, the
	// stateless export never materializes, the database is never closed, and the
	// -j error envelope is never emitted. A consumer saw a truncated stream and
	// exit 1 with no stated cause.
	scanRunner, err := runner.New(scanOpts)
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	if scanRunner == nil {
		return nil
	}

	// Set settings and repository on runner
	scanRunner.SetSettings(settings)
	if repo != nil {
		scanRunner.SetRepository(repo)
	}

	scanErr := runNativeScanPass(scanRunner)
	// A failed scan must abort visibly: returning the error makes cobra print it
	// (it's an ErrorLevel-and-above world by default, so the old INFO log was
	// invisible without --verbose) and exit non-zero, and skips the "completed"
	// banner below — which would otherwise claim success over stale/partial DB
	// data (e.g. a session-init failure where no scanning ran at all).
	if scanErr != nil {
		return scanErr
	}

	recordExportFailure(&err, reportNativeScanSuccess(db, settings, repo, scanStart))
	return err
}

// reportNativeScanSuccess runs the post-scan tail shared by every native-scan
// entry point: report-file generation, result upload, and the completion
// summary banner. It is invoked only when RunNativeScan returned no error — a
// failed scan returns its error to the caller instead, so this success banner
// never paints over a scan that didn't actually run. A scan curtailed by
// --scanning-max-duration returns nil (graceful), so time-boxed partial scans
// still reach this path and keep their reports.
//
// It returns the joined failures of the three artifact-producing steps. The
// summary, the finding/traffic prints and the gate still run after one of them
// fails, deliberately: the scan's results exist and are worth showing, and the
// gate's verdict is about the findings rather than about the files. What changes
// is that the caller folds the error in with recordExportFailure, so a run that
// did not write what it was asked for exits non-zero instead of printing
// "Failed to generate html" and exiting 0.
func reportNativeScanSuccess(db *database.DB, settings *config.Settings, repo *database.Repository, scanStart time.Time) error {
	// The upload is the one step that is NOT shared with the lightweight
	// commands: it is opt-in on --upload-results, but it also fires the
	// configured webhook unconditionally, and scan-url/scan-request have never
	// done that. Keeping it here rather than in reportScanCompletion is what lets
	// both callers share the rest without changing what either one emits.
	return errors.Join(
		reportScanCompletion(db, settings, repo, scanOpts, scanStart),
		uploadNativeScanResults(settings, scanOpts, repo),
	)
}

// reportScanCompletion is the artifact-and-report tail every native-scan entry
// point runs, lightweight commands included: reports, the fs tree, the
// completion summary, the optional finding/traffic prints, and the --fail-on
// gate. opts is a parameter rather than the scanOpts global precisely so
// runRunnerScan can call it — it was a hand-copy of this body for want of one
// argument.
func reportScanCompletion(
	db *database.DB,
	settings *config.Settings,
	repo *database.Repository,
	opts *types.Options,
	scanStart time.Time,
) error {
	// maybeGenerateReports self-guards on opts.Output=="" (blanked on the
	// stateless path, where finishStatelessExport handles reports instead).
	artifacts := errors.Join(
		maybeGenerateReports(db, opts),
		finishFSExport(db, opts),
	)
	if !opts.Silent {
		hosts := summaryScopeHosts(context.Background(), repo, settings, opts.Targets, opts.ProjectUUID, opts.ScanUUID)
		printScanCompletionSummary(repo, opts.ProjectUUID, hosts, time.Since(scanStart))
	}
	maybePrintScanFindings(context.Background(), db, opts.ProjectUUID, opts.ScanUUID)
	maybePrintScanTraffic(context.Background(), db, opts.ProjectUUID)
	evaluateFailOnGate(repo, opts.ProjectUUID, opts.ScanUUID, opts.Silent)
	return artifacts
}

// skipDeferredJSONLExport reports whether the deferred persisted-jsonl export
// must not run.
//
// One predicate, because every native-scan entry point registers that defer and
// the rule is subtle enough that a second copy drifts:
//
//   - stateless WITH -o: finishStatelessExport already materializes every format
//     to the file, and opts.Output is temporarily blanked, so
//     finishScanJSONLExport cannot detect this case itself — without this guard
//     it would ALSO stream the envelope to stdout (double output).
//   - a hard-failed persisted scan: don't write a success-looking file or stream
//     of stale or partial project data (mirrors the skipped "completed" banner).
//     Stateless is exempt — its temp DB is discarded after the run, so the stdout
//     stream is the only chance to surface whatever was found.
//   - an export failure is NOT a failed scan: an unwritable html path says
//     nothing about the findings, and skipping the jsonl export over it loses the
//     one format that would still have landed. Each --format is attempted
//     independently (see isExportFailure).
func skipDeferredJSONLExport(err error, stateless bool, statelessOutputPath string) bool {
	if stateless && statelessOutputPath != "" {
		return true
	}
	return err != nil && !stateless && !isExportFailure(err)
}

// runStatelessTargetFile iterates over each non-blank line in
// scanOpts.TargetsFilePaths, allocating an isolated temporary database per
// target and tearing it down before moving on. When --output is provided, the
// output path is suffixed with the target's hostname so per-target results do
// not overwrite each other. This is the --split-by-host path; without that flag
// runScanCmd instead runs a single shared pass over the whole target file for a
// unified output file.
func runStatelessTargetFile(cmd *cobra.Command, settings *config.Settings, strategyName string) error {
	targets, err := readTargetFilesLines(scanOpts.TargetsFilePaths)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("target file(s) %s contain no targets", strings.Join(scanOpts.TargetsFilePaths, ", "))
	}

	// Fan-out dispatch: any multi-target run routes through the fan-out, which
	// scans targets as isolated child processes and prints the compact
	// start/done progress lines plus a roll-up. With -P > 1 it runs several at a
	// time; at -P 1 the same path serializes (one worker slot) so a sequential
	// run gets the identical progress output — only the concurrency differs. A
	// single target keeps the in-process path below (live per-target console,
	// full banner) — there is nothing to fan out and no exec overhead.
	if len(targets) > 1 {
		return runStatelessTargetsParallel(cmd, settings, strategyName, targets)
	}

	if scanOpts.Resume && !scanOpts.Silent {
		fmt.Fprintf(os.Stderr, "%s --resume currently applies only to the parallel fan-out (-S -T --split-by-host -P>1); running a full sequential scan over all targets\n",
			terminal.WarnPrefix())
	}

	origTargets := append([]string(nil), scanOpts.Targets...)
	origFiles := scanOpts.TargetsFilePaths
	origOutput := scanOpts.Output
	origPrinted := scanOpts.ScanConfigPrinted
	origCaptured := scanOpts.CapturedConsole
	scanOpts.TargetsFilePaths = nil
	defer func() {
		scanOpts.Targets = origTargets
		scanOpts.TargetsFilePaths = origFiles
		scanOpts.Output = origOutput
		scanOpts.ScanConfigPrinted = origPrinted
		scanOpts.CapturedConsole = origCaptured
	}()

	// Per-target console capture: mirror each target's live console session to a
	// sibling <output>-<host>.console.log — the same artifact the -P parallel
	// fan-out writes for every child, so a sequential (non-P) split-by-host run is
	// no longer missing it. Only worthwhile when the requested output is deferred
	// to files (jsonl/html/sqlite/fs): with a plain console format the console IS
	// the output and a second copy would be redundant (and would nest with the
	// console-format transcript executeNativeScan starts itself). Skipped when
	// there's no live console to capture (silent, -j JSON, CI output). Setting
	// CapturedConsole makes each per-target run read like a console scan (findings
	// streamed in human-readable form, no repetitive "[status]" ticker), matching
	// what the -P children write; the terminal still sees everything live because
	// the capture passes bytes through to the real streams.
	captureConsole := !scanOpts.Silent && !globalJSON && !globalCIOutput && hasDeferredOutputFormat(scanOpts.OutputFormats)
	if captureConsole {
		scanOpts.CapturedConsole = true
	}

	multi := len(targets) > 1
	for i, target := range targets {
		scanOpts.Targets = []string{target}
		// Force the scan summary banner to print per target.
		scanOpts.ScanConfigPrinted = false
		// This function is only reached on the --split-by-host path, so name each
		// output file by host. With a base path that's "<base>-<host>.<ext>"; with
		// no -o it's just "<host>.<ext>" (perTargetOutputPath handles the empty
		// base). A single target with a base keeps the literal -o (no host suffix).
		switch {
		case origOutput == "":
			scanOpts.Output = perTargetOutputPath("", target, i)
		case multi:
			scanOpts.Output = perTargetOutputPath(origOutput, target, i)
		default:
			scanOpts.Output = origOutput
		}

		if !scanOpts.Silent {
			fmt.Fprintf(os.Stderr, "\n%s %s %s\n",
				terminal.Purple(terminal.SymbolTarget),
				terminal.BoldHiBlue(fmt.Sprintf("[%d/%d]", i+1, len(targets))),
				terminal.HiCyan(target))
		}

		// Start the per-target console capture after the [i/N] header (a parent-loop
		// line, not part of the scan) so the log opens on the scan banner — the same
		// shape a -P child writes. Anchored to the resolved per-target output so it
		// lands next to the sqlite/html files as <output>-<host>.console.log.
		var (
			tc          *transcriptCapture
			consolePath string
		)
		if captureConsole {
			consolePath = perTargetConsolePath(scanOpts.Output)
			if c, terr := startTranscriptCapture(consolePath); terr != nil {
				fmt.Fprintf(os.Stderr, "%s Failed to capture console log to %s (%v); scanning without it\n",
					terminal.WarnPrefix(), terminal.Cyan(consolePath), terr)
				consolePath = ""
			} else {
				tc = c
			}
		}

		scanErr := executeNativeScan(cmd, settings, strategyName)

		// Restore the real streams before printing where the log landed, so that
		// note reaches the terminal instead of being swallowed into the log file.
		if tc != nil {
			tc.Stop()
		}
		if consolePath != "" && !scanOpts.Silent {
			fmt.Fprintf(os.Stderr, "%s Console log written to %s\n",
				terminal.InfoSymbol(), terminal.Cyan(consolePath))
		}

		if scanErr != nil {
			zap.L().Error("Stateless target scan failed",
				zap.String("target", target),
				zap.Error(scanErr))
			fmt.Fprintf(os.Stderr, "%s scan for %s failed: %v\n",
				terminal.WarnPrefix(), terminal.HiCyan(target), scanErr)
			// Continue with remaining targets instead of aborting the batch.
		}
	}

	return nil
}

// hasDeferredOutputFormat reports whether formats requests any file-based output
// (jsonl/html/sqlite/fs) rather than only the live console. It's the signal that
// a captured <output>.console.log is worth writing: with a plain console format
// the console already IS the output.
func hasDeferredOutputFormat(formats []string) bool {
	for _, f := range formats {
		if f != "console" {
			return true
		}
	}
	return false
}

// readTargetFilesLines reads every target file in paths (each one URL/address
// per line) and concatenates their lines in order, preserving duplicates. It is
// the multi-file (`-T a -T b`) form of readTargetFileLines.
func readTargetFilesLines(paths []string) ([]string, error) {
	var lines []string
	for _, p := range paths {
		fileLines, err := readTargetFileLines(p)
		if err != nil {
			return nil, err
		}
		lines = append(lines, fileLines...)
	}
	return lines, nil
}

// targetFileLines memoizes the targets each -T file yielded. One invocation asks
// for the same file three times — the empty-file guard in runNativeScan, the
// banner's count, and the promotion into Options.Targets — and each parse is two
// full reads of the file (burpscope.SniffFile reads it whole, then the line
// scanner does), so caching the LINES rather than just the count is what keeps a
// large recon list to one pass. For a Burp scope export it also avoids
// re-expanding the include rules each time.
var (
	targetFileLinesMu sync.Mutex
	targetFileLines   = map[string][]string{}
)

// countTargetFileTargets returns the number of targets the given -T files
// contribute. It answers from the cache readTargetFileLines fills during flag
// validation and only falls back to reading when a caller reaches the banner
// first. A read failure reports what it has: the banner must never be the thing
// that fails a scan.
func countTargetFileTargets(paths []string) int {
	total := 0
	for _, p := range paths {
		lines, err := readTargetFileLines(p)
		if err != nil {
			continue
		}
		total += len(lines)
	}
	return total
}

// readTargetFileLines reads a target file (one URL or address per line),
// trimming whitespace and skipping blank lines and `#` comments. A Burp Suite
// scope export is expanded into the URLs its include rules describe instead —
// see expandBurpScopeTargets. Repeat calls for the same path are served from
// targetFileLines.
func readTargetFileLines(path string) ([]string, error) {
	targetFileLinesMu.Lock()
	cached, ok := targetFileLines[path]
	targetFileLinesMu.Unlock()
	if ok {
		return cached, nil
	}
	lines, err := parseTargetFileLines(path)
	if err != nil {
		return nil, err
	}
	targetFileLinesMu.Lock()
	targetFileLines[path] = lines
	targetFileLinesMu.Unlock()
	return lines, nil
}

// isTargetLine reports whether an already-trimmed line names a target, i.e. is
// neither blank nor a `#` comment. The -T file reader and the piped-stdin
// promotion both ask through here, so the two accept the same list verbatim —
// the contract seedTargetsFromStdinLines documents, with one rule behind it.
// (The file path stays on a bufio.Scanner rather than sharing targetLinesFrom:
// it streams, and its buffer cap is what keeps a very long URL line from
// silently truncating.)
func isTargetLine(line string) bool {
	return line != "" && !strings.HasPrefix(line, "#")
}

// targetLinesFrom splits target-list content into targets under isTargetLine.
func targetLinesFrom(content string) []string {
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		if line = strings.TrimSpace(line); isTargetLine(line) {
			lines = append(lines, line)
		}
	}
	return lines
}

func parseTargetFileLines(path string) ([]string, error) {
	if burpscope.SniffFile(path) {
		return expandBurpScopeTargets(path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open target file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); isTargetLine(line) {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read target file %q: %w", path, err)
	}
	return lines, nil
}

// perTargetOutputPath returns a target-specific variant of basePath so that
// per-target stateless exports do not clobber each other. The sanitized
// host[:port] is inserted before the format extension; if the target can't be
// parsed as a URL or yields an empty host, the iteration index is used.
func perTargetOutputPath(basePath, target string, idx int) string {
	stripped := types.StripFormatExtension(basePath)
	suffix := perTargetSuffix(target, idx)
	rest := strings.TrimPrefix(basePath, stripped)
	// No base path (e.g. --split-by-host without -o): the per-host file is named by
	// the host alone (<host><ext>), with no leading "-" separator to a base.
	if stripped == "" {
		return suffix + rest
	}
	return stripped + "-" + suffix + rest
}

// perTargetSuffix derives a filesystem-safe suffix from a target URL/host.
func perTargetSuffix(target string, idx int) string {
	candidate := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		candidate = u.Host
	}
	candidate = strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_",
	).Replace(candidate)
	candidate = strings.Trim(candidate, "._")
	if candidate == "" {
		return fmt.Sprintf("%03d", idx+1)
	}
	return candidate
}

// runScanWithIngest delegates to the Runner's 3-phase pipeline when -i is provided.
// The Runner's Phase 1 ingests the input file, Phase 2 runs KnownIssueScan if enabled,
// and Phase 3 scans from DB with all modules.
func runScanWithIngest(settings *config.Settings, db *database.DB, repo *database.Repository, scanStart time.Time) error {
	// Auto-detect format from file extension
	inputFormat := globalInputMode
	if inputFormat == "urls" {
		if detected := detectInputFormat(globalInput); detected != "" {
			inputFormat = detected
			zap.L().Info("Auto-detected input format", zap.String("format", inputFormat))
		}
	}

	// OpenAPI defaults: auto-enable UseSpecServers when no -t given
	useSpecServers := globalSpecURL
	if (inputFormat == "openapi" || inputFormat == "swagger") &&
		len(globalTargets) == 0 && !useSpecServers {
		useSpecServers = true
		zap.L().Info("Auto-enabled --spec-url (no -t provided)")
	}

	// Create InputSource from the input file
	inputSource, err := source.NewInputSource(source.SourceConfig{
		Targets:       globalTargets,
		FilePath:      globalInput,
		Format:        inputFormat,
		BufferSize:    100,
		EnableModules: scanOpts.Modules,
	})
	if err != nil {
		return fmt.Errorf("failed to create input source: %w", err)
	}

	// Configure spec-format options on the file parser. FirstFileSource unwraps a
	// MultiSource so the override still lands when -t is combined with -i (a bare
	// *FileSource assertion would miss it). The -t target is the OpenAPI BaseURL /
	// WSDL endpoint host override; the shared --spec-header / --spec-var flags
	// carry headers and field values.
	if fs := source.FirstFileSource(inputSource); fs != nil {
		var targetURL string
		if len(globalTargets) > 0 {
			targetURL = globalTargets[0]
		}
		switch parser := fs.Format().(type) {
		case *openapi.Format:
			parser.SetOpenAPIOptions(openapi.Options{
				BaseURL:              targetURL,
				UseSpecServers:       useSpecServers,
				Headers:              ingestParseHeaders(globalSpecHeader),
				Variables:            ingestParseVariables(globalSpecVar),
				DefaultFallbackValue: globalSpecDefault,
			})
		case *wsdl.Format:
			parser.SetWSDLOptions(wsdl.Options{
				EndpointURL: targetURL,
				Headers:     ingestParseHeaders(globalSpecHeader),
				Variables:   ingestParseVariables(globalSpecVar),
			})
		}
	}

	// Create Runner with the input source — RunNativeScan handles all 3 phases
	scanRunner, err := runner.NewWithInputSource(scanOpts, inputSource)
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)

	// A failed scan must abort visibly (return non-zero, skip the success
	// banner) rather than logging at INFO and claiming completion — matching the
	// direct-target path. See reportNativeScanSuccess.
	//
	// runNativeScanPass owns the release, replacing a `defer Close()`: on the
	// interrupted-before-start path the runner is Discarded, and a deferred
	// Close would then block for the whole shutdown timeout waiting on a run
	// that never happened.
	if err := runNativeScanPass(scanRunner); err != nil {
		return err
	}

	var tailErr error
	recordExportFailure(&tailErr, reportNativeScanSuccess(db, settings, repo, scanStart))
	return tailErr
}

// runDBScan scans records already in the database (no explicit targets).
// Delegates to RunNativeScan(): Phase 1 is a no-op (empty source),
// Phase 2 runs KnownIssueScan if enabled, Phase 3 reads existing DB records.
func runDBScan(settings *config.Settings, db *database.DB, repo *database.Repository, scanStart time.Time) error {
	// Create Runner with an empty input source — Phase 1 becomes a no-op
	scanRunner, err := runner.NewWithInputSource(scanOpts, &emptySource{})
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)

	// A failed scan must abort visibly (return non-zero, skip the success
	// banner) rather than logging at INFO and claiming completion — matching the
	// direct-target path. See reportNativeScanSuccess and runNativeScanPass.
	if err := runNativeScanPass(scanRunner); err != nil {
		return err
	}

	var tailErr error
	recordExportFailure(&tailErr, reportNativeScanSuccess(db, settings, repo, scanStart))
	return tailErr
}

// emptySource is an InputSource that immediately returns io.EOF.
// Used when no external input is provided (DB-only scan mode).
type emptySource struct{}

func (e *emptySource) Next(_ context.Context) (*work.WorkItem, error) { return nil, io.EOF }
func (e *emptySource) Close() error                                   { return nil }

// generateReportFromDB queries data from the database and generates a report at
// the specified output path using the given generator function. projectUUID
// scopes the query: "" exports the whole DB (stateless temp DB), a non-empty
// value scopes to one project so a persisted report matches the sibling jsonl
// export and never leaks other projects' findings. scanUUID further restricts the
// findings to a single scan (empty = all of the project's), so a persisted scan's
// report reflects that run rather than the project's whole history.
func generateReportFromDB(ctx context.Context, db *database.DB, outputPath string, omitResponse bool, projectUUID, scanUUID string, rf reportFormatEntry, onTrim func(output.ReportTrimInfo)) error {
	autoTarget, autoDuration := computeReportMeta(ctx, db)
	meta := output.HTMLReportMeta{
		Title:           "Vigolium Scan Report",
		Version:         getVersion(),
		ScanDuration:    autoDuration,
		ScanTarget:      autoTarget,
		ReportSharedURL: scanReportSharedURL,
		// nil keeps the generator's default inline "Note:" line; the stateless
		// export path passes a collector so the trim summary folds into "Exports".
		OnTrim: onTrim,
	}
	// Prefer the streaming generator when the format has one: it renders the
	// report by pulling rows one at a time instead of loading the whole result
	// set into memory. The HTML renderer derives the displayed request/response
	// bodies from the raw bytes (HTTPRecord.MarshalJSON) and only then drops the
	// redundant raw_request/raw_response copies, so those columns MUST be loaded;
	// honor only an explicit --omit-response, never force it on here.
	if rf.streamGenerate != nil {
		produce := func(emit func(any) error) error {
			// Reports render the whole envelope: --export-only documents itself as
			// narrowing the jsonl stream, and a report with its findings silently
			// removed is worse than no report.
			return streamExportData(ctx, db, fullExportScope, omitResponse, projectUUID, scanUUID, emit)
		}
		return rf.streamGenerate(produce, outputPath, meta)
	}
	// Materialized branch: MUST carry scanUUID too. The streaming branch above
	// already scoped to the current scan, but `report`, `pdf` and `sarif` have no
	// streaming generator, so they fell through here and rendered the project's
	// whole finding history as if it were this run's result — contradicting this
	// function's own contract and, for sarif, re-reporting every historical finding
	// to GitHub code scanning on each scan.
	items, err := queryExportData(ctx, db, omitResponse, projectUUID, scanUUID)
	if err != nil {
		return err
	}
	return rf.generate(items, outputPath, meta)
}

// parseFormats splits a comma-separated format string, defaulting to "console".
func parseFormats(raw string) []string {
	parts := strings.Split(raw, ",")
	formats := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			formats = append(formats, p)
		}
	}
	if len(formats) == 0 {
		return []string{"console"}
	}
	return formats
}

// scanOutputFormats is the canonical set of --format values the scan commands
// and the agentic-scan -S export accept — one list, because both materialize
// their output through the same exporter (finishStatelessExport).
var scanOutputFormats = []string{"console", "jsonl", "html", "report", "pdf", "sarif", "sqlite", "fs"}

// formatAliases maps every accepted alias spelling onto its canonical format
// name, so only canonical names reach the downstream switches and path helpers.
//
// One table for both `--format` flavors rather than one per command: `fs` is
// valid on the scan commands AND on `vigolium export`, so a per-command table
// would have to carry its aliases twice — the kind of split that leaves an
// alias working on one command and unknown on the other. An alias that
// canonicalizes to a format a given command does not accept still fails that
// command's own valid-list check, and the error quotes what the user typed.
var formatAliases = map[string]string{
	"md":          "markdown",
	"gz":          "bundle",
	"sqlite3":     "sqlite",
	"db":          "sqlite",
	"file-system": "fs",
}

// canonicalFormat resolves one --format token to its canonical name. Matching is
// case-insensitive, which `vigolium export` already was; the scan side used to
// fold case only for the sqlite aliases, so `--format SQLITE` worked while
// `--format HTML` did not.
func canonicalFormat(token string) string {
	lower := strings.ToLower(strings.TrimSpace(token))
	if canonical, ok := formatAliases[lower]; ok {
		return canonical
	}
	return lower
}

// normalizeScanFormats canonicalizes aliases in place and rejects anything
// outside scanOutputFormats. Shared by reconcileOutputFormats and
// planAgentStateless so a format accepted by `scan -S` is accepted by
// `agent autopilot -S` too.
func normalizeScanFormats(formats []string) error {
	for i, f := range formats {
		formats[i] = canonicalFormat(f)
		if !slices.Contains(scanOutputFormats, formats[i]) {
			return fmt.Errorf("invalid --format value %q; valid formats: %s", f, strings.Join(scanOutputFormats, ", "))
		}
	}
	return nil
}

// reconcileOutputFormats applies --json and --ci-output-format overrides to
// OutputFormats and validates the result. Shared by scan and scan-url commands.
func reconcileOutputFormats(opts *types.Options) error {
	if globalJSON && len(opts.OutputFormats) == 1 && opts.OutputFormats[0] == "console" {
		opts.OutputFormats = []string{"jsonl"}
	}
	if opts.HasFormat("jsonl") {
		opts.JSONOutput = true
	}
	if globalCIOutput {
		opts.CIOutput = true
		opts.OutputFormats = []string{"jsonl"}
		opts.JSONOutput = true
		opts.Silent = true
	}
	if err := normalizeScanFormats(opts.OutputFormats); err != nil {
		return err
	}
	// The sqlite format dumps this run's database to a standalone file, which is
	// only well-defined in stateless mode (a per-run temp DB). A persisted run
	// writes into the shared project DB, where "this scan's sqlite" is ambiguous.
	if opts.HasFormat("sqlite") && !globalStateless {
		return fmt.Errorf("--format sqlite requires -S/--stateless (it exports the standalone per-run database; for the persisted DB use `vigolium export`)")
	}
	// Route jsonl through the post-scan project-scoped envelope export so the
	// scan output matches `vigolium export`/stateless. CI output keeps its own
	// findings-only emitter (see outputScanResult), so leave it on the legacy
	// live path.
	opts.DeferredJSONLExport = opts.HasFormat("jsonl") && !opts.CIOutput
	return nil
}

// reportFormatEntry maps a --format value to its generator and display label.
type reportFormatEntry struct {
	format string
	label  string
	// generate materializes all items, then renders. Used when streamGenerate
	// is nil, and as the fallback path for the streaming generators.
	generate func([]any, string, output.HTMLReportMeta) error
	// streamGenerate, when set, renders the report by pulling items one at a
	// time from a producer, so the result set never lives in memory at once.
	streamGenerate func(output.ReportItemProducer, string, output.HTMLReportMeta) error
	beforeMsg      string // optional stderr message before generation
}

var reportFormats = []reportFormatEntry{
	{format: "html", label: "HTML report", generate: output.GenerateHTMLReport, streamGenerate: output.GenerateHTMLReportStreaming},
	{format: "report", label: "Document report", generate: output.GenerateDocumentReport},
	{format: "pdf", label: "PDF report", generate: output.GeneratePDFReport, beforeMsg: "Generating PDF report (headless Chrome)..."},
	{format: "sarif", label: "SARIF report", generate: output.GenerateSARIFReport},
}

// formatNeedsOutput reports whether a format writes a file the command cannot
// name on its own, so `--format X` without `-o` must be rejected rather than
// silently producing nothing. Shared by the scan commands and `export`/`import`,
// which previously carried two predicates whose defaults for an unrecognized
// format were opposite.
//
// A deny-list on purpose: `console` writes nothing, `jsonl` streams to stdout,
// and `fs` defaults its base to the cwd — every other format names a file.
// Stated the other way round, as a list of file formats, a newly added format
// defaults to "needs no -o" and silently no-ops, which is exactly how `sarif`
// shipped able to be requested and unable to be written.
func formatNeedsOutput(format string) bool {
	switch canonicalFormat(format) {
	case "console", "jsonl", "fs":
		return false
	}
	return true
}

// maybeGenerateReports generates all requested file-based reports post-scan and
// returns the joined per-format failures.
//
// Every format named on the command line is a requested output, and a scan that
// could not write one did not do what it was asked. It used to print "Failed to
// generate html" to stderr and exit 0, so a CI job that asked for a report and
// read the exit code was told the run succeeded while the file it was about to
// publish did not exist. The error now reaches the caller, which folds it in
// with recordExportFailure.
//
// Nothing is printed for a failure here, for the same reason as
// finishStatelessExport: the root handler renders the returned error once, and
// printing as well announced the same cause twice in two wordings. Each format
// is still attempted independently, so one unwritable destination does not cost
// the others.
func maybeGenerateReports(db *database.DB, opts *types.Options) error {
	if opts.Output == "" {
		return nil
	}
	ctx := context.Background()
	// Scope the report's findings to this scan on a persisted (shared) DB, so a
	// re-run's report reflects that run rather than the project's whole history. A
	// stateless run's temp DB already holds only this scan, so it needs no filter.
	scanScope := ""
	if !opts.Stateless {
		scanScope = opts.ScanUUID
	}
	var failures []error
	for _, rf := range reportFormats {
		if !opts.HasFormat(rf.format) {
			continue
		}
		outPath := opts.OutputPathForFormat(rf.format)
		if rf.beforeMsg != "" {
			fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), rf.beforeMsg)
		}
		if err := generateReportFromDB(ctx, db, outPath, opts.OmitResponse, exportProjectScope(opts), scanScope, rf, nil); err != nil {
			failures = append(failures, fmt.Errorf("generate %s %s: %w", rf.label, outPath, err))
			continue
		}
		fmt.Fprintf(os.Stderr, "%s %s: %s\n", terminal.InfoSymbol(), rf.label, terminal.Cyan(outPath))
	}
	return errors.Join(failures...)
}

// finishFSExport writes the post-scan flat filesystem tree (the `fs` format)
// for a persisted run, scoped to the scan's project. Stateless runs are handled
// by finishStatelessExport (their temp DB is whole-run-scoped and opts.Output is
// blanked), so this no-ops for them. The base defaults to "vigolium" in the cwd
// when no -o was given, matching the documented fs behavior.
//
// Like maybeGenerateReports, a failure is returned rather than printed: `--format
// fs` is a requested output, and a run that wrote no tree has not delivered it.
func finishFSExport(db *database.DB, opts *types.Options) error {
	if !opts.HasFormat("fs") || opts.Stateless {
		return nil
	}
	base := opts.Output
	if len(opts.OutputFormats) > 1 {
		base = opts.OutputBasePath()
	}
	filters := database.QueryFilters{ProjectUUID: exportProjectScope(opts)}
	stats, err := writeFSExport(context.Background(), db, filters, base, fsExportOptions{omitResponse: opts.OmitResponse})
	if err != nil {
		return fmt.Errorf("export fs tree: %w", err)
	}
	fsPrintSummary(stats)
	return nil
}

// exportedFile records one materialized file/directory for the unified stateless
// export summary printed at the end of finishStatelessExport. detail is an
// optional parenthetical (e.g. "53 records").
type exportedFile struct {
	label  string // format name: console, jsonl, sqlite, html, fs, …
	path   string
	detail string
}

// fsExportOutputs turns an fs-export result into unified summary rows — one per
// directory actually written (traffic and/or findings) — so the fs format lists
// alongside the other formats instead of printing its own separate block.
func fsExportOutputs(stats fsExportStats) []exportedFile {
	var out []exportedFile
	if stats.TrafficDir != "" {
		out = append(out, exportedFile{label: "fs", path: stats.TrafficDir, detail: fmt.Sprintf("%d records", stats.Traffic)})
	}
	if stats.FindingsDir != "" {
		out = append(out, exportedFile{label: "fs", path: stats.FindingsDir, detail: fmt.Sprintf("%d findings", stats.Findings)})
	}
	return out
}

// displayExportPath renders an export destination as an absolute path with the
// home directory collapsed to "~", so the summary shows exactly where a file
// landed regardless of the cwd. Falls back to the raw path if it can't be made
// absolute.
func displayExportPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return terminal.ShortenHome(abs)
}

// printExportSummary lists every materialized output under one aligned "Exports"
// header, so a multi-format run reports its files consistently instead of
// interleaving differently-shaped per-format "exported to" messages. Paths are
// shown absolute (home collapsed to "~"). No-ops when nothing was written.
func printExportSummary(outputs []exportedFile) {
	if len(outputs) == 0 {
		return
	}
	labelW := 0
	for _, o := range outputs {
		if len(o.label) > labelW {
			labelW = len(o.label)
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.InfoSymbol(), terminal.BoldAqua("Exports"))
	for _, o := range outputs {
		line := fmt.Sprintf("  %-*s  %s", labelW, o.label, terminal.Cyan(displayExportPath(o.path)))
		if o.detail != "" {
			line += "  " + terminal.Gray("("+o.detail+")")
		}
		fmt.Fprintln(os.Stderr, line)
	}
}

// finishStatelessExport writes the full database export to the output file(s)
// when running in stateless mode. StandardWriter's live file output is
// suppressed in stateless mode, so every requested format (console, jsonl,
// html, report, pdf) is materialized here from the database, then listed under a
// single unified "Exports" summary.
//
// Every format is attempted even after one fails — a caller that asked for jsonl
// AND sqlite is better served by the one that can be written than by neither —
// and the formats that did not land are joined into the returned error. Callers
// fold that into their result with recordExportFailure; the per-format detail is
// already on stderr by then, so the error's job is only to make the failure
// reachable by exit code and by the terminal event.
func finishStatelessExport(db *database.DB, opts *types.Options, outputPath string, skipConsole bool) error {
	if !opts.Stateless {
		return nil
	}
	ctx := context.Background()
	if outputPath == "" {
		// Every file-based format needs an explicit -o, but fs defaults its base
		// to the cwd ("vigolium"), so it still writes a tree with no -o.
		if opts.HasFormat("fs") {
			stats, err := writeFSExport(ctx, db, database.QueryFilters{}, "", fsExportOptions{omitResponse: opts.OmitResponse})
			if err != nil {
				return fmt.Errorf("export fs tree: %w", err)
			}
			printExportSummary(fsExportOutputs(stats))
		}
		return nil
	}

	basePath := types.StripFormatExtension(outputPath)

	// Materialize every requested format, collecting one row per output file/dir,
	// then print them together under a single "Exports" summary. Failures print
	// inline (they're not successes to list); the trailing summary lists only what
	// was actually written, and the joined failures go back to the caller.
	var outputs []exportedFile
	var failures []error
	// One place decides what a per-format outcome does, so a format cannot be
	// added that collects its failure but forgets to report it. Nothing is printed
	// here: the joined failures become the command's error, which the root handler
	// renders once — the exporters used to print too, so a failing run announced
	// the same cause twice in two wordings. recordExportFailure owns the one case
	// where that render does not happen (an earlier failure already won).
	record := func(e exportedFile, err error) {
		if err != nil {
			failures = append(failures, err)
			return
		}
		outputs = append(outputs, e)
	}
	for _, format := range opts.OutputFormats {
		outPath := types.FormatOutputPath(basePath, format)
		switch format {
		case "console":
			if skipConsole {
				// A transcript was captured to this path; do not overwrite it.
				continue
			}
			record(exportStatelessConsole(ctx, db, outPath, opts.OmitResponse))
		case "jsonl":
			record(exportStatelessJSONL(ctx, db, opts, outPath))
		case "sqlite":
			record(exportStatelessSQLite(ctx, db, outPath))
		case "fs":
			// The stateless temp DB holds only this run → whole-DB tree ("").
			// Several rows per success, so it cannot go through record.
			stats, err := writeFSExport(ctx, db, database.QueryFilters{}, outPath, fsExportOptions{omitResponse: opts.OmitResponse})
			if err != nil {
				record(exportedFile{}, fmt.Errorf("export fs tree %s: %w", outPath, err))
				continue
			}
			outputs = append(outputs, fsExportOutputs(stats)...)
		default:
			for _, rf := range reportFormats {
				if rf.format != format {
					continue
				}
				if rf.beforeMsg != "" {
					fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), rf.beforeMsg)
				}
				// Capture the report's body-trim summary (HTML only) so it lands as
				// the row's detail in the unified "Exports" list instead of a long
				// inline note printed mid-run.
				var trim output.ReportTrimInfo
				// Stateless temp DB holds only this run → whole-DB report ("").
				err := generateReportFromDB(ctx, db, outPath, opts.OmitResponse, "", "", rf, func(t output.ReportTrimInfo) { trim = t })
				if err != nil {
					record(exportedFile{}, fmt.Errorf("generate %s %s: %w", rf.label, outPath, err))
					continue
				}
				record(exportedFile{label: rf.format, path: outPath, detail: trim.Summary()}, nil)
			}
		}
	}
	printExportSummary(outputs)
	return errors.Join(failures...)
}

// dbIsolateAgentFlagUsage is the shared --db-isolate help text for the agent
// subcommands (autopilot, swarm). scan/run use a variant that also references
// --stateless, so it keeps its own string.
const dbIsolateAgentFlagUsage = "Run into a private temporary database, then merge results into --db (or the default DB) at the end — lets parallel runs share one --db without write contention (SQLite only)"

// dbIsolateYieldsToStateless applies the precedence between --db-isolate and
// --stateless: -S wins and --db-isolate is ignored with a warning.
//
// The pair used to be a hard error. It is a warning because tools that compose
// vigolium's flags pass both, and refusing to start stops a whole workflow over
// a flag that simply has nothing to do: -S discards the run's database, so there
// is no database left to merge anywhere. Which side wins is not arbitrary:
// were --db-isolate to win, a run that asked for -S would begin merging into the
// operator's project DB, the one thing -S promises will not happen.
//
// The flag is dropped outright rather than half-honored, so every remaining
// combination validates exactly as if it had never been typed: -S --db-isolate
// --db still reports the --db conflict, and -S --db-isolate -P still meets the
// -P isolation gate (which asks for --split-by-host). Anything softer would make
// adding an ignored flag *widen* what the CLI accepts.
//
// It clears globalDBIsolate rather than reporting the conflict, because the flag
// var IS the flag: dbIsolateBegin reads it directly (not an Options field), and
// by the time that runs the stateless path has already repointed
// settings.Database/globalDB at its throwaway file — a stale flag there would
// merge a second scratch database into one that is about to be deleted. Callers
// that copy the flag into Options must therefore copy it AFTER this runs.
func dbIsolateYieldsToStateless(stateless bool) {
	if !stateless || !globalDBIsolate {
		return
	}
	if !machineOutputMode() {
		fmt.Fprintf(os.Stderr,
			"%s %s is ignored under %s: this run's database is discarded, so there is nothing to merge into %s.\n",
			terminal.WarnPrefix(),
			terminal.BoldCyan("--db-isolate"),
			terminal.BoldCyan("--stateless"),
			terminal.BoldCyan("--db"))
	}
	globalDBIsolate = false
}

// dbIsolateDestPath records the real destination database that a --db-isolate
// run merges into at the end. dbIsolateBegin repoints settings.Database and
// globalDB at the scratch file, which erases the original destination from
// those, so we stash it here for the config banner (printScanSummary) to show.
var dbIsolateDestPath string

// resolveDBIsolateDest resolves the real destination database a --db-isolate run
// merges into: the global --db when set, otherwise the configured database. It
// errors when that destination is not SQLite (the merge is SQLite-to-SQLite).
// Shared by dbIsolateBegin (single-process runs) and the db-isolate parallel
// fan-out, which needs the destination both to validate up front and to export
// the unified output from once every child has merged in.
func resolveDBIsolateDest(settings *config.Settings) (config.DatabaseConfig, error) {
	destCfg := settings.Database
	if globalDB != "" {
		destCfg.Driver = "sqlite"
		destCfg.SQLite.Path = globalDB
	}
	if destCfg.Driver != "sqlite" {
		return destCfg, fmt.Errorf("--db-isolate requires a SQLite database (got driver %q)", destCfg.Driver)
	}
	return destCfg, nil
}

// dbIsolateBegin, when --db-isolate is active, swaps the run's database to a
// private scratch SQLite file and returns a finisher that merges the scratch
// into the real destination (--db when set, else the configured DB) and cleans
// it up. It repoints BOTH database-acquisition paths at the scratch:
// settings.Database (native scan and swarm via NewDB) and the global --db value
// (autopilot via getDB → clicommon.GetDB). When isolation is off it returns a
// no-op finisher, so callers can unconditionally `defer finish(err)`.
//
// Shared by `scan`/`run`, `agent autopilot`, and `agent swarm`; register the
// returned finisher in a defer BEFORE opening the DB so the merge runs after
// the DB is closed (defers are LIFO).
func dbIsolateBegin(settings *config.Settings, silent bool) (finish func(error) error, err error) {
	noop := func(runErr error) error { return runErr }
	if !globalDBIsolate {
		return noop, nil
	}
	// Resolve the real destination: --db wins, else the configured DB.
	destCfg, err := resolveDBIsolateDest(settings)
	if err != nil {
		return nil, err
	}
	// Stash the destination before we repoint settings/globalDB below, so the
	// config banner can report where results will be merged.
	dbIsolateDestPath = destCfg.SQLite.Path

	tmpFile, tmpErr := scratch.CreateTemp("isolate-*.sqlite")
	if tmpErr != nil {
		return nil, fmt.Errorf("failed to create temporary database: %w", tmpErr)
	}
	scratchPath := tmpFile.Name()
	_ = tmpFile.Close()

	settings.Database.Driver = "sqlite"
	settings.Database.SQLite.Path = scratchPath
	// autopilot opens via getDB() → clicommon.GetDB(globalConfig, globalDB),
	// which ignores settings.Database, so the scratch path must be reflected in
	// globalDB too. Harmless for the native/swarm paths (they read settings).
	globalDB = scratchPath

	return func(runErr error) error {
		return finishDBIsolateMerge(destCfg, scratchPath, silent, runErr)
	}, nil
}

// finishDBIsolateMerge merges the scratch database produced by a --db-isolate
// run into the real destination database, then discards the scratch on
// success. It is called from a defer that runs after the run's DB handle is
// closed, so the scratch DB's writes are fully flushed before the merge reads
// them. scanErr is the run's own error (if any): on a clean merge it is
// returned unchanged; on a merge failure the scratch is preserved and the
// command still exits non-zero.
func finishDBIsolateMerge(destCfg config.DatabaseConfig, scratchPath string, silent bool, scanErr error) error {
	ctx := context.Background()
	destPath := database.ExpandPath(destCfg.SQLite.Path)

	// Serialize the ENTIRE destination-DB critical section — open, schema
	// creation, default seeding, and the merge — under one cross-process lock.
	// When many --db-isolate finishers target a single fresh shared --db (the
	// -P fan-out and parallel-process case), opening the DB runs a WAL-mode
	// switch + initial checkpoint and CreateSchema runs a batch of
	// CREATE TABLE/INDEX IF NOT EXISTS DDL — all write operations that, outside
	// the lock, run with no busy-retry of their own and can surface SQLITE_BUSY
	// under heavy concurrent load, failing the merge. Holding the lock across
	// open→schema→seed→merge means only one process initializes/writes the
	// shared destination at a time; the rest see an already-initialized DB and
	// their IF NOT EXISTS DDL is a fast no-op. The lock stays best-effort (it
	// degrades to DB-level serialization on timeout), and MergeSQLiteFile keeps
	// its own busy-retry for that degraded path.
	var stats *database.MergeStats
	mergeErr := database.WithMergeLock(destPath, 60*time.Second, func() error {
		dest, err := database.NewDB(&destCfg)
		if err != nil {
			return fmt.Errorf("open destination database: %w", err)
		}
		defer func() { _ = dest.Close() }()

		if err := dest.CreateSchema(ctx); err != nil {
			return fmt.Errorf("prepare destination schema: %w", err)
		}
		// Best-effort: seed the default project/FTS so a brand-new destination is
		// fully usable; a failure here doesn't block the merge of the result rows.
		_ = dest.SeedDefaults(ctx)

		var e error
		stats, e = database.MergeSQLiteFile(ctx, dest, scratchPath)
		return e
	})
	if mergeErr != nil {
		return dbIsolateMergeFailed(scratchPath, scanErr, mergeErr)
	}

	// Success: discard the scratch database and its WAL sidecars.
	removeWorkingDB(scratchPath)
	if !silent && stats != nil {
		fmt.Fprintf(os.Stderr, "%s Merged results into %s (%d records, %d findings)\n",
			terminal.InfoSymbol(), terminal.Cyan(destCfg.SQLite.Path), stats.RecordsMerged, stats.FindingsMerged)
	}
	return scanErr
}

// dbIsolateMergeFailed moves the scratch database somewhere that outlives the
// process, prints a recovery hint naming that path, and returns the error the
// command should exit with: the original scan error when the scan itself
// failed, otherwise the merge error.
//
// The move is the fix for a false promise. This used to print "This scan's
// results are preserved in the temporary database: <scratch path>" — and that
// path is inside the process scratch directory, which releaseScratch removes at
// exit, moments later. The operator was told where to find results that were
// already being deleted. The word "preserved" is now never printed next to a
// scratch path: either the file has been moved out, or the message says it could
// not be.
func dbIsolateMergeFailed(scratchPath string, scanErr, mergeErr error) error {
	fmt.Fprintf(os.Stderr, "%s --db-isolate merge failed: %v\n", terminal.ErrorPrefix(), mergeErr)

	dest, keepErr := preserveWorkingDB(scratchPath, "isolate")
	if keepErr != nil {
		fmt.Fprintf(os.Stderr, "   This scan's results could NOT be preserved: %v\n", keepErr)
		zap.L().Error("db-isolate merge failed and the scratch database could not be preserved",
			zap.String("scratch", scratchPath), zap.Error(mergeErr), zap.NamedError("preserve_error", keepErr))
		if scanErr != nil {
			return scanErr
		}
		// keepErr's text, not keepErr itself: it is an os error that may wrap
		// os.ErrNotExist, and adding that to the chain would make the error
		// classify as source_missing — telling a driver the database it had just
		// been scanning is not there. mergeErr is the cause worth classifying.
		return fmt.Errorf("db-isolate merge failed (results lost: %s): %w", keepErr.Error(), mergeErr)
	}

	fmt.Fprintf(os.Stderr,
		"   This scan's results are preserved at:\n     %s\n   Merge them later with: %s\n",
		terminal.Cyan(dest),
		terminal.BoldCyan(fmt.Sprintf("vigolium import --db %s %s", dbIsolateDestPath, dest)))
	zap.L().Error("db-isolate merge failed; working database preserved",
		zap.String("scratch", scratchPath), zap.String("preserved", dest), zap.Error(mergeErr))

	if scanErr != nil {
		return fmt.Errorf("%w (db-isolate results kept at %s)", scanErr, dest)
	}
	return fmt.Errorf("db-isolate merge failed (results kept at %s): %w", dest, mergeErr)
}

// exportProjectScope returns the project filter for a post-scan export: empty
// (whole DB) for stateless runs, whose temp DB holds only this scan; the run's
// project (defaulting to DefaultProjectUUID) for persisted runs, so the export
// is scoped to this scan's project on a shared DB. Shared by the jsonl and
// report post-scan exporters so their scopes stay in sync.
func exportProjectScope(opts *types.Options) string {
	if opts.Stateless {
		return ""
	}
	if opts.ProjectUUID != "" {
		return opts.ProjectUUID
	}
	return database.DefaultProjectUUID
}

// encodeJSONL writes each item to w as a unified {"type":...,"data":...} envelope
// line, returning the number written. Callers query first (so a query failure
// never leaves a created-but-empty output file) and encode into an already-open
// writer here.
func encodeJSONL(w io.Writer, items []any) (int, error) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return 0, err
		}
	}
	return len(items), nil
}

// streamJSONLExport streams the unified {"type":...,"data":...} envelope to w,
// encoding each item as it is read from the database so the full result set is
// never held in memory. Returns the per-type tally the export summary prints
// (counts.total is the number of lines written). A mid-stream write error aborts
// and is returned; callers writing to a file should stage to a temp path (see
// streamJSONLToFile) so a partial stream never replaces a good file.
//
// SetEscapeHTML(false) is load-bearing and shared with encodeJSONL: payload
// evidence is full of & < >, which Go escapes by default.
func streamJSONLExport(ctx context.Context, db *database.DB, w io.Writer, omitResponse bool, projectUUID string) (exportCounts, error) {
	counts := newExportCounts()
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	err := streamExportData(ctx, db, scanExportScope, omitResponse, projectUUID, "", func(item any) error {
		if err := enc.Encode(item); err != nil {
			return err
		}
		counts.add(item)
		return nil
	})
	return counts, err
}

// streamJSONLToFile streams the JSONL envelope to outputPath atomically: it
// writes to a temp sibling and renames into place on success, so a failed or
// partial export never replaces or half-writes the destination file. Returns the
// number of records written.
func streamJSONLToFile(ctx context.Context, db *database.DB, outputPath string, omitResponse bool, projectUUID string) (int, error) {
	var counts exportCounts
	err := atomicfile.Write(outputPath, func(w *bufio.Writer) error {
		var werr error
		counts, werr = streamJSONLExport(ctx, db, w, omitResponse, projectUUID)
		return werr
	})
	if err != nil {
		return 0, err
	}
	return counts.total, nil
}

// writeJSONLExport streams the (optionally project-scoped) database export to w.
// projectUUID == "" exports the whole DB. Used for the stdout path, where there
// is no output file to leave half-written on error.
func writeJSONLExport(ctx context.Context, db *database.DB, w io.Writer, omitResponse bool, projectUUID string) (int, error) {
	counts, err := streamJSONLExport(ctx, db, w, omitResponse, projectUUID)
	return counts.total, err
}

// exportStatelessJSONL writes all records in the (temporary) database to a JSONL
// file. Used only in stateless mode, where the temp DB holds just this run, so
// the whole-DB export is implicitly scoped to the current scan. The query runs
// before the file is created so a query failure leaves no empty output file.
func exportStatelessJSONL(ctx context.Context, db *database.DB, opts *types.Options, outputPath string) (exportedFile, error) {
	n, err := streamJSONLToFile(ctx, db, outputPath, opts.OmitResponse, "")
	if err != nil {
		return exportedFile{}, fmt.Errorf("export jsonl %s: %w", outputPath, err)
	}
	return exportedFile{label: "jsonl", path: outputPath, detail: fmt.Sprintf("%d records", n)}, nil
}

// exportStatelessSQLite materializes the stateless run's database to a
// standalone SQLite file via VACUUM INTO, which produces a clean, fully
// checkpointed copy (WAL contents included, page freelist compacted) from the
// live connection. The result is a self-contained .sqlite the operator can open
// later with `vigolium finding/traffic -S --db <file>.sqlite`.
//
// The export is staged and then renamed into place. VACUUM INTO refuses to
// overwrite, so SOMETHING has to clear the way for a re-export, and this used to
// delete the destination (plus its -wal/-shm sidecars) before running the
// VACUUM. That made every failure destructive: a full disk, a cancelled context,
// a Ctrl-C mid-copy, and the operator was left with neither the new export nor
// the previous one they had just overwritten. Staging costs nothing — the stage
// sits in the destination's own directory, so publishing it is a same-filesystem
// rename, which is atomic and cannot half-replace the old file.
func exportStatelessSQLite(ctx context.Context, db *database.DB, outputPath string) (exportedFile, error) {
	// CreateTemp reserves a name no concurrent writer can guess, in the
	// destination's own directory so publishing is a same-filesystem rename, and
	// proves that directory is writable before the VACUUM does any work. VACUUM
	// INTO then needs the name free, so the reservation is released immediately —
	// a predictable stage name would be cheaper but lets anyone with write access
	// to a shared output directory (-o /tmp/scan.sqlite) pre-empt it.
	stage, err := os.CreateTemp(filepath.Dir(outputPath), "."+filepath.Base(outputPath)+".*.partial")
	if err == nil {
		err = stage.Close()
	}
	var stagePath string
	if err == nil {
		stagePath = stage.Name()
		err = os.Remove(stagePath)
	}
	if err != nil {
		return exportedFile{}, fmt.Errorf("prepare sqlite export %s: %w", outputPath, err)
	}
	// Unconditional: after a successful rename the stage no longer exists and this
	// is a no-op, so nothing has to track whether we got that far. VACUUM INTO
	// closes its target and journals it in delete mode, so there are no sidecars
	// of its own to collect.
	defer func() { _ = os.Remove(stagePath) }()

	// stagePath derives from the operator-supplied outputPath (not
	// attacker-controlled); single-quote escape keeps a path with quotes from
	// breaking the statement.
	stmt := fmt.Sprintf("VACUUM INTO '%s'", strings.ReplaceAll(stagePath, "'", "''"))
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return exportedFile{}, fmt.Errorf("export sqlite %s: %w", outputPath, err)
	}
	// The old sidecars belong to the file being replaced, not to the stage. Left
	// behind they would describe a database that no longer exists, and SQLite
	// would rather trust a stale -wal than the fresh file next to it.
	for _, p := range []string{outputPath + "-wal", outputPath + "-shm"} {
		_ = os.Remove(p)
	}
	if err := os.Rename(stagePath, outputPath); err != nil {
		return exportedFile{}, fmt.Errorf("publish sqlite export %s: %w", outputPath, err)
	}
	return exportedFile{label: "sqlite", path: outputPath}, nil
}

// finishScanJSONLExport emits the post-scan unified JSONL envelope for a scan
// run with --format jsonl. Persisted runs are scoped to the scan's project;
// stateless runs export the whole temp DB. Output goes to the -o file or, when
// no -o was given, to stdout. Stateless runs WITH -o are materialized by
// finishStatelessExport (all formats), so only the stateless no-output case is
// handled here (otherwise jsonl results would be silently discarded with the
// temp DB). CI output keeps its own emitter and never sets DeferredJSONLExport.
func finishScanJSONLExport(db *database.DB, opts *types.Options) error {
	if !opts.DeferredJSONLExport {
		return nil
	}
	if opts.Stateless && opts.Output != "" {
		return nil
	}
	ctx := context.Background()
	projectUUID := exportProjectScope(opts)

	if opts.Output == "" {
		// No -o: stream the envelope to stdout once the scan completes. A failure
		// here is reported like any other: the stream is the artifact, and a
		// consumer that read a truncated envelope needs to know it was truncated.
		if _, err := writeJSONLExport(ctx, db, os.Stdout, opts.OmitResponse, projectUUID); err != nil {
			return fmt.Errorf("export jsonl to stdout: %w", err)
		}
		return nil
	}

	// Single format honors the literal -o path the user gave; with multiple
	// formats each writes to its own extension-qualified path so the jsonl
	// export never collides with the live console / html / report files.
	outPath := opts.Output
	if len(opts.OutputFormats) > 1 {
		outPath = opts.OutputPathForFormat("jsonl")
	}
	n, err := streamJSONLToFile(ctx, db, outPath, opts.OmitResponse, projectUUID)
	if err != nil {
		return fmt.Errorf("export jsonl %s: %w", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "%s Results exported to %s (%d records)\n",
		terminal.InfoSymbol(), terminal.Cyan(outPath), n)
	return nil
}

// exportStatelessConsole writes all database records to a plain-text file using
// the same human-readable layout as the live console output (minus ANSI colors
// and the phase prefix, which don't belong in a file). Used for stateless runs
// with the default console format so -o always produces a populated file even
// when the phase only ingests HTTP records (e.g. discovery) and emits no
// findings.
func exportStatelessConsole(ctx context.Context, db *database.DB, outputPath string, omitResponse bool) (exportedFile, error) {
	var lines int
	err := atomicfile.Write(outputPath, func(w *bufio.Writer) error {
		return streamExportData(ctx, db, fullExportScope, omitResponse, "", "", func(item any) error {
			env, ok := item.(exportEnvelope)
			if !ok {
				return nil
			}
			var line string
			switch env.Type {
			case "http_record":
				line = consoleHTTPRecordLine(env.Data)
			case "finding":
				line = consoleFindingLine(env.Data)
			}
			if line == "" {
				return nil
			}
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
			lines++
			return nil
		})
	})
	if err != nil {
		return exportedFile{}, fmt.Errorf("export console %s: %w", outputPath, err)
	}
	return exportedFile{label: "console", path: outputPath, detail: fmt.Sprintf("%d lines", lines)}, nil
}

// consoleHTTPRecordLine renders an HTTP record export item as a plain-text
// console-style line: [status] METHOD content-type url
func consoleHTTPRecordLine(data any) string {
	r, ok := data.(*database.HTTPRecord)
	if !ok {
		return ""
	}
	return fmt.Sprintf("[%d] %s %s %s", r.StatusCode, r.Method, shortContentType(r.ResponseContentType), r.URL)
}

// consoleFindingLine renders a finding export item as a plain-text
// console-style line: [severity] [module-id] location [extracted-results]
func consoleFindingLine(data any) string {
	f, ok := data.(*database.Finding)
	if !ok {
		return ""
	}
	loc := f.URL
	if len(f.MatchedAt) > 0 && f.MatchedAt[0] != "" {
		loc = f.MatchedAt[0]
	}
	if loc == "" {
		loc = f.Hostname
	}
	line := fmt.Sprintf("[%s] [%s] %s", strings.ToUpper(f.Severity), f.ModuleID, loc)
	if len(f.ExtractedResults) > 0 {
		line += " [" + output.EscapeOneLine(strings.Join(f.ExtractedResults, ",")) + "]"
	}
	return line
}

// shortContentType trims parameters from a content type
// (application/json; charset=utf-8 → application/json), returning "-" when empty.
func shortContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if ct = strings.TrimSpace(ct); ct == "" {
		return "-"
	}
	return ct
}

// scanShutdownSignals are the signals that cancel a running scan.
//
// SIGTERM is here for parity with scanevents.TrapSignals, which has always
// trapped both. Trapping only SIGINT meant a SIGTERM (a `timeout`, a container
// stop, a supervisor) emitted a terminal scan.finished{interrupted} on the event
// stream — latching the emitter shut — while the runner carried on to completion
// and later wrote `completed | complete` to the scan row. The stream and the row
// disagreed, and the row's real terminal event was dropped by the once-latch. Now
// both paths take the same cancellation route — see scanSignalCoordinator, which
// is the single handler both facts now come from.
var scanShutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

// heapCeilingConfigLine renders the memory-ceiling detail shown inside the
// Native Scan Configuration block under a parallel fan-out (-P > 1): plain
// (uncolored) descriptive text with only the byte amounts highlighted, matching
// the rest of the config lines. The common auto-derived case reads "Memory
// ceiling 12 GiB/process (auto from 36 GiB RAM)"; explicit/percent/disabled/
// inherited ceilings fall back to the raw note (which carries its own
// descriptor). Returns "" when there is nothing to report (machine too small or
// RAM undetectable).
func heapCeilingConfigLine(res memlimit.Result) string {
	if res.Note == "" {
		return ""
	}
	if res.Auto && res.TotalRAMBytes > 0 {
		return fmt.Sprintf("Memory ceiling %s/process (auto from %s RAM)",
			terminal.Orange(humanize.IBytes(uint64(res.LimitBytes))),
			terminal.Orange(humanize.IBytes(res.TotalRAMBytes)))
	}
	return res.Note
}

// printScanSummary prints a human-readable scan configuration overview to stderr.
// progressFile, when non-empty, is the resume progress manifest written by the
// stateless parallel fan-out; it is appended to the Output line so the operator
// can see (and resume from) it. Empty for every other scan mode.
func printScanSummary(opts *types.Options, settings *config.Settings, strategyName string, repo *database.Repository, progressFile string) {
	if opts.Silent || globalJSON || globalCIOutput {
		return
	}

	// Credit the discovery co-authors when the run is discovery/spidering-only
	// (e.g. `vigolium run discover` or `vigolium scan --only discovery`).
	// Through emitBanner, so the once-guard covers this and the root hook
	// together: whichever runs first wins and the other is a no-op, with no
	// annotation or command list keeping them apart.
	if isDiscoveryOnlyPhases(opts.OnlyPhase) {
		emitBanner(GetDiscoveryBanner())
	} else {
		emitBanner(GetBanner())
	}

	discoveryEnabled := opts.DiscoverEnabled
	spideringEnabled := opts.SpideringEnabled
	knownIssueScanEnabled := opts.KnownIssueScanEnabled
	daEnabled := !opts.SkipDynamicAssessment
	ehEnabled := opts.ExternalHarvestEnabled

	// Strategy name
	strategy := strategyName
	if strategy == "" {
		strategy = "default"
	}

	// Module counts, less the hardening advisories the intensity suppresses —
	// counting modules the scan will not run makes the gate look like a lost
	// finding when their rows are absent from the report.
	var activeMods []modules.ActiveModule
	if len(opts.Modules) > 0 && opts.Modules[0] == "all" {
		activeMods = modules.GetActiveModules()
	} else {
		activeMods = modules.GetActiveModulesByIDs(opts.Modules)
	}
	activeCount, passiveCount, hygieneNote := runner.HygieneBannerCounts(opts, settings, activeMods, modules.GetPassiveModules())

	// Scope origin mode
	scopeOrigin := config.ResolveCLIOriginMode(settings.Scope.CLIOriginMode)

	fmt.Fprintf(os.Stderr, "\n  %s %s %s %s %s %s\n",
		terminal.TipPrefix(), terminal.Gray("run"), terminal.HiCyan("vigolium traffic list"), terminal.Gray("and"), terminal.HiCyan("vigolium findings list"), terminal.Gray("to view ingested data and vulnerabilities"))
	fmt.Fprintf(os.Stderr, "  %s %s %s %s\n",
		terminal.TipPrefix(), terminal.Gray("run each phase separately via"), terminal.HiCyan("vigolium run <phase>"), terminal.Gray("(e.g. vigolium run dynamic-assessment)"))
	fmt.Fprintf(os.Stderr, "  %s %s %s %s\n\n",
		terminal.TipPrefix(), terminal.Gray("skip phases you don't need via"), terminal.HiCyan("--skip <phase>"), terminal.Gray("(e.g. --skip discovery,known-issue-scan)"))
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.Green(terminal.SymbolStart), terminal.BoldHiBlue("Native Scan Configuration"))
	// In stateless mode the scan lives in a throwaway database, so the UUID
	// can't be used to query results later — printing it is just noise.
	if opts.ScanUUID != "" && !opts.Stateless {
		fmt.Fprintf(os.Stderr, "  %s Scan ID: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ScanUUID))
	}
	if opts.Stateless {
		statelessLine := "Stateless mode: using temporary database"
		if globalVerbose && settings.Database.SQLite.Path != "" {
			statelessLine += " " + terminal.Gray("("+settings.Database.SQLite.Path+")")
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), statelessLine)
	}
	if opts.DBIsolate {
		dest := dbIsolateDestPath
		if dest == "" {
			dest = "--db"
		}
		isolateLine := "DB isolation: scanning into a private temporary database, merged into " +
			terminal.HiTeal(dest) + " at the end"
		if globalVerbose && settings != nil && settings.Database.SQLite.Path != "" {
			isolateLine += " " + terminal.Gray("(scratch: "+settings.Database.SQLite.Path+")")
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), isolateLine)
	}
	// Only surface the project when it's a real, operator-chosen one. The
	// auto-created default project is implementation noise, and in stateless
	// mode the project lives in a throwaway database anyway.
	if opts.ProjectUUID != "" && opts.ProjectUUID != database.DefaultProjectUUID && !opts.Stateless {
		fmt.Fprintf(os.Stderr, "  %s Project: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ProjectUUID))
	}
	fmt.Fprintf(os.Stderr, "  %s Strategy: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(strategy))
	if opts.ScanningProfile != "" {
		fmt.Fprintf(os.Stderr, "  %s Profile: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ScanningProfile))
	}
	// The headline count is every target the scan will actually seed, CLI and
	// -T file alike. Counting only the CLI ones reported "Targets: 0" for a run
	// driven entirely by a target file, which reads as though nothing was found.
	fileTargets := countTargetFileTargets(opts.TargetsFilePaths)
	seededTargets := len(opts.Targets) + fileTargets
	targetsLine := fmt.Sprintf("Targets: %s", terminal.Orange(fmt.Sprintf("%d", seededTargets)))
	if len(opts.Targets) > 0 {
		targetsLine += fmt.Sprintf(" (CLI: %s)", terminal.HiBlue(summarizeTargetList(opts.Targets, 3)))
	}
	if len(opts.TargetsFilePaths) > 0 {
		label := "file"
		if len(opts.TargetsFilePaths) > 1 {
			label = "files"
		}
		targetsLine += fmt.Sprintf(" (+%d from %s: %s)", fileTargets, label, terminal.HiTeal(strings.Join(opts.TargetsFilePaths, ", ")))
	}
	if repo != nil {
		ctx := context.Background()
		// Scoped to this run's project. Unscoped, this counted every project in
		// the store and printed the total on the Targets line, which reads as
		// "these records are input for this scan" — they are not, and a
		// project-scoped scan cannot even see them.
		if dbCount, err := repo.CountRecordsAfterCursor(ctx, opts.ProjectUUID, time.Time{}, ""); err == nil && dbCount > 0 {
			targetsLine += fmt.Sprintf(" | %s (HTTP Records)", terminal.Orange(fmt.Sprintf("%d", dbCount)))
		}
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolTarget), targetsLine)
	fmt.Fprintf(os.Stderr, "  %s Phases: %s | %s | %s\n",
		terminal.Purple(terminal.SymbolInfo),
		runner.PhaseLabel(settings, "ExternalHarvest", "external_harvester", ehEnabled, 0),
		runner.PhaseLabel(settings, "Spidering", "spidering", spideringEnabled, runner.SpideringBudget(settings, opts)),
		runner.PhaseLabel(settings, "Discovery", "discovery", discoveryEnabled, runner.DiscoveryBudget(settings, opts)))
	fmt.Fprintf(os.Stderr, "           %s | %s\n",
		runner.PhaseLabel(settings, "KnownIssueScan", "known-issue-scan", knownIssueScanEnabled, 0),
		runner.PhaseLabel(settings, "DynamicAssessment", "dynamic-assessment", daEnabled, 0))
	// Total scan-duration budget (from --scanning-max-duration). The per-phase
	// durations above are factor-scaled slices of this cap and share it — the
	// whole scan is bounded by it. Under a parallel fan-out (-P > 1) each target
	// is an isolated child process with its own budget, so the cap applies per
	// target line, not across the whole batch.
	if opts.ScanMaxDuration > 0 {
		budgetLine := "Max scan duration: " + terminal.HiBlue(opts.ScanMaxDuration.String())
		if opts.Parallel > 1 {
			budgetLine += " " + terminal.Gray("per target line (each -P child runs its own budget)")
		} else {
			budgetLine += " " + terminal.Gray("(whole scan, all phases share this budget)")
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), budgetLine)
	}
	heuristicsDesc := map[string]string{
		"basic":    "probe target root pages to detect content type (HTML, JSON, blank) and skip spidering for non-HTML targets",
		"advanced": "basic checks + deep HTML analysis to detect SPA frameworks and optimize phase selection",
		"none":     "skip all heuristic probes, run all enabled phases unconditionally",
	}
	if desc, ok := heuristicsDesc[opts.HeuristicsCheck]; ok {
		fmt.Fprintf(os.Stderr, "  %s Heuristics: %s %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(opts.HeuristicsCheck),
			terminal.Gray(desc))
	} else {
		fmt.Fprintf(os.Stderr, "  %s Heuristics: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(opts.HeuristicsCheck))
	}
	fmt.Fprintf(os.Stderr, "  %s Speed: concurrency=%s | rate-limit=%s | max-per-host=%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiBlue(fmt.Sprintf("%d", opts.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", globalRateLimit)),
		terminal.HiBlue(fmt.Sprintf("%d", opts.MaxPerHost)))
	// Under a parallel fan-out (-P > 1), surface the per-process heap ceiling the
	// isolated child scans inherit. A single scan omits it — the ceiling is rarely
	// worth a line when only one process runs.
	if opts.Parallel > 1 {
		if line := heapCeilingConfigLine(scanHeapCeiling); line != "" {
			fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), line)
		}
	}
	originDesc := map[string]string{
		"relaxed":  "host must contain the target's keyword (e.g. \"example\")",
		"all":      "no origin restriction, all hosts are in scope",
		"balanced": "host must share the target's eTLD+1 (e.g. *.example.com)",
		"strict":   "host must exactly match the target host",
	}
	originDescStr := ""
	if desc, ok := originDesc[scopeOrigin]; ok {
		originDescStr = " " + terminal.Gray(desc)
	}
	fmt.Fprintf(os.Stderr, "  %s Scope: origin=%s | ignore-static=%s%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiPurple(scopeOrigin),
		terminal.HiPurple(fmt.Sprintf("%v", settings.Scope.IgnoreStaticFile)),
		originDescStr)
	modulesLine := fmt.Sprintf("Modules: %s active, %s passive",
		terminal.Orange(fmt.Sprintf("%d", activeCount)),
		terminal.Orange(fmt.Sprintf("%d", passiveCount)))
	if settings != nil && settings.DynamicAssessment.Extensions.Enabled {
		extCount := countExtensionFiles(&settings.DynamicAssessment.Extensions)
		modulesLine += fmt.Sprintf(" + %s extensions", terminal.HiTeal(fmt.Sprintf("%d", extCount)))
	}
	if hygieneNote != "" {
		modulesLine += " " + hygieneNote
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), modulesLine)
	// Output destination & format(s) — shown when -o or a non-default --format
	// is in play so it's clear where (and in what shape) results land.
	formats := opts.OutputFormats
	if len(formats) == 0 {
		formats = []string{"console"}
	}
	isDefaultFormat := len(formats) == 1 && formats[0] == "console"
	if opts.Output != "" || !isDefaultFormat {
		formatStr := strings.Join(formats, ", ")
		dest := "stdout"
		if opts.Output != "" {
			base := types.StripFormatExtension(opts.Output)
			seen := make(map[string]struct{}, len(formats))
			paths := make([]string, 0, len(formats))
			for _, f := range formats {
				p := types.FormatOutputPath(base, f)
				if p == "" {
					continue
				}
				if _, dup := seen[p]; dup {
					continue
				}
				seen[p] = struct{}{}
				paths = append(paths, p)
			}
			if len(paths) > 0 {
				dest = strings.Join(paths, ", ")
			}
		}
		// Surface the resume progress manifest (stateless parallel fan-out) on the
		// same line so the operator can see where progress is checkpointed and what
		// --resume reads. Appended after the per-host output files.
		if progressFile != "" {
			if dest == "stdout" {
				dest = progressFile
			} else {
				dest += ", " + progressFile
			}
		}
		fmt.Fprintf(os.Stderr, "  %s Output: %s %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(dest),
			terminal.Gray("(format: "+formatStr+")"))
	}
	// The spidering fan-out hint. Placed with the tips rather than beside the
	// Phases line because it is advice, not configuration — and printed before
	// the verbose-only block so it lands whether or not -v is on.
	printSpiderFanOutTip(opts, seededTargets)
	if globalVerbose {
		fmt.Fprintf(os.Stderr, "\n  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("view scope details via"), terminal.HiCyan("vigolium config ls scope"))
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("view scanning pace via"), terminal.HiCyan("vigolium config ls scanning_pace"))
		if knownIssueScanEnabled && !settings.KnownIssueScan.EnrichTargets {
			fmt.Fprintf(os.Stderr, "  %s %s %s\n",
				terminal.TipPrefix(), terminal.Gray("enrich KnownIssueScan targets with discovered paths via"), terminal.HiCyan("vigolium config known_issue_scan.enrich_targets=true"))
		}
	}
	fmt.Fprintln(os.Stderr)
}

// countExtensionFiles counts JS/TS/YAML extension files from the configured directories without loading them.
func countExtensionFiles(cfg *config.ExtensionsConfig) int {
	count := len(cfg.CustomDir)

	if cfg.ExtensionDir != "" {
		dir := config.ExpandPath(cfg.ExtensionDir)
		if entries, err := os.ReadDir(dir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				name := entry.Name()
				if strings.HasSuffix(name, ".d.ts") {
					continue
				}
				if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".vgm.yaml") {
					count++
				}
			}
		}
	}

	return count
}

// summaryScopeHosts returns the in-scope (scheme, hostname, port) origins present in the
// project's DB for the given CLI targets, delegating to Repository.InScopeHosts (the same
// scoping the runner phases use). With no targets (or no settings/repo) it returns nil —
// meaning "no filter", a project-wide pass. The scan-completion summary uses this so its
// counts cover only the origins actually scanned, not leftovers from prior scans of other
// origins in the project.
func summaryScopeHosts(ctx context.Context, repo *database.Repository, settings *config.Settings, targets []string, projectUUID, scanUUID string) []database.HostTarget {
	if repo == nil || settings == nil {
		return nil
	}
	return repo.InScopeHosts(ctx, settings.Scope, targets, projectUUID, scanUUID)
}

// printScanCompletionSummary prints a compact summary of ingested records,
// findings, and total wall-clock duration after scan completion. The record count is
// scoped to the in-scope origins (scheme/host/port); the finding count is scoped to the
// same project + in-scope hostnames (findings carry no port column), so the summary
// reflects the current scan's targets rather than the whole project.
func printScanCompletionSummary(repo *database.Repository, projectUUID string, hosts []database.HostTarget, elapsed time.Duration) {
	// Header line carries the total wall-clock duration, so it prints first and
	// unconditionally: even if the count queries below fail, the operator still
	// sees the completion banner and how long the run took.
	fmt.Fprintf(os.Stderr, "\n%s %s %s%s\n",
		terminal.Aqua(terminal.SymbolSparkle),
		terminal.BoldAqua("Native scan completed"),
		terminal.Gray("in "),
		terminal.Magenta(elapsed.Round(time.Second).String()))

	if repo == nil {
		return
	}

	ctx := context.Background()

	// Records line, with the status-class breakdown (2xx/3xx/4xx/5xx…) appended
	// inline, both scoped to this project and the in-scope origins — the same
	// scope as the findings count below, so every line of the summary describes
	// one population.
	//
	// The total comes from summing the breakdown rather than from a second query.
	// The classes cover exactly the rows the count would, so they sum to it by
	// construction, and one grouped scan is cheaper than a scan plus a count
	// (measured at 200k records: 22.9ms versus 28.2ms). CountRecordsAfterCursor
	// is the fallback for when the group-by fails, since the total is the part
	// the operator needs and the breakdown is decoration.
	var recordCount int64
	byCode, err := repo.CountRecordsByStatusCode(ctx, projectUUID, hosts...)
	classes := ""
	if err == nil {
		for _, n := range byCode {
			recordCount += n
		}
		classes = formatStatusClassLine(bucketStatusCounts(byCode))
	} else if recordCount, err = repo.CountRecordsAfterCursor(ctx, projectUUID, time.Time{}, "", hosts...); err != nil {
		return
	}

	recordsLine := fmt.Sprintf("  %s Records: %s http records ingested",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Cyan(fmt.Sprintf("%d", recordCount)))
	if classes != "" {
		recordsLine += terminal.Gray(" — ") + classes
	}
	fmt.Fprintln(os.Stderr, recordsLine)

	// Count findings by severity, scoped to the same project + in-scope hostnames.
	counts, err := database.CountFindingsBySeverity(ctx, repo.DB(), projectUUID, database.HostnamesOf(hosts)...)
	if err != nil {
		return
	}

	var totalFindings int64
	for _, c := range counts {
		totalFindings += c
	}

	if totalFindings == 0 {
		fmt.Fprintf(os.Stderr, "  %s Findings: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Gray("no issues found"))
		return
	}

	// Build severity breakdown
	var parts []string
	for _, s := range []struct {
		key string
		fn  func(string) string
		sym func() string
	}{
		{"critical", terminal.BoldMagenta, terminal.CriticalSymbol},
		{"high", terminal.BoldRed, terminal.HighSymbol},
		{"medium", terminal.BoldYellow, terminal.MediumSymbol},
		{"low", terminal.BoldGreen, terminal.LowSymbol},
		{"suspect", terminal.BoldCyan, terminal.SuspectSymbol},
		{"info", terminal.BoldBlue, terminal.InfoSeveritySymbol},
	} {
		if c, ok := counts[s.key]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%s %s %s", s.sym(), s.fn(fmt.Sprintf("%d", c)), s.key))
		}
	}

	fmt.Fprintf(os.Stderr, "  %s Findings: %s issues found — %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Orange(fmt.Sprintf("%d", totalFindings)),
		strings.Join(parts, ", "))
}
