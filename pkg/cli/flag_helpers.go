package cli

import (
	"time"

	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/input/source"
)

// Flag-registration helpers shared by the scan, run, ingest, scan-url, and
// scan-request commands. They live here (rather than as PersistentFlags on
// the root command) so flags only show up on the commands that actually use
// them — keeping `vigolium db --help` / `project --help` / etc. uncluttered.
//
// The variables themselves stay package-level (defined in root.go) so reads
// from helper code (e.g. resolveModules, ingest opts copying) keep working
// without plumbing.

// registerInputSourceFlags registers the target/input/input-mode set used by
// commands that ingest or scan from external sources.
func registerInputSourceFlags(flags *pflag.FlagSet) {
	flags.StringArrayVarP(&globalTargets, "target", "t", nil, "Target URL to scan (repeatable). Commas are literal so a URL query like ?ids=1,2,3 stays one target — repeat -t for multiple targets.")
	flags.StringArrayVarP(&globalTargetFiles, "target-file", "T", nil, "File containing target URLs (one per line; repeatable for multiple files). Commas in the path are literal.")
	flags.StringVarP(&globalInput, "input", "i", "-", "Input file path or spec (use - for stdin)")
	flags.StringVarP(&globalInputMode, "input-mode", "I", "urls", inputModeFlagUsage())
	registerInputReadTimeoutFlag(flags)
}

// inputModeFlagUsage builds the -I help text from the format registry, so a
// format added in pkg/input/source is advertised without a second edit here.
// The hand-written list it replaced had drifted: it offered "swagger" and
// "burp" (aliases) beside canonical names, and omitted postman, burpraw,
// burpscope and deparos entirely.
func inputModeFlagUsage() string {
	return "Input format: " + source.SupportedFormats() + " (aliases accepted, see --list-input-mode)"
}

// registerInputReadTimeoutFlag declares --input-read-timeout. One definition,
// shared by the ingesting commands and the lightweight single-request ones:
// scan-url and scan-request both read stdin and both lacked the dial that
// bounds it.
//
// Enforced by readStdin (see stdin.go). It used to be registered, assigned into
// Options.InputReadTimeout, and read by nothing at all, so a pipe that never
// closed hung the process regardless of what was passed.
func registerInputReadTimeoutFlag(flags *pflag.FlagSet) {
	flags.DurationVar(&globalInputReadTimeout, inputReadTimeoutFlag, defaultInputReadTimeout,
		"Deadline for reading input from stdin; 0 disables it")
}

// registerHTTPClientFlags registers the network/concurrency knobs shared by
// every command that makes HTTP requests.
func registerHTTPClientFlags(flags *pflag.FlagSet) {
	flags.DurationVar(&globalTimeout, "timeout", 15*time.Second, "HTTP request timeout (e.g. 30s, 1m, 2h)")
	registerPaceFlags(flags)
	flags.BoolVar(&globalNoWafPacing, "no-waf-pacing", false, "Disable proactive CDN/WAF-edge pacing (don't pre-throttle per-host concurrency when a CloudFront/Cloudflare/etc. edge is detected); reactive back-off after a WAF block still applies")
	flags.IntVar(&globalMaxHostError, "max-host-error", 30, "Skip host after reaching this many consecutive errors")
	flags.IntVar(&globalMaxFindingsPerModule, "max-findings-per-module", 10, "Stop reporting after N findings per module (0 = unlimited)")
	flags.BoolVar(&globalNoClustering, "no-clustering", false, "Disable deduplication of identical concurrent HTTP requests")
}

// scopeOriginFlagUsage is shared by every command registering --scope-origin
// (scan/run here, ingest in ingest.go). The default is spelled in the text
// because the flag's zero value has to stay "" to distinguish "not passed" from
// an explicit choice, so pflag cannot print it.
const scopeOriginFlagUsage = "Host scope strictness: all, relaxed, balanced, strict (default balanced; balanced admits any host sharing the target's eTLD+1, including subdomains already in the database from earlier scans)"

// registerScanPipelineFlags registers the phase/strategy/profile knobs that
// only make sense for the full native scan pipeline (scan + run).
func registerScanPipelineFlags(flags *pflag.FlagSet) {
	flags.StringVar(&globalOnly, "only", "", "Run only these phases (comma-separated: "+runner.PhaseNamesDesc(false)+"; aliases accepted, see `vigolium run --help`)")
	flags.StringSliceVar(&globalSkipPhases, "skip", nil, "Skip these phases (repeatable: "+runner.PhaseNamesDesc(true)+"; aliases accepted, see `vigolium run --help`)")
	flags.StringVar(&globalStrategy, "strategy", "", "Scanning strategy preset (lite, balanced, deep)")
	flags.StringVar(&globalScanningProfile, "scanning-profile", "", "Scanning profile name or YAML file path")
	flags.StringVar(&globalIntensity, "intensity", "", "Scan intensity preset: quick, balanced, or deep (maps to scanning profile + strategy)")
	flags.StringVar(&globalScopeOrigin, "scope-origin", "", scopeOriginFlagUsage)
	flags.DurationVar(&globalScanningMaxDuration, "scanning-max-duration", 0, "Maximum total scan duration (overrides config, e.g. 1h, 30m)")
	flags.StringVar(&globalHeuristicsCheck, "heuristics-check", "", `Pre-scan heuristics level: none, basic, advanced (default: basic)`)
	flags.BoolVar(&globalSkipHeuristics, "skip-heuristics", false, "Disable pre-scan heuristics (equivalent to --heuristics-check=none)")
}

// registerSpecFlags registers OpenAPI/Swagger spec options shared by scan
// (when -i is an OpenAPI file) and ingest.
func registerSpecFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&globalSpecURL, "spec-url", false, "Use base URLs from the OpenAPI spec's servers field")
	flags.StringArrayVar(&globalSpecHeader, "spec-header", nil, "Add HTTP header to OpenAPI-generated requests (repeatable; commas are literal)")
	flags.StringSliceVar(&globalSpecVar, "spec-var", nil, "Set OpenAPI parameter value as key=value (repeatable)")
	flags.StringVar(&globalSpecDefault, "spec-default", "1", "Fallback value for required OpenAPI parameters that lack examples")
}

// registerScanModuleFlags registers --modules/-m and --module-tag, used by
// every command that filters scanner modules at runtime (scan, run, ingest,
// scan-url, scan-request).
func registerScanModuleFlags(flags *pflag.FlagSet) {
	flags.StringSliceVarP(&globalModules, "modules", "m", nil, `Scan modules to enable (default "all", supports fuzzy match on ID/name, e.g. -m xss -m sqli)`)
	flags.StringSliceVar(&globalModuleTags, "module-tag", nil, `Filter modules by tag (OR condition, e.g. --module-tag spring --module-tag injection)`)
	flags.BoolVar(&globalNoTechFilter, "no-tech-filter", false, "Disable the tech-stack allowlist (run every module regardless of detected stack). Auto-enabled by --intensity=deep.")
}

// registerLightweightScanIOFlags registers the output/persistence/phase-skip
// flags shared by the lightweight single-request commands (scan-url,
// scan-request) so their output surface matches `vigolium scan`'s -o/--output,
// -S/--stateless, and --skip. When any of these (or a file output --format) is
// set, the command routes the request through the full native-scan Runner (see
// runRunnerScan) instead of the in-memory direct path, so the flags produce real
// jsonl/html files and a discarded temp DB exactly like the full scan command.
func registerLightweightScanIOFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&scanOpts.Output, "output", "o", "", "Write findings to this file (use with --format jsonl|html; pairs with -S/--stateless)")
	flags.BoolVarP(&globalStateless, "stateless", "S", false, "Use a temporary database that is discarded after the scan (pass --output/--format to persist results)")
	registerKeepDBOnErrorFlag(flags)
	flags.StringSliceVar(&globalSkipPhases, "skip", nil, "Skip these phases (repeatable: "+runner.PhaseNamesDesc(true)+"; aliases accepted, see `vigolium run --help`)")
	flags.StringVar(&scanFailOn, "fail-on", "", "Exit non-zero if a finding at or above this severity is present (info|low|medium|high|critical) — for CI/agent gating; --soft-fail overrides.")
	flags.BoolVar(&scanPrintFinding, "print-finding", false, "After the scan, print each finding to stdout as Markdown (description + matched evidence + request/response), like 'vigolium finding --markdown'. Pairs well with -S and --silent for a quick single-target scan.")
	flags.BoolVar(&scanPrintTrafficTree, "print-traffic-tree", false, "After the scan, print the run's HTTP traffic to stdout as a host/path hierarchy tree, like 'vigolium traffic --tree'. Pairs well with -S and --silent.")
	flags.BoolVar(&scanPrintTraffic, "print-traffic", false, "After the scan, print the run's raw HTTP request/response pairs to stdout, like 'vigolium traffic --raw'. Pairs well with -S and --silent.")
	registerEventsFlag(flags)
	// scan-url and scan-request read a request from stdin just as scan does,
	// so they get the same deadline dial. Neither registers
	// registerInputSourceFlags, so there is no double registration.
	registerInputReadTimeoutFlag(flags)
}

// registerKeepDBOnErrorFlag declares --keep-db-on-error, for the same reason
// registerEventsFlag exists: it is offered by both the full scan commands and
// the lightweight ones, and two literal registrations are two help texts waiting
// to diverge.
func registerKeepDBOnErrorFlag(flags *pflag.FlagSet) {
	flags.BoolVar(&globalKeepDBOnError, "keep-db-on-error", false,
		"On a failed -S/--stateless scan, move the throwaway working database to ~/.vigolium/recovered instead of deleting it, so the partial results survive the failure (requires -S)")
}

// registerEventsFlag declares --events. One definition, shared by the full scan
// commands and the lightweight ones: registering it twice with different help
// text meant `scan --help` and `scan-url --help` documented the same flag
// differently.
func registerEventsFlag(flags *pflag.FlagSet) {
	flags.StringVar(&scanOpts.Events, "events", "",
		"Emit a machine-readable event stream to stdout while the scan runs: 'ndjson' (one JSON object per line, flushed per event). "+
			"The human console stays on stderr, so a driver reads the stream with 2>/dev/null. "+
			"Events: scan.started, phase.started/progress/finished, waf.block, waf.pacing, finding.new, error, scan.finished.")
}

// markFlagDeprecated hides oldName from --help and makes pflag emit a one-time
// stderr warning ("Flag --<oldName> has been deprecated, use --<replacement>")
// when it is set. Use after registering a hidden alias whose variable is shared
// with the canonical flag. pflag's MarkDeprecated sets both Deprecated and Hidden
// (Deprecated alone still renders in usage, since FlagUsages only skips Hidden);
// the error is ignored — it only fires for an unknown flag or an empty message.
func markFlagDeprecated(flags *pflag.FlagSet, oldName, replacement string) {
	_ = flags.MarkDeprecated(oldName, "use --"+replacement)
}
