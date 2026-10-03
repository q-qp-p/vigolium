package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/fuzz"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/replay"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	// Source.
	fuzzInput      string
	fuzzInputFile  string
	fuzzRecordUUID string
	fuzzTargetURL  string

	// Curl-style request builder (used with a positional URL).
	fuzzMethod  string
	fuzzHeaders []string
	fuzzData    string

	// Positions.
	fuzzSelector    string
	fuzzPoints      []string
	fuzzFuzzHeaders []string
	fuzzKeyword     string

	// Payloads.
	fuzzWordlists []string
	fuzzClasses   []string
	fuzzPayloads  []string

	// Matchers (keep) and excludes (drop). Long flags only; pflag shorthands
	// are single-char. Numeric values take the predicate grammar (N, N-M, >N,
	// <N, !N). The flags bind straight into the struct buildCriteria consumes,
	// so adding a category is one field plus one registration rather than a
	// global, a struct field, and two hand-written copy lines that the compiler
	// cannot check.
	fuzzMatch   = criteriaFlags{kind: "match"}
	fuzzExclude = criteriaFlags{kind: "exclude"}

	// Attack mode / multi-marker.
	fuzzMode            string
	fuzzBaselineSamples int

	// Anomaly detection.
	fuzzAnomaly          bool
	fuzzAnomalyThreshold string
	fuzzAnomalyMinPop    int

	// Behaviour / output.
	fuzzDryRun      bool
	fuzzIgnoreScope bool
	fuzzNoCalibrate bool
	fuzzConcurrency int
	fuzzDelayMs     int
	fuzzTimeout     time.Duration
	fuzzNoRedirects bool
	fuzzOutputPath  string
	fuzzAllResults  bool
	fuzzPretty      bool
	fuzzFailOnMatch bool

	// Burp bridge.
	fuzzSendViaBurp        bool
	fuzzBurpBridgeURL      string
	fuzzHTTPMode           string
	fuzzSendTimeout        time.Duration
	fuzzMatchesToOrganizer bool
)

var fuzzCmd = &cobra.Command{
	Use:   "fuzz [url]",
	Short: "Inject payloads into a request and report per-payload response anomalies",
	Long: `Fuzz a single HTTP request: inject a payload set into chosen positions and stream
per-payload response signals (status, size, words, lines, time, reflection, baseline
delta) with match/exclude gating and auto-calibration against the target's
catch-all.

fuzz is a low-level PRIMITIVE, not a scanner. It sends exactly the payloads you give it
at exactly the positions you pick, and reports raw signals — it makes no vulnerability
decision and emits no findings. Bring your own intelligence (this is what a coding agent
drives): pick a position, pick a wordlist, read the anomalies. For opinionated,
confirmation-backed detection use the module scanner instead:
'vigolium scan-request -i req.txt -m xss,sqli -j'.

SOURCE (one of):
  vigolium fuzz https://acme.test/api?id=FUZZ         # positional URL (+ -X/-H/-d)
  vigolium fuzz -i req.txt                            # curl/raw HTTP/Burp/base64/URL/stdin
  vigolium fuzz -u <record-uuid>                      # a stored HTTP record as baseline
  cat req.txt | vigolium fuzz                         # piped request on stdin

POSITIONS (what to fuzz):
  a literal FUZZ marker anywhere (request line, path, header, body) wins if present;
  otherwise --fuzz method|path|params|param-name|headers|cookies|all (default: all
  discovered insertion points), or --point TYPE:name (e.g. URL_PARAM:id) / --header Name.

PAYLOADS (combine freely):
  --class <name,..>              built-in class: ` + strings.Join(fuzz.PayloadClasses(), ", ") + `
  -w/--wordlist <file|builtin>   builtins: ` + strings.Join(fuzz.BuiltinNames(), ", ") + `
  -p/--payload <literal>         inline payload (repeatable)

ANOMALY DETECTION (-a/--anomaly) — the alternative to writing matchers by hand:
  Writing a matcher means knowing the interesting size or status up front. Instead,
  --anomaly scores every response against the baseline AND against the run's own
  population, and keeps the ones that stand out. Signals: a rare status, a body no
  other payload produced, size/time outliers (median-absolute-deviation, so the
  outliers can't hide themselves), an error signature the baseline didn't have,
  a changed Location/Set-Cookie/WWW-Authenticate, and unencoded reflection.
  Each result carries "anomaly_score" and "anomaly_reasons" explaining the score.
    --anomaly-threshold low|medium|high   how strong a signal must be (default medium)
  With --anomaly and no explicit matchers, "interesting" replaces "keep everything".
  It reports where to look, never a verdict — confirm with the module scanner.

MATCHERS keep a response, EXCLUDES drop it. Numeric flags take a predicate:
  N (exact)  N-M (range)  >N  >=N  <N  <=N  !N (not), comma-separated:
  --match-status-code 200,301  --match-size '>1000'  --match-words 50-80
  --match-lines '!0'  --match-regex <re>  --match-time '>500'
  --match-header 'Location: /admin'      (presence-only: --match-header Location)
  --match-mode all                       require every matcher instead of any
  (every flag has an --exclude-* twin, with --exclude-mode)
  --match-status-code all keeps every status. Auto-calibration (on by default) suppresses
  the target's wildcard/catch-all response; suppressed results carry "calibrated":true.

OUTPUT:
  default        JSONL (one object per send) to stdout — matched only unless --all-results
  -j/--json      stream JSONL to stderr, print ONE summary object to stdout (agent handle:
                 baseline, counts, ranked top anomalies, a ready follow-up query)
Honors HTTP_PROXY / HTTPS_PROXY for Burp inspection.

BURP ENGINE (needs --burp-bridge-url, the extension's loopback listener):
  --send-via-burp         send every payload through Burp's own HTTP stack so exact bytes
                          hit the wire — the way to fuzz malformed/smuggling requests
                          (pair with --http-mode http1 so 'auto' doesn't reframe them)
  --matches-to-organizer  hand each matched request to Burp's Organizer (Burp re-issues it)
                          for manual triage
Neither changes the default send path — without them fuzz sends via Go's client as before.

fuzz reports raw signals, not verdicts — for confirmation-backed detection of known
classes use 'vigolium scan-request -m xss,sqli -j' instead.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runFuzz,
}

func init() {
	rootCmd.AddCommand(fuzzCmd)
	f := fuzzCmd.Flags()

	// Source.
	f.StringVarP(&fuzzInput, "input", "i", "", "Raw input: curl, raw HTTP, Burp XML, base64, URL, or '-' for stdin")
	f.StringVar(&fuzzInputFile, "input-file", "", "Read --input value from a file")
	f.StringVarP(&fuzzRecordUUID, "record-uuid", "u", "", "Use a stored HTTP record (by UUID) as the request to fuzz")
	f.StringVarP(&fuzzTargetURL, "target", "t", "", "Override scheme/host/port the request is sent to (e.g. https://staging.acme.test)")

	// Curl-style builder — applied to whatever source resolved the request.
	f.StringVarP(&fuzzMethod, "request", "X", "", "HTTP method override (default: the source request's, or GET)")
	f.StringArrayVarP(&fuzzHeaders, "header", "H", nil, "Request header 'Name: value', added or replaced on the source request (repeatable)")
	f.StringVarP(&fuzzData, "data", "d", "", "Request body override (refreshes Content-Length)")

	// Positions.
	f.StringVar(&fuzzSelector, "fuzz", "", "What to fuzz: method|path|params|param-name|headers|cookies|all (default: all insertion points)")
	f.StringArrayVar(&fuzzPoints, "point", nil, "Explicit insertion point 'TYPE:name' e.g. URL_PARAM:id (repeatable)")
	f.StringArrayVar(&fuzzFuzzHeaders, "fuzz-header", nil, "Fuzz a specific header by name (repeatable)")
	f.StringVar(&fuzzKeyword, "keyword", fuzz.DefaultKeyword, "Marker keyword replaced by each payload when present in the request")

	// Payloads.
	f.StringSliceVar(&fuzzClasses, "class", nil, "Built-in payload class to inject: "+strings.Join(fuzz.PayloadClasses(), ",")+" (comma-list)")
	f.StringArrayVarP(&fuzzWordlists, "wordlist", "w", nil, "Payload wordlist: a builtin name or file path (repeatable)")
	f.StringArrayVarP(&fuzzPayloads, "payload", "p", nil, "Inline payload literal (repeatable)")

	// Matchers keep a response; excludes drop it. Same surface on both sides,
	// registered from one table so they cannot drift.
	registerCriteriaFlags(f, &fuzzMatch, "match", "Match")
	registerCriteriaFlags(f, &fuzzExclude, "exclude", "Exclude")

	f.StringVar(&fuzzMode, "mode", "sniper",
		"With several markers (FUZZ, FUZZ2, ...): sniper (one at a time) | batteringram (same payload everywhere) | pitchfork (lists in lockstep) | clusterbomb (every combination)")
	f.IntVar(&fuzzBaselineSamples, "baseline-samples", 0,
		"Send the un-fuzzed request this many times to measure timing jitter, enabling time_z (default 1, or 3 with --anomaly)")

	// Anomaly detection — the alternative to writing matchers by hand.
	f.BoolVarP(&fuzzAnomaly, "anomaly", "a", false,
		"Auto-detect interesting responses instead of requiring explicit matchers: score each response against the baseline AND the run's own population (rare status, unique body, size/time outliers, new error signatures, changed headers, unencoded reflection)")
	f.StringVar(&fuzzAnomalyThreshold, "anomaly-threshold", "medium",
		"How strong a signal must be to report: low|medium|high, or a number")
	f.IntVar(&fuzzAnomalyMinPop, "anomaly-min-population", 0,
		"Responses needed before population signals (rarity/outliers) count (default 12)")

	// Behaviour / output.
	f.BoolVar(&fuzzDryRun, "dry-run", false, "Resolve positions and payloads, print what would be sent, and exit without any network traffic")
	f.BoolVar(&fuzzIgnoreScope, "ignore-scope", false, "Fuzz a host outside the project's configured scope")
	f.BoolVar(&fuzzNoCalibrate, "no-calibrate", false, "Disable auto-calibration of the target's catch-all response")
	f.IntVarP(&fuzzConcurrency, "concurrency", "c", 10, "Concurrent requests")
	f.IntVar(&fuzzDelayMs, "delay", 0, "Delay in ms before each request (per worker)")
	f.DurationVar(&fuzzTimeout, "timeout", replay.DefaultTimeout, "Per-request timeout (e.g. 30s)")
	f.BoolVar(&fuzzNoRedirects, "no-redirects", false, "Don't follow 30x redirects")
	f.StringVarP(&fuzzOutputPath, "output", "o", "", "Write JSONL results to this file (default: stdout)")
	f.BoolVar(&fuzzAllResults, "all-results", false, "Emit every result, not just matched ones")
	f.BoolVar(&fuzzPretty, "pretty", false, "Human-readable table instead of JSONL")
	f.BoolVar(&fuzzFailOnMatch, "fail-on-match", false, "Exit non-zero (3) if any result matches (for agent/CI gating)")

	// Burp bridge — route each payload through Burp's engine (exact bytes) and,
	// optionally, hand matched anomalies to Burp's Organizer for triage.
	f.BoolVar(&fuzzSendViaBurp, "send-via-burp", false,
		"Send each payload through Burp's own HTTP stack (exact bytes — malformed/smuggling preserved) instead of Go's client; requires --burp-bridge-url")
	registerBridgeURLFlag(fuzzCmd, &fuzzBurpBridgeURL,
		"Loopback Burp/Caido bridge URL used by --send-via-burp / --matches-to-organizer")
	f.StringVar(&fuzzHTTPMode, "http-mode", "",
		"With --send-via-burp: wire protocol — auto|http1|http2|http2_ignore_alpn (default auto; use http1 for request smuggling/desync)")
	f.DurationVar(&fuzzSendTimeout, "send-timeout", 0,
		"With --send-via-burp: per-request response timeout (<=2m; default uses the bridge's 30s)")
	f.BoolVar(&fuzzMatchesToOrganizer, "matches-to-organizer", false,
		"Push each matched result's request to Burp's Organizer (Burp re-issues it) for manual triage; requires --burp-bridge-url")

	// Curl-compatible request/transport/session flags.
	registerFuzzNetFlags(f)

}

// fuzzOrganizerCap bounds how many matched requests are pushed to Burp's
// Organizer, so a wide-open match set can't flood Burp with tabs/items.
const fuzzOrganizerCap = 200

func runFuzz(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()
	ctx := cmd.Context()

	if err := validateFuzzNetFlags(); err != nil {
		return err
	}

	src, err := resolveFuzzSource(ctx, args)
	if err != nil {
		return err
	}
	if fuzzTargetURL != "" {
		if err := applyTargetOverride(src, fuzzTargetURL); err != nil {
			return err
		}
	}
	// A line-trimming stdin reader can strip the request's header terminator;
	// repair it so insertion-point analysis and the send path both parse.
	src.BaselineRequest = fuzz.NormalizeRawRequest(src.BaselineRequest)

	// -X/-H/-d and the curl request flags apply to every source, not just a
	// positional URL, and land before position analysis so a marker introduced
	// by -H is discovered like any other.
	overrides, err := buildFuzzOverrides(ctx, src, len(args) == 1)
	if err != nil {
		return err
	}
	src.BaselineRequest, err = overrides.Apply(src.BaselineRequest)
	if err != nil {
		return err
	}

	if err := checkFuzzScope(src.Hostname); err != nil {
		return err
	}

	positions, err := fuzz.ResolvePositions(src.BaselineRequest, fuzz.Selectors{
		Mode:        fuzzSelector,
		NamedPoints: fuzzPoints,
		HeaderNames: fuzzFuzzHeaders,
		Keyword:     fuzzKeyword,
	})
	if err != nil {
		return err
	}

	payloads, sets, err := loadFuzzPayloadSets(positions)
	if err != nil {
		return err
	}

	mode, err := fuzz.ParseAttackMode(fuzzMode)
	if err != nil {
		return err
	}
	cases, err := fuzz.BuildCases(mode, positions, sets, payloads)
	if err != nil {
		return err
	}

	// --dry-run answers "will this do what I meant?" before any traffic —
	// which position selector resolved to what, and the exact bytes a payload
	// produces. Everything above this line is offline; nothing below is.
	if fuzzDryRun {
		return emitFuzzDryRun(src, positions, payloads, cases)
	}

	bridge, err := setupFuzzBurpBridge(ctx, src)
	if err != nil {
		return err
	}

	matchers, err := buildMatchers()
	if err != nil {
		return err
	}
	filters, err := buildFilters()
	if err != nil {
		return err
	}
	anomalyCfg, err := buildAnomalyConfig()
	if err != nil {
		return err
	}

	// Result-stream sink. Under -j, stdout is reserved for the single summary
	// object, so per-payload JSONL streams to stderr (the agent can still tail
	// it); an explicit -o file always wins.
	out := os.Stdout
	switch {
	case fuzzOutputPath != "":
		f, err := os.Create(fuzzOutputPath)
		if err != nil {
			return fmt.Errorf("create --output %q: %w", fuzzOutputPath, err)
		}
		defer func() { _ = f.Close() }()
		out = f
	case globalJSON:
		out = os.Stderr
	}
	// Buffered: the engine calls OnResult on its serialized path, so an
	// unbuffered write(2) per result put every worker behind one syscall.
	sink := bufio.NewWriter(out)
	defer func() { _ = sink.Flush() }()
	enc := json.NewEncoder(sink)

	cookies, jarLoaded, saveJar, err := fuzzCookieJar()
	if err != nil {
		return err
	}
	defer saveJar()
	client, err := buildFuzzClient(cookies)
	if err != nil {
		return err
	}
	if jarLoaded > 0 {
		fmt.Fprintf(os.Stderr, "%s session %s: preloaded %d cookie(s)\n",
			terminal.InfoSymbol(), fuzzSessionID, jarLoaded)
	}

	fmt.Fprintf(os.Stderr, "%s fuzzing %s://%s (%d position(s), %s, %d sends)\n",
		terminal.InfoSymbol(), src.Scheme, src.Hostname, len(positions), mode, len(cases))

	// OnResult is called serially by the engine, so no extra locking is needed
	// to accumulate the ranked top anomalies for the -j summary.
	var topResults []fuzz.Result
	job := fuzz.Job{
		Raw:             src.BaselineRequest,
		Scheme:          src.Scheme,
		Hostname:        src.Hostname,
		Port:            src.Port,
		Positions:       positions,
		Payloads:        payloads,
		Cases:           cases,
		Matchers:        matchers,
		Filters:         filters,
		Anomaly:         anomalyCfg,
		BaselineSamples: resolveBaselineSamples(anomalyCfg != nil),
		AutoCalibrate:   !fuzzNoCalibrate,
		// buildFuzzClient (not replay.NewDefaultClient) so the global --proxy
		// flag actually routes fuzz traffic — it was accepted and silently
		// ignored here — and so the curl TLS/redirect/resolve options apply.
		Client:      client,
		NoRedirects: fuzzNoRedirects,
		Concurrency: fuzzConcurrency,
		DelayMs:     fuzzDelayMs,
		OnResult: func(r fuzz.Result) {
			if fuzzAllResults || r.Matched {
				if fuzzPretty {
					_, _ = fmt.Fprintln(sink, prettyResult(r))
				} else {
					_ = enc.Encode(r)
				}
			}
			if globalJSON && r.Matched && len(topResults) < fuzzTopResultsCollect {
				topResults = append(topResults, r)
			}
		},
	}
	// --send-via-burp: every send goes through Burp's engine byte-for-byte.
	if bridge != nil && bridge.sendViaBurp {
		job.Sender = burpbridge.BridgeSender(bridge.client, src.Scheme, src.Hostname, src.Port, bridge.sendOpts, fuzzExcerptCap())
	}
	// --matches-to-organizer: collect matched requests (cheap, on the engine's
	// serialized path) so they can be handed to Burp's Organizer after the run
	// without blocking sends.
	var organizerMatches []fuzzOrganizerMatch
	var organizerOverflow int
	if bridge != nil && bridge.toOrganizer {
		job.OnMatch = func(r fuzz.Result, rawRequest []byte) {
			if len(organizerMatches) >= fuzzOrganizerCap {
				organizerOverflow++
				return
			}
			organizerMatches = append(organizerMatches, fuzzOrganizerMatch{
				rawRequest: append([]byte(nil), rawRequest...),
				notes:      fmt.Sprintf("fuzz %s:%s=%s", r.PositionType, r.Position, r.Payload),
				highlight:  fuzzMatchHighlight(r),
			})
		}
	}

	report, runErr := fuzz.Run(ctx, job)
	_ = sink.Flush()
	if report != nil {
		fmt.Fprintf(os.Stderr, "%s baseline: status=%d len=%d | sent=%d matched=%d calibrated=%d errors=%d\n",
			terminal.InfoSymbol(), report.Baseline.Status, report.Baseline.Length,
			report.Sent, report.Matched, report.Calibrated, report.Errors)
		if anomalyCfg != nil {
			emitAnomalyReport(out, report)
		}
	}
	if runErr != nil {
		return runErr
	}

	organizerPushed := 0
	if bridge != nil && bridge.toOrganizer {
		organizerPushed = pushFuzzMatchesToOrganizer(ctx, bridge, src, organizerMatches, organizerOverflow)
	}

	if globalJSON && report != nil {
		if err := emitFuzzJSONSummary(src, args, len(positions), len(payloads), report, topResults, bridge != nil && bridge.sendViaBurp, organizerPushed); err != nil {
			return err
		}
	}
	if fuzzFailOnMatch && report != nil && report.Matched > 0 {
		return asMatchErrorf("--fail-on-match: %d request(s) matched", report.Matched)
	}
	return nil
}

// requestMethodOf reports a raw request's verb for display, tolerating a
// malformed request rather than failing the whole dry run over it.
func requestMethodOf(raw []byte) string {
	method, err := httpmsg.GetMethod(raw)
	if err != nil {
		return ""
	}
	return method
}

// loadFuzzPayloadSets assembles the shared payload list plus, when a wordlist
// or class was bound to a marker with the "ref:KEYWORD" suffix, a per-position
// list.
//
// The binding syntax is what makes pitchfork and clusterbomb usable: they need
// to know which list belongs to FUZZ and which to FUZZ2, and there is no way
// to say that with a flat payload set. Unbound lists stay in the shared pool,
// so single-marker runs are unaffected.
func loadFuzzPayloadSets(positions []fuzz.Position) (shared []string, sets [][]string, err error) {
	indexOf := make(map[string]int, len(positions))
	for i, p := range positions {
		indexOf[strings.ToUpper(p.Name)] = i
	}
	sets = make([][]string, len(positions))

	var sharedWordlists, sharedClasses []string
	boundWordlists := make(map[int][]string)
	boundClasses := make(map[int][]string)

	// bind splits "value:KEYWORD" when KEYWORD names a resolved marker. A
	// wordlist path containing a colon is far more likely than a stray marker
	// name, so the suffix only counts when it actually matches a position.
	bind := func(ref string, sharedDst *[]string, boundDst map[int][]string) {
		if base, keyword, ok := lastCut(ref, ":"); ok {
			if idx, known := indexOf[strings.ToUpper(keyword)]; known {
				boundDst[idx] = append(boundDst[idx], base)
				return
			}
		}
		*sharedDst = append(*sharedDst, ref)
	}
	for _, w := range fuzzWordlists {
		bind(w, &sharedWordlists, boundWordlists)
	}
	for _, c := range fuzzClasses {
		bind(c, &sharedClasses, boundClasses)
	}

	// Inline -p payloads are always shared; there is no sensible place to hang
	// a keyword off a literal.
	shared, err = fuzz.LoadPayloads(sharedWordlists, sharedClasses, fuzzPayloads)
	if err != nil && len(boundWordlists)+len(boundClasses) == 0 {
		return nil, nil, err
	}

	for idx := range positions {
		if len(boundWordlists[idx]) == 0 && len(boundClasses[idx]) == 0 {
			continue
		}
		list, lerr := fuzz.LoadPayloads(boundWordlists[idx], boundClasses[idx], nil)
		if lerr != nil {
			return nil, nil, fmt.Errorf("payloads for %s: %w", positions[idx].Name, lerr)
		}
		sets[idx] = list
	}
	return shared, sets, nil
}

// lastCut splits s at the final occurrence of sep.
func lastCut(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

// resolveBaselineSamples picks how many baseline sends to make. Anomaly runs
// default to 3 because the detector's timing signal is worthless without a
// deviation to compare against; plain runs stay at 1 so nothing gets slower
// for a statistic nobody asked for.
func resolveBaselineSamples(anomalyOn bool) int {
	if fuzzBaselineSamples > 0 {
		return fuzzBaselineSamples
	}
	if anomalyOn {
		return 3
	}
	return 1
}

// emitAnomalyReport prints the ranked anomalies after a --anomaly run.
//
// It goes to stderr (not the result sink) so it never contaminates the JSONL
// stream a caller is parsing; the same anomalies also ride in the -j summary
// object, which is where an agent should read them from.
func emitAnomalyReport(sink *os.File, report *fuzz.Report) {
	if len(report.Anomalies) == 0 {
		fmt.Fprintf(os.Stderr, "%s no anomalies at the %s threshold — every response looked like the others\n",
			terminal.InfoSymbol(), fuzzAnomalyThreshold)
		return
	}
	// Only render the human table when the results themselves aren't already
	// going to stdout as JSONL for something else to read.
	if sink != os.Stdout || fuzzPretty {
		fmt.Fprintf(os.Stderr, "%s %d anomal%s found:\n",
			terminal.InfoSymbol(), len(report.Anomalies), plural(len(report.Anomalies), "y", "ies"))
		for _, a := range report.Anomalies {
			fmt.Fprintf(os.Stderr, "  [%3d] %s:%s = %q  status=%d len=%d\n",
				a.AnomalyScore, a.PositionType, a.Position, a.Payload, a.Status, a.Length)
			for _, reason := range a.AnomalyReasons {
				fmt.Fprintf(os.Stderr, "        +%-2d %s%s\n", reason.Weight, reason.Signal, detailSuffix(reason.Detail))
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s %d anomal%s found (scored in the JSONL stream)\n",
			terminal.InfoSymbol(), len(report.Anomalies), plural(len(report.Anomalies), "y", "ies"))
	}
	if report.AnomaliesElided > 0 {
		fmt.Fprintf(os.Stderr, "  ... and %d more above the threshold\n", report.AnomaliesElided)
	}
}

func detailSuffix(detail string) string {
	if detail == "" {
		return ""
	}
	return " — " + detail
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// checkFuzzScope refuses to fuzz a host outside the project's configured
// scope. fuzz sends a lot of traffic at whatever it's pointed at, and the
// source is often a pasted command whose target isn't obvious at a glance, so
// the cheap guard is worth it. A project with no host scope configured passes
// everything, and --ignore-scope is the deliberate override.
func checkFuzzScope(hostname string) error {
	if fuzzIgnoreScope || hostname == "" {
		return nil
	}
	// Scope is a guard rail, not a gate: an unreadable config must not stop an
	// operator who asked for a specific target. It must not do so SILENTLY
	// either — the fallback scope is "everything in the config's scope section",
	// which an empty default makes vacuous, so the warning is the only sign the
	// guard rail is not the one that was configured.
	settings := settingsOrDefaults()
	matcher := config.NewScopeMatcher(settings.Scope, globalTargets...)
	if matcher.HostInScope(hostname) {
		return nil
	}
	return fmt.Errorf("%s is outside the project's configured scope; pass --ignore-scope to fuzz it anyway", hostname)
}

// fuzzDryRun is the --dry-run report: what fuzz resolved, and the exact bytes
// the first payload produces at each position.
type fuzzDryRunReport struct {
	Target      string             `json:"target"`
	Method      string             `json:"method"`
	Mode        string             `json:"mode,omitempty"`
	Positions   []fuzzDryRunPos    `json:"positions"`
	Payloads    fuzzDryRunPayloads `json:"payloads"`
	Sends       int                `json:"sends"`
	Request     string             `json:"baseline_request"`
	ExampleCase string             `json:"example_case,omitempty"`
}

type fuzzDryRunPos struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Base    string `json:"base_value,omitempty"`
	Example string `json:"example_request"`
}

type fuzzDryRunPayloads struct {
	Count  int      `json:"count"`
	Sample []string `json:"sample"`
	Elided int      `json:"elided,omitempty"`
}

// fuzzDryRunSample bounds how many payloads the report echoes back.
const fuzzDryRunSample = 10

func emitFuzzDryRun(src *replaySource, positions []fuzz.Position, payloads []string, cases []fuzz.Case) error {
	probe := "FUZZED"
	if len(payloads) > 0 {
		probe = payloads[0]
	}
	report := fuzzDryRunReport{
		Target:  replaySourceURL(src),
		Method:  requestMethodOf(src.BaselineRequest),
		Mode:    fuzzMode,
		Sends:   len(cases),
		Request: string(src.BaselineRequest),
		Payloads: fuzzDryRunPayloads{
			Count:  len(payloads),
			Sample: payloads[:min(len(payloads), fuzzDryRunSample)],
			Elided: max(0, len(payloads)-fuzzDryRunSample),
		},
	}
	for _, p := range positions {
		report.Positions = append(report.Positions, fuzzDryRunPos{
			Type:    p.Label,
			Name:    p.Name,
			Base:    p.Base,
			Example: string(fuzz.BuildAt(p, src.BaselineRequest, probe)),
		})
	}
	// Under a multi-position mode the per-position example understates what
	// actually goes on the wire, so show the first real case too.
	if len(cases) > 0 && len(cases[0].Assignments) > 1 {
		report.ExampleCase = string(fuzz.BuildCase(cases[0], src.BaselineRequest))
	}

	if globalJSON {
		return writeAgentJSON(report)
	}
	fmt.Printf("%s dry run — %d position(s), %s, %d sends, nothing sent\n\n",
		terminal.InfoSymbol(), len(positions), fuzzMode, report.Sends)
	for _, p := range report.Positions {
		fmt.Printf("  %s:%s\n", p.Type, p.Name)
		if p.Base != "" {
			fmt.Printf("    base value: %q\n", p.Base)
		}
		fmt.Printf("    with payload %q:\n", probe)
		for _, line := range strings.Split(strings.TrimRight(p.Example, "\r\n"), "\n") {
			fmt.Printf("      %s\n", strings.TrimRight(line, "\r"))
		}
		fmt.Println()
	}
	if report.ExampleCase != "" {
		fmt.Printf("  first %s case (all positions at once):\n", fuzzMode)
		for _, line := range strings.Split(strings.TrimRight(report.ExampleCase, "\r\n"), "\n") {
			fmt.Printf("      %s\n", strings.TrimRight(line, "\r"))
		}
		fmt.Println()
	}
	fmt.Printf("  payloads (%d): %s\n", report.Payloads.Count, strings.Join(report.Payloads.Sample, ", "))
	if report.Payloads.Elided > 0 {
		fmt.Printf("  ... and %d more\n", report.Payloads.Elided)
	}
	return nil
}

// fuzzBurpBridge holds the resolved bridge client and send settings for a fuzz
// run; nil when no Burp flag was set.
type fuzzBurpBridge struct {
	client      *burpbridge.Client
	sendViaBurp bool
	toOrganizer bool
	sendOpts    burpbridge.SendOptions
}

// fuzzOrganizerMatch is one matched request queued for Burp's Organizer.
type fuzzOrganizerMatch struct {
	rawRequest []byte
	notes      string
	highlight  string
}

// setupFuzzBurpBridge validates the bridge flags and preflights the listener so
// an unavailable bridge fails clearly up front. Returns nil (no error) when no
// Burp flag is set — the default send path is untouched.
func setupFuzzBurpBridge(ctx context.Context, _ *replaySource) (*fuzzBurpBridge, error) {
	if !fuzzSendViaBurp && !fuzzMatchesToOrganizer {
		if fuzzHTTPMode != "" {
			fmt.Fprintf(os.Stderr, "%s --http-mode only applies with --send-via-burp; ignoring\n", terminal.WarningSymbol())
		}
		return nil, nil
	}
	if strings.TrimSpace(fuzzBurpBridgeURL) == "" {
		return nil, fmt.Errorf("--send-via-burp/--matches-to-organizer require --burp-bridge-url")
	}
	httpMode, err := burpbridge.ParseHTTPMode(fuzzHTTPMode)
	if err != nil {
		return nil, fmt.Errorf("--http-mode: %w", err)
	}
	if fuzzHTTPMode != "" && !fuzzSendViaBurp {
		fmt.Fprintf(os.Stderr, "%s --http-mode only applies with --send-via-burp; ignoring\n", terminal.WarningSymbol())
	}
	validated, err := burpbridge.ValidateURL(fuzzBurpBridgeURL)
	if err != nil {
		return nil, fmt.Errorf("--burp-bridge-url: %w", err)
	}
	client, err := burpbridge.New(validated)
	if err != nil {
		return nil, err
	}
	if _, err := preflightBridge(ctx, client, true); err != nil {
		return nil, err
	}
	return &fuzzBurpBridge{
		client:      client,
		sendViaBurp: fuzzSendViaBurp,
		toOrganizer: fuzzMatchesToOrganizer,
		sendOpts:    burpbridge.SendOptions{Mode: httpMode, Timeout: fuzzSendTimeout},
	}, nil
}

// pushFuzzMatchesToOrganizer hands each collected match to Burp's Organizer,
// letting Burp re-issue the request (send:true) so the stored item carries a
// live response for manual triage. Runs after the fuzz loop so it never slows
// sending; per-item failures are counted, not fatal.
func pushFuzzMatchesToOrganizer(ctx context.Context, bridge *fuzzBurpBridge, src *replaySource, matches []fuzzOrganizerMatch, overflow int) int {
	if len(matches) == 0 {
		return 0
	}
	target := replaySourceURL(src)
	pushed, failed := 0, 0
	for _, m := range matches {
		_, err := bridge.client.SendToOrganizer(ctx, target, "", m.rawRequest, nil, burpbridge.OrganizerOptions{
			Source:    "vigolium-fuzz",
			Notes:     m.notes,
			Highlight: m.highlight,
			Send:      true,
			Mode:      bridge.sendOpts.Mode,
			Timeout:   bridge.sendOpts.Timeout,
		})
		if err != nil {
			failed++
			continue
		}
		pushed++
	}
	fmt.Fprintf(os.Stderr, "%s pushed %d matched request(s) to Burp Organizer", terminal.InfoSymbol(), pushed)
	if failed > 0 {
		fmt.Fprintf(os.Stderr, " (%d failed)", failed)
	}
	if overflow > 0 {
		fmt.Fprintf(os.Stderr, "; %d more matched but the %d-item cap was hit", overflow, fuzzOrganizerCap)
	}
	fmt.Fprintln(os.Stderr)
	return pushed
}

// fuzzMatchHighlight picks a Burp Organizer highlight colour by anomaly type so
// a batch is visually triageable: status change (red), reflection (orange), else
// yellow.
func fuzzMatchHighlight(r fuzz.Result) string {
	switch {
	case r.StatusChanged:
		return "red"
	case r.Reflected:
		return "orange"
	default:
		return "yellow"
	}
}

// fuzzExcerptCap returns the excerpt clip size used for the run (mirrors the
// engine default) so the Burp sender's Summary excerpt matches the native path.
func fuzzExcerptCap() int {
	return replay.DefaultExcerptCap
}

// resolveFuzzSource picks the request to fuzz from a positional URL, -i/--input,
// -u/--record-uuid, or piped stdin — reusing replay's source resolvers.
func resolveFuzzSource(ctx context.Context, args []string) (*replaySource, error) {
	set := 0
	if len(args) == 1 {
		set++
	}
	if fuzzInput != "" || fuzzInputFile != "" {
		set++
	}
	if fuzzRecordUUID != "" {
		set++
	}
	if set > 1 {
		return nil, fmt.Errorf("choose one source: a positional URL, --input/--input-file, or --record-uuid")
	}

	var repo *database.Repository
	if db, dbErr := openReadDB(globDBSkipSet{}); dbErr == nil {
		repo = database.NewRepository(db)
	}

	switch {
	case len(args) == 1:
		// -X defaults to empty so it can mean "leave the source request's verb
		// alone"; a URL has no verb to leave alone, so it falls back to GET.
		method := fuzzMethod
		if method == "" {
			method = "GET"
		}
		rr, err := buildRequestFromFlags(args[0], method, fuzzData, fuzzHeaders)
		if err != nil {
			return nil, err
		}
		u, err := rr.URL()
		if err != nil || u == nil || u.URL == nil {
			return nil, fmt.Errorf("could not derive URL from %q", args[0])
		}
		return &replaySource{
			BaselineRequest: rr.Request().Raw(),
			Scheme:          u.Scheme,
			Hostname:        u.Hostname(),
			Port:            portFromURL(u.URL),
		}, nil

	case fuzzInput != "" || fuzzInputFile != "":
		return sourceFromInput(ctx, repo, fuzzInput, fuzzInputFile)

	case fuzzRecordUUID != "":
		if repo == nil {
			return nil, fmt.Errorf("--record-uuid requires database access")
		}
		return sourceFromRecord(ctx, repo, fuzzRecordUUID)

	default:
		if data, ok := readStdinIfPiped(); ok {
			return sourceFromInputString(ctx, repo, data, "")
		}
		return nil, fmt.Errorf("no source: pass a URL, --input, --record-uuid, or pipe a request on stdin")
	}
}

// registerCriteriaFlags registers one criteria family (keep or drop) against
// its own destination struct. verb is the flag prefix ("match"/"exclude") and
// Verb its capitalized form for help text.
func registerCriteriaFlags(f *pflag.FlagSet, dst *criteriaFlags, verb, Verb string) {
	const grammar = "N, N-M, >N, <N, !N"
	f.StringSliceVar(&dst.status, verb+"-status-code", nil, Verb+" status codes: "+grammar+", or 'all'")
	f.StringSliceVar(&dst.sizes, verb+"-size", nil, Verb+" response sizes in bytes: "+grammar)
	f.StringSliceVar(&dst.words, verb+"-words", nil, Verb+" response word counts: "+grammar)
	f.StringSliceVar(&dst.lines, verb+"-lines", nil, Verb+" response line counts: "+grammar)
	f.StringVar(&dst.regex, verb+"-regex", "", Verb+" responses whose body matches this regex")
	f.StringSliceVar(&dst.times, verb+"-time", nil, Verb+" response times in ms: "+grammar+" (bare N means >=N)")
	f.StringSliceVar(&dst.timeZ, verb+"-time-z", nil,
		Verb+" response times by standard deviations above the baseline mean (needs --baseline-samples > 1); e.g. 4 or '>3'")
	f.StringArrayVar(&dst.headers, verb+"-header", nil,
		Verb+" on a response header: 'Name' for presence, or 'Name: regex' (repeatable)")
	f.StringVar(&dst.mode, verb+"-mode", "any", "Combine "+verb+" flags with 'any' (OR) or 'all' (AND)")
}

func buildMatchers() (fuzz.Matchers, error) { return buildCriteria(fuzzMatch) }

func buildFilters() (fuzz.Filters, error) { return buildCriteria(fuzzExclude) }

// criteriaFlags is the raw flag input for one criteria set; kind names the
// flag family so errors point at the flag the operator actually typed.
type criteriaFlags struct {
	kind    string
	status  []string
	sizes   []string
	words   []string
	lines   []string
	times   []string
	timeZ   []string
	regex   string
	headers []string
	mode    string
}

func buildCriteria(in criteriaFlags) (fuzz.Criteria, error) {
	var c fuzz.Criteria

	// "all" is only meaningful on the keep side, but accepting it either way
	// and letting it mean "every status" keeps the two families symmetrical.
	var statusTokens []string
	for _, s := range in.status {
		if strings.EqualFold(strings.TrimSpace(s), "all") {
			c.AllStatus = true
			continue
		}
		statusTokens = append(statusTokens, s)
	}

	var err error
	if c.Status, err = fuzz.ParseNumPredicates(statusTokens, "--"+in.kind+"-status-code"); err != nil {
		return c, err
	}
	if c.Sizes, err = fuzz.ParseNumPredicates(in.sizes, "--"+in.kind+"-size"); err != nil {
		return c, err
	}
	if c.Words, err = fuzz.ParseNumPredicates(in.words, "--"+in.kind+"-words"); err != nil {
		return c, err
	}
	if c.Lines, err = fuzz.ParseNumPredicates(in.lines, "--"+in.kind+"-lines"); err != nil {
		return c, err
	}
	// Bare numbers on the time flags mean "at least this", which is the only
	// reading that ever fires against a millisecond measurement.
	if c.TimeMs, err = fuzz.ParseNumPredicatesDefaultOp(in.times, ">=", "--"+in.kind+"-time"); err != nil {
		return c, err
	}
	if c.TimeZ, err = fuzz.ParseNumPredicatesDefaultOp(in.timeZ, ">=", "--"+in.kind+"-time-z"); err != nil {
		return c, err
	}

	if in.regex != "" {
		re, cerr := regexp.Compile(in.regex)
		if cerr != nil {
			return c, fmt.Errorf("bad --%s-regex: %w", in.kind, cerr)
		}
		c.Regex = re
	}

	for _, h := range in.headers {
		hm, herr := parseHeaderMatcher(h, "--"+in.kind+"-header")
		if herr != nil {
			return c, herr
		}
		c.Headers = append(c.Headers, hm)
	}

	switch strings.ToLower(strings.TrimSpace(in.mode)) {
	case "", "any", "or":
		c.Mode = fuzz.MatchAny
	case "all", "and":
		c.Mode = fuzz.MatchAll
	default:
		return c, fmt.Errorf("bad --%s-mode %q: want 'any' or 'all'", in.kind, in.mode)
	}
	return c, nil
}

// parseHeaderMatcher accepts "Name" (presence) or "Name: regex".
func parseHeaderMatcher(spec, flag string) (fuzz.HeaderMatcher, error) {
	name, pattern, hasPattern := strings.Cut(spec, ":")
	name = strings.TrimSpace(name)
	if name == "" {
		return fuzz.HeaderMatcher{}, fmt.Errorf("%s %q: want 'Name' or 'Name: regex'", flag, spec)
	}
	hm := fuzz.HeaderMatcher{Name: name}
	if pattern = strings.TrimSpace(pattern); hasPattern && pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return hm, fmt.Errorf("%s %q: bad regex: %w", flag, spec, err)
		}
		hm.Value = re
	}
	return hm, nil
}

// buildAnomalyConfig returns the detector config, or nil when --anomaly is off.
func buildAnomalyConfig() (*fuzz.AnomalyConfig, error) {
	if !fuzzAnomaly {
		return nil, nil
	}
	cfg := fuzz.DefaultAnomalyConfig()
	if t := strings.TrimSpace(fuzzAnomalyThreshold); t != "" {
		if score, ok := fuzz.ParseAnomalyThreshold(t); ok {
			cfg.Threshold = score
		} else if n, err := strconv.Atoi(t); err == nil && n > 0 {
			cfg.Threshold = n
		} else {
			return nil, fmt.Errorf("bad --anomaly-threshold %q: want low|medium|high or a positive number", t)
		}
	}
	if fuzzAnomalyMinPop > 0 {
		cfg.MinPopulation = fuzzAnomalyMinPop
	}
	return &cfg, nil
}

const (
	// fuzzTopResultsCollect caps how many matched results are held in memory to
	// rank for the -j summary; fuzzTopResultsEmit caps how many are printed.
	fuzzTopResultsCollect = 500
	fuzzTopResultsEmit    = 20
)

// fuzzJSONSummary is the single object printed to stdout under -j: a compact,
// agent-friendly handle on the run (baseline, counts, ranked anomalies, and a
// ready confirmation command) so an agent needn't parse the JSONL stream.
type fuzzJSONSummary struct {
	Target          string        `json:"target"`
	Positions       int           `json:"positions"`
	Payloads        int           `json:"payloads"`
	Sent            int           `json:"sent"`
	Matched         int           `json:"matched"`
	Calibrated      int           `json:"calibrated"`
	Errors          int           `json:"errors"`
	Baseline        fuzz.Baseline `json:"baseline"`
	TopResults      []fuzz.Result `json:"top_results"`
	Anomalies       []fuzz.Result `json:"anomalies,omitempty"`
	AnomaliesElided int           `json:"anomalies_elided,omitempty"`
	Query           string        `json:"query,omitempty"`
	SentViaBurp     bool          `json:"sent_via_burp,omitempty"`
	OrganizerPushed int           `json:"organizer_pushed,omitempty"`
}

func emitFuzzJSONSummary(src *replaySource, args []string, positions, payloadCount int, report *fuzz.Report, top []fuzz.Result, sentViaBurp bool, organizerPushed int) error {
	sort.SliceStable(top, func(i, j int) bool { return fuzzResultRank(top[i]) > fuzzResultRank(top[j]) })
	if len(top) > fuzzTopResultsEmit {
		top = top[:fuzzTopResultsEmit]
	}
	return writeAgentJSON(fuzzJSONSummary{
		Target:          fmt.Sprintf("%s://%s", src.Scheme, src.Hostname),
		Positions:       positions,
		Payloads:        payloadCount,
		Sent:            report.Sent,
		Matched:         report.Matched,
		Calibrated:      report.Calibrated,
		Errors:          report.Errors,
		Baseline:        report.Baseline,
		TopResults:      top,
		Anomalies:       report.Anomalies,
		AnomaliesElided: report.AnomaliesElided,
		Query:           fuzzFollowUpQuery(args, report.Matched),
		SentViaBurp:     sentViaBurp,
		OrganizerPushed: organizerPushed,
	})
}

// fuzzResultRank scores a matched result so the most investigation-worthy
// anomalies sort first: a changed status, then reflection, then the magnitude
// of the size delta, then response time.
func fuzzResultRank(r fuzz.Result) int {
	score := 0
	if r.StatusChanged {
		score += 1_000_000
	}
	if r.Reflected {
		score += 500_000
	}
	delta := r.LengthDelta
	if delta < 0 {
		delta = -delta
	}
	score += delta
	score += int(r.TimeMs)
	return score
}

// fuzzFollowUpQuery returns a copy-pasteable command to confirm anomalies with
// the hardened module scanner, seeded from the same source the user supplied.
// Empty when nothing matched or the source can't be re-expressed as a flag.
func fuzzFollowUpQuery(args []string, matched int) string {
	if matched == 0 {
		return ""
	}
	var srcArg string
	switch {
	case len(args) == 1:
		srcArg = "-i '" + args[0] + "'"
	case fuzzInputFile != "":
		srcArg = "-i " + fuzzInputFile
	case fuzzInput != "" && fuzzInput != "-":
		srcArg = "-i '" + fuzzInput + "'"
	default:
		return ""
	}
	return "vigolium scan-request " + srcArg + " -m " + fuzzConfirmModules() + " -j   # confirm anomalies with hardened modules"
}

// fuzzConfirmModules maps the payload classes used into module-selection terms
// for the confirmation follow-up, defaulting to a broad injection set.
func fuzzConfirmModules() string {
	if len(fuzzClasses) > 0 {
		return strings.Join(fuzzClasses, ",")
	}
	return "xss,sqli,lfi,ssrf,cmdi"
}

func prettyResult(r fuzz.Result) string {
	flags := ""
	if r.Reflected {
		flags += " reflected"
	}
	if r.StatusChanged {
		flags += " status-changed"
	}
	if r.Error != "" {
		return fmt.Sprintf("  %-24s %-40q ERROR %s", r.PositionType+":"+r.Position, r.Payload, r.Error)
	}
	return fmt.Sprintf("  %-24s %-40q status=%-3d len=%-7d words=%-5d lines=%-4d %dms%s",
		r.PositionType+":"+r.Position, r.Payload, r.Status, r.Length, r.Words, r.Lines, r.TimeMs, flags)
}
