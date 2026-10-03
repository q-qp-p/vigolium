package runner

import (
	"bufio"
	"context"
	"fmt"
	neturl "net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

// spiderDOMXssModuleID labels DOM-XSS findings synthesized by the spider's browser
// probe (not a registered scanner module — the finding's Info is self-describing).
const spiderDOMXssModuleID = "spider-dom-xss"

// emitSpiderDOMXssFindings persists the crawl's browser-confirmed DOM-XSS findings.
// Each was proven by observing an injection canary execute in a real browser, so it
// is a firm finding — attributed to a spider-scoped module id with a self-describing
// Info block (it is not produced by a registered scanner module).
func (r *Runner) emitSpiderDOMXssFindings(ctx context.Context, scanUUID string, findings []spitolas.DOMXssFinding) {
	if r.repository == nil {
		return
	}
	// The crawl typically consumes the whole spidering-phase deadline, so ctx is
	// often already expired here. These findings are browser-confirmed and must be
	// persisted regardless — save under a fresh short-lived context.
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
	}
	for _, f := range findings {
		host := httpmsg.HostnameFromURL(f.URL)
		event := &output.ResultEvent{
			ModuleID:         spiderDOMXssModuleID,
			ModuleType:       database.ModuleTypeActive,
			FindingSource:    database.FindingSourceSpidering,
			RecordKind:       output.RecordKindFinding,
			EvidenceGrade:    output.EvidenceGradeImpact,
			Host:             host,
			URL:              f.URL,
			Matched:          f.URL,
			FuzzingParameter: f.Param,
			ExtractedResults: []string{
				"Parameter: " + f.Param,
				"Payload: " + f.Payload,
				"Sink: " + f.Evidence,
			},
			Info: output.Info{
				Name:        "DOM-based XSS (Browser-Confirmed)",
				Description: "A reflected client-route parameter flows into a DOM HTML sink (e.g. innerHTML / Angular bypassSecurityTrustHtml) without sanitization. A headless browser navigated the route with an injection canary and observed it execute (img onerror), so arbitrary JavaScript runs in a victim's browser via a crafted link. Fix: contextually encode URL-derived data on output, avoid dangerous DOM sinks, and enforce a strict Content-Security-Policy.",
				Severity:    severity.Medium,
				Confidence:  severity.Certain,
				Tags:        []string{"xss", "dom-xss", "browser", "spidering"},
			},
			ModuleShort: "Browser-confirmed DOM-based XSS on a reflected client route",
		}
		if err := r.repository.SaveFinding(ctx, event, nil, scanUUID, r.options.ProjectUUID); err != nil {
			zap.L().Warn("Spidering: failed to persist DOM-XSS finding", zap.String("url", f.URL), zap.Error(err))
		}
	}
}

func (r *Runner) runDiscoveryPhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	// phaseCtx owns everything this phase starts: the deparos producer goroutine,
	// the concurrent-source readers and the executor. Cancelling it after Execute
	// returns is what stops the producer from burning the rest of a target's
	// MaxDuration on work nobody will read. ctx itself stays live for the
	// post-phase bookkeeping below.
	phaseCtx, phaseCancel := context.WithCancel(ctx)
	defer phaseCancel()

	var sources []source.InputSource
	var discoveryTargets []string

	expandSeedParents := false
	if r.settings != nil {
		expandSeedParents = r.settings.Discovery.ExpandSeedParents
	}

	// Decide up front whether to auto-enable FUZZ fuzzing (must be set before
	// buildDeparosConfig/resolveDiscoveryWordlists read discoveryFuzzingState).
	// Reset first so shouldAutoFuzzDiscovery's "already fuzzing" check reads the
	// explicit modes only, not a value left over from a prior run on a reused
	// Runner (agent rescans).
	r.autoFuzzDiscovery = false
	r.autoFuzzDiscovery = r.shouldAutoFuzzDiscovery()

	var discoverSrc *source.DeparosDiscoverySource
	if r.options.DiscoverEnabled && len(r.options.Targets) > 0 {
		// In-scope origins (scheme/host/port) for this scan's CLI targets, shared by the
		// host-URL expansion and the path enrichment below so neither pulls in records
		// left by prior scans of a different origin (e.g. a different port on the host).
		inScopeHosts := r.getInScopeDBHosts(ctx)
		additionalTargets := hostURLsFromHostTargets(inScopeHosts)

		// When auto-fuzzing, keep the off-host SSO/login domain(s) the target
		// redirected to out of scope — fuzz the original target host for hidden
		// routes, not the identity provider.
		if r.autoFuzzDiscovery && len(r.spidering.ssoHosts) > 0 {
			before := len(additionalTargets)
			additionalTargets = filterOutHosts(additionalTargets, r.spidering.ssoHosts)
			if removed := before - len(additionalTargets); removed > 0 {
				zap.L().Info("Discovery: excluded SSO redirect host(s) from fuzzing scope",
					zap.Int("removed", removed), zap.Strings("hosts", r.spidering.ssoHosts))
			}
		}

		if expandSeedParents {
			expanded := discovery.ExpandSeedParents(r.options.Targets)
			before := len(additionalTargets)
			additionalTargets = dedupTargets(additionalTargets, expanded)
			added := len(additionalTargets) - before
			zap.L().Info("Discovery: expanded seed URLs into parent directories",
				zap.Int("seeds", len(r.options.Targets)),
				zap.Int("parents_added", added))
		}

		enrichTargets := false
		if r.settings != nil {
			enrichTargets = r.settings.Discovery.EnrichTargets
		}
		if enrichTargets && r.repository != nil {
			pathTargets, pathErr := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID, inScopeHosts...)
			if pathErr != nil {
				zap.L().Warn("Discovery: failed to get DB paths for enrichment", zap.Error(pathErr))
			} else if len(pathTargets) > 0 {
				pathURLs := buildDiscoveryTargetsFromPaths(pathTargets)
				additionalTargets = dedupTargets(additionalTargets, pathURLs)
				zap.L().Info("Discovery: enriched targets with paths from prior phases",
					zap.Int("path_targets", len(pathURLs)))
			}
		}

		discoveryTargets = dedupTargets(r.options.Targets, additionalTargets)
		deparosCfg := r.buildDeparosConfig(additionalTargets)
		// The egress seam. Deparos has its own HTTP client, so the executor's scope
		// check (which runs on records it has already fetched) could only ever
		// discard an excluded host's response AFTER contacting it. An explicit
		// exclusion is a request not to contact it, so it is enforced here: the
		// engine refuses the request before sending, and never queues the link.
		//
		// Explicit denials only — see ScopeMatcher.ExplicitlyExcluded and triage
		// C12. Include lists and origin mode stay with ScopeMode, which already
		// decides how wide the crawl goes.
		if matcher := infra.scopeMatcher; matcher != nil {
			deparosCfg.RequestFilter = func(u *neturl.URL) bool {
				if u == nil {
					return true
				}
				return !matcher.ExplicitlyExcluded(u.Hostname(), u.Path)
			}
		}
		src, srcErr := source.NewDeparosDiscoverySource(phaseCtx, deparosCfg)
		if srcErr != nil {
			zap.L().Warn("Failed to initialize deparos discovery", zap.Error(srcErr))
		} else {
			discoverSrc = src
			sources = append(sources, discoverSrc)
			// Deparos' traffic does not pass through the shared requester, so without
			// this the phase reported ≈0 requests for the crawl that produced every
			// record it emitted.
			r.currentPhase.Load().addCounter(discoverSrc.RequestsSent)
		}
	} else {
		discoveryTargets = r.options.Targets
	}

	sources = append(sources, r.inputSource)

	var compositeSource source.InputSource
	if len(sources) == 1 {
		compositeSource = sources[0]
	} else {
		compositeSource = source.NewConcurrentMultiSource(phaseCtx, sources...)
	}

	r.printPhaseStart("Discovery", "ingest inputs and discover directories, files, and hidden endpoints via Deparos content discovery")

	// Only the dials discovery actually applies (config.phasePaceSupport): the
	// engine's thread count and, when one is explicitly configured, its request
	// rate. max-per-host used to be printed here and has never been enforced on
	// this phase — deparos has its own HTTP client and no host semaphore — and the
	// concurrency printed was the global value rather than the section's.
	rateDetail := "unlimited"
	if rate := r.discoveryRateLimit(); rate > 0 {
		rateDetail = fmt.Sprintf("%d/s", rate)
	}
	speedDetail := fmt.Sprintf("Speed: threads=%s, rate-limit=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.discoveryConcurrency())),
		terminal.HiBlue(rateDetail))
	// The option is what buildDeparosConfig hands the phase, so it is what gets
	// reported.
	if budget := PhaseSpeedDetail(r.settings, "discovery", r.options.DiscoverMaxDuration); budget != "" {
		speedDetail += ", " + budget
	}
	r.printPhaseDetail(speedDetail)

	// Content-discovery status: whether deparos runs this phase (vs. plain input
	// ingestion), the dictionary wordlists feeding it, and whether FUZZ fuzzing is
	// on — each on its own line. Shown unconditionally because "is this scan
	// discovering/fuzzing, and with what" is the first thing operators ask of the
	// Discovery phase.
	r.printDiscoveryStatusLines(discoverSrc != nil)

	if r.autoFuzzDiscovery && !r.options.Silent {
		reason := fmt.Sprintf("spidering found little content (%d records)", r.spidering.records)
		if !r.spidering.complete {
			reason = fmt.Sprintf("spidering kept little content (%d records; capture incomplete, %d lost)",
				r.spidering.records, r.spidering.lost)
		}
		if r.spidering.sawSSO {
			reason = "spidering hit an SSO/login wall"
		}
		msg := fmt.Sprintf("%s Fuzzing auto-enabled — %s; brute-forcing %s for hidden routes",
			terminal.Yellow(terminal.SymbolArrow),
			reason,
			terminal.Orange("the original target(s)"))
		if len(r.spidering.ssoHosts) > 0 {
			msg += terminal.Gray(fmt.Sprintf(" (excluding SSO host(s): %s)", strings.Join(r.spidering.ssoHosts, ", ")))
		}
		r.printPhaseDetail(msg)
	}

	showDiscoveryConfig := r.options.Verbose || strings.EqualFold(r.options.Intensity, "deep")
	if r.settings != nil && showDiscoveryConfig {
		discCfg := &r.settings.Discovery
		recursion := "off"
		if discCfg.Recursion.Enabled {
			recursion = fmt.Sprintf("max_depth=%d", discCfg.Recursion.MaxDepth)
		}
		intensity := r.options.Intensity
		if intensity == "" {
			intensity = "default"
		}
		configDetail := fmt.Sprintf("Config: mode=%s, scope=%s, recursion=%s, intensity=%s, malformed_path_probe=%s, backup_ext=%s, numeric_fuzz=%s, enrich_targets=%s, expand_seed_parents=%s",
			terminal.HiTeal(discCfg.Mode),
			terminal.HiTeal(discCfg.ScopeMode),
			terminal.HiTeal(recursion),
			terminal.HiTeal(intensity),
			terminal.HiTeal(fmt.Sprintf("%v", discCfg.EnableMalformedPathProbe)),
			terminal.HiTeal(fmt.Sprintf("%v", discCfg.Extensions.TestBackupExtensions)),
			terminal.HiTeal(fmt.Sprintf("%v", discCfg.Wordlists.EnableNumericFuzzing)),
			terminal.HiTeal(fmt.Sprintf("%v", discCfg.EnrichTargets)),
			terminal.HiTeal(fmt.Sprintf("%v", discCfg.ExpandSeedParents)))
		r.printPhaseDetail(configDetail)
	}

	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	r.printVerboseTargets(discoveryTargets)

	// The "turn fuzzing on" tip is for a run that simply didn't ask for it. Under
	// --no-discovery-fuzz the operator asked for the opposite, and a tip telling
	// them how to enable what they just disabled reads as the flag not working.
	if fuzzEnabled, _ := r.discoveryFuzzingState(); !fuzzEnabled && !r.options.NoDiscoveryFuzz && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("enable on-the-fly directory fuzzing with a custom wordlist via"), terminal.HiCyan("--discovery-wordlist <path>"))
	}

	enrichTargetsEnabled := false
	if r.settings != nil {
		enrichTargetsEnabled = r.settings.Discovery.EnrichTargets
	}
	if !enrichTargetsEnabled && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("enrich discovery targets with discovered paths via"), terminal.HiCyan("vigolium config discovery.enrich_targets=true"))
	}

	zap.L().Info("Discovery: ingesting input into database")

	var discoveryRecordWriter *database.RecordWriter
	if r.repository != nil {
		discoveryRecordWriter = database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
	}

	authWalls := newAuthWallCollector()

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		RecordWriter:  discoveryRecordWriter,
		ScanUUID:      infra.scanUUID,
		ProjectUUID:   r.options.ProjectUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("discovery"),
		// Deparos' own client never follows a redirect, so this fires only for
		// the items that reach fetchBaseline: CLI targets and request-only
		// spec-endpoint stubs. Those are precisely the entry points most likely
		// to be gated.
		OnAuthWall: authWalls.Observe,
		// Deparos already captured a response for each crawled URL and emits it on
		// the work item (deparos_discovery.go saveAndEmit); reuse it instead of
		// issuing a second identical request per URL. Request-only items (spec-
		// endpoint stubs, which carry no response) still fall through to a single
		// baseline fetch in fetchBaseline, so routes aren't left empty.
		SkipBaseline: true,
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	var discoveryPassive []modules.PassiveModule
	if r.settings != nil && len(r.settings.Discovery.PassiveModuleTags) > 0 {
		ids := modules.ResolveModuleTags(r.settings.Discovery.PassiveModuleTags)
		if len(ids) > 0 {
			discoveryPassive = modules.GetPassiveModulesByIDs(ids)
			if len(discoveryPassive) > 0 {
				zap.L().Info("Discovery: passive modules enabled",
					zap.Int("count", len(discoveryPassive)),
					zap.Strings("tags", r.settings.Discovery.PassiveModuleTags))
			}
		}
	}

	executor := core.NewExecutor(executorCfg, compositeSource, nil, discoveryPassive)
	_, err := executor.Execute(phaseCtx)
	r.currentPhase.Load().noteExecution(executor.Report())

	// Shut down in producer-then-writer order: phaseCancel stops the deparos
	// engine and the concurrent readers, Close joins the producer so the records
	// it already collected are persisted (bounded by DrainTimeout), and only then
	// is the record writer drained — it is what those records are written through.
	//
	// compositeSource is deliberately NOT closed: when more than one source was
	// merged it wraps r.inputSource, whose lifetime belongs to releaseResources,
	// and closing it here would tear down an input later phases still read.
	phaseCancel()
	if discoverSrc != nil {
		if closeErr := discoverSrc.Close(); closeErr != nil {
			zap.L().Warn("Discovery: failed to close deparos source", zap.Error(closeErr))
		}
	}
	r.shutdownWriters("discovery", discoveryRecordWriter)
	if err != nil {
		return err
	}

	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("Discovery: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("Discovery", fmt.Sprintf("completed — %s items ingested (deparos=%s) in %s",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed())),
		terminal.HiTeal(fmt.Sprintf("%v", r.options.DiscoverEnabled)),
		terminal.HiPurple(fmtDuration(elapsed))))
	r.reportAuthWalls("Discovery", authWalls)
	zap.L().Info("Discovery: completed", zap.Int64("processed", executor.Processed()))

	if discoverSrc != nil {
		stats := discoverSrc.Stats()
		if stats.TotalDiscovered > 0 {
			r.printPhaseFeedback("Discovery", fmt.Sprintf("discovered %s records — %s",
				terminal.Orange(fmt.Sprintf("%d", stats.TotalDiscovered)),
				formatStatusCodeArray(stats.AllCodes)))
		}
		if stats.HardDedupRemoved > 0 {
			r.printPhaseFeedback("Discovery", fmt.Sprintf("deduplicated %s redundant records — %s",
				terminal.Orange(fmt.Sprintf("%d", stats.HardDedupRemoved)),
				formatStatusCodeArray(stats.DedupedCodes)))
		}
		if stats.FuzzyCappedRemoved > 0 {
			r.printPhaseFeedback("Discovery", fmt.Sprintf("capped %s near-identical responses (max %s kept per cluster) — %s",
				terminal.Orange(fmt.Sprintf("%d", stats.FuzzyCappedRemoved)),
				terminal.HiTeal(fmt.Sprintf("%d", stats.ClusterCap)),
				formatStatusCodeArray(stats.CappedCodes)))
		}
		r.reportDiscoveryCoverage(stats)
	}

	return nil
}

// reportDiscoveryCoverage reports what the phase did NOT get to, on both
// channels: an operator-facing stderr line, and a structured reason on the
// phase's outcome.
//
// Discovery used to log per-target failures at warn level and move on, so a run
// where every target errored, timed out, or was cancelled before it started
// looked exactly like a run that honestly found nothing. Both channels carry it
// because they answer different questions: the stderr line tells the operator
// watching the scan, the reason tells the scan row and the event stream — and a
// driver reading `--events` has no stderr to scrape.
//
// Timed-out targets are a LIMIT, not a reason: a per-target time box doing its
// job is configured behaviour, and marking it as degraded coverage would flag
// every properly bounded discovery run.
func (r *Runner) reportDiscoveryCoverage(stats source.DiscoveryStats) {
	tracker := r.currentPhase.Load()

	if stats.TargetsFailed > 0 {
		msg := fmt.Sprintf("%s target(s) failed discovery",
			terminal.Orange(fmt.Sprintf("%d", stats.TargetsFailed)))
		if len(stats.TargetErrors) > 0 {
			msg += " — " + terminal.Gray(stats.TargetErrors[0])
		}
		r.printPhaseFeedback("Discovery", msg)
		tracker.markPartial(database.ReasonTargetsFailed)
	}
	if stats.TargetsTimedOut > 0 {
		r.printPhaseFeedback("Discovery", fmt.Sprintf(
			"%s target(s) hit their discovery time budget — coverage is partial",
			terminal.Orange(fmt.Sprintf("%d", stats.TargetsTimedOut))))
		tracker.noteLimit(database.LimitTargetBudget)
	}
	if stats.TargetsSkipped > 0 {
		r.printPhaseFeedback("Discovery", fmt.Sprintf(
			"%s target(s) never attempted — the phase stopped first",
			terminal.Orange(fmt.Sprintf("%d", stats.TargetsSkipped))))
		tracker.markPartial(database.ReasonTargetsSkipped)
	}
	if stats.ImportFailed > 0 {
		r.printPhaseFeedback("Discovery", fmt.Sprintf(
			"%s discovered record(s) could not be stored",
			terminal.Orange(fmt.Sprintf("%d", stats.ImportFailed))))
		tracker.markPartial(database.ReasonPersistence)
	}
	if stats.Abandoned {
		r.printPhaseFeedback("Discovery", terminal.Orange(
			"the discovery producer did not exit in time and was abandoned; some discovered records may be missing"))
		tracker.markPartial(database.ReasonProducerAbandoned)
	}
}

// printDiscoveryStatusLines prints the Discovery phase's content-discovery status
// and, when deparos is active, its wordlist and fuzzing lines as separate detail
// rows. deparosActive mirrors the runDiscoveryPhase gate (DiscoverEnabled &&
// targets present && source init succeeded).
func (r *Runner) printDiscoveryStatusLines(deparosActive bool) {
	if !deparosActive {
		r.printPhaseDetail(fmt.Sprintf("Content discovery: %s — %s",
			terminal.Orange("disabled"), terminal.Gray(r.discoveryDisabledReason())))
		return
	}
	r.printPhaseDetail(fmt.Sprintf("Content discovery: %s (deparos)", terminal.HiTeal("enabled")))
	r.printPhaseDetail("Wordlists: " + r.discoveryWordlistSummary())
	r.printPhaseDetail("Fuzzing: " + r.discoveryFuzzingSummary())
}

// discoveryDisabledReason explains why deparos content discovery is not running,
// so a plain ingest-only Discovery phase doesn't read as a silent no-op.
func (r *Runner) discoveryDisabledReason() string {
	switch {
	case !r.options.DiscoverEnabled:
		return "deparos off for this run (enable with --discover or a deeper strategy) — ingest-only"
	case len(r.options.Targets) == 0:
		return "no CLI seed targets for deparos — ingest-only"
	default:
		return "deparos unavailable (init failed, see runtime log) — ingest-only"
	}
}

// discoveryWordlistSummary names the dictionary wordlists (short/long file & dir)
// feeding deparos, plus which "observed" token sources (names/paths/files
// harvested while crawling) are on. Lists are tagged embedded vs operator-supplied
// by comparing their directory to the materialized-defaults dir. The fuzz list is
// reported separately by discoveryFuzzingSummary, so it is excluded here.
func (r *Runner) discoveryWordlistSummary() string {
	w := r.resolveDiscoveryWordlists()
	embeddedDir := wordlistDir()

	var dicts []string
	var anyEmbedded, anyConfigured bool
	for _, p := range []string{w.shortFile, w.longFile, w.shortDir, w.longDir} {
		if p == "" {
			continue
		}
		dicts = append(dicts, formatWordlistEntry(p))
		if filepath.Dir(p) == embeddedDir {
			anyEmbedded = true
		} else {
			anyConfigured = true
		}
	}

	var observed []string
	if r.settings != nil {
		wl := r.settings.Discovery.Wordlists
		if wl.UseObservedNames {
			observed = append(observed, "names")
		}
		if wl.UseObservedPaths {
			observed = append(observed, "paths")
		}
		if wl.UseObservedFiles {
			observed = append(observed, "files")
		}
	}

	var parts []string
	if len(dicts) > 0 {
		// Each dict is already colored (name + orange count), so join without an
		// outer color wrap and append the source tag in gray.
		label := strings.Join(dicts, ", ")
		switch {
		case anyEmbedded && anyConfigured:
			label += " " + terminal.Gray("(incl. embedded defaults)")
		case anyEmbedded:
			label += " " + terminal.Gray("(embedded defaults)")
		}
		parts = append(parts, label)
	} else {
		parts = append(parts, terminal.Orange("observed-only (no dictionary resolved)"))
	}
	if len(observed) > 0 {
		parts = append(parts, terminal.Gray("observed "+strings.Join(observed, "+")))
	}
	return strings.Join(parts, " | ")
}

// formatWordlistEntry renders a wordlist path as "<basename> (<count>)" with the
// basename in teal and the entry count in orange. The count is omitted when the
// file can't be read.
func formatWordlistEntry(path string) string {
	entry := terminal.HiTeal(filepath.Base(path))
	if n := wordlistEntryCount(path); n >= 0 {
		entry += " " + terminal.Orange(fmt.Sprintf("(%d)", n))
	}
	return entry
}

// wordlistEntryCount counts non-empty, whitespace-trimmed lines in a wordlist
// file, matching how deparos loads it (pkg/deparos/discovery/payload loadWordlist).
// Returns -1 on read error so callers can omit the count rather than show a wrong 0.
func wordlistEntryCount(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer func() { _ = f.Close() }()

	count := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			count++
		}
	}
	if sc.Err() != nil {
		return -1
	}
	return count
}

// discoveryFuzzingSummary reports whether deparos FUZZ fuzzing is on (it appends
// /FUZZ and brute-forces the fuzz wordlist), the wordlist in play, and why.
func (r *Runner) discoveryFuzzingSummary() string {
	enabled, reason := r.discoveryFuzzingState()
	if !enabled {
		return fmt.Sprintf("%s — %s", terminal.Orange("disabled"), terminal.Gray(reason))
	}

	w := r.resolveDiscoveryWordlists()
	src := "embedded default"
	if r.options.FuzzWordlistPath != "" {
		src = "via --discovery-wordlist"
	}
	list := terminal.HiTeal("fuzz.txt")
	if w.fuzz != "" {
		list = formatWordlistEntry(w.fuzz)
	}
	return fmt.Sprintf("%s — %s (%s), appends /FUZZ %s",
		terminal.HiTeal("enabled"),
		list,
		terminal.Gray(src),
		terminal.Gray("["+reason+"]"))
}

// seedCLITargets ingests CLI targets into the database without running deparos or modules.
// This is used when discovery is skipped but downstream phases (KnownIssueScan, DynamicAssessment)
// need DB records to operate on.
func (r *Runner) seedCLITargets(ctx context.Context, infra *phaseInfra) error {
	r.printPhaseStart("Seed", "ingest CLI targets into database (discovery skipped)")

	authWalls := newAuthWallCollector()

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		ScanUUID:      infra.scanUUID,
		ProjectUUID:   r.options.ProjectUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("seed"),
		OnAuthWall:    authWalls.Observe,
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	executor := core.NewExecutor(executorCfg, r.inputSource, nil, nil)
	_, err := executor.Execute(ctx)
	r.currentPhase.Load().noteExecution(executor.Report())
	if err != nil {
		return err
	}

	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("Seed: failed to increment processed count", zap.Error(err))
		}
	}

	zap.L().Info("Seed: CLI targets ingested", zap.Int64("processed", executor.Processed()))
	r.printPhaseComplete("Seed", fmt.Sprintf("completed — %s items ingested",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed()))))
	r.reportAuthWalls("Seed", authWalls)
	return nil
}

// spideringPhaseBudgetCap bounds how many per-target max-duration budgets the
// whole spidering phase may consume. Each target still gets its own full
// max-duration; the overall phase deadline is max-duration × min(targets, cap),
// so a small target list is unaffected while a large merged list (CLI targets +
// many in-scope DB hosts) can't blow the phase out to len(targets) × max-duration.
//
// Exported because it is the number the CLI's fan-out hint quotes: the phase
// crawls hosts one at a time, so on a target list larger than this the cap — not
// the pace flags — is what decides how much of the list is reached, and the
// operator has to be told the figure to act on it. One constant, so the hint and
// the ceiling it describes cannot drift apart.
const spideringPhaseBudgetCap = 8

// spideringPhaseCeiling returns the overall wall-clock budget for the spidering
// phase. Each of numTargets gets up to maxDuration, but the total is capped at
// max-duration × min(numTargets, spideringPhaseBudgetCap). A non-positive
// maxDuration (unlimited) or non-positive target count returns 0, meaning "no
// ceiling" — the caller should then run without a phase deadline.
func spideringPhaseCeiling(maxDuration time.Duration, numTargets int) time.Duration {
	if maxDuration <= 0 || numTargets <= 0 {
		return 0
	}
	return maxDuration * time.Duration(min(numTargets, spideringPhaseBudgetCap))
}

// spideringTeardownGrace is how long past a target's max-duration the watchdog
// waits before declaring RunSpider wedged. Legitimate teardown (browser/page
// close, record-writer drain) is bounded and quick; this only fires on a true
// hang — e.g. an unresponsive/anti-bot browser, or a rod CDP call without a
// bound — guaranteeing the spidering phase can never block the scan forever.
//
// A var, not a const, only so a test can shorten it: a wedged-teardown test at
// the production value would take 90 seconds.
var spideringTeardownGrace = 90 * time.Second

// runWithWatchdog runs work in a goroutine and returns its result, or — if work
// does not finish within timeout — calls onTimeout and returns that instead,
// along with whether the watchdog fired. The work goroutine is abandoned on
// timeout (it leaks until it finishes on its own, if ever), which is the whole
// point: a wedged operation can never block the caller past timeout. The done
// channel is buffered so a late-finishing abandoned worker never blocks on send.
// Generic + side-effect-free so it can be unit-tested without a browser.
//
// The wedged bool is returned rather than encoded into the result because it is
// the one fact only this function knows, and callers need it to decide whether a
// browser session can still be closed: a wedge must be abandoned (closing an
// unresponsive browser hangs the very phase the watchdog protects), while an
// ordinary crawl failure leaves a healthy browser AND a record writer still
// holding that host's captured traffic. Conflating them leaked a Chrome process
// per host group and discarded records earlier seeds had already produced.
// Returning it keeps the distinction impossible to lose in transit.
func runWithWatchdog[T any](timeout time.Duration, work func() T, onTimeout func() T) (result T, wedged bool) {
	done := make(chan T, 1)
	go func() { done <- work() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case v := <-done:
		return v, false
	case <-timer.C:
		return onTimeout(), true
	}
}

// crawlOutcome is what both watchdog wrappers return: the crawl's own result and
// error, plus whether the watchdog fired. wedged is NOT derivable from err —
// both a wedge and an ordinary navigation failure produce a non-nil error, and
// only the first means the browser cannot be safely closed.
type crawlOutcome struct {
	res    *spitolas.SpiderResult
	err    error
	wedged bool
}

// capture is the receipt a phase total should fold in for this crawl.
//
// A wedged crawl has no trustworthy receipt — the watchdog abandoned it with the
// writer still open — so it contributes an explicitly incomplete one. An
// ordinary failure does have a receipt: RunSpider returns a partial result
// carrying it alongside the error, deliberately, so a failed crawl's account is
// not lost. A crawl with neither contributes nothing.
func (oc crawlOutcome) capture() spitolas.CaptureReceipt {
	switch {
	case oc.wedged:
		return spitolas.IncompleteCaptureReceipt()
	case oc.res != nil:
		return oc.res.Capture
	default:
		return spitolas.CaptureReceipt{}
	}
}

// sessionCapture is the receipt a phase total should fold in for a shared
// SpiderSession, and the one place that decides whether to close it.
//
// A session abandoned after a wedged crawl is left to the process to reclaim,
// exactly as the per-target watchdog does — closing a browser that did not
// answer would hang the phase we are trying to protect — so its running
// snapshot (never complete) is the account. A live session is closed, which
// yields its final receipt.
func sessionCapture(sess respiderSession, rw *database.RecordWriter, abandoned bool) spitolas.CaptureReceipt {
	if abandoned {
		return sess.Receipt()
	}
	return closeReSpiderSession(sess, rw)
}

// dumpWedgedGoroutines logs the watchdog's diagnosis: which operation hung, and
// a full goroutine dump so the stuck call site is identifiable after the fact.
func dumpWedgedGoroutines(what, subject string, budget time.Duration) {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	zap.L().Error(what+" watchdog fired — did not return within budget+grace; abandoning the run (browser/goroutines leak until exit)",
		zap.String("subject", subject),
		zap.Duration("budget", budget),
		zap.Duration("grace", spideringTeardownGrace))
	zap.L().Warn(what + " watchdog goroutine dump follows:\n" + string(buf[:n]))
}

// runSpiderWatchdog runs spitolas.RunSpider (and closes rw) under a hard
// watchdog: it always returns within budget + spideringTeardownGrace. If the run
// wedges past that, it logs a full goroutine dump (so the stuck call site is
// diagnosable) and returns wedged=true rather than hanging the scan; the stuck
// run and its browser are abandoned and leak until the process exits. rw is
// closed inside the worker so a stuck close is abandoned with it, not awaited.
func runSpiderWatchdog(ctx context.Context, cfg spitolas.SpiderConfig, rw *database.RecordWriter, budget time.Duration, target string) crawlOutcome {
	oc, wedged := runWithWatchdog(
		budget+spideringTeardownGrace,
		func() crawlOutcome {
			res, err := spitolas.RunSpider(ctx, cfg, rw)
			rw.Close()
			return crawlOutcome{res: res, err: err}
		},
		func() crawlOutcome {
			dumpWedgedGoroutines("Spidering", target, budget)
			return crawlOutcome{err: fmt.Errorf("spidering timed out for %s (exceeded %s)", target, budget+spideringTeardownGrace)}
		},
	)
	oc.wedged = wedged
	return oc
}

// runReSpiderSessionCrawl runs one seed on a shared SpiderSession under the same
// hang-proofing as runSpiderWatchdog: if Crawl does not return within
// budget+grace the run is abandoned (the shared browser/goroutines leak until
// exit) and wedged=true tells the caller not to close the host session.
func runReSpiderSessionCrawl(ctx context.Context, sess *spitolas.SpiderSession, seedURL string, budget time.Duration) crawlOutcome {
	oc, wedged := runWithWatchdog(
		budget+spideringTeardownGrace,
		func() crawlOutcome {
			res, err := sess.Crawl(ctx, seedURL)
			return crawlOutcome{res: res, err: err}
		},
		func() crawlOutcome {
			dumpWedgedGoroutines("Re-spider session-crawl", seedURL, budget)
			return crawlOutcome{err: fmt.Errorf("re-spider seed timed out for %s (exceeded %s)", seedURL, budget+spideringTeardownGrace)}
		},
	)
	oc.wedged = wedged
	return oc
}

// respiderSession is what closeReSpiderSession needs of a SpiderSession: drain
// it, give up on it, and report what its capture got.
//
// An interface purely so the teardown-watchdog path is testable without a
// browser — and specifically so the kill-on-wedge escalation is. That branch only
// runs when a real Chromium has stopped answering, which no unit test can arrange.
// *spitolas.SpiderSession is the only production implementation.
type respiderSession interface {
	Close() error
	Kill()
	Receipt() spitolas.CaptureReceipt
}

// closeReSpiderSession flushes and tears down a shared SpiderSession (and its
// backing RecordWriter) under a teardown watchdog, so a wedged browser close
// can't hang the phase. It returns the session's capture receipt: final when
// the close completed, the running snapshot (never complete) when the watchdog
// abandoned it.
func closeReSpiderSession(sess respiderSession, rw *database.RecordWriter) spitolas.CaptureReceipt {
	rc, _ := runWithWatchdog(
		spideringTeardownGrace,
		func() spitolas.CaptureReceipt {
			if err := sess.Close(); err != nil {
				zap.L().Warn("Spider session closed with lost records", zap.Error(err))
			}
			rw.Close()
			return sess.Receipt()
		},
		func() spitolas.CaptureReceipt {
			zap.L().Error("Re-spider session-close watchdog fired — browser teardown wedged; killing the browser process")
			// The abandoned Close goroutine still holds the browser's and the
			// pool's locks, so Kill deliberately takes neither (see
			// SpiderSession.Kill). In its own goroutine because the launcher's kill
			// has a built-in wait and this path exists to return promptly.
			go sess.Kill()
			return sess.Receipt()
		},
	)
	return rc
}

// captureOutcome maps a browser capture receipt onto the persistence vocabulary
// the scan row and the event stream report.
//
// The two types stay separate deliberately — see spitolas.CaptureReceipt. The
// receipt distinguishes Refused (known turned away) from the writer's Unknown
// (may have landed), and a spec-ingested endpoint can legitimately push
// Persisted past Accepted; collapsing them would lose the first distinction and
// produce negative counts on the second. This is the translation, not a merge.
func captureOutcome(rc spitolas.CaptureReceipt) database.PersistenceOutcome {
	if !rc.Enabled {
		return database.PersistenceOutcome{}
	}
	o := database.PersistenceOutcome{
		Writer:    database.PersistenceWriterRecords,
		Accepted:  int64(rc.Accepted),
		Committed: int64(rc.Persisted),
		// Refused and Failed are both "captured and did not reach the database",
		// which is what Failed means on this side; Unknown is reserved for the
		// entries an abandoned drain never resolved either way.
		Failed: int64(rc.Lost()),
	}
	if !rc.DrainComplete {
		o.TimedOut = true
		// Clamped: Persisted counts spec-ingested rows the capture never
		// accepted, so the difference can be negative without anything being
		// wrong.
		if unknown := o.Accepted - o.Committed - o.Failed; unknown > 0 {
			o.Unknown = unknown
		}
	}
	return o
}

// recordCapture folds a phase's total browser-capture receipt into its outcome,
// so a crawl that lost records says so where every other lost write does — on
// the phase outcome, hence in phase_outcomes and on scan.finished.
//
// Spidering and re-spider were the only phases left whose writer loss reached
// nothing but a yellow suffix on a stderr line: they close their RecordWriter
// fire-and-forget rather than through shutdownWriters, so a crawl that lost its
// entire corpus to a failing database still wrote state: "completed".
//
// Both halves are needed. addPersistence marks the phase partial on Failed or
// Unknown; a receipt abandoned before its writer drained carries NO counts at
// all (IncompleteCaptureReceipt), so it is clean by that rule and lost by the
// receipt's own. The receipt is the authority on whether capture is accounted
// for, so its verdict is applied directly. markPartial is idempotent per code,
// so the overlapping case records one reason.
func recordCapture(t *phaseTracker, rc spitolas.CaptureReceipt) {
	if !rc.Enabled {
		return
	}
	t.addPersistence(captureOutcome(rc))
	if !rc.Clean() {
		t.markPartial(database.ReasonPersistence)
	}
}

// captureIncompleteNote is the completion-line suffix for a phase whose
// capture lost records or never finished draining; "" when nothing was lost.
func captureIncompleteNote(rc spitolas.CaptureReceipt) string {
	if rc.Clean() {
		return ""
	}
	if lost := rc.Lost(); lost > 0 {
		return fmt.Sprintf(" (%d failed — run incomplete)", lost)
	}
	return " (capture did not finish draining — run incomplete)"
}

// groupByHost groups items by the host their key function returns, preserving
// both the order hosts first appear and each host's own item order, so one
// browser context can crawl all of a host's items consecutively. An item with no
// resolvable host gets its own group rather than being dropped.
//
// Shared by the spidering and re-spider phases: both need exactly this ordering
// contract, and the only thing that differs between them is the element type.
func groupByHost[T any](items []T, host func(T) string) [][]T {
	idx := make(map[string]int, len(items))
	var groups [][]T
	for _, item := range items {
		h := host(item)
		if h == "" {
			groups = append(groups, []T{item})
			continue
		}
		if i, ok := idx[h]; ok {
			groups[i] = append(groups[i], item)
			continue
		}
		idx[h] = len(groups)
		groups = append(groups, []T{item})
	}
	return groups
}

// buildSpiderConfig assembles the crawl configuration for one target: browser
// settings from the resolved spidering config, the operator's auth bridge and
// scope boundary, and the intensity-derived login and registration policy.
//
// Both browser phases build from here. They differ only in their budgets and
// their record source, which the caller overrides — everything else (the auth
// bridge, the scope adapter, the intensity policy, the graph output) is one
// decision, and keeping two copies is how a field added to one phase silently
// goes missing from the other.
func (r *Runner) buildSpiderConfig(target string, settingsCfg config.SpideringConfig, maxDuration time.Duration, infra *phaseInfra) spitolas.SpiderConfig {
	rp := resolveBrowserPolicy(settingsCfg, r.options.Intensity)
	policy := rp.policy
	compat := resolveBrowserCompat(settingsCfg)
	// Bridge the operator's session/custom headers into the browser so the crawl
	// explores authenticated content, not just the login shell.
	browserCookies, browserHeaders := browserAuthFromHeaders(r.options.Headers)

	cfg := spitolas.SpiderConfig{
		TargetURL:           target,
		MaxDepth:            settingsCfg.MaxDepth,
		MaxStates:           settingsCfg.MaxStates,
		MaxDuration:         maxDuration,
		MaxConsecutiveFails: settingsCfg.MaxConsecutiveFails,
		Headless:            settingsCfg.Headless,
		BrowserCount:        settingsCfg.BrowserCount,
		Strategy:            settingsCfg.Strategy,
		IncludeResponseBody: settingsCfg.IncludeResponseBody,
		IncludeHeaders:      true,
		Silent:              r.options.Silent,
		Verbose:             r.options.Verbose,
		BrowserEngine:       settingsCfg.BrowserEngine,
		BrowserPath:         settingsCfg.BrowserPath,
		NoCDP:               settingsCfg.NoCDP,
		ProxyURL:            r.options.ProxyURL,
		ProjectUUID:         r.options.ProjectUUID,
		// The resolved interaction policy is authoritative; the legacy switches
		// below mirror it so a reader of either sees the same decision.
		// Credential attempts default on at balanced (minimal list) and deep
		// (full list), off at quick/lite; registration is off unless configured
		// at any intensity. See resolveAccountActions.
		Policy:                  &policy,
		BrowserCompat:           &compat,
		NoForms:                 !policy.EditFields && !policy.SubmitForms,
		LoginCredentialAttempts: policy.LoginAttempts,
		LoginCredentialFullList: rp.fullList,
		SelfRegister:            policy.RegisterAccount,
		IdentityEmailDomain:     settingsCfg.IdentityEmailDomain,
		MaxCaptureBodyBytes:     settingsCfg.MaxCaptureBodyBytes,
		InitialCookies:          browserCookies,
		ExtraHeaders:            browserHeaders,
		RequireAuth:             settingsCfg.RequireAuth,
		// A directory, not a path: the crawl names its own file from the target it
		// actually runs against, so a session reusing this config across a host's
		// seeds still writes each graph under the right name.
		GraphOutputDir:     settingsCfg.GraphOutputDir,
		GraphIncludeValues: settingsCfg.GraphIncludeValues,
		RunID:              infra.scanUUID,
	}

	if infra.scopeMatcher != nil && !infra.scopeMatcher.IsPassAll() {
		sm := infra.scopeMatcher
		cfg.ScopeFilter = func(host, path string) bool {
			return sm.InScopeRequest(host, path, "", "")
		}
	}
	return cfg
}

// openSpiderSession starts one browser context for a host group's targets, or
// returns nil when a session is not wanted: a single-target group (the shared
// context buys nothing), the operator's opt-out, or a launch failure — in which
// case each target falls back to its own fresh browser, which is the path that
// ran before sessions existed.
func (r *Runner) openSpiderSession(ctx context.Context, group []string, settingsCfg config.SpideringConfig, maxDuration time.Duration, infra *phaseInfra) (*spitolas.SpiderSession, *database.RecordWriter) {
	if len(group) < 2 || spiderSessionReuseDisabled() {
		return nil, nil
	}
	base := r.buildSpiderConfig(group[0], settingsCfg, maxDuration, infra)
	rw := database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
	sess, err := spitolas.NewSpiderSession(ctx, base, rw)
	if err != nil {
		zap.L().Warn("Spidering: shared session launch failed, falling back to one browser per target",
			zap.String("host", httpmsg.HostnameFromURL(group[0])), zap.Error(err))
		rw.Close()
		return nil, nil
	}
	zap.L().Info("Spidering: reusing one browser context across a host's targets",
		zap.String("host", httpmsg.HostnameFromURL(group[0])),
		zap.Int("targets", len(group)))
	return sess, rw
}

// reportSpiderCoverage surfaces what the crawl reached beyond ordinary clicking:
// locations its own route declarations named, strings scraped out of the rendered
// document, an account it registered, and the extra sweeps it ran. Each is
// reported only when it did something, so a plain crawl stays quiet.
func (r *Runner) reportSpiderCoverage(result *spitolas.SpiderResult, target string) {
	if result.SeedURLsDiscovered > 0 {
		zap.L().Info("Spidering: seeded frontier from the host's route declarations",
			zap.String("target", target),
			zap.Int("declared", result.SeedURLsDiscovered),
			zap.Int("browsed", result.SeedURLsCrawled))
		r.printPhaseDetail(fmt.Sprintf("%s robots.txt/sitemap declared %s location(s) on %s — all recorded, %s browsed into the crawl.",
			terminal.Purple(terminal.SymbolArrow),
			terminal.Orange(fmt.Sprintf("%d", result.SeedURLsDiscovered)),
			terminal.Gray(target),
			terminal.Orange(fmt.Sprintf("%d", result.SeedURLsCrawled))))
	}
	if result.SpeculativeLinksFetched > 0 {
		zap.L().Info("Spidering: fetched URLs scraped from comments and inline script",
			zap.String("target", target), zap.Int("count", result.SpeculativeLinksFetched))
	}
	if result.SelfRegistered {
		zap.L().Info("Spidering: registered an account to reach authenticated content",
			zap.String("target", target), zap.String("identity", result.SelfRegisterIdentity))
		r.printPhaseDetail(fmt.Sprintf("%s Registered %s on %s so the crawl could continue past the signup wall.",
			terminal.Purple(terminal.SymbolArrow),
			terminal.Orange(result.SelfRegisterIdentity),
			terminal.Gray(target)))
	}
	if result.FollowUpPassesRun > 0 || result.ActionsRecovered > 0 {
		zap.L().Info("Spidering: extra sweeps after the first pass drained",
			zap.String("target", target),
			zap.Int("follow_up_passes", result.FollowUpPassesRun),
			zap.Int("actions_retried", result.ActionsRetried),
			zap.Int("actions_recovered", result.ActionsRecovered))
	}
}

// runSpideringPhase runs browser-based crawling using spitolas.
// Captured traffic is stored in vigolium's HTTPRecord table via RepositoryWriter.
// Targets are merged from CLI targets and in-scope hosts discovered by prior phases.
func (r *Runner) runSpideringPhase(ctx context.Context, infra *phaseInfra) error {
	if r.repository == nil {
		return fmt.Errorf("spidering requires a database repository")
	}

	phaseStart := time.Now()
	r.printPhaseStart("Spidering", "browser-based crawling to discover dynamic content and API endpoints")

	settingsCfg := r.settings.Spidering
	// VIGOLIUM_BROWSER_HEADED (set by the agent --headed flag) forces a visible
	// browser window even when settings default to headless. settingsCfg is a
	// value copy, so this never mutates shared settings. This is the same env
	// override ProbeURL honors, extended here so agent pre-scan / --discover
	// spidering is visible too — not just the in-process browser probes.
	if utils.EnvTruthy(spitolas.EnvBrowserHeaded) {
		settingsCfg.Headless = false
	}
	// Each target runs under context.WithTimeout(phaseCtx, maxDuration), so a
	// non-positive budget here is an already-expired deadline, not "unlimited".
	// MaxDurationParsed guarantees a positive value; this catches the nil-settings
	// path, which would otherwise crawl nothing without saying so.
	maxDuration := SpideringBudget(r.settings, r.options)
	if maxDuration <= 0 {
		maxDuration = config.DefaultSpideringConfig().MaxDurationParsed()
	}

	targets := r.options.Targets
	dbHosts := r.getInScopeHostURLs(ctx)
	targets = dedupTargets(targets, dbHosts)

	expandSeedParents := false
	if r.settings != nil {
		expandSeedParents = r.settings.Discovery.ExpandSeedParents
	}
	var parentsAdded int
	if expandSeedParents && len(r.options.Targets) > 0 {
		expanded := discovery.ExpandSeedParents(r.options.Targets)
		before := len(targets)
		targets = dedupTargets(targets, expanded)
		parentsAdded = len(targets) - before
	}

	zap.L().Info("Spidering: merged targets",
		zap.Int("cli", len(r.options.Targets)),
		zap.Int("from_db", len(dbHosts)),
		zap.Int("parents_added", parentsAdded),
		zap.Int("total", len(targets)))

	if r.heuristicsResults != nil {
		before := len(targets)
		targets = filterTargetsByHeuristics(targets, r.heuristicsResults, func(hr *HeuristicsResult) bool {
			return hr.SkipSpidering
		})
		if skipped := before - len(targets); skipped > 0 {
			zap.L().Info("Spidering: targets filtered by heuristics",
				zap.Int("skipped", skipped), zap.Int("remaining", len(targets)))
		}
		if len(targets) == 0 {
			r.printPhaseComplete("Spidering", "skipped — all targets excluded by heuristics check")
			return nil
		}
	}

	configDetail := fmt.Sprintf("Config: strategy=%s, max-depth=%s, max-states=%s, headless=%s",
		terminal.HiTeal(settingsCfg.Strategy),
		terminal.HiTeal(fmt.Sprintf("%d", settingsCfg.MaxDepth)),
		terminal.HiTeal(fmt.Sprintf("%d", settingsCfg.MaxStates)),
		terminal.HiTeal(fmt.Sprintf("%v", settingsCfg.Headless)))
	if budget := PhaseSpeedDetail(r.settings, "spidering", maxDuration); budget != "" {
		configDetail += ", " + budget
	}
	r.printPhaseDetail(configDetail)
	// What the browser may change, resolved once for the phase. Every target's
	// config resolves the same policy from the same settings (buildSpiderConfig),
	// so this line and the conflict warnings describe all of them.
	policy := resolveBrowserPolicy(settingsCfg, r.options.Intensity)
	for _, c := range policy.conflicts {
		zap.L().Warn("Spidering: interaction policy key overrides a legacy key", zap.String("override", c))
	}
	r.printPhaseDetail("Policy: " + terminal.HiTeal(policy.detail()))
	r.printPhaseDetail("Browser security: " + terminal.HiTeal(securityDetail(spitolas.EffectiveBrowserSecurity(resolveBrowserCompat(settingsCfg)))))
	if infra.scopeMatcher != nil && !infra.scopeMatcher.IsPassAll() {
		// The in-page primers fetch only what the operator scope admits; the
		// service-worker primer fetches inside its own script and cannot be held
		// to a path boundary, so a custom scope turns it off.
		r.printPhaseDetail("Priming: " + terminal.HiTeal("in-page fetches limited to the operator scope, service_worker=off (custom scope)"))
	}
	r.printTargetDetail(r.formatTargetCounts(ctx, len(targets)))
	r.printVerboseTargets(targets)

	// Per-target budget with an overall phase ceiling. Each target still gets
	// its own full max-duration, but the whole phase is bounded so a large
	// merged target list (CLI targets + many in-scope DB hosts) can't make
	// spidering run for len(targets) × max-duration. The ceiling is
	// max-duration × min(targets, spideringPhaseBudgetCap); each per-target
	// context derives from it, so the last target before the ceiling gets
	// whatever budget remains and any targets beyond it are skipped (logged).
	// phaseDeadline treats a zero ceiling (unlimited max-duration) as unbounded.
	phaseCeiling := spideringPhaseCeiling(maxDuration, len(targets))
	phaseCtx, phaseCancel := r.trackedPhaseDeadline(ctx, phaseCeiling)
	defer phaseCancel()

	var totalStates, totalActions, totalRecords, totalPrevented, totalUncertain int
	// phaseCapture sums the final capture receipts: one per RunSpider, one per
	// closed (or abandoned) session. Per-seed session receipts are deltas of a
	// still-open writer and are not summed.
	var phaseCapture spitolas.CaptureReceipt
	var ssoHosts []string
	var skippedTargets int
	// Targets that used their whole per-target budget. Reported as a LIMIT, not a
	// defect: the time box did what it was configured to do.
	var budgetExhaustedTargets int

	// Carry the browser's WAF/bot-cleared session (cookies + optionally its UA)
	// forward into discovery and scanning. On by default; scoped per-host below.
	// The UA is only pinned when the operator opted away from the honest "preset"
	// default (a custom/random UA or VIGOLIUM_DEFAULT_UA) — otherwise the honest
	// self-identifying UA is left untouched. Clearance cookies stay valid because
	// downstream requests keep the same UA the WAF issued them to.
	carrySession := r.options.CarryBrowserSession
	carryUA := !httpmsg.UserAgentIsHonestPreset()
	var harvested map[string]httpmsg.CarriedSession
	if carrySession {
		harvested = make(map[string]httpmsg.CarriedSession)
	}

	// Crawl one host's targets consecutively on a single browser context.
	// Cookies, local storage and capture-level dedup then persist between them,
	// so a session established on one seed is still in force on the next and a
	// shared asset is recorded once rather than once per target — neither of
	// which a fresh browser per target can do.
	groups := groupByHost(targets, httpmsg.HostnameFromURL)
	processed := 0

	for _, group := range groups {
		// Overall ceiling exhausted — skip the remaining targets rather than
		// launching crawls against an already-expired context.
		if phaseCtx.Err() != nil {
			skippedTargets = len(targets) - processed
			zap.L().Warn("Spidering: phase budget ceiling reached, skipping remaining targets",
				zap.Int("skipped", skippedTargets),
				zap.Int("total", len(targets)),
				zap.Duration("max_duration", maxDuration),
				zap.Int("budget_cap", spideringPhaseBudgetCap))
			break
		}

		// A shared session only pays for itself across several seeds; for a lone
		// target it is machinery around the proven single-crawl path.
		sess, sessRW := r.openSpiderSession(phaseCtx, group, settingsCfg, maxDuration, infra)
		abandoned := false

		for gi, target := range group {
			if phaseCtx.Err() != nil {
				break
			}
			processed++
			zap.L().Info("Spidering target", zap.String("target", target))

			// Derive from phaseCtx so the per-target budget is min(max-duration,
			// remaining phase ceiling) — the overall cap is enforced automatically.
			// The watchdog guarantees this returns within budget+grace even if the
			// browser/teardown wedges, so a single target can never hang the scan.
			timeoutCtx, cancel := context.WithTimeout(phaseCtx, maxDuration)
			var oc crawlOutcome
			if sess != nil {
				oc = runReSpiderSessionCrawl(timeoutCtx, sess, target, maxDuration)
			} else {
				cfg := r.buildSpiderConfig(target, settingsCfg, maxDuration, infra)
				rw := database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
				oc = runSpiderWatchdog(timeoutCtx, cfg, rw, maxDuration, target)
				phaseCapture.Merge(oc.capture())
			}
			// Asked BEFORE cancel(): cancelling a context whose deadline had not
			// fired overwrites Err with Canceled, and the question "did this target
			// use its whole budget" then has no answer.
			if targetBudgetExhausted(timeoutCtx, phaseCtx) {
				budgetExhaustedTargets++
			}
			cancel()

			if oc.err != nil {
				zap.L().Error("Spidering failed",
					zap.String("target", target), zap.Error(oc.err))
				if sess != nil {
					// Either way the rest of this host's targets are not attempted:
					// replaying the same failure per target buys nothing. What differs
					// is whether the session can be closed.
					//
					// A wedged browser must be abandoned — closing it would hang the
					// phase. An ordinary failure must NOT be: the browser is fine, and
					// the shared writer is still holding this host's captured records.
					// Abandoning there dropped traffic the earlier seeds had already
					// produced and leaked a Chrome process, for something as routine as
					// one unreachable target.
					abandoned = oc.wedged
					if abandoned {
						zap.L().Warn("Spidering: browser wedged, abandoning shared session for host and killing its browser process",
							zap.String("target", target))
						// Abandoned means nothing will ever close this session, so the
						// Chromium process and its profile would live for the rest of the
						// scan — one per wedged host group. Kill takes no lock the wedged
						// crawl goroutine might hold; its own goroutine because the
						// launcher's kill waits for the process to go.
						go sess.Kill()
					} else {
						zap.L().Warn("Spidering: crawl failed, closing shared browser session for host",
							zap.String("target", target))
					}
					// The rest of this host's targets are never attempted, so count
					// them as processed — they are abandoned, not waiting on budget,
					// and reporting them as "skipped by the ceiling" would misattribute
					// a browser failure to the phase clock.
					processed += len(group) - gi - 1
					break
				}
				continue
			}
			result := oc.res

			totalStates += result.StatesDiscovered
			totalActions += result.ActionsExecuted
			totalRecords += result.RecordsSaved
			totalPrevented += result.FormSubmitsPrevented
			totalUncertain += result.FormSubmitsUncertain

			if carrySession && (len(result.HarvestedCookies) > 0 || result.HarvestedAuthorization != "") {
				// Scope the session to the host the crawl actually settled on: the
				// adopted/landing host when the start URL relocated off-host, else the
				// target host.
				sessionHost := httpmsg.HostnameFromURL(target)
				sessionURL := target
				if result.HostAdopted && result.LandingURL != "" {
					if adopted := httpmsg.HostnameFromURL(result.LandingURL); adopted != "" {
						sessionHost = adopted
						sessionURL = result.LandingURL
					}
				}
				cookieHeader := httpmsg.FlattenCookiesForHost(sessionHost, result.HarvestedCookies)
				// Carry the session when the crawl earned EITHER cookies (cookie-auth
				// apps + WAF clearance) OR a token (token-auth SPAs send Authorization,
				// not a cookie — carrying only cookies would leave the scan unauthenticated).
				if cookieHeader != "" || result.HarvestedAuthorization != "" {
					// Named `carried`, not `sess`: the enclosing scope already holds the
					// shared browser session under that name, and shadowing it here
					// would make a later `sess.Close()` in this block close the wrong
					// thing while still compiling.
					// Both forms: Cookies is authoritative on the HTTP path
					// (evaluated per request, so a /admin or Secure cookie is
					// not sent where a browser wouldn't send it), CookieHeader
					// remains the flat summary and the fallback for consumers
					// that cannot evaluate a jar.
					carried := httpmsg.CarriedSession{
						CookieHeader: cookieHeader,
						Cookies:      httpmsg.CarriedCookiesFromHTTP(sessionHost, result.HarvestedCookies),
					}
					if carryUA {
						carried.UserAgent = result.BrowserUserAgent
					}
					if result.HarvestedAuthorization != "" {
						carried.AuthorizationHeader = "Bearer " + result.HarvestedAuthorization
						// Scope the bearer token to the exact origin (scheme+host+port) the
						// crawl harvested it from, so it isn't attached to a different
						// service sharing the hostname on another port/scheme.
						carried.Origin = httpmsg.OriginFromURL(sessionURL)
					}
					harvested[sessionHost] = carried
				}
			}

			// Persist any browser-confirmed DOM-XSS the crawl found on reflected client routes.
			if len(result.DOMXssFindings) > 0 {
				r.emitSpiderDOMXssFindings(ctx, infra.scanUUID, result.DOMXssFindings)
				r.printPhaseDetail(fmt.Sprintf("%s confirmed %s DOM-based XSS on reflected client route(s) during the crawl.",
					terminal.Orange(terminal.SymbolArrow),
					terminal.Orange(fmt.Sprintf("%d", len(result.DOMXssFindings)))))
			}

			zap.L().Info("Spidering completed for target",
				zap.String("target", target),
				zap.Int("states", result.StatesDiscovered),
				zap.Int("actions", result.ActionsExecuted),
				zap.Int("records_saved", result.RecordsSaved),
				zap.Int("forms_submitted", result.FormsSubmitted),
				zap.Int("form_submits_prevented", result.FormSubmitsPrevented),
				zap.Int("form_submits_uncertain", result.FormSubmitsUncertain),
				zap.Int("records_failed", result.Capture.Failed+result.Capture.Refused),
				zap.Int("wait_conditions_failed", result.WaitConditionsFailed),
				zap.String("auth_state", result.AuthState),
				zap.Int("aux_fetches_denied", result.AuxFetchesDenied),
				zap.Strings("credential_hosts_denied", result.CredentialHostsDenied))

			// Configured authentication that did not reach the browser means this
			// target was (at least partly) crawled anonymously — say so rather
			// than let it read as an authenticated crawl.
			if result.AuthState == spitolas.AuthFailed {
				r.printPhaseDetail(fmt.Sprintf("%s %s: configured authentication could not be applied to the browser — crawled unauthenticated (set spidering.require_auth or --require-auth to fail instead).",
					terminal.Yellow(terminal.SymbolWarning),
					terminal.Gray(target)))
				// The same code the HTTP path records when a configured session
				// could not be established. Without it, whether an operator's
				// scan row says `auth_unavailable` depended on which subsystem
				// failed to log in, not on whether the login failed.
				r.currentPhase.Load().markPartial(database.ReasonAuthUnavailable)
			}
			if len(result.CredentialHostsDenied) > 0 {
				r.printPhaseDetail(fmt.Sprintf("%s %s: credential headers withheld from %s (outside the operator scope).",
					terminal.Gray(terminal.SymbolArrow),
					terminal.Gray(target),
					strings.Join(result.CredentialHostsDenied, ", ")))
			}

			// A readiness condition that never met explains a thin crawl better
			// than "the site has little content" does.
			if result.WaitConditionsFailed > 0 {
				r.printPhaseDetail(fmt.Sprintf("%s %s: %s readiness condition(s) never met (%s) — the crawl saw the page before it was ready.",
					terminal.Yellow(terminal.SymbolWarning),
					terminal.Gray(target),
					terminal.Orange(fmt.Sprintf("%d", result.WaitConditionsFailed)),
					strings.Join(result.WaitConditionFailures, ", ")))
			}

			// A landing whose "Log on" CTA was driven means the crawler entered the
			// app's OAuth/SAML/SSO flow — surface it so the captured login-flow URLs
			// aren't a surprise.
			if result.LoginCTADriven {
				zap.L().Info("Spidering: drove login CTA into the auth flow",
					zap.String("target", target),
					zap.String("cta", result.LoginCTAText))
				r.printPhaseDetail(fmt.Sprintf("%s clicked the %s call-to-action on %s to enter and capture the OAuth/SAML login flow.",
					terminal.Purple(terminal.SymbolArrow),
					terminal.Orange(fmt.Sprintf("%q", result.LoginCTAText)),
					terminal.Gray(target)))
			}

			// The start URL bounced the browser off-host. Two cases: a login/SSO wall
			// (the crawler can't go past it unauthenticated, so the run yields next
			// to nothing — advise auth), or a relocated app on another host (the
			// crawler adopts that host and crawls it). Either way, say so — a silent
			// near-empty result otherwise reads like the site has no content.
			switch {
			case result.OffHostRedirect && result.LandingIsLogin:
				ssoHosts = append(ssoHosts, ssoHostsFromSpider(result.WallHosts, result.LandingURL)...)
				zap.L().Warn("Spidering: start URL redirected off-host to a login wall",
					zap.String("target", target),
					zap.String("landing", result.LandingURL),
					zap.Strings("wall_hosts", result.WallHosts))
				r.printPhaseDetail(fmt.Sprintf("%s %s redirected off-host to %s — likely an SSO/login wall. The wall's host(s) are now out of scope, so little was discovered. Supply authentication (--auth) or add the redirect host to scope to crawl behind the login.",
					terminal.Yellow(terminal.SymbolArrow),
					terminal.Gray(target),
					terminal.Yellow(result.LandingURL)))
			case result.OffHostRedirect && result.HostAdopted:
				zap.L().Info("Spidering: adopted off-host redirect target into scope",
					zap.String("target", target),
					zap.String("landing", result.LandingURL))
				r.printPhaseDetail(fmt.Sprintf("%s %s redirected off-host to %s — not a login page, so its host was added to scope and crawled.",
					terminal.Purple(terminal.SymbolArrow),
					terminal.Gray(target),
					terminal.Orange(result.LandingURL)))
			case result.OffHostRedirect:
				zap.L().Info("Spidering: start URL redirected off-host",
					zap.String("target", target),
					zap.String("landing", result.LandingURL))
				r.printPhaseDetail(fmt.Sprintf("%s %s redirected off-host to %s.",
					terminal.Purple(terminal.SymbolArrow),
					terminal.Gray(target),
					terminal.Orange(result.LandingURL)))
			}

			r.reportSpiderCoverage(result, target)
		}

		if sess != nil {
			phaseCapture.Merge(sessionCapture(sess, sessRW, abandoned))
		}
	}

	// Carry the harvested per-host sessions forward: store them for the Discovery
	// phase (buildDeparosConfig reads r.browserSessions) and inject them into the
	// shared scan requester used by discovery ingestion and dynamic assessment.
	// The requester is shared across all phases (executeNativePhase threads one
	// infra), so a single injection reaches every downstream request.
	if len(harvested) > 0 {
		r.browserSessions = harvested
		if infra.httpRequester != nil {
			infra.httpRequester.SetCarriedSessions(harvested)
		}
		hosts := make([]string, 0, len(harvested))
		for h := range harvested {
			hosts = append(hosts, h)
		}
		zap.L().Info("Spidering: carried browser session forward",
			zap.Strings("hosts", hosts), zap.Bool("pin_user_agent", carryUA))
		uaNote := ""
		if carryUA {
			uaNote = " and pinned its User-Agent"
		}
		r.printPhaseDetail(fmt.Sprintf("%s Carried the browser's cleared session (cookies%s) forward to discovery and scanning for %s.",
			terminal.Purple(terminal.SymbolArrow),
			uaNote,
			terminal.Orange(strings.Join(hosts, ", "))))
	}

	// Record the outcome for the Discovery phase's low-yield auto-fuzz decision.
	r.spidering = spideringOutcome{
		ran:      true,
		records:  totalRecords,
		lost:     phaseCapture.Lost(),
		complete: phaseCapture.Clean(),
		sawSSO:   len(ssoHosts) > 0,
		ssoHosts: ssoHosts,
	}

	if r.repository != nil && totalRecords > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, int64(totalRecords)); err != nil {
			zap.L().Warn("Spidering: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	completion := fmt.Sprintf("completed — %s records%s, %s states, %s actions in %s",
		terminal.Orange(fmt.Sprintf("%d", totalRecords)),
		terminal.Yellow(captureIncompleteNote(phaseCapture)),
		terminal.Orange(fmt.Sprintf("%d", totalStates)),
		terminal.Orange(fmt.Sprintf("%d", totalActions)),
		terminal.HiPurple(fmtDuration(elapsed)))
	if totalPrevented > 0 {
		completion += fmt.Sprintf(", %s form submission(s) prevented by policy",
			terminal.Yellow(fmt.Sprintf("%d", totalPrevented)))
	}
	if totalUncertain > 0 {
		completion += fmt.Sprintf(", %s POST form(s) with an uncertain outcome — dependent writes stopped (no fallback, no retry)",
			terminal.Yellow(fmt.Sprintf("%d", totalUncertain)))
	}
	if skippedTargets > 0 {
		completion += fmt.Sprintf(" (%s targets skipped — phase budget ceiling of %s reached)",
			terminal.Yellow(fmt.Sprintf("%d", skippedTargets)),
			terminal.Yellow(fmtDuration(phaseCeiling)))
	}
	r.printPhaseComplete("Spidering", completion)

	// The two coverage facts this phase owns, onto the phase outcome: targets the
	// ceiling never let it reach (a gap), and targets that spent their whole
	// per-target budget (a configured bound, hence a limit).
	tracker := r.currentPhase.Load()
	if skippedTargets > 0 {
		tracker.markPartial(database.ReasonTargetsSkipped)
	}
	if budgetExhaustedTargets > 0 {
		tracker.noteLimit(database.LimitTargetBudget)
	}
	// What the browser capture actually managed to persist — the same fact the
	// HTTP phases get from shutdownWriters.
	recordCapture(tracker, phaseCapture)
	// Name the way out at the moment it bit. The ceiling is not a pace the flags
	// can widen — the phase crawls one host at a time — so an operator told only
	// that N targets were dropped has no move to make from that line alone. The
	// flags come from SpiderFanOutSuggestion, the same resolver the pre-scan hint
	// uses, so both the advice and its preconditions match this run.
	if flags, ok := SpiderFanOutSuggestion(r.options, len(targets)); ok && skippedTargets > 0 {
		r.printPhaseDetail(fmt.Sprintf("%s Re-run with %s to scan the list as parallel child processes, each with its own browser and its own budget.",
			terminal.Yellow(terminal.SymbolArrow),
			terminal.HiCyan(flags)))
	}
	return nil
}
