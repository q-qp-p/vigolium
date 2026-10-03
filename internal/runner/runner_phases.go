package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/knownissuescan"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/active/authz_compare"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/passive/secret_detect"
	"github.com/vigolium/vigolium/pkg/notify"
	"github.com/vigolium/vigolium/pkg/notify/discord"
	"github.com/vigolium/vigolium/pkg/notify/telegram"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/secretscan"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// stderrCaptureActive guards the process-global os.Stderr redirection used for
// raw-stderr scan-log capture. Only the scan that wins the claim redirects
// os.Stderr; concurrent scans skip capture so they can't restore/close each
// other's descriptors.
var stderrCaptureActive atomic.Bool

// cursorFlushBudget bounds the post-round cursor checkpoint. It runs on a
// context detached from the phase's, so it needs a bound of its own; ten seconds
// is generous for one UPDATE and short enough that a wedged database delays
// teardown by a visible-but-tolerable amount rather than hanging it.
const cursorFlushBudget = 10 * time.Second

// teeDrainTimeout bounds the wait for the stderr-capture reader to finish after
// the write end is closed. The healthy path takes microseconds and never
// reaches it; the timeout exists only so a wedged reader cannot hang a scan's
// teardown, at the cost of a few trailing log lines.
const teeDrainTimeout = 2 * time.Second

// RunNativeScan orchestrates the native scan plan:
//
//	HeuristicsCheck   — optional root-page probe to optimize downstream phase selection
//	ExternalHarvest   — harvest URLs from external intelligence sources (opt-in)
//	Spidering         — browser-based crawling (opt-in)
//	Discovery         — ingest all input + deparos content discovery into DB (no modules)
//	Seed              — ingest CLI targets when discovery is skipped but DB-backed phases still need records
//	KnownIssueScan    — nuclei + secret scan (opt-in via --known-issue-scan)
//	DynamicAssessment — modules + extensions scan DB records
func (r *Runner) RunNativeScan() (err error) {
	defer close(r.done)
	ctx := r.ctx

	// A Runner is reused across agent rescans, so the phase ledger starts empty
	// here rather than at construction — otherwise the second run's scan row
	// would carry the first run's curtailment.
	r.scanOutcome.reset()

	// Total scan budget: when --scanning-max-duration is set, bound the WHOLE scan
	// (all phases combined). Each phase wraps this ctx with its own per-phase
	// deadline via phaseDeadline, which keeps the earlier deadline — so phases can
	// share and never exceed this total budget. End-of-scan DB bookkeeping below
	// stays on r.ctx (the un-bounded parent) so the scan record is still finalized
	// after the budget fires.
	if r.options.ScanMaxDuration > 0 {
		zap.L().Info("Total scan budget active — the whole scan is bounded by --scanning-max-duration; phases share it and remaining phases are skipped once it elapses",
			zap.Duration("scan_max_duration", r.options.ScanMaxDuration))
		var totalCancel context.CancelFunc
		ctx, totalCancel = context.WithTimeout(ctx, r.options.ScanMaxDuration)
		defer totalCancel()
	}

	plan := BuildNativeScanPlan(r.options)

	infra, err := r.buildInfrastructure(ctx, plan)
	if err != nil {
		return err
	}
	defer infra.Close()

	// Warn the operator (once per host) when the edge WAF/CDN starts filtering
	// scan traffic, across all phases that share this requester.
	r.attachWAFBlockNotifier(infra.httpRequester)
	// Proactively pace a host the first time an earlier phase reveals it is behind a
	// CDN/WAF edge, so the active phase does not burst the edge into a rate-based
	// block before the high-value probes run. Hangs off the shared host limiter (not a
	// single requester), so the notice fires once per host regardless of which
	// requester — heuristics, auth prep, discovery — first tripped the pre-arm.
	r.attachWAFPacingNotifier(infra.hostLimiter)
	// Route every finding the writer emits onto the machine event stream. One
	// seam rather than one per OnResult callback; see attachEventObserver.
	r.attachEventObserver()

	// Initialize scan logger (must happen before printScanConfig so the tee captures it)
	r.scanLogger = database.NewScanLogger(r.repository, infra.scanUUID)
	r.scanLogger.StartBatcher()
	defer r.scanLogger.Close()

	// Create scan record in the database so every scan is tracked with its lifecycle.
	// Skip when ScanOnReceive or ManagedScanRecord — the server already created the
	// scan record and owns its pending/queued/running transitions.
	if r.repository != nil && !r.options.ScanOnReceive && !r.options.ManagedScanRecord {
		target := strings.Join(r.options.Targets, ", ")
		scan := &database.Scan{
			UUID:            infra.scanUUID,
			ProjectUUID:     r.options.ProjectUUID,
			Name:            "cli-scan",
			Status:          "running",
			Target:          target,
			Threads:         r.options.Concurrency,
			ScopeOriginMode: r.resolvedScopeOriginMode(),
			ScanSource:      "cli",
			ScanMode:        "full",
			StartedAt:       time.Now(),
		}
		if err := r.repository.CreateScan(ctx, scan); err != nil {
			zap.L().Warn("Failed to create scan record", zap.Error(err))
		}
	}
	// Stamp the resolved scope mode on the row, whoever created it — there are ten
	// scan-creation sites and only the runner knows the settings the matcher will
	// actually be built from.
	r.persistScopeOriginMode(ctx, infra.scanUUID)
	if r.repository != nil {
		defer func() {
			// Terminal status, most-truthful first: a returned error (including a
			// recovered panic — the recovery defer below sets err, and runs before
			// this one since it is registered later) marks the scan failed;
			// otherwise a cancelled run context marks it cancelled; otherwise it
			// completed cleanly.
			var errMsg string
			switch {
			case err != nil:
				errMsg = err.Error()
			case r.ctx.Err() != nil:
				errMsg = "cancelled"
			}
			// Finalize on a detached, bounded context: r.ctx is already cancelled on
			// a stop/Ctrl-C, which would fail this write and leave the row stuck at
			// "running". WithoutCancel keeps values (project/tenant) but not the
			// cancellation, so the terminal status always lands. This makes the
			// runner the single finalization owner — the server no longer overwrites.
			finalCtx, finalCancel := context.WithTimeout(context.WithoutCancel(r.ctx), 30*time.Second)
			defer finalCancel()
			// WithOutcome, not CompleteScan: the runner is the only component that
			// saw every phase, so it is the only one that can say whether the run
			// actually covered its input. Everything else writes "unknown".
			if completeErr := r.repository.CompleteScanWithOutcome(finalCtx, infra.scanUUID, errMsg, r.Completion()); completeErr != nil {
				zap.L().Warn("Failed to complete scan record", zap.Error(completeErr))
			}
			r.finalized.Store(true)
		}()
	}

	// Set up TeeWriter to capture raw stderr output as trace-level scan logs.
	//
	// This redirects the PROCESS-GLOBAL os.Stderr to a pipe, so only one scan may
	// own the capture at a time: two concurrent scans (server mode) would otherwise
	// restore or close each other's descriptors and corrupt process-wide stderr.
	// A single-owner claim keeps the common single-scan (CLI) case fully captured
	// while a concurrent secondary scan simply skips raw capture rather than racing.
	if r.repository != nil && stderrCaptureActive.CompareAndSwap(false, true) {
		defer stderrCaptureActive.Store(false)
		origStderr := os.Stderr
		// Optionally mirror raw console output to ~/.vigolium/native-sessions/{uuid}/run.log.
		var sessionLogFile *os.File
		var teeInner io.Writer = origStderr
		if r.settings != nil && r.settings.ScanningStrategy.ScanLogs.IsPersistLogsEnabled() {
			sessionDir := filepath.Join(r.settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(), infra.scanUUID)
			if mkErr := os.MkdirAll(sessionDir, 0o755); mkErr == nil {
				logPath := filepath.Join(sessionDir, config.RuntimeLogFilename)
				if f, openErr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); openErr == nil {
					sessionLogFile = f
					r.sessionLogFile = f
					teeInner = io.MultiWriter(origStderr, sessionLogFile)
				} else {
					zap.L().Warn("Failed to open native session log file", zap.String("path", logPath), zap.Error(openErr))
				}
			} else {
				zap.L().Warn("Failed to create native session directory", zap.String("path", sessionDir), zap.Error(mkErr))
			}
		}
		r.teeWriter = newTeeWriter(teeInner, r.scanLogger)
		pr, pw, err := os.Pipe()
		if err == nil {
			os.Stderr = pw
			// Goroutine reads from the pipe and writes through the tee, and
			// closes drained when the pipe reports EOF.
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				buf := make([]byte, 4096)
				for {
					n, readErr := pr.Read(buf)
					if n > 0 {
						_, _ = r.teeWriter.Write(buf[:n])
					}
					if readErr != nil {
						break
					}
				}
			}()
			defer func() {
				// Closing the write end is what ends the reader's loop, so wait
				// for the goroutine to say it is done rather than guessing how
				// long that takes. The old blind 50ms sleep was both a floor on
				// every scan's teardown - visible on a probe that finishes in
				// under a fifth of a second - and no guarantee at all on a busy
				// machine, where the drain could still be unfinished when the
				// descriptor was yanked. The timeout only bounds a reader that
				// is stuck, which costs at most a few trailing log lines.
				_ = pw.Close()
				select {
				case <-drained:
				case <-time.After(teeDrainTimeout):
					zap.L().Warn("stderr capture did not drain within the timeout; some trace logs may be missing")
				}
				_ = pr.Close()
				os.Stderr = origStderr
				r.teeWriter.Flush()
				if sessionLogFile != nil {
					r.sessionLogMu.Lock()
					r.sessionLogFile = nil
					r.sessionLogMu.Unlock()
					_ = sessionLogFile.Close()
				}
			}()
		} else if sessionLogFile != nil {
			// Pipe setup failed; still close the log file we opened.
			defer func() { _ = sessionLogFile.Close() }()
		}
	}

	// Print scan configuration summary
	r.printScanConfig()

	r.scanLogger.Info("", "scan started")

	// Log scan configuration snapshot as structured metadata.
	r.logConfigSnapshot()

	// Banner the end of the scan lifecycle on stderr so operators see at a glance
	// when scanning wraps up, with wall-clock duration and finding count.
	// Suppressed by --silent. The scan kickoff is already announced by the Scan ID
	// line in the configuration banner above, so there is no separate "started"
	// marker here.
	scanStartedAt := time.Now()
	if !r.options.Silent {
		defer func() {
			duration := time.Since(scanStartedAt)
			findingSummary := ""
			if r.repository != nil {
				// Use the run context (consistent with the CompleteScan defer
				// above) so this terminal summary read participates in
				// cancellation instead of running on a detached Background.
				if scan, err := r.repository.GetScanByUUID(ctx, infra.scanUUID); err == nil && scan != nil {
					findingSummary = fmt.Sprintf(", findings: %d", scan.TotalFindings)
				}
			}
			fmt.Fprintf(os.Stderr, "  %s Scan finished %s %s%s\n",
				terminal.SuccessSymbol(),
				terminal.BoldCyan(infra.scanUUID),
				terminal.Gray(fmt.Sprintf("duration: %s%s", fmtDuration(duration), findingSummary)),
				partialBannerSuffix(r.Completion()))
		}()
	}

	// Panic recovery with notification. Sets the named return so the panic
	// surfaces as a scan error instead of being swallowed into a nil return that
	// the finalizer (and the server) would record as a successful scan.
	defer func() {
		if rec := recover(); rec != nil {
			stack := make([]byte, 4096)
			length := goruntime.Stack(stack, false)
			stackTrace := string(stack[:length])

			errorMessage := fmt.Sprintf(
				"Recovered from panic in runner execution: %+v\nStack Trace:\n%s",
				rec,
				stackTrace,
			)
			zap.L().Error(errorMessage)
			r.scanLogger.Error("", "panic recovered: "+fmt.Sprintf("%+v", rec))
			if infra.notifier != nil {
				_ = infra.notifier.SendRaw(errorMessage)
			}
			err = errors.Errorf("panic recovered in runner execution: %+v", rec)
		}
	}()

	// Final project-wide finding grouping, on every exit path (success, phase error,
	// budget cutoff, panic) via defer, so findings on redirected / third-party hosts —
	// and any scan that skipped known-issue-scan — still collapse per-asset rows before
	// results are read. Registered here (after infra/scanLogger exist) so it runs first
	// among the teardown defers: while stderr is still tee'd to the run log and before
	// the finished-banner reads the finding count. Idempotent when prior passes already
	// covered everything; see finalizeFindingGrouping.
	defer r.finalizeFindingGrouping()

	// Full-scan-on-receive: loop waiting for new records, then run all phases
	// on just the new batch. Each iteration swaps r.inputSource to a one-shot
	// DB source so Discovery processes only newly arrived records.
	if r.options.FullNativeScanOnReceive && r.repository != nil {
		for ctx.Err() == nil {
			if err := r.waitForNewRecords(ctx, infra.scanUUID, 2*time.Second); err != nil {
				break
			}
			r.inputSource = database.NewOneShotDBInputSource(r.repository.DB(), r.repository, infra.scanUUID)
			for i, step := range plan.Steps {
				if !step.Enabled {
					continue
				}
				if ctx.Err() != nil {
					r.recordSkippedSteps(plan.Steps[i:], scanStopReason(ctx, r.ctx))
					break
				}
				if err := r.executeNativePhase(ctx, infra, step.Phase); err != nil {
					zap.L().Error("Full-scan-on-receive: phase error", zap.Error(err))
					break
				}
			}
		}
		r.scanLogger.Info("", "scan finished")
		return nil
	}

	for i, step := range plan.Steps {
		if !step.Enabled {
			continue
		}
		// Stop launching phases once the total scan budget (--scanning-max-duration)
		// has elapsed. Mirrors the full-scan-on-receive loop guard above so a
		// curtailed scan ends cleanly instead of starting phases that would
		// immediately abort on the already-expired ctx.
		if ctx.Err() != nil {
			zap.L().Warn("Scan budget (scanning-max-duration) reached; skipping remaining phases",
				zap.String("phase", string(step.Phase)))
			// Record the phases that never ran. Without this the scan row shows
			// outcomes only for the phases that happened to start, which reads
			// exactly like a scan whose plan was that short to begin with.
			r.recordSkippedSteps(plan.Steps[i:], scanStopReason(ctx, r.ctx))
			break
		}
		if err := r.executeNativePhase(ctx, infra, step.Phase); err != nil {
			return err
		}
	}
	if r.options.SkipIngestion && !r.options.KnownIssueScanEnabled && r.options.SkipDynamicAssessment {
		zap.L().Info("Discovery skipped, no downstream phases need DB records")
		r.scanLogger.Info("discovery", "skipped, no downstream phases need DB records")
	}
	if r.options.SkipDynamicAssessment {
		zap.L().Info("Dynamic-assessment skipped by scanning strategy")
		r.scanLogger.Info("dynamic-assessment", "skipped by scanning strategy")
	}

	r.scanLogger.Info("", "scan finished")
	return nil
}

func (r *Runner) executeNativePhase(ctx context.Context, infra *phaseInfra, phase NativePhase) (err error) {
	// One tracker per phase, wrapped around the whole switch rather than
	// duplicated into its nine arms: the arms disagree about what an error means
	// (most log and continue, discovery and seed return), and a per-arm emitter
	// would have to restate that disagreement nine times. Here the tracker sees
	// the same outcome the caller does.
	//
	// r.currentPhase is set so the module result callbacks — which run on worker
	// goroutines with no idea which phase they belong to — can count a finding
	// against the phase that produced it.
	tracker := r.beginPhase(ctx, string(phase), infra.httpRequester)
	r.currentPhase.Store(tracker)
	defer func() {
		r.currentPhase.Store((*phaseTracker)(nil))
		r.scanOutcome.append(tracker.finish(ctx, err))
	}()

	switch phase {
	case PhaseHeuristicsCheck:
		r.setPhaseTag("heuristics")
		r.scanLogger.Info("heuristics", "phase started")
		results, err := r.runHeuristicsCheckPhase(ctx, infra)
		if err != nil {
			zap.L().Error("HeuristicsCheck phase failed", zap.Error(err))
			r.scanLogger.Error("heuristics", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.heuristicsResults = results
			r.scanLogger.Info("heuristics", "phase completed")
		}
	case PhasePortSweep:
		r.setPhaseTag("port-sweep")
		r.scanLogger.Info("port-sweep", "phase started")
		if err := r.runPortSweepPhase(ctx, infra); err != nil {
			zap.L().Error("PortSweep phase failed", zap.Error(err))
			r.scanLogger.Error("port-sweep", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("port-sweep", "phase completed")
		}
	case PhaseExternalHarvest:
		r.setPhaseTag("harvest")
		r.scanLogger.Info("harvest", "phase started")
		if err := r.runExternalHarvestPhase(ctx, infra); err != nil {
			zap.L().Error("ExternalHarvest phase failed", zap.Error(err))
			r.scanLogger.Error("harvest", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("harvest", "phase completed")
		}
	case PhaseSpidering:
		r.setPhaseTag("spider")
		r.scanLogger.Info("spidering", "phase started")
		if err := r.runSpideringPhase(ctx, infra); err != nil {
			zap.L().Error("Spidering phase failed", zap.Error(err))
			r.scanLogger.Error("spidering", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("spidering", "phase completed")
		}
	case PhaseProbe:
		r.setPhaseTag("probe")
		r.scanLogger.Info("probe", "phase started")
		if err := r.runProbePhase(ctx, infra); err != nil {
			zap.L().Error("Probe phase failed", zap.Error(err))
			r.scanLogger.Error("probe", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("probe", "phase completed")
		}
	case PhaseDiscovery:
		r.setPhaseTag("discovery")
		r.scanLogger.Info("discovery", "phase started")
		if err := r.runDiscoveryPhase(ctx, infra); err != nil {
			r.scanLogger.Error("discovery", "phase failed: "+err.Error())
			// No noteError here: this error is RETURNED, so it ends the scan and
			// rides out on scan.finished. The tracker records it once, in finish.
			return fmt.Errorf("discovery phase failed: %w", err)
		}
		r.scanLogger.Info("discovery", "phase completed")
		if r.repository != nil {
			r.cleanupDeparosRecords(ctx)
		}
	case PhaseTargetedReSpider:
		r.setPhaseTag("respider")
		r.scanLogger.Info("respider", "phase started")
		if err := r.runTargetedReSpiderPhase(ctx, infra); err != nil {
			zap.L().Error("Targeted re-spider phase failed", zap.Error(err))
			r.scanLogger.Error("respider", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("respider", "phase completed")
		}
	case PhaseSeed:
		r.setPhaseTag("seed")
		r.scanLogger.Info("seed", "seeding CLI targets")
		if err := r.seedCLITargets(ctx, infra); err != nil {
			r.scanLogger.Error("seed", "CLI target seeding failed: "+err.Error())
			return fmt.Errorf("CLI target seeding failed: %w", err)
		}
		r.scanLogger.Info("seed", "seeding completed")
	case PhaseKnownIssueScan:
		r.setPhaseTag("known-issue-scan")
		r.scanLogger.Info("known-issue-scan", "phase started")
		if err := r.runKnownIssueScanPhase(ctx, infra); err != nil {
			zap.L().Error("KnownIssueScan phase failed", zap.Error(err))
			r.scanLogger.Error("known-issue-scan", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("known-issue-scan", "phase completed")
			r.deduplicateFindings(ctx, "KnownIssueScan")
		}
	case PhaseDynamicAssessment:
		r.setPhaseTag("dynamic-assessment")
		activeModules, passiveModules := r.resolveAllModules(infra)
		if len(activeModules) > 0 || len(passiveModules) > 0 {
			r.scanLogger.InfoWithMeta("dynamic-assessment", "phase started", map[string]interface{}{
				"active_modules":  len(activeModules),
				"passive_modules": len(passiveModules),
			})
			if err := r.runDynamicAssessmentPhase(ctx, infra, activeModules, passiveModules); err != nil {
				zap.L().Error("Dynamic-assessment phase failed", zap.Error(err))
				r.scanLogger.Error("dynamic-assessment", "phase failed: "+err.Error())
				tracker.noteError(err)
			} else {
				r.scanLogger.Info("dynamic-assessment", "phase completed")
			}
		} else {
			zap.L().Info("No modules to execute")
			r.scanLogger.Info("dynamic-assessment", "skipped, no modules to execute")
			// Skipped, not completed: a scan that ran no modules at all must not
			// be reportable as a clean assessment. It is still a COMPLETE scan —
			// nothing was missed, there was nothing to do — which is why
			// no_modules is the one skip reason Completion treats as benign.
			tracker.markSkipped(database.ReasonNoModules)
		}
	}
	return nil
}

// cleanupDeparosRecords runs the post-discovery record-dedup passes over the full
// stored set (the in-engine hard dedup only sees one target at a time):
//
//  1. status-retention policy — drop 4xx discovery rejections (a fuzzed path the
//     server answers with a client error is not a discovered resource), keeping a
//     single representative per host for "auth wall exists" statuses;
//  2. reflected-URL-robust dedup — collapse records that differ only by an echoed
//     request URL/path or per-request dynamic tokens (the error-page-mirrors-the-URI
//     case that defeats exact-hash dedup);
//  3. shape-based soft-dedup backstop.
//
// (1) and (2) are config-gated (Discovery.DeparosDedup); (3) always runs,
// preserving prior behavior. Each pass emits one feedback line when it removes
// anything.
func (r *Runner) cleanupDeparosRecords(ctx context.Context) {
	report := func(label string, res database.RecordCleanupResult) {
		if res.Deleted <= 0 && res.KeptReferenced <= 0 {
			return
		}
		detail := fmt.Sprintf("%s %s records", label, terminal.Orange(fmt.Sprintf("%d", res.Deleted)))
		if len(res.ByStatus) > 0 {
			detail += " — " + formatStatusCodeMap(res.ByStatus)
		}
		// Say when a pass spared evidence, so a smaller-than-expected deletion
		// count does not read as the pass having failed.
		if res.KeptReferenced > 0 {
			detail += fmt.Sprintf(" (kept %d referenced by findings)", res.KeptReferenced)
		}
		r.printPhaseFeedback("Discovery", detail)
		r.scanLogger.Info("discovery", fmt.Sprintf("%s %d records (kept %d referenced)", label, res.Deleted, res.KeptReferenced))
	}

	// Refresh query-planner statistics before the dedup window queries run:
	// discovery just bulk-inserted thousands of records, and without fresh stats
	// SQLite plans the PARTITION-BY dedup scans against default row guesses.
	if r.repository != nil && r.repository.DB() != nil {
		r.repository.DB().Optimize(ctx)
	}

	if r.settings != nil && r.settings.Discovery.DeparosDedup.IsEnabled() {
		dedupCfg := &r.settings.Discovery.DeparosDedup
		if dedupCfg.DropClientErrorsEnabled() {
			statusPolicy := database.DeparosStatusPolicy{
				KeepOnePerHost: dedupCfg.KeepOneStatuses(),
				KeepPerPath:    dedupCfg.KeepPerPathStatuses(),
				PerPathCap:     dedupCfg.PerPathCapValue(),
			}
			res, err := r.repository.ApplyDeparosStatusPolicy(ctx, r.options.ProjectUUID, statusPolicy)
			if err != nil {
				zap.L().Warn("Deparos status-policy cleanup failed", zap.Error(err))
			} else {
				report("dropped client-error", res)
			}
		}
		if dedupCfg.NormalizeReflectedEnabled() {
			res, err := r.repository.DeduplicateDeparosByNormHash(ctx, r.options.ProjectUUID)
			if err != nil {
				zap.L().Warn("Deparos reflected-URL dedup failed", zap.Error(err))
			} else {
				report("collapsed reflected-URL", res)
			}
		}
	}

	softRes, err := r.repository.DeduplicateSoftDeparosRecords(ctx, r.options.ProjectUUID)
	if err != nil {
		zap.L().Warn("Deparos soft deduplication failed", zap.Error(err))
	} else {
		report("soft-deduplicated", softRes)
	}
}

// buildInfrastructure extracts common setup from the old RunNativeScan into a reusable struct.
//
// ctx is the scan context (already carrying --scanning-max-duration when set),
// threaded in so the one piece of setup that talks to the network — the session
// login flows — is cancellable and bounded like everything else. Nothing else
// here blocks: the rest is in-process construction.
func (r *Runner) buildInfrastructure(ctx context.Context, plan NativeScanPlan) (*phaseInfra, error) {
	// Auto-generate scan UUID when not provided via --scan-uuid
	scanUUID := r.options.ScanUUID
	if scanUUID == "" {
		scanUUID = uuid.New().String()
		r.options.ScanUUID = scanUUID
	}

	infra := &phaseInfra{
		scanUUID: scanUUID,
	}

	// If SharedInfra is available, reuse its components instead of building fresh
	if r.sharedInfra != nil {
		// Borrowed, not owned — phaseInfra.Close must leave these to the owner.
		infra.borrowedInfra = true
		infra.httpRequester = r.sharedInfra.HTTPRequester
		infra.scopeMatcher = r.sharedInfra.ScopeMatcher
		infra.hostLimiter = r.sharedInfra.HostLimiter
		infra.svc = r.sharedInfra.Services
		infra.jsEngine = r.sharedInfra.JSEngine
		infra.hookChain = r.sharedInfra.HookChain
		// Still need to initialize sessions
		if err := r.initSessions(ctx, infra); err != nil {
			if len(r.options.AuthFiles) > 0 || len(r.options.AuthInline) > 0 {
				return nil, fmt.Errorf("session initialization failed: %w", err)
			}
			// Continuing unauthenticated. Recorded so the assessment phases can
			// say so instead of letting a wall of 401s read as an open app.
			infra.authFailureReason = authFailureReason(ctx, err)
			zap.L().Warn("Failed to initialize sessions", zap.Error(err))
		}
		return infra, nil
	}

	// Create notifier with backends. Each backend is gated by the
	// notify.provider selector — empty means "all", a specific value
	// activates only that channel.
	if r.settings != nil && r.settings.Notify.Enabled {
		var backends []notify.Backend
		notifyCfg := &r.settings.Notify

		// Telegram backend (from settings or env). Construction no longer
		// contacts Telegram (see telegram.NewClient), so this cannot delay the
		// first phase; what it can still report is a malformed token or chat id,
		// which used to be dropped on the floor — an operator who enabled
		// notifications and mistyped the config got no notifications and no
		// explanation, matching the Discord branch below.
		if notifyCfg.IsProviderActive(config.NotifyProviderTelegram) {
			tgOpts := r.buildTelegramOptions()
			if tg, err := telegram.NewBackend(tgOpts...); err == nil {
				backends = append(backends, tg)
				zap.L().Info("[Notify] Telegram backend enabled")
			} else {
				zap.L().Warn("[Notify] Failed to create Telegram backend", zap.Error(err))
			}
		}

		// Discord backend (from settings or env)
		if notifyCfg.IsProviderActive(config.NotifyProviderDiscord) {
			webhookURL := notifyCfg.Discord.WebhookURL
			if webhookURL == "" {
				webhookURL = os.Getenv("DISCORD_WEBHOOK_URL")
			}
			if webhookURL != "" {
				if dc, err := discord.NewBackend(webhookURL); err == nil {
					backends = append(backends, dc)
					zap.L().Info("[Notify] Discord backend enabled")
				} else {
					zap.L().Warn("[Notify] Failed to create Discord backend", zap.Error(err))
				}
			}
		}

		if len(backends) > 0 {
			infra.notifier = notify.New(notify.Config{
				Backends:          backends,
				AllowedSeverities: notifyCfg.Severities,
			})
		}
	}

	// Create runtime services
	svc := &services.Services{
		Options:      r.options,
		Notifier:     infra.notifier,
		DedupManager: r.dedupManager,
		RateLimiter:  buildScanRateLimiter(effectiveRateLimit(r.options)),
	}

	if r.options.ShouldUseHostError() {
		cache := hosterrors.New(
			r.options.MaxHostError,
			hosterrors.DefaultMaxHostsCount,
			[]string{},
		)
		cache.SetVerbose(r.options.Verbose)
		svc.HostErrors = cache
	}

	// Create HostLimiter for per-host concurrency control
	maxPerHost := r.options.MaxPerHost
	if !r.options.MaxPerHostExplicitlySet {
		// Not chosen on the CLI: let newHostLimiter apply the common
		// scanning_pace value, then its own floor.
		maxPerHost = 0
	}
	hostLimiter := newHostLimiter(maxPerHost, r.settings, r.options.NoWafPacing)
	svc.HostLimiter = hostLimiter
	infra.hostLimiter = hostLimiter
	infra.svc = svc

	httpRequester, err := http.NewRequester(r.options, svc)
	if err != nil {
		infra.Close()
		return nil, errors.Wrap(err, "could not create http requester")
	}
	infra.httpRequester = httpRequester

	// Create scope matcher from settings, passing CLI targets for cli_origin_mode filtering
	if r.settings != nil {
		infra.scopeMatcher = config.NewScopeMatcher(r.settings.Scope, r.options.Targets...)
	}

	// Phases that never contact the target are unaffected by session headers and
	// request hooks, so neither is built for them. See SendsTargetTraffic for why
	// this is not merely about setup cost.
	reachesTarget := plan.SendsTargetTraffic()

	// Initialize JS extension engine
	if reachesTarget && r.settings != nil && r.settings.DynamicAssessment.Extensions.Enabled {
		jsEngineOpts := &jsext.EngineOptions{
			ScanUUID:   r.options.ScanUUID,
			Repository: r.repository,
			LLMClient:  extensionLLMClient(r.settings),
		}
		if r.settings != nil {
			scopeCfg := r.settings.Scope
			jsEngineOpts.ScopeConfig = &scopeCfg
			// The same matcher, from the same settings and the same targets, as
			// the one built above - so share it rather than paying for a second.
			jsEngineOpts.ScopeMatcher = infra.scopeMatcher
		}
		jsEngine, err := jsext.NewEngine(&r.settings.DynamicAssessment.Extensions, httpRequester, jsEngineOpts)
		if err != nil {
			zap.L().Warn("Failed to initialize JS extensions", zap.Error(err))
		} else {
			// Create hook chain if hooks are defined
			preHooks := jsEngine.PreHooks()
			postHooks := jsEngine.PostHooks()
			if len(preHooks) > 0 || len(postHooks) > 0 {
				infra.hookChain = jsext.NewHookChain(preHooks, postHooks)
				zap.L().Info("JS hooks loaded",
					zap.Int("pre_hooks", len(preHooks)),
					zap.Int("post_hooks", len(postHooks)))
			}
			// Store the engine in infra for module resolution
			infra.jsEngine = jsEngine
		}
	}

	// Initialize multi-session support for IDOR/BOLA testing. Skipped when no
	// enabled phase will reach the target: see reachesTarget above.
	if reachesTarget {
		if err := r.initSessions(ctx, infra); err != nil {
			// If the user explicitly configured sessions, surface the error clearly
			hasCLIAuth := len(r.options.AuthFiles) > 0 || len(r.options.AuthInline) > 0
			if hasCLIAuth && !r.options.AuthBestEffort {
				return nil, fmt.Errorf("session initialization failed: %w", err)
			}
			// Continuing unauthenticated. Recorded so the assessment phases can
			// say so instead of letting a wall of 401s read as an open app.
			infra.authFailureReason = authFailureReason(ctx, err)
			zap.L().Warn("Failed to initialize sessions, continuing without session support", zap.Error(err))
		}
	}

	return infra, nil
}

// runDiscoveryPhase ingests all input into the database without running modules.
// It combines the original input source with deparos content discovery (if enabled),
// expanding deparos targets with hosts discovered by prior phases (ExternalHarvest, Spidering).
// phaseDeadline derives a phase-scoped context bounded by maxDuration so a phase
// cannot run past its configured scanning_pace max_duration. It is the single
// chokepoint for the "wrap the WHOLE phase, not just one leg" invariant that
// known-issue-scan once regressed on (the Nuclei leg was bounded but the
// secret-scan leg ran on the raw ctx). When maxDuration <= 0 the phase is
// unbounded: the parent ctx is returned unchanged with a no-op cancel so callers
// can always `defer cancel()`. When the parent already has an earlier deadline
// (e.g. the overall scan budget), context.WithTimeout keeps that earlier
// deadline, so a phase can never extend the scan.
func phaseDeadline(ctx context.Context, maxDuration time.Duration) (context.Context, context.CancelFunc) {
	if maxDuration <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, maxDuration)
}

// coversAllSeverities reports whether the configured severity list already
// includes every nuclei severity level, so the "widen the filter" tip can be
// suppressed. Order- and duplicate-insensitive; inputs are normalized.
func coversAllSeverities(sevs []string) bool {
	want := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	have := make(map[string]bool, len(sevs))
	for _, s := range sevs {
		have[strings.ToLower(strings.TrimSpace(s))] = true
	}
	for s := range want {
		if !have[s] {
			return false
		}
	}
	return true
}

// formatKnownIssueScanTemplateScope renders the nuclei template selection (tags,
// excluded tags, and any custom templates dir) as a compact colored string for
// the KnownIssueScan phase header. Returns "all built-in" when no filters narrow
// the default template set.
func formatKnownIssueScanTemplateScope(cfg *config.KnownIssueScanConfig) string {
	var parts []string
	if len(cfg.Tags) > 0 {
		parts = append(parts, "tags="+terminal.HiTeal(strings.Join(cfg.Tags, ",")))
	}
	if len(cfg.ExcludeTags) > 0 {
		parts = append(parts, "exclude="+terminal.HiPurple(strings.Join(cfg.ExcludeTags, ",")))
	}
	if cfg.TemplatesDir != "" {
		parts = append(parts, "dir="+terminal.HiCyan(terminal.ShortenHome(config.ExpandPath(cfg.TemplatesDir))))
	}
	if len(parts) == 0 {
		return terminal.Gray("all built-in")
	}
	return strings.Join(parts, " ")
}

// runKnownIssueScanPhase orchestrates nuclei + secret scan scanning.
func (r *Runner) runKnownIssueScanPhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	r.printPhaseStart("KnownIssueScan", "assess security posture with Nuclei templates and third-party validation checks")
	var kisMaxDuration time.Duration
	if r.settings != nil {
		kisMaxDuration = r.settings.ScanningPace.ResolvePhase("known-issue-scan").MaxDuration
		if budget := PhaseSpeedDetail(r.settings, "known-issue-scan", 0); budget != "" {
			r.printPhaseDetail("Speed: " + budget)
		}

		// Surface the active severity filter and template scope as static detail
		// lines so the operator can see exactly what nuclei will run, not just how
		// many targets it runs against.
		sevDetail := terminal.Gray("all")
		if sevs := r.settings.KnownIssueScan.Severities; len(sevs) > 0 {
			sevDetail = terminal.HiTeal(strings.Join(sevs, ", "))
		}
		r.printPhaseDetail(fmt.Sprintf("Severities: %s", sevDetail))
		r.printPhaseDetail(fmt.Sprintf("Templates: %s", formatKnownIssueScanTemplateScope(&r.settings.KnownIssueScan)))
	}

	// bookkeepingCtx is the un-bounded parent context (still cancelled if the whole
	// scan is cancelled). End-of-phase DB writes use it so progress counters still
	// land when only a leg's deadline — not the scan — has fired. The Nuclei and
	// secret-scan legs below each derive their OWN max_duration budget from it (see
	// the per-leg comments), so they are bounded independently but never exceed the
	// overall scan budget.
	bookkeepingCtx := ctx
	enrichTargets := true
	if r.settings != nil {
		enrichTargets = r.settings.KnownIssueScan.EnrichTargets
	}
	if !enrichTargets && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("enrich KnownIssueScan targets with discovered paths via"), terminal.HiCyan("vigolium config known_issue_scan.enrich_targets=true"))
	}
	// Surface the active severity filter and how to widen it. An empty list means
	// "all severities", so only hint when the configured set does not already
	// cover all five (the default balanced intensity ships with critical+high).
	if r.settings != nil && !r.options.Silent {
		sevs := r.settings.KnownIssueScan.Severities
		if len(sevs) > 0 && !coversAllSeverities(sevs) {
			fmt.Fprintf(os.Stderr, "  %s %s %s\n",
				terminal.TipPrefix(),
				terminal.Gray(fmt.Sprintf("known-issue-scan limited to %s severities; scan all via", strings.Join(sevs, ","))),
				terminal.HiCyan(`vigolium config set known_issue_scan.severities "critical,high,medium,low,info"`))
		}
	}
	// Restrict KnownIssueScan to the same in-scope origins DynamicAssessment uses, so
	// targets/bodies from prior scans of other origins in this project (e.g. localhost
	// records on a different port left in the default project) don't leak into this scan.
	// Empty means no CLI targets/scope — fall back to a project-wide pass (mirrors DA).
	inScopeHosts := r.getInScopeDBHosts(ctx)

	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	if r.repository != nil && r.options.Verbose {
		paths, _ := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID, inScopeHosts...)
		if len(paths) > 0 {
			var knownIssueScanTargets []string
			if enrichTargets {
				knownIssueScanTargets = buildKnownIssueScanTargetsFromPaths(paths)
			} else {
				knownIssueScanTargets = buildKnownIssueScanHostTargets(paths)
			}
			r.printVerboseTargets(knownIssueScanTargets)
		}
	}
	zap.L().Info("KnownIssueScan: running security posture assessment")

	// Collapse live output for findings that repeat the same extracted value
	// (e.g. one leaked secret seen on many URLs) into a single console line per
	// value. The grouper also owns the grouped severity tallies for the phase
	// summary; the full finding still streams to file/DB on every occurrence.
	grouper := newFindingGrouper(r.resolveFindingGrouping())

	onResult := func(result *output.ResultEvent) {
		if grouper.observe(result) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("KnownIssueScan: failed to write result", zap.Error(err))
			}
			// Echo to stderr when the stdout stream is deferred (jsonl/html), so
			// secret/CVE findings are visible live and not just post-scan. No-op
			// in console mode — r.output.Write above already printed them.
			r.echoLiveFinding("known-issue-scan", result)
		} else if err := r.output.WriteFileOnly(result); err != nil {
			zap.L().Error("KnownIssueScan: failed to write result", zap.Error(err))
		}
	}

	// Nuclei scan on distinct hosts. It gets its OWN max_duration budget so that a
	// long Nuclei run no longer starves the secret scan below — the two
	// legs are bounded independently rather than sharing one budget. A ctx error
	// means this leg's max_duration (or the overall scan) elapsed — that is a
	// curtailment, not a failure.
	nucleiCtx, nucleiCancel := r.trackedPhaseDeadline(ctx, kisMaxDuration)
	defer nucleiCancel()
	if err := r.runKnownIssueScan(nucleiCtx, infra, onResult, inScopeHosts); err != nil {
		if nucleiCtx.Err() != nil {
			zap.L().Warn("KnownIssueScan: Nuclei scan stopped at phase max_duration", zap.Error(nucleiCtx.Err()))
		} else {
			zap.L().Error("KnownIssueScan: Nuclei scan failed", zap.Error(err))
		}
	}

	// secret scan on all response bodies. It gets a FRESH max_duration
	// budget that starts now (derived from the parent ctx, so still bounded by the
	// overall scan budget), so it always runs even when the Nuclei leg above was
	// curtailed at its deadline. secret scan reads DB response bodies locally (no
	// network) and normally finishes well within this budget. Worst-case phase
	// wall-clock is ~2× max_duration, capped by the overall scan budget. A ctx error
	// is a curtailment, distinct from a genuine scanner failure.
	secretScanCtx, secretScanCancel := r.trackedPhaseDeadline(ctx, kisMaxDuration)
	defer secretScanCancel()
	if err := r.runSecretScanBatch(secretScanCtx, infra, onResult, inScopeHosts); err != nil {
		if secretScanCtx.Err() != nil {
			zap.L().Warn("KnownIssueScan: secret scan curtailed before all response bodies were scanned — phase max_duration reached", zap.Error(secretScanCtx.Err()))
		} else {
			zap.L().Error("KnownIssueScan: secret scan failed", zap.Error(err))
		}
	}

	// Print summary using grouped tallies (repeats of the same value count once),
	// then one muted rollup line per collapsed value noting how many URLs it spanned.
	counts := grouper.summaryCounts()
	var total int
	for _, c := range counts {
		total += c
	}
	if total > 0 {
		r.printPhaseDetail(formatKnownIssueScanSummary(counts, total))
		for _, line := range grouper.rollupLines() {
			r.printPhaseDetail(line)
		}
	}

	// Increment processed_count for KnownIssueScan phase using the raw finding
	// count — every emitted finding was written to the DB at this point (the
	// post-phase grouping pass merges them afterward). Use the un-bounded parent
	// ctx so the counter still updates when the phase deadline fired mid-scan.
	if r.repository != nil && total > 0 {
		if err := r.repository.IncrementProcessedCount(bookkeepingCtx, infra.scanUUID, int64(grouper.rawTotal())); err != nil {
			zap.L().Warn("KnownIssueScan: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("KnownIssueScan", fmt.Sprintf("completed in %s", terminal.HiPurple(fmtDuration(elapsed))))
	return nil
}

// runSecretScanBatch scans all response bodies in the database for secrets using
// the native in-process detector (pkg/secretscan). Detection runs inline per
// record — no external binary, no temp files.
func (r *Runner) runSecretScanBatch(ctx context.Context, infra *phaseInfra, onResult func(*output.ResultEvent), inScopeHosts []database.HostTarget) error {
	if r.repository == nil {
		return fmt.Errorf("secret scan: database repository required")
	}

	det, err := secretscan.Default()
	if err != nil {
		return fmt.Errorf("secret scan: detector unavailable: %w", err)
	}

	zap.L().Info("KnownIssueScan: native secret scan — scanning response bodies for secrets")

	var cursor string
	var totalFindings int
	// Collapse the same secret re-observed on the same URL across records (the
	// same page can survive record-dedup under different paths/sources): emit one
	// finding per (host, url, rule, snippet) so near-identical request/response
	// copies don't pile up as redundant Additional Evidence. Run-scoped across
	// batches; bounded by the number of distinct secrets, which is small.
	seenSecret := make(map[string]struct{})
	for {
		// Break promptly when the phase/scan budget elapses. Returning ctx.Err()
		// lets the caller log the secret-scan curtailment notice rather than
		// treating it as a failure.
		if err := ctx.Err(); err != nil {
			return err
		}

		records, err := r.repository.GetRecordsWithResponseBody(ctx, r.options.ProjectUUID, cursor, secretScanBatchSize, inScopeHosts...)
		if err != nil {
			return fmt.Errorf("secret scan: failed to fetch records: %w", err)
		}
		if len(records) == 0 {
			break
		}

		for _, record := range records {
			cursor = record.UUID

			if err := ctx.Err(); err != nil {
				return err
			}

			// Parse the raw response once so we can both scan the body and inspect
			// the status/headers for the severity decision below.
			resp := record.ParsedResponse()
			if resp == nil {
				continue
			}
			// A WAF/CDN edge block is the edge talking, not the application, so its
			// challenge/error page's random tokens must never be scanned as app
			// secrets — same guard the passive path applies.
			if modkit.IsEdgeBlockedResponse(resp) {
				continue
			}
			body := resp.Body()
			// Shared eligibility policy (size cap + media + text MIME) — the batch
			// previously filtered on MIME alone, letting oversized or mislabeled
			// binary bodies reach the detector.
			if !secret_detect.ShouldScanBody(record.ResponseContentType, record.URL, len(body)) {
				continue
			}

			matches := det.Detect(body)
			if len(matches) == 0 {
				continue
			}

			ev := secret_detect.EvidenceContext{
				Body:         body,
				Host:         record.Hostname,
				URL:          record.URL,
				Request:      string(record.RawRequest),
				RespHead:     string(resp.Head()),
				StatusCode:   resp.StatusCode(),
				ContentType:  record.ResponseContentType,
				HeaderValues: secret_detect.JoinHeaderValues(resp.Headers()),
			}

			totalFindings += r.emitSecretFindings(ctx, infra, matches, ev, seenSecret, onResult, secretEmitOptions{
				RecordUUIDs: []string{record.UUID},
				ModuleShort: "Leaked secret detected in HTTP response body",
			})
		}

		if len(records) < secretScanBatchSize {
			break
		}
	}

	recovered, err := r.scanRecoveredSourcesForSecrets(ctx, infra, det, seenSecret, onResult, inScopeHosts)
	if err != nil {
		return err
	}
	totalFindings += recovered

	zap.L().Info("KnownIssueScan: native secret scan completed", zap.Int("findings", totalFindings))
	return nil
}

// secretEmitOptions varies the parts of a secret finding that differ by corpus.
type secretEmitOptions struct {
	// RecordUUIDs anchors the finding to the traffic it came from. May be empty.
	RecordUUIDs []string
	// ModuleShort is the one-line label shown in reports.
	ModuleShort string
	// ExtraTags are appended after the shared known-issue-scan tag.
	ExtraTags []string
	// DescriptionSuffix appends provenance the shared grading cannot know.
	DescriptionSuffix string
}

// emitSecretFindings turns graded detector matches into saved findings.
//
// Both secret-scan corpora — stored response bodies and source-map-recovered
// originals — funnel through here so the rule for what becomes a finding has one
// home. The two were written separately at first and had already drifted on which
// guards they applied, the same way the size cap and media filtering drifted
// before ShouldScanBodyForSecrets centralized them.
func (r *Runner) emitSecretFindings(
	ctx context.Context,
	infra *phaseInfra,
	matches []secretscan.Match,
	ev secret_detect.EvidenceContext,
	seenSecret map[string]struct{},
	onResult func(*output.ResultEvent),
	opts secretEmitOptions,
) int {
	emitted := 0
	for _, mt := range matches {
		// Skip a secret already reported on this URL. Marked seen only after
		// GradeMatch's body-dependent guards pass, so a blob/JS-escape drop never
		// suppresses a genuine match of the same value elsewhere. The map is shared
		// across corpora: the same credential usually appears both in the shipped
		// bundle and in the original source it was compiled from, and that is one
		// finding.
		dedupKey := secret_detect.SecretDedupKey(ev.Host, ev.URL, mt.RuleID, mt.Secret)
		if _, dup := seenSecret[dedupKey]; dup {
			continue
		}

		// Grade the match — structural false-positive guard, severity downgrades
		// (redirect/header/request reflections, docs-demo samples, public
		// reCAPTCHA/OAuth identifiers, low-value JWTs, Google API keys), and evidence
		// reconstruction — via the same helper the passive module uses.
		event, ok := secret_detect.GradeMatch(mt, ev)
		if !ok {
			continue
		}
		seenSecret[dedupKey] = struct{}{}

		// Tag with the secret-detect module ID (same as the passive path) so the
		// URL-keyed finding dedup excludes these too — distinct secrets on one URL
		// are not duplicates. Without it KIS findings carry an empty module_id and
		// would merge with each other (and other empty-id findings) by URL+severity.
		event.ModuleID = secret_detect.ModuleID
		event.Info.Tags = append(event.Info.Tags, "known-issue-scan")
		event.Info.Tags = append(event.Info.Tags, opts.ExtraTags...)
		event.Info.Description += opts.DescriptionSuffix
		// secret-detect is a passive module; label it "passive" like its
		// dynamic-assessment path does (where the executor sets that automatically).
		// FindingSource still records that this one came from known-issue-scan.
		event.ModuleType = database.ModuleTypePassive
		event.FindingSource = database.FindingSourceKnownIssueScan
		event.ModuleShort = opts.ModuleShort

		if saveErr := r.repository.SaveFinding(ctx, event, opts.RecordUUIDs, infra.scanUUID, r.options.ProjectUUID); saveErr != nil {
			zap.L().Debug("Failed to save secret finding", zap.Error(saveErr))
		}
		if onResult != nil {
			onResult(event)
		}
		emitted++
	}
	return emitted
}

// scanRecoveredSourcesForSecrets scans original source files recovered from
// source maps, which are stored as analysis artifacts beside the bundle record
// rather than as response bodies of their own — so the record loop above never
// reaches them.
//
// This is where the yield is. A minified bundle mangles local identifiers, so the
// name-anchored rules ("apiKey", "secret", "password" near a literal) that catch
// most hardcoded credentials fire far less often on the shipped bundle than on
// the original TypeScript the map hands back verbatim.
//
// Findings are attributed to the generated bundle's URL and record, because that
// is the URL an operator can actually re-fetch; the source path travels in the
// evidence and the finding name.
func (r *Runner) scanRecoveredSourcesForSecrets(
	ctx context.Context,
	infra *phaseInfra,
	det *secretscan.Detector,
	seenSecret map[string]struct{},
	onResult func(*output.ResultEvent),
	inScopeHosts []database.HostTarget,
) (int, error) {
	// Same host scope as the record loop above. Artifacts are project-scoped in the
	// database, so without this the corpus would silently differ between the two
	// halves of one secret scan — and include hosts this scan was told to skip.
	hostInScope := func(hostname string) bool {
		if len(inScopeHosts) == 0 {
			return true
		}
		for _, target := range inScopeHosts {
			if strings.EqualFold(target.Hostname, hostname) {
				return true
			}
			if port := fmt.Sprintf("%s:%d", target.Hostname, target.Port); strings.EqualFold(port, hostname) {
				return true
			}
		}
		return false
	}

	found := 0
	var lastGeneratedURL, lastHostname string
	err := r.repository.StreamAnalysisArtifactsByKind(
		ctx, r.options.ProjectUUID, database.AnalysisArtifactKindSourceMapOriginal, secretScanBatchSize,
		func(artifact *database.AnalysisArtifact) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !secret_detect.ShouldScanBody(artifact.MediaType, artifact.Filename, len(artifact.Content)) {
				return nil
			}

			generatedURL, sourcePath := sourceMapArtifactOrigin(artifact)
			// One map contributes up to 512 artifacts, and the stream is in id order,
			// so they arrive consecutively with identical origins. Memo the parse.
			if generatedURL != lastGeneratedURL {
				lastGeneratedURL = generatedURL
				lastHostname = ""
				if parsed, parseErr := url.Parse(generatedURL); parseErr == nil {
					lastHostname = parsed.Host
				}
			}
			hostname := lastHostname
			if !hostInScope(hostname) {
				return nil
			}

			matches := det.Detect(artifact.Content)
			if len(matches) == 0 {
				return nil
			}

			ev := secret_detect.EvidenceContext{
				Body: artifact.Content,
				Host: hostname,
				URL:  generatedURL,
			}
			var recordUUIDs []string
			if artifact.HTTPRecordUUID != "" {
				recordUUIDs = []string{artifact.HTTPRecordUUID}
			}

			found += r.emitSecretFindings(ctx, infra, matches, ev, seenSecret, onResult, secretEmitOptions{
				RecordUUIDs: recordUUIDs,
				ModuleShort: "Leaked secret detected in source-map-recovered source",
				ExtraTags:   []string{"source-map", "recovered-source"},
				DescriptionSuffix: fmt.Sprintf(
					"\n\nRecovered from the source map of %s, in original source %s.",
					generatedURL, sourcePath),
			})
			return nil
		})
	if err != nil {
		return found, err
	}
	if found > 0 {
		zap.L().Info("KnownIssueScan: secrets recovered from source-map originals", zap.Int("findings", found))
	}
	return found, nil
}

// sourceMapArtifactOrigin reads the generated bundle URL and original source path
// an artifact was recovered from. Both live in the artifact metadata written by
// the discovery source; the filename is the fallback for the source path.
func sourceMapArtifactOrigin(artifact *database.AnalysisArtifact) (generatedURL, sourcePath string) {
	sourcePath = artifact.Filename
	if artifact.Metadata == "" {
		return "", sourcePath
	}
	var meta struct {
		GeneratedURL string `json:"generated_url"`
		SourcePath   string `json:"source_path"`
	}
	// The column is declared jsonb. PostgreSQL stores the object natively; SQLite
	// round-trips the Go string through JSON encoding, so the same value comes back
	// as a quoted string containing JSON. A leading quote says which shape this is,
	// so the common path costs one unmarshal on either driver rather than failing
	// into a retry.
	raw := []byte(strings.TrimSpace(artifact.Metadata))
	if len(raw) > 0 && raw[0] == '"' {
		var nested string
		if err := json.Unmarshal(raw, &nested); err != nil {
			return "", sourcePath
		}
		raw = []byte(nested)
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return "", sourcePath
	}
	if meta.SourcePath != "" {
		sourcePath = meta.SourcePath
	}
	return meta.GeneratedURL, sourcePath
}

// freshenPerScanModules returns a copy of mods with per-scan-stateful active
// modules replaced by fresh instances. Those modules keep mutable state that is
// meaningful only within one scan (per-host dedup maps, per-scan budgets, compare
// clients, discovery maps), but the registry stores one shared singleton of each
// (GetActiveModules copies the pointers). Two concurrent server-mode scans sharing
// a singleton would race on / clobber that state and leak it across scans. Modules
// opt in by implementing modules.PerScanModule; swapping in their Fresh() instance
// for this scan's slice leaves the registry singleton untouched. Modules whose
// per-scan state is already isolated via dedup.Lazy(scanCtx.DedupMgr()) or
// ScanContext need not implement it.
func freshenPerScanModules(mods []modules.ActiveModule) []modules.ActiveModule {
	out := make([]modules.ActiveModule, len(mods))
	copy(out, mods)
	for i, mod := range out {
		if f, ok := mod.(modules.PerScanModule); ok {
			if fresh, ok := f.Fresh().(modules.ActiveModule); ok {
				out[i] = fresh
			}
		}
	}
	return out
}

// runDynamicAssessmentPhase runs all modules on DB records with a feedback loop for newly discovered URLs.
func (r *Runner) runDynamicAssessmentPhase(ctx context.Context, infra *phaseInfra, activeModules []modules.ActiveModule, passiveModules []modules.PassiveModule) error {
	phaseStart := time.Now()

	if r.repository == nil {
		return fmt.Errorf("dynamic-assessment: database repository required")
	}

	r.printPhaseStart("DynamicAssessment", "execute dynamic security assessments through coordinated active and passive scanning modules")
	modulesLine := fmt.Sprintf("Modules: %s active, %s passive",
		terminal.Orange(fmt.Sprintf("%d", len(activeModules))),
		terminal.Orange(fmt.Sprintf("%d", len(passiveModules))))
	if infra.jsEngine != nil {
		jsActive := len(infra.jsEngine.ActiveModules())
		jsPassive := len(infra.jsEngine.PassiveModules())
		if jsActive+jsPassive > 0 {
			modulesLine += fmt.Sprintf(" (incl. %s extensions)",
				terminal.HiTeal(fmt.Sprintf("%d", jsActive+jsPassive)))
		}
	}
	r.printPhaseDetail(modulesLine)

	daSpeedDetail := fmt.Sprintf("Speed: concurrency=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.options.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", r.options.MaxPerHost)))
	if budget := PhaseSpeedDetail(r.settings, "dynamic-assessment", 0); budget != "" {
		daSpeedDetail += ", " + budget
	}
	r.printPhaseDetail(daSpeedDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))

	// Resolve feedback rounds early so we can show it in the phase header
	feedbackRounds := maxFeedbackRounds
	if r.settings != nil && r.settings.DynamicAssessment.MaxFeedbackRounds > 0 {
		feedbackRounds = r.settings.DynamicAssessment.MaxFeedbackRounds
	}
	r.printPhaseDetail(fmt.Sprintf("Feedback rounds: %s", terminal.HiBlue(fmt.Sprintf("%d", feedbackRounds))))
	if feedbackRounds <= 1 && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("increase feedback rounds to re-scan newly discovered URLs via"), terminal.HiCyan("vigolium config dynamic-assessment.max_feedback_rounds=3"))
	}

	zap.L().Info("DynamicAssessment: running modules on database records",
		zap.Int("active", len(activeModules)),
		zap.Int("passive", len(passiveModules)))

	// Log quarantined hosts from prior phases so users see cross-phase propagation
	if infra.svc != nil && infra.svc.HostErrors != nil {
		if qc := infra.svc.HostErrors.QuarantinedCount(); qc > 0 {
			zap.L().Info("DynamicAssessment: carrying forward host errors from prior phases",
				zap.Int("quarantined_hosts", qc))
		}
	}

	// If KnownIssueScan was enabled, filter out secret-detect to avoid duplicate secret findings
	if r.options.KnownIssueScanEnabled {
		passiveModules = filterOutPassiveModule(passiveModules, secret_detect.ModuleID)
	}

	// Isolate per-scan-stateful modules from the shared registry singletons before
	// wiring or running them, so concurrent server-mode scans can't race on or
	// clobber each other's state (authz_compare's compare clients below, and
	// nextjs_chunk_audit's per-host discovery map).
	activeModules = freshenPerScanModules(activeModules)

	// The requester every module in this phase sends through. Under
	// session.use_in_discovery: false the primary session's credentials are
	// deliberately absent from infra.httpRequester (discovery and spidering must
	// stay anonymous) and arrive here instead, on a view that shares that
	// requester's pool, limiter and carried browser sessions. Derived ONCE for the
	// phase: a view per round or per module would split the response cache
	// partition and the connection pool for no gain.
	daRequester, err := r.assessmentRequester(infra)
	if err != nil {
		return fmt.Errorf("dynamic-assessment: %w", err)
	}

	// Configured authentication that never reached the scan means the assessment
	// is probing an authenticated app anonymously. Report it rather than let the
	// resulting 401s read as an application with nothing behind the login.
	if infra.authFailureReason != "" {
		r.printPhaseDetail(fmt.Sprintf("%s configured authentication could not be applied — assessment runs unauthenticated.",
			terminal.Yellow(terminal.SymbolWarning)))
		r.scanLogger.Warn("dynamic-assessment", "configured authentication could not be applied — assessment runs unauthenticated")
		tracker := r.currentPhase.Load()
		// auth_unavailable is always marked so a consumer has one code to look
		// for; the specific cause (cancelled, login_budget, …) rides alongside.
		// They coincide when the cause is an ordinary failure, and marking is
		// idempotent per code, so that case reports one reason.
		tracker.markPartial(database.ReasonAuthUnavailable)
		tracker.markPartial(infra.authFailureReason)
	}

	// Wire compare session clients into the authz-compare module
	if len(infra.compareSessions) > 0 {
		clients := make([]*http.Requester, len(infra.compareSessions))
		names := make([]string, len(infra.compareSessions))
		hostnames := make([]string, len(infra.compareSessions))
		for i, cs := range infra.compareSessions {
			clients[i] = cs.Client
			names[i] = cs.Name
			hostnames[i] = cs.Hostname
		}
		for _, mod := range activeModules {
			if ac, ok := mod.(*authz_compare.Module); ok {
				ac.SetCompareClients(clients, names, hostnames)
				break
			}
		}
	}

	// Update the top-level scan record with module info for cursor tracking.
	// The scan record was already created at the start of RunNativeScan().
	if _, err := r.repository.DB().NewUpdate().
		Model((*database.Scan)(nil)).
		Set("modules = ?", r.buildModulesString(activeModules, passiveModules)).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", infra.scanUUID).
		Exec(ctx); err != nil {
		zap.L().Warn("Failed to update scan modules", zap.Error(err))
	}

	// Resolve dynamic-assessment concurrency: scanning_pace.dynamic-assessment overrides global when CLI not explicit
	daConcurrency := r.phaseConcurrency("dynamic-assessment")

	// Initialize OAST service if enabled
	var oastService *oast.Service
	if r.settings != nil && r.settings.OAST.Enabled {
		onOASTResult := func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write OAST result", zap.Error(err))
			}
		}
		var err error
		oastService, err = oast.New(&r.settings.OAST, onOASTResult, r.repository, infra.scanUUID, r.options.ProjectUUID, nil)
		if err != nil {
			zap.L().Warn("DynamicAssessment: OAST initialization failed, continuing without OAST", zap.Error(err))
		}
		if oastService != nil {
			oastService.Start()
			defer oastService.Close()
			r.printPhaseDetail(fmt.Sprintf("OAST: enabled via %s (out-of-band callback detection active)", oastService.ServerURL()))
		}
	}

	// Compute in-scope origins (scheme/host/port) to filter DB records by CLI targets.
	// inScopeHostnames is derived for the hostname-only paths (finding dedup), which
	// carry no port column.
	inScopeHosts := r.getInScopeDBHosts(ctx)
	inScopeHostnames := database.HostnamesOf(inScopeHosts)

	// Shared insertion point cache across feedback rounds to avoid cold-start overhead
	ipCache := core.NewInsertionPointCache(4096)

	// Resolve per-phase settings from scanning pace config (static across rounds)
	var daMaxDuration time.Duration
	daParallelPassive := true // default for dynamic-assessment phase
	var daFeedbackDrain time.Duration
	var daActiveModuleTimeout time.Duration
	if r.settings != nil {
		daPace := r.settings.ScanningPace.ResolvePhase("dynamic-assessment")
		daMaxDuration = daPace.MaxDuration
		daParallelPassive = daPace.ParallelPassive
		daFeedbackDrain = daPace.FeedbackDrainTimeout
		daActiveModuleTimeout = daPace.ActiveModuleTimeout
	}

	// Enforce dynamic-assessment phase deadline across all feedback rounds. Without this wrap
	// each round's executor would start a fresh timeout, letting total phase time
	// reach feedbackRounds × daMaxDuration.
	var phaseCancel context.CancelFunc
	ctx, phaseCancel = r.trackedPhaseDeadline(ctx, daMaxDuration)
	defer phaseCancel()

	// Reset cursor so dynamic-assessment reads all records from the beginning
	// (seed phase advances the cursor past all records when saving them).
	// Skip reset for scan-on-receive — the cursor tracks which records have been scanned.
	if !r.options.ScanOnReceive {
		if err := r.repository.ResetScanCursor(ctx, infra.scanUUID); err != nil {
			zap.L().Warn("DynamicAssessment: failed to reset scan cursor", zap.Error(err))
		}
	}

	var recordWriter *database.RecordWriter
	var findingWriter *database.FindingWriter
	if r.repository != nil {
		recordWriter = database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
		// Batched, async finding persistence so module workers aren't blocked on
		// a synchronous SaveFinding round-trip.
		findingWriter = database.NewFindingWriter(r.repository, database.FindingWriterConfig{})
		// One deferred shutdown rather than two deferred Closes: findings drain
		// first (today's LIFO order, and the order the data depends on — a finding's
		// evidence is written through the record writer), and the two outcomes are
		// reported together instead of being discarded.
		defer func() {
			r.shutdownWriters("dynamic-assessment", findingWriter, recordWriter)
		}()
	}

	// phaseModuleTimeouts is shared across every per-round executor so the
	// timed-out total in the status line accumulates over the whole phase rather
	// than resetting each feedback round (Records/Findings are per-round by design).
	var phaseModuleTimeouts atomic.Int64

	// Shared across every per-round executor: a wall is a fact about the host,
	// not about the round that happened to hit it, so reporting per round would
	// repeat the same notice once per feedback round.
	authWalls := newAuthWallCollector()

	// One finding admission for the whole phase, for the same reason. Each round
	// gets a fresh executor, so executor-local admission reset the per-module cap
	// every round — a cap documented as holding for the remainder of the phase —
	// and let a root cause already reported in an earlier round re-fire every
	// callback and notification when the next round found it again.
	phaseAdmission := core.NewFindingAdmission()

	baseExecutorCfg := core.ExecutorConfig{
		Workers:  daConcurrency,
		Services: infra.svc,
		// The authenticated view when use_in_discovery is false; otherwise
		// infra.httpRequester itself. See assessmentRequester.
		HTTPRequester: daRequester,
		Repository:    r.repository,
		RecordWriter:  recordWriter,
		FindingWriter: findingWriter,
		ScanUUID:      infra.scanUUID,
		ProjectUUID:   r.options.ProjectUUID,
		ScopeMatcher:  infra.scopeMatcher,
		// Subdomain feed-back is wired only here, on the dynamic-assessment phase —
		// the only phase that runs the full passive set with live feed-back. The
		// executor guard (FollowSubdomains && ScopeMatcher && !DisableFeedback) makes
		// it a no-op elsewhere, so subdomain_harvest stays recon-only in other phases.
		FollowSubdomains:     r.options.FollowSubdomains || strings.EqualFold(r.options.Intensity, "deep"),
		DeepScan:             strings.EqualFold(r.options.Intensity, "deep"),
		ModuleTimeouts:       &phaseModuleTimeouts,
		SkipBaseline:         true,
		PauseCtrl:            r.pauseCtrl,
		MaxFindingsPerModule: r.options.MaxFindingsPerModule,
		FindingAdmission:     phaseAdmission,
		TechFilterDisabled:   r.options.NoTechFilter || strings.EqualFold(r.options.Intensity, "deep"),
		// Seed the per-host content-class fallback from the heuristics root probe
		// so markup-only passive modules (clickjacking, autocomplete, SRI, mixed-
		// content) defer on confirmed JSON/XML API hosts even when a record lacks
		// its own Content-Type. Honors the same TechFilterDisabled switch.
		ContentClassByHost: r.contentClassByHostFromHeuristics(),
		OnTechDetected: func(host, tag string) {
			line := fmt.Sprintf("%s %s %s %s %s %s\n",
				terminal.PhasePrefix(string(PhaseDynamicAssessment)),
				terminal.BoldCyan("[tech-stack-detected]"),
				terminal.HiBlue(host),
				terminal.Muted("→"),
				terminal.Yellow(tag),
				terminal.Muted("(skips incompatible modules unless --no-tech-filter)"))
			r.writeSessionLog(line)
			if !r.options.Silent {
				fmt.Fprint(os.Stderr, line)
			}
		},
		// Phase-level ctx already carries the dynamic-assessment deadline; leaving this at 0
		// prevents each feedback round from starting a fresh per-round timeout.
		MaxDuration:          0,
		ParallelPassive:      daParallelPassive,
		FeedbackDrainTimeout: daFeedbackDrain,
		ActiveModuleTimeout:  daActiveModuleTimeout,
		IPCache:              ipCache,
		OnTraffic:            r.makeOnTrafficVerbose("dynamic-assessment"),
		OnAuthWall:           authWalls.Observe,
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
		OnStatus: func(processed, total, findings, distinctModules, activeCount, passiveCount, timedOut int64, elapsed time.Duration) {
			// CapturedConsole drops the periodic ticker — it's repetitive noise in a
			// captured per-target log file (the -P fan-out's child console.log).
			if r.options.Silent || r.options.CapturedConsole {
				return
			}
			prefix := terminal.Muted(terminal.SymbolChevron + " dynamic-assessment " + terminal.SymbolPipe)
			var recordsStr string
			if total > 0 {
				recordsStr = fmt.Sprintf("%d/%d", processed, total)
			} else {
				recordsStr = fmt.Sprintf("%d", processed)
			}
			totalModules := activeCount + passiveCount
			// timedOut is phase-cumulative (shared across feedback rounds); the
			// helper appends it to the breakdown only when > 0.
			modulesStr := terminal.FormatModuleProgress(distinctModules, totalModules, activeCount, passiveCount, timedOut)
			fmt.Fprintf(os.Stderr, "%s %s Records: %s | Findings: %s | Modules: %s | Runtime: %s\n",
				prefix,
				terminal.BoldCyan("[status]"),
				terminal.HiBlue(recordsStr),
				terminal.Orange(fmt.Sprintf("%d", findings)),
				terminal.Yellow(modulesStr),
				terminal.Gray(fmtDuration(elapsed)))
		},
		StatusInterval: 1 * time.Minute,
	}
	if oastService != nil {
		baseExecutorCfg.OASTProvider = oastService
		baseExecutorCfg.OASTService = oastService
	}
	if infra.hookChain != nil {
		baseExecutorCfg.Hooks = infra.hookChain
	}

	// Continuous scan-on-receive mode: use a polling DBInputSource that waits
	// indefinitely for new records instead of snapshot-based feedback rounds.
	if r.options.ScanOnReceive && !r.options.FullNativeScanOnReceive {
		sorCfg := baseExecutorCfg
		// scan-on-receive scans each ingested request exactly once with no
		// fan-out. Feedback is disabled so passive-module URL discoveries
		// (link extractors, redirect followers) don't persist new work items;
		// RecordWriter is nil so the executor doesn't write scanner-produced
		// rows that would get polled back into the scan. For targeted one-
		// request scans drive /api/scan-request directly.
		sorCfg.DisableFeedback = true
		sorCfg.RecordWriter = nil
		// In server mode the console stays terse (status line at a 2-minute cadence
		// is the only stderr output by default). The same events are always written
		// verbosely to runtime.log so operators can reconstruct activity after the
		// fact — see runner.writeSessionLog.
		// Fire the first status tick at 30s so users see progress quickly when
		// a scan kicks off, then fall back to the 2-minute cadence.
		sorCfg.StatusInterval = 2 * time.Minute
		sorCfg.FirstStatusInterval = 30 * time.Second
		origOnResult := sorCfg.OnResult
		sorCfg.OnTraffic = func(method, url string, statusCode int, contentType string) {
			line := formatTrafficLine("scan-on-receive", method, url, statusCode, contentType)
			r.writeSessionLog(line)
			if !r.options.Silent {
				fmt.Fprint(os.Stderr, line)
			}
		}
		sorCfg.OnResult = func(result *output.ResultEvent) {
			if origOnResult != nil {
				origOnResult(result)
			}
			if result == nil {
				return
			}
			line := fmt.Sprintf("  %s %s [%s] %s — %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan("finding"),
				terminal.Orange(result.Info.Severity.String()),
				terminal.BoldCyan(result.ModuleID),
				terminal.Gray(result.URL))
			r.writeSessionLog(line)
			if !r.options.Silent {
				fmt.Fprint(os.Stderr, line)
			}
		}
		shortScanID := strings.TrimPrefix(infra.scanUUID, "scan-")
		if len(shortScanID) > 8 {
			shortScanID = shortScanID[:8]
		}

		// Threshold for treating a fetch as a "resume from idle" event. Below
		// this, batches are considered back-to-back and we stay silent to avoid
		// spamming the console while the scan is steadily processing.
		const activityIdleThreshold = 5 * time.Second

		// Restrict the DB poller to records that came from user ingestion.
		// Without this, "finding" records persisted by the executor's
		// emitResult (executor.go:1474-1488 — one row per finding with an
		// attached request/response pair) would get polled back into the
		// scan and fan out 1 ingested request → hundreds of re-scanned rows.
		sorSourceFilter := database.IngestRecordSources

		continuousSource := database.NewDBInputSource(r.repository.DB(), r.repository, infra.scanUUID, 2*time.Second).
			WithHostScopes(inScopeHosts).
			WithIncludeSources(sorSourceFilter).
			WithIdleTimeout(r.options.ScanOnReceiveIdleTimeout).
			WithOnActivity(func(records int, idleFor time.Duration, firstBatch bool) {
				// Print a one-line confirmation that the scan is actively processing
				// records. Two cases qualify: the very first batch ever (so the user
				// knows the scan started without waiting for the 2-min status tick),
				// or any batch that arrives after a quiet period.
				if !firstBatch && idleFor < activityIdleThreshold {
					return
				}
				prefix := terminal.Muted(terminal.SymbolChevron + " scan-on-receive " + terminal.SymbolPipe)
				var line string
				if firstBatch {
					line = fmt.Sprintf("%s %s scan-%s picked up %s — scanning started\n",
						prefix,
						terminal.BoldGreen("[start]"),
						shortScanID,
						terminal.HiBlue(fmt.Sprintf("%d record(s)", records)))
				} else {
					line = fmt.Sprintf("%s %s scan-%s picked up %s after %s idle\n",
						prefix,
						terminal.BoldGreen("[resume]"),
						shortScanID,
						terminal.HiBlue(fmt.Sprintf("%d record(s)", records)),
						terminal.Gray(fmtDuration(idleFor)))
				}
				r.writeSessionLog(line)
				// Always surface start/resume to stderr — even in server mode
				// where Silent is true — so the user sees confirmation that an
				// ingested request was picked up for scanning. Without this the
				// ingest HTTP log is the only signal, and the 2-min status tick
				// is too late.
				fmt.Fprint(os.Stderr, line)
			})

		// Forward-declared so OnStatus can query the executor's in-flight counter.
		// Assigned right before Execute() below.
		var sorExecutor *core.Executor

		// Threshold for showing the "idle Ns" suffix in the status line. We only
		// surface idle state once the source has been quiet for at least one poll
		// interval — otherwise the suffix would flicker on/off between ticks.
		const idleDisplayThreshold = 10 * time.Second

		// Tracks the ingested-record count at the previous status tick so we can
		// report the delta ("new ingested records" since last line). Accessed
		// only from the ticker goroutine, so no locking needed.
		var prevIngestedCount int64 = -1

		sorCfg.OnStatus = func(processed, total, findings, distinctModules, activeCount, passiveCount, timedOut int64, elapsed time.Duration) {
			// Use the phase context (captured from the enclosing function) so
			// these periodic status DB reads stop once the scan is cancelled
			// rather than outliving it on a detached context.Background().

			// Count HTTP records ingested since the scan started, scoped to the
			// in-scope hostnames if any were configured. Cheap enough at a
			// 2-minute cadence. Uses scan.StartedAt as the cursor reference.
			var ingestedCount int64 = -1
			var scanRow *database.Scan
			if r.repository != nil {
				if s, err := r.repository.GetScanByUUID(ctx, infra.scanUUID); err == nil && s != nil {
					scanRow = s
					// Count only user-ingested records so the "new ingested
					// records" counter matches what the DB poller will
					// actually scan (see sorSourceFilter above).
					if cnt, cErr := r.repository.CountRecordsAfterCursorBySource(ctx, r.options.ProjectUUID, s.StartedAt, "", sorSourceFilter, inScopeHosts); cErr == nil {
						ingestedCount = cnt
					}
				}
			}

			// Processed Records: X / Y (new ingested records: Z)
			//   X = records the executor has finished scanning
			//   Y = total records this scan has ever seen (ingested so far)
			//   Z = records that arrived since the previous status tick
			totalModules := activeCount + passiveCount
			var recordsStr string
			if ingestedCount >= 0 {
				delta := ingestedCount
				if prevIngestedCount >= 0 {
					delta = ingestedCount - prevIngestedCount
					if delta < 0 {
						delta = 0
					}
				}
				recordsStr = fmt.Sprintf("%d / %d (new ingested records: %d)",
					processed, ingestedCount, delta)
				prevIngestedCount = ingestedCount
			} else {
				recordsStr = fmt.Sprintf("%d", processed)
			}

			// Modules: <scanned> / <total> — how many enabled modules have been
			// evaluated against any record so far, out of the full set. Counts
			// both modules that ran AND modules whose CanProcess rejected the
			// input shape (e.g., POST-only modules on a GET request) — so the
			// counter can reach parity with the total once every module has been
			// seen, instead of stalling on the "always-rejected" set forever.
			scannedModules := distinctModules
			if sorExecutor != nil {
				scannedModules = sorExecutor.ConsideredModuleCount()
			}
			modulesStr := terminal.FormatModuleCount(scannedModules, totalModules, timedOut)

			// Optional suffix: when no workers are in-flight and the source has
			// been quiet for a while, surface "idle <duration>" so the user knows
			// the scan is alive but waiting for new ingested records.
			var idleSuffix string
			inFlight := int64(0)
			if sorExecutor != nil {
				inFlight = sorExecutor.InFlight()
			}
			if inFlight == 0 {
				if idleFor := continuousSource.IdleFor(); idleFor >= idleDisplayThreshold {
					idleSuffix = " | " + terminal.Muted(fmt.Sprintf("idle %s", fmtDuration(idleFor)))
				}
			}

			prefix := terminal.Muted(terminal.SymbolChevron + " scan-on-receive " + terminal.SymbolPipe)
			fmt.Fprintf(os.Stderr, "%s %s %s Processed Records: %s | Findings: %s | Modules: %s | Runtime: %s%s\n",
				prefix,
				terminal.BoldCyan("[status]"),
				terminal.Cyan("scan-"+shortScanID),
				terminal.HiBlue(recordsStr),
				terminal.Orange(fmt.Sprintf("%d", findings)),
				terminal.Yellow(modulesStr),
				terminal.Gray(fmtDuration(elapsed)),
				idleSuffix)
			if r.repository != nil && scanRow != nil {
				_ = r.repository.RefreshScanStats(ctx, infra.scanUUID)
			}
		}

		sorExecutor = core.NewExecutor(sorCfg, continuousSource, activeModules, passiveModules)
		executor := sorExecutor
		if oastService != nil {
			oastService.SetRequestUUIDResolver(executor.ResolveRequestUUID)
		}
		_, err := executor.Execute(ctx)
		r.currentPhase.Load().noteExecution(executor.Report())
		if metrics := executor.ModuleMetrics(); len(metrics) > 0 {
			logModuleMetrics(metrics)
		}
		if err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	}

	// Stream findings to stderr as they're discovered so the phase shows live
	// results even when the stdout result stream is deferred to files (jsonl/
	// html) — otherwise only the periodic status heartbeat moves. No-op in
	// console mode (findings already print to stdout) or when silent, so the
	// wrap is installed only when stdout won't show them. Repeated-value findings
	// (one secret across many URLs) collapse to a single line via the same
	// grouper the post-phase dedup uses; the grouper persists across feedback
	// rounds so cross-round repeats also collapse.
	if !r.findingsVisibleOnStdout() {
		liveGrouper := newFindingGrouper(r.resolveFindingGrouping())
		baseOnResult := baseExecutorCfg.OnResult
		baseExecutorCfg.OnResult = func(result *output.ResultEvent) {
			if baseOnResult != nil {
				baseOnResult(result)
			}
			if result != nil && liveGrouper.observe(result) {
				r.echoLiveFinding("dynamic-assessment", result)
			}
		}
	}

	// Feedback loop: re-scan newly discovered URLs.
	//
	// roundsRun / roundErr / deadlineHit record HOW the loop ended, because the
	// completion line used to claim "all rounds completed" on every exit path
	// including a round that errored out — the one case where it was certainly
	// false. roundErr is returned at the end rather than swallowed: a round that
	// failed is a failed phase, and the scan continues past it exactly as it does
	// past any other non-fatal phase error.
	var (
		roundsRun   int
		roundErr    error
		deadlineHit bool
	)
	for round := 0; round < feedbackRounds; round++ {
		res, err := r.runDynamicAssessmentRound(ctx, infra, round, inScopeHosts, activeModules, passiveModules, baseExecutorCfg, oastService)
		roundsRun = round + 1
		if err != nil {
			zap.L().Error("DynamicAssessment: executor error", zap.Error(err), zap.Int("round", round))
			roundErr = err
			break
		}
		// A checkpoint that did not land means the next round would re-read the
		// same resume cursor and re-serve the records this one just scanned. Stop
		// instead of burning the remaining rounds on repeated work; the phase is
		// already marked partial, so the shortfall is reported rather than hidden.
		if res.checkpointFailed {
			break
		}
		processed := res.processed

		// Deduplicate findings after each dynamic-assessment round, scoped to the
		// hosts being scanned. DA runs before known-issue-scan and only scans
		// in-scope hosts, so every finding present now is on one of these hosts —
		// host-scoping is coverage-equivalent here but avoids re-scanning the whole
		// project's findings table each round. Empty inScopeHostnames (no targets/
		// scope) falls back to a project-wide pass.
		r.deduplicateFindings(ctx, "DynamicAssessment", inScopeHostnames...)

		if ctx.Err() != nil {
			zap.L().Info("DynamicAssessment: phase deadline reached, stopping feedback loop",
				zap.Int("round", round+1), zap.Error(ctx.Err()))
			deadlineHit = true
			break
		}

		if round < feedbackRounds-1 {
			newCount, countErr := r.countRemainingDynamicAssessmentRecords(ctx, infra.scanUUID, inScopeHosts)
			if countErr != nil || newCount == 0 {
				if countErr != nil {
					zap.L().Debug("DynamicAssessment: failed to count remaining records", zap.Error(countErr))
				}
				break
			}
			r.printPhaseFeedback("DynamicAssessment",
				fmt.Sprintf("%s new records discovered, starting round %d", terminal.Orange(fmt.Sprintf("%d", newCount)), round+2))
			zap.L().Info("DynamicAssessment: new records discovered, starting next round",
				zap.Int64("new_records", newCount))
		}

		if processed == 0 {
			break
		}

		if round == feedbackRounds-1 {
			newCount, countErr := r.countRemainingDynamicAssessmentRecords(ctx, infra.scanUUID, inScopeHosts)
			if countErr == nil && newCount > 0 {
				fmt.Fprintf(os.Stderr, "  %s %s %s\n",
					terminal.TipPrefix(), terminal.Orange(fmt.Sprintf("%d", newCount)), terminal.Gray(fmt.Sprintf("new records discovered but skipped (max_feedback_rounds=%d)", feedbackRounds)))
				fmt.Fprintf(os.Stderr, "  %s %s %s\n",
					terminal.TipPrefix(), terminal.Gray("enable multi-round scanning via"), terminal.Cyan("vigolium config dynamic-assessment.max_feedback_rounds=3"))
			}
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("DynamicAssessment", dynamicAssessmentExitLine(roundsRun, elapsed, roundErr, deadlineHit))
	r.reportAuthWalls("DynamicAssessment", authWalls)

	if roundErr != nil {
		r.currentPhase.Load().markPartial(database.ReasonRoundError)
		return fmt.Errorf("dynamic-assessment round %d: %w", roundsRun, roundErr)
	}
	return nil
}

// dynamicAssessmentExitLine describes how the feedback loop actually ended.
//
// It used to print "all rounds completed in …" unconditionally — on a round that
// errored, on a phase cut off at its deadline, and on a loop that stopped early
// because there was nothing left to scan. Three of the four cases were false, and
// the one an operator most needs to see (a failed round) was the most misleading.
func dynamicAssessmentExitLine(rounds int, elapsed time.Duration, roundErr error, deadlineHit bool) string {
	d := terminal.HiPurple(fmtDuration(elapsed))
	switch {
	case roundErr != nil:
		return fmt.Sprintf("stopped after round %d error in %s", rounds, d)
	case deadlineHit:
		return fmt.Sprintf("stopped at phase deadline after %d round(s) in %s", rounds, d)
	default:
		return fmt.Sprintf("completed %d round(s) in %s", rounds, d)
	}
}

func (r *Runner) runDynamicAssessmentRound(
	ctx context.Context,
	infra *phaseInfra,
	round int,
	inScopeHosts []database.HostTarget,
	activeModules []modules.ActiveModule,
	passiveModules []modules.PassiveModule,
	baseCfg core.ExecutorConfig,
	oastService *oast.Service,
) (daRoundResult, error) {
	var res daRoundResult
	roundStart := time.Now()
	dbSource := database.NewRiskPrioritizedDBInputSource(r.repository.DB(), r.repository, infra.scanUUID).
		WithHostScopes(inScopeHosts).
		WithParamShapeCoalescing(r.resolveMaxParamShapeSamples())

	executor := core.NewExecutor(baseCfg, dbSource, activeModules, passiveModules)
	if oastService != nil {
		oastService.SetRequestUUIDResolver(executor.ResolveRequestUUID)
	}
	_, err := executor.Execute(ctx)
	tracker := r.currentPhase.Load()
	tracker.noteExecution(executor.Report())

	// Checkpoint the round's cursor, with a reported result.
	//
	// On a detached context with its own short budget: ctx is already expired on
	// the path that most needs this (a phase deadline, a Ctrl-C), and a checkpoint
	// that cannot be written is exactly the condition this exists to surface, so
	// running it on the dead context would guarantee the failure it is testing
	// for. WithoutCancel keeps the request values and drops the cancellation.
	flushCtx, flushCancel := context.WithTimeout(context.WithoutCancel(ctx), cursorFlushBudget)
	flushErr := dbSource.FlushCursor(flushCtx)
	flushCancel()
	if flushErr != nil {
		// The round's work is done but the cursor does not know it. Reporting the
		// phase as partial is what keeps the scan row from reading as a clean
		// predecessor — a later scan-on-receive run inherits a completed scan's
		// cursor, so a lying checkpoint under a clean verdict is how records get
		// skipped permanently rather than merely re-scanned.
		zap.L().Error("DynamicAssessment: failed to checkpoint the scan cursor; the round's records may be re-served",
			zap.Int("round", round+1), zap.Error(flushErr))
		r.scanLogger.Error("dynamic-assessment",
			fmt.Sprintf("round %d: scan cursor checkpoint failed: %s", round+1, flushErr))
		tracker.markPartial(database.ReasonCheckpointFailed)
		res.checkpointFailed = true
	}
	if unresolved := dbSource.Unresolved(); unresolved > 0 {
		zap.L().Warn("DynamicAssessment: round ended with records still unresolved; they stay behind the cursor and will be re-served",
			zap.Int("round", round+1), zap.Int("unresolved", unresolved))
	}

	if metrics := executor.ModuleMetrics(); len(metrics) > 0 {
		logModuleMetrics(metrics)
	}
	if c := infra.httpRequester.Clusterer(); c != nil {
		c.LogStats()
	}
	infra.httpRequester.LogPoolStats()
	if err != nil {
		return res, err
	}

	processed := executor.Processed()
	res.processed = processed
	roundElapsed := time.Since(roundStart)
	// Surface how many redundant value-only-different records the param-shape
	// coalescing skipped this round, so the reduced item count isn't mistaken
	// for missing coverage (no silent caps).
	if dropped := dbSource.CoalescedDropped(); dropped > 0 {
		r.printPhaseFeedback("DynamicAssessment", fmt.Sprintf("coalesced %s same-shape records (kept up to %s value-distinct samples per endpoint shape: query, form, or JSON params)",
			terminal.Orange(fmt.Sprintf("%d", dropped)),
			terminal.Orange(fmt.Sprintf("%d", r.resolveMaxParamShapeSamples()))))
		r.scanLogger.Info("DynamicAssessment", fmt.Sprintf("param-shape coalescing skipped %d redundant records", dropped))
	}
	r.printPhaseComplete("DynamicAssessment",
		fmt.Sprintf("round %d — %s items in %s", round+1, terminal.Orange(fmt.Sprintf("%d", processed)), terminal.HiPurple(fmtDuration(roundElapsed))))
	fields := []zap.Field{
		zap.Int("round", round+1),
		zap.Int64("processed", processed),
	}
	// Surface how many candidate findings the body-differential safety net
	// dropped, so a quiet target is distinguishable from a confirmed-clean one.
	if suppressed := executor.SuppressedFindings(); suppressed > 0 {
		fields = append(fields, zap.Int64("findings_dropped_unconfirmed", suppressed))
	}
	zap.L().Info("DynamicAssessment: round completed", fields...)
	return res, nil
}

// daRoundResult is what one dynamic-assessment feedback round reports back to the
// loop that drives it.
//
// checkpointFailed is here rather than folded into the returned error because the
// two mean different things to the caller: an error ends the phase, while a
// failed checkpoint means the round's WORK succeeded and only its bookkeeping
// did not. The loop must stop either way — a cursor that did not advance makes
// the next round re-serve the same records forever — but a scan that produced
// findings should not be reported as a failed phase because one UPDATE lost a
// race with a locked database.
type daRoundResult struct {
	processed        int64
	checkpointFailed bool
}

func (r *Runner) countRemainingDynamicAssessmentRecords(ctx context.Context, scanUUID string, hosts []database.HostTarget) (int64, error) {
	currentScan, err := r.repository.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		return 0, err
	}
	return r.repository.CountRecordsAfterCursor(ctx, r.options.ProjectUUID, currentScan.CursorAt, currentScan.CursorUUID, hosts...)
}

// waitForNewRecords polls until at least one record exists after the scan cursor,
// or the context is cancelled. Used by full-native-scan-on-receive to block between iterations.
func (r *Runner) waitForNewRecords(ctx context.Context, scanUUID string, pollInterval time.Duration) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		count, err := r.countRemainingDynamicAssessmentRecords(ctx, scanUUID, nil)
		if err != nil {
			zap.L().Debug("waitForNewRecords: query error", zap.Error(err))
		}
		if count > 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// runKnownIssueScan executes known issue scanning using the nuclei Go library.
// inScopeHosts restricts targets to the current scan's in-scope origins (scheme/host/port;
// empty = project-wide pass, mirroring DynamicAssessment), so records left in the project
// by prior scans of other origins don't leak into this scan's targets.
func (r *Runner) runKnownIssueScan(ctx context.Context, infra *phaseInfra, onResult func(*output.ResultEvent), inScopeHosts []database.HostTarget) error {
	if r.repository == nil {
		return fmt.Errorf("known-issue-scan: database repository required")
	}

	// Query distinct paths from DB (scoped to in-scope origins) and build targets
	paths, err := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID, inScopeHosts...)
	if err != nil {
		return fmt.Errorf("known-issue-scan: failed to query paths: %w", err)
	}
	if len(paths) == 0 {
		zap.L().Info("KnownIssueScan: no hosts in database, skipping")
		return nil
	}

	enrichTargets := true
	if r.settings != nil {
		enrichTargets = r.settings.KnownIssueScan.EnrichTargets
	}

	var targets []string
	if enrichTargets {
		targets = buildKnownIssueScanTargetsFromPaths(paths)
	} else {
		targets = buildKnownIssueScanHostTargets(paths)
	}

	zap.L().Info("KnownIssueScan: targets from database",
		zap.Int("count", len(targets)),
		zap.Int("in_scope_origins", len(inScopeHosts)))

	// Build KnownIssueScan config from settings
	cfg := knownissuescan.Config{
		Targets:     targets,
		Concurrency: r.options.Concurrency,
		ScanUUID:    r.options.ScanUUID,
		ProjectUUID: r.options.ProjectUUID,
		ProxyURL:    r.options.ProxyURL,
		// nuclei runs its own HTTP stack, so it cannot use the assessment
		// requester's view — it needs the headers themselves. Under
		// use_in_discovery: false this is the only way the primary session
		// reaches this phase; it previously ran unauthenticated.
		Headers:    r.assessmentHeaderSlice(infra),
		OnResult:   onResult,
		Repository: r.repository,
		// nuclei owns its own HTTP stack, so it cannot page through the shared
		// requester. These hooks give it the next best thing: the shared
		// requester's block detection and the limiter's per-host verdict, so this
		// phase stops being the one active phase that can neither slow down nor
		// say that it was blocked.
		Edge: r.knownIssueScanEdge(infra),
	}

	// Apply YAML settings
	if r.settings != nil {
		knownIssueScanCfg := &r.settings.KnownIssueScan
		cfg.Tags = knownIssueScanCfg.Tags
		cfg.ExcludeTags = knownIssueScanCfg.ExcludeTags
		cfg.Severities = knownIssueScanCfg.Severities
		cfg.SeverityOverrides = knownIssueScanCfg.SeverityOverrides
		if knownIssueScanCfg.TemplatesDir != "" {
			cfg.TemplatesDir = config.ExpandPath(knownIssueScanCfg.TemplatesDir)
		}

		// scanning_pace.known-issue-scan controls speed
		knownIssueScanPace := r.settings.ScanningPace.ResolvePhase("known-issue-scan")
		cfg.Concurrency = r.phaseConcurrency("known-issue-scan")
		if knownIssueScanPace.RateLimit > 0 {
			cfg.RateLimit = knownIssueScanPace.RateLimit
		}
		if knownIssueScanPace.MaxDuration > 0 {
			cfg.Timeout = knownIssueScanPace.MaxDuration
		}
	}

	return knownissuescan.Run(ctx, cfg)
}

// runExternalHarvestPhase runs external intelligence harvesting as a standalone phase.
// Harvested URLs are ingested into the httpRecords table via an Executor with zero modules.
func (r *Runner) runExternalHarvestPhase(ctx context.Context, infra *phaseInfra) error {
	if len(r.options.Targets) == 0 {
		return nil
	}

	phaseStart := time.Now()

	src := r.buildExternalHarvesterSource()
	if src == nil {
		zap.L().Warn("ExternalHarvest: no source could be built, skipping")
		return nil
	}

	r.printPhaseStart("ExternalHarvest", "harvest URLs from external intelligence sources")

	ehSpeedDetail := fmt.Sprintf("Speed: concurrency=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.options.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", r.options.MaxPerHost)))
	if budget := PhaseSpeedDetail(r.settings, "external_harvester", 0); budget != "" {
		ehSpeedDetail += ", " + budget
	}
	r.printPhaseDetail(ehSpeedDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	r.printVerboseTargets(r.options.Targets)

	zap.L().Info("ExternalHarvest: ingesting harvested URLs into database")

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		ScanUUID:      infra.scanUUID,
		ProjectUUID:   r.options.ProjectUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("harvest"),
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	executor := core.NewExecutor(executorCfg, src, nil, nil)
	_, err := executor.Execute(ctx)
	r.currentPhase.Load().noteExecution(executor.Report())
	if err != nil {
		return err
	}

	// Increment processed_count for external harvest phase
	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("ExternalHarvest: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("ExternalHarvest", fmt.Sprintf("completed — %s items ingested in %s",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed())), terminal.HiPurple(fmtDuration(elapsed))))
	zap.L().Info("ExternalHarvest: completed", zap.Int64("processed", executor.Processed()))
	return nil
}
