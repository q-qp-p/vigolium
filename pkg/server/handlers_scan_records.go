package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// maxSelectiveScanRecords caps the record_uuids list POST /api/scan-records
// accepts. The list was previously bounded only by the request body limit,
// which at 4 MB is roughly 100k UUIDs — every one of which becomes an entry in
// an IN (...) predicate and then a resident element of the scan's input source,
// held for the run's whole duration. A selection larger than this is not a
// selection; it wants /api/scan-all-records with filters.
const maxSelectiveScanRecords = 10000

// projectScanRunning reports whether the project already has a scan running.
//
// It is an early-out, not the admission decision — that is still made under
// scanMu alongside the runner build, as in HandleStartScan. It exists only for
// the filter path, where losing the race after enumerating every matching
// record UUID would mean paying for a corpus-sized query to learn something a
// map lookup answers.
func (h *Handlers) projectScanRunning(projectUUID string) bool {
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	return h.getProjectScanState(projectUUID).running
}

// newSelectiveScanRecord builds the scan row for POST /api/scan-records. It is
// created already "running": the row is only persisted once admission has been
// won, so there is no window in which "pending" would be the truth.
func newSelectiveScanRecord(scanID, projectUUID string, modules []string) *database.Scan {
	return &database.Scan{
		UUID:        scanID,
		ProjectUUID: projectUUID,
		Name:        "selective-scan",
		Status:      "running",
		Modules:     strings.Join(modules, ","),
		ScanSource:  "api",
		ScanMode:    "selective",
		StartedAt:   time.Now(),
	}
}

// HandleScanRecords handles POST /api/scan-records — starts a scan on specific HTTP records by UUID.
func (h *Handlers) HandleScanRecords(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	var req ScanRecordsRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if len(req.RecordUUIDs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrMissingRecordUUIDs.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}
	if len(req.RecordUUIDs) > maxSelectiveScanRecords {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: fmt.Sprintf("too many record_uuids: %d exceeds the limit of %d",
				len(req.RecordUUIDs), maxSelectiveScanRecords),
			Code: fiber.StatusBadRequest,
		})
	}

	// Detached on purpose: registers a scan that runs in a background goroutine
	// below, so the record must outlive this request rather than cancel with it.
	ctx := context.Background()
	projectUUID := getProjectUUID(c)

	// Validate UUIDs exist in DB, scoped to the request's project. Only the
	// UUIDs are needed here — the scan feed re-fetches each record's content
	// itself (NewUUIDListDBInputSource below) — and RecordUUIDs is a
	// caller-supplied list, so this must not load whole records.
	validUUIDs, err := h.repo.ExistingRecordUUIDs(c.Context(), projectUUID, req.RecordUUIDs)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to validate record UUIDs: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}
	if len(validUUIDs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrNoValidRecords.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	modules := []string{"all"}
	if len(req.EnableModules) > 0 {
		modules = req.EnableModules
	}

	// Build runner options
	scanID := uuid.New().String()
	opts := types.DefaultOptions()
	// Must match the Scan row created below: the record feed resolves its
	// project from that row, so an unset value here has the executor writing
	// findings to the default project while the feed reads this one.
	opts.ProjectUUID = projectUUID
	concurrency := h.config.Concurrency
	if concurrency <= 0 {
		concurrency = types.DefaultConcurrency
	}
	opts.Concurrency = concurrency
	opts.Modules = modules

	dbSource := database.NewUUIDListDBInputSource(h.repo, validUUIDs)

	// Admission before heavyweight allocation, as in HandleStartScan: decide
	// the outcome under the lock, and only then build a runner and persist the
	// record — already "running", so there is no pending state to repair. A
	// rejected request leaves no row and no leaked runner, which is what the
	// old check-after-create ordering could not promise.
	h.scanMu.Lock()
	st := h.getProjectScanState(projectUUID)
	if st.running {
		h.scanMu.Unlock()
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
			Error: ErrScanAlreadyRunning.Error(),
		})
	}

	scanRunner, err := runner.NewWithInputSource(opts, dbSource)
	if err != nil {
		h.scanMu.Unlock()
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create scan runner: " + err.Error(),
		})
	}
	scanRunner.SetSettings(forceNativePersistLogs(h.settings))
	scanRunner.SetRepository(h.repo)

	if err := h.repo.CreateScan(ctx, newSelectiveScanRecord(scanID, projectUUID, modules)); err != nil {
		h.scanMu.Unlock()
		scanRunner.Discard()
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create scan: " + err.Error(),
		})
	}

	st.runner = scanRunner
	st.running = true
	st.scanID = scanID
	h.scanMu.Unlock()

	// Launch background scan
	go h.runBackgroundScan(scanID, scanRunner, projectUUID, false)

	zap.L().Info("Selective scan started",
		zap.String("scan_uuid", scanID),
		zap.Int("record_count", len(validUUIDs)))

	return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
		ProjectUUID:   projectUUID,
		ScanUUID:      scanID,
		Status:        "running",
		Message:       "selective scan started",
		RecordsToScan: int64(len(validUUIDs)),
	})
}

// validateScanAllRecordsRequest validates the ScanAllRecordsRequest fields.
func validateScanAllRecordsRequest(req ScanAllRecordsRequest) error {
	if req.Timeout != "" {
		if _, err := time.ParseDuration(req.Timeout); err != nil {
			return fmt.Errorf("invalid timeout %q: %w", req.Timeout, err)
		}
	}
	if req.ScanningMaxDuration != "" {
		if _, err := time.ParseDuration(req.ScanningMaxDuration); err != nil {
			return fmt.Errorf("invalid scanning_max_duration %q: %w", req.ScanningMaxDuration, err)
		}
	}
	if req.HeuristicsCheck != "" {
		switch req.HeuristicsCheck {
		case "none", "basic", "advanced":
		default:
			return fmt.Errorf("invalid heuristics_check %q; valid values: none, basic, advanced", req.HeuristicsCheck)
		}
	}
	if req.Concurrency < 0 {
		return fmt.Errorf("concurrency must be > 0")
	}
	if req.MaxPerHost < 0 {
		return fmt.Errorf("max_per_host must be > 0")
	}
	return nil
}

// newAllRecordsScanRecord builds the scan row for POST /api/scan-all-records.
// Both the dry run and the real run go through it so the two branches of one
// endpoint cannot disagree about the row they describe; status is the only
// thing that differs.
func newAllRecordsScanRecord(scanID, projectUUID, scanMode, status string, modules []string) *database.Scan {
	return &database.Scan{
		UUID:        scanID,
		ProjectUUID: projectUUID,
		Name:        "all-records-scan",
		Status:      status,
		Modules:     strings.Join(modules, ","),
		ScanSource:  "api",
		ScanMode:    scanMode,
		StartedAt:   time.Now(),
	}
}

// respondScanAllRecordsDryRun records and returns the planning-only result of a
// scan-all-records request. It writes the same "dry_run" scan row and the same
// ScanResponse shape the non-dry path used to produce, so a caller sees no
// difference; only the way records_to_scan is obtained changed, from
// enumerating every matching UUID to counting them.
func (h *Handlers) respondScanAllRecordsDryRun(c fiber.Ctx, projectUUID, scanMode string, modules []string, matchCount int64) error {
	scanID := uuid.New().String()
	// Detached on purpose: the row outlives this request as scan history.
	if err := h.repo.CreateScan(context.Background(),
		newAllRecordsScanRecord(scanID, projectUUID, scanMode, "dry_run", modules)); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.Status(fiber.StatusOK).JSON(ScanResponse{
		ProjectUUID:   projectUUID,
		ScanUUID:      scanID,
		Status:        "dry_run",
		Message:       "scan record created (dry run)",
		RecordsToScan: matchCount,
		ScanMode:      scanMode,
	})
}

// HandleScanAllRecords handles POST /api/scan-all-records — scans existing HTTP records
// from the database with optional filtering by hostname, method, path, status code, etc.
func (h *Handlers) HandleScanAllRecords(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	// Parse request body (allow empty body → scan all records)
	var req ScanAllRecordsRequest
	if len(c.Body()) > 0 {
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: "invalid request body: " + err.Error(),
				Code:  fiber.StatusBadRequest,
			})
		}
	}

	if err := validateScanAllRecordsRequest(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	projectUUID := getProjectUUID(c)

	// Both branches below describe the same run, so derive these once.
	modules := resolveAPIModules(req.Modules, req.ModuleTags)
	scanMode := "full"
	if !req.Force {
		scanMode = "incremental"
	}

	// Early-out before the matching query: it enumerates every matching UUID,
	// so running it only to answer 409 would make a rejection cost proportional
	// to the corpus. The authoritative admission check is still under scanMu
	// below. Skipped for a dry run, which starts nothing and so conflicts with
	// nothing.
	if !req.DryRun && h.projectScanRunning(projectUUID) {
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
			Error: ErrScanAlreadyRunning.Error(),
		})
	}

	// Build query filters from request
	filters := database.QueryFilters{
		ProjectUUID:     projectUUID,
		HostPattern:     req.Hostname,
		Methods:         req.Methods,
		PathPattern:     req.Path,
		StatusCodes:     req.StatusCodes,
		Source:          req.Source,
		SearchTerm:      req.Search,
		MinRiskScore:    req.MinRiskScore,
		MinSurfaceScore: req.MinSurfaceScore,
		Remark:          req.Remark,
	}

	qb := database.NewQueryBuilder(h.db, filters)
	ctx := c.Context()

	// A dry run reports how many records the filters match and starts nothing,
	// so it counts instead of materializing every UUID — the enumeration was
	// pure waste on the one path guaranteed never to consume it, and on a large
	// corpus it is the difference between a COUNT and a multi-million-element
	// []string held for the length of the request.
	if req.DryRun {
		matchCount, err := qb.Count(ctx)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Error: "failed to query records: " + err.Error(),
				Code:  fiber.StatusInternalServerError,
			})
		}
		if matchCount == 0 {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: "no records match the specified filters",
				Code:  fiber.StatusBadRequest,
			})
		}
		return h.respondScanAllRecordsDryRun(c, projectUUID, scanMode, modules, matchCount)
	}

	var matchingUUIDs []string
	if err := qb.BuildRecordsQuery().Column("r.uuid").Scan(ctx, &matchingUUIDs); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to query records: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	if len(matchingUUIDs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "no records match the specified filters",
			Code:  fiber.StatusBadRequest,
		})
	}

	// Build runner options
	opts := types.DefaultOptions()
	opts.Modules = modules
	opts.ProjectUUID = projectUUID
	opts.SkipIngestion = true
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.SpideringEnabled = false
	opts.KnownIssueScanEnabled = false
	opts.SkipDynamicAssessment = false

	concurrency := h.config.Concurrency
	if concurrency <= 0 {
		concurrency = types.DefaultConcurrency
	}
	if req.Concurrency > 0 {
		concurrency = req.Concurrency
	}
	opts.Concurrency = concurrency

	if req.MaxPerHost > 0 {
		opts.MaxPerHost = req.MaxPerHost
	}

	if req.Timeout != "" {
		d, _ := time.ParseDuration(req.Timeout) // already validated
		opts.Timeout = d
	}

	if len(req.Headers) > 0 {
		headers := make([]string, 0, len(req.Headers))
		for k, v := range req.Headers {
			headers = append(headers, k+": "+v)
		}
		opts.Headers = headers
	}

	// Resolve intensity to scanning profile
	if req.Intensity != "" {
		if profileName, resolvedIntensity, err := agent.ResolveNativeScanIntensity(req.Intensity); err == nil {
			opts.Intensity = resolvedIntensity
			if req.ScanningProfile == "" {
				req.ScanningProfile = profileName
			}
		}
	}

	if req.ScanningProfile != "" {
		opts.ScanningProfile = req.ScanningProfile
	}

	// Clone settings
	var settings *config.Settings
	if h.settings != nil {
		clone := *h.settings
		settings = &clone
	} else {
		settings = config.DefaultSettings()
	}

	// Load and apply scanning profile to settings
	if opts.ScanningProfile != "" {
		profilePath := settings.ScanningStrategy.ResolveProfilePath(opts.ScanningProfile)
		if profile, profileErr := config.LoadProfile(profilePath); profileErr == nil {
			_ = config.ApplyProfile(settings, profile)
		}
	}

	if req.HeuristicsCheck != "" {
		opts.HeuristicsCheck = req.HeuristicsCheck
	}
	if req.ScanningMaxDuration != "" {
		settings.ScanningPace.MaxDuration = req.ScanningMaxDuration
	}
	applyRequestRateLimit(opts, &settings.ScanningPace, req.RateLimit)

	// Resolve per-phase durations from scanning_pace (mirrors CLI behavior in scan.go)
	applyResolvedPhaseDurations(opts, &settings.ScanningPace)

	scanID := uuid.New().String()
	dbSource := database.NewUUIDListDBInputSource(h.repo, matchingUUIDs)

	// Admission before heavyweight allocation, as in HandleStartScan: decide
	// the outcome under the lock, and only then build a runner and persist the
	// record — already "running", so there is no pending state to repair. The
	// early-out above has already handled the ordinary conflict; this closes
	// the race, and leaves nothing behind when it loses.
	h.scanMu.Lock()
	st := h.getProjectScanState(projectUUID)
	if st.running {
		h.scanMu.Unlock()
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
			Error: ErrScanAlreadyRunning.Error(),
		})
	}

	scanRunner, err := runner.NewWithInputSource(opts, dbSource)
	if err != nil {
		h.scanMu.Unlock()
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create scan runner: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}
	scanRunner.SetSettings(forceNativePersistLogs(settings))
	scanRunner.SetRepository(h.repo)

	// Detached on purpose: the row outlives this request as scan history.
	if err := h.repo.CreateScan(context.Background(),
		newAllRecordsScanRecord(scanID, projectUUID, scanMode, "running", modules)); err != nil {
		h.scanMu.Unlock()
		scanRunner.Discard()
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	st.runner = scanRunner
	st.running = true
	st.scanID = scanID
	h.scanMu.Unlock()

	go h.runBackgroundScan(scanID, scanRunner, projectUUID, false)

	zap.L().Info("All-records scan started",
		zap.String("scan_uuid", scanID),
		zap.Int("record_count", len(matchingUUIDs)),
		zap.String("scan_mode", scanMode))

	return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
		ProjectUUID:   projectUUID,
		ScanUUID:      scanID,
		Status:        "running",
		Message:       "all-records scan started",
		RecordsToScan: int64(len(matchingUUIDs)),
		ScanMode:      scanMode,
	})
}
