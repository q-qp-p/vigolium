package database

import (
	"context"
	"reflect"
	"testing"
)

// TestCompleteScanWithOutcome_RoundTrip pins the persisted shape: the verdict,
// the reason and the per-phase detail all survive a write/read cycle, and the
// status vocabulary is untouched so existing consumers keep working.
func TestCompleteScanWithOutcome_RoundTrip(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	completion := ScanCompletion{
		Completeness: CompletenessPartial,
		StopReason:   ReasonScanBudget,
		Phases: []PhaseOutcome{
			{
				Phase:      "discovery",
				State:      PhasePartial,
				Reasons:    []string{ReasonTargetsFailed},
				Limits:     []string{LimitTargetBudget},
				Errors:     2,
				Message:    "dial tcp: no such host",
				DurationMS: 1234,
				Persistence: &PersistenceOutcome{
					Writer: PersistenceWriterRecords, Accepted: 10, Committed: 8, Failed: 2,
				},
			},
			{
				Phase:       "dynamic-assessment",
				State:       PhaseSkipped,
				Reasons:     []string{ReasonScanBudget},
				Unprocessed: 7,
			},
		},
	}
	if err := repo.CompleteScanWithOutcome(ctx, scanUUID, "", completion); err != nil {
		t.Fatalf("CompleteScanWithOutcome: %v", err)
	}

	scan, err := repo.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		t.Fatalf("GetScanByUUID: %v", err)
	}
	if scan.Status != "completed" {
		t.Errorf("Status = %q — completeness is a second axis and must not change it", scan.Status)
	}
	if scan.Completeness != CompletenessPartial {
		t.Errorf("Completeness = %q, want %q", scan.Completeness, CompletenessPartial)
	}
	if scan.StopReason != ReasonScanBudget {
		t.Errorf("StopReason = %q, want %q", scan.StopReason, ReasonScanBudget)
	}
	if len(scan.PhaseOutcomes) != 2 {
		t.Fatalf("PhaseOutcomes = %d, want 2: %+v", len(scan.PhaseOutcomes), scan.PhaseOutcomes)
	}

	got := scan.PhaseOutcomes[0]
	if got.Phase != "discovery" || got.State != PhasePartial {
		t.Errorf("phase 0 = %+v", got)
	}
	if !reflect.DeepEqual(got.Reasons, []string{ReasonTargetsFailed}) {
		t.Errorf("phase 0 Reasons = %v", got.Reasons)
	}
	if !reflect.DeepEqual(got.Limits, []string{LimitTargetBudget}) {
		t.Errorf("phase 0 Limits = %v", got.Limits)
	}
	if got.Errors != 2 || got.Message != "dial tcp: no such host" || got.DurationMS != 1234 {
		t.Errorf("phase 0 scalars lost: %+v", got)
	}
	if got.Persistence == nil || got.Persistence.Failed != 2 || got.Persistence.Writer != PersistenceWriterRecords {
		t.Errorf("phase 0 Persistence = %+v", got.Persistence)
	}
	if scan.PhaseOutcomes[1].Unprocessed != 7 {
		t.Errorf("phase 1 Unprocessed = %d, want 7", scan.PhaseOutcomes[1].Unprocessed)
	}
}

// TestCompleteScanLeavesCompletenessUnknown: a caller with no outcome data (the
// server's finalization paths, an agent rescan) must record "unknown" rather
// than assert a coverage verdict. Empty is unknown, and must never be read as
// complete — an older binary's rows look exactly the same.
func TestCompleteScanLeavesCompletenessUnknown(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	if err := repo.CompleteScan(ctx, scanUUID, ""); err != nil {
		t.Fatalf("CompleteScan: %v", err)
	}

	scan, err := repo.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		t.Fatalf("GetScanByUUID: %v", err)
	}
	if scan.Status != "completed" {
		t.Errorf("Status = %q, want completed", scan.Status)
	}
	if scan.Completeness != "" {
		t.Errorf("Completeness = %q, want empty (unknown)", scan.Completeness)
	}
	if scan.StopReason != "" {
		t.Errorf("StopReason = %q, want empty", scan.StopReason)
	}
	if len(scan.PhaseOutcomes) != 0 {
		t.Errorf("PhaseOutcomes = %+v, want none", scan.PhaseOutcomes)
	}
}

// TestCompleteScanWithOutcome_ZeroCompletionWritesNothing: a zero completion is
// how a caller says "I don't know", and it must not overwrite a verdict with a
// guess.
func TestCompleteScanWithOutcome_ZeroCompletionWritesNothing(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	if err := repo.CompleteScanWithOutcome(ctx, scanUUID, "", ScanCompletion{
		Completeness: CompletenessPartial,
		StopReason:   ReasonCancelled,
	}); err != nil {
		t.Fatalf("first CompleteScanWithOutcome: %v", err)
	}
	if err := repo.CompleteScanWithOutcome(ctx, scanUUID, "", ScanCompletion{}); err != nil {
		t.Fatalf("second CompleteScanWithOutcome: %v", err)
	}

	scan, _ := repo.GetScanByUUID(ctx, scanUUID)
	if scan.Completeness != CompletenessPartial {
		t.Errorf("Completeness = %q — a zero completion must leave the verdict alone", scan.Completeness)
	}
	if scan.StopReason != ReasonCancelled {
		t.Errorf("StopReason = %q", scan.StopReason)
	}
}

// TestCompleteScanWithOutcome_FailedScanKeepsBothAxes: a scan that failed AND
// was partial reports both. The status is the more serious fact and keeps its
// meaning; completeness says how much was covered before it failed.
func TestCompleteScanWithOutcome_FailedScanKeepsBothAxes(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	if err := repo.CompleteScanWithOutcome(ctx, scanUUID, "discovery phase failed", ScanCompletion{
		Completeness: CompletenessPartial,
		StopReason:   ReasonError,
		Phases:       []PhaseOutcome{{Phase: "discovery", State: PhaseFailed, Errors: 1}},
	}); err != nil {
		t.Fatalf("CompleteScanWithOutcome: %v", err)
	}

	scan, _ := repo.GetScanByUUID(ctx, scanUUID)
	if scan.Status != "failed" {
		t.Errorf("Status = %q, want failed", scan.Status)
	}
	if scan.Completeness != CompletenessPartial || scan.StopReason != ReasonError {
		t.Errorf("completeness axis lost: %q / %q", scan.Completeness, scan.StopReason)
	}
}

// TestCompleteScanWithOutcome_CompleteVerdict is the common case: a clean scan
// records "complete" with no reason, which is what distinguishes it from the
// "unknown" an older binary leaves behind.
func TestCompleteScanWithOutcome_CompleteVerdict(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	if err := repo.CompleteScanWithOutcome(ctx, scanUUID, "", ScanCompletion{
		Completeness: CompletenessComplete,
		Phases: []PhaseOutcome{
			{Phase: "discovery", State: PhaseCompleted, DurationMS: 10},
		},
	}); err != nil {
		t.Fatalf("CompleteScanWithOutcome: %v", err)
	}

	scan, _ := repo.GetScanByUUID(ctx, scanUUID)
	if scan.Completeness != CompletenessComplete {
		t.Errorf("Completeness = %q, want %q", scan.Completeness, CompletenessComplete)
	}
	if scan.StopReason != "" {
		t.Errorf("StopReason = %q, want empty", scan.StopReason)
	}
	if len(scan.PhaseOutcomes) != 1 || scan.PhaseOutcomes[0].State != PhaseCompleted {
		t.Errorf("PhaseOutcomes = %+v", scan.PhaseOutcomes)
	}
}

// TestScanCompletenessColumnsOnALegacyDatabase mirrors the schema-migration
// guard for the three new columns: a database written by a binary that predates
// them must gain them on upgrade, or every scan listing errors with "no such
// column".
func TestScanCompletenessColumnsOnALegacyDatabase(t *testing.T) {
	ctx := context.Background()
	db := newEmptyDB(t)

	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("initial CreateSchema: %v", err)
	}
	cols := []string{"completeness", "stop_reason", "phase_outcomes"}
	for _, col := range cols {
		if _, err := db.ExecContext(ctx, "ALTER TABLE scans DROP COLUMN "+col); err != nil {
			t.Fatalf("drop scans.%s: %v", col, err)
		}
		if columnExists(t, db, "scans", col) {
			t.Fatalf("setup failed: scans.%s survived the drop", col)
		}
	}

	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema on a legacy DB must succeed, got: %v", err)
	}
	for _, col := range cols {
		if !columnExists(t, db, "scans", col) {
			t.Errorf("scans.%s was not re-added — add a column migration for it", col)
		}
	}

	// And a row written before the columns existed reads as unknown, never as
	// complete.
	repo := NewRepository(db)
	scanUUID := createTestScan(t, repo)
	if err := repo.CompleteScan(ctx, scanUUID, ""); err != nil {
		t.Fatalf("CompleteScan: %v", err)
	}
	scan, err := repo.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		t.Fatalf("GetScanByUUID: %v", err)
	}
	if scan.Completeness != "" {
		t.Errorf("Completeness = %q, want empty", scan.Completeness)
	}
}
