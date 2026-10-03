package database

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

// drainSource serves every item the source yields and acknowledges it, returning
// how many were served. The shape every cursor test needs before it can assert
// anything about the commit.
func drainSource(t *testing.T, s *RiskPrioritizedDBInputSource) int {
	t.Helper()
	ctx := context.Background()
	served := 0
	for {
		item, err := s.Next(ctx)
		if errors.Is(err, io.EOF) {
			return served
		}
		if err != nil {
			t.Fatalf("Next(): %v", err)
		}
		served++
		item.Complete()
	}
}

// TestFlushCursor_RecoversAFailedCheckpoint is the WP6 cursor fix.
//
// The steady commit used to set `committed = true` BEFORE the write, so a failed
// checkpoint latched the source shut and told nobody: the round's work was done,
// the durable cursor still sat at the start of it, and the scan went on to record
// a clean completion. FlushCursor is the reported retry — and `committed` now
// only becomes true once the write has actually landed.
func TestFlushCursor_RecoversAFailedCheckpoint(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "flush.example.com"
	const n = 3
	insertTestRecordsWithHost(t, repo, host, n)

	source := NewRiskPrioritizedDBInputSource(db, repo, scanUUID).
		WithHostScopes([]HostTarget{{Hostname: host}})

	// Fail the first write, then let every later one through.
	var attempts atomic.Int64
	source.advanceCursor = func(ctx context.Context, scan string, at time.Time, id string, delta int64) error {
		if attempts.Add(1) == 1 {
			return errors.New("database is locked")
		}
		return repo.AdvanceScanCursorBy(ctx, scan, at, id, delta)
	}

	if served := drainSource(t, source); served != n {
		t.Fatalf("served %d records, want %d", served, n)
	}

	// The steady commit failed, so the cursor must still be where it started and
	// the source must NOT consider itself committed.
	scan, _ := repo.GetScanByUUID(ctx, scanUUID)
	if !scan.CursorAt.IsZero() {
		t.Fatalf("cursor advanced despite a failed checkpoint write: %v", scan.CursorAt)
	}
	source.mu.Lock()
	committed := source.commitErr == nil && source.committed
	source.mu.Unlock()
	if committed {
		t.Fatal("a failed write must not latch the commit shut")
	}

	if err := source.FlushCursor(ctx); err != nil {
		t.Fatalf("FlushCursor(): %v", err)
	}

	scan, _ = repo.GetScanByUUID(ctx, scanUUID)
	if scan.CursorAt.IsZero() {
		t.Fatal("FlushCursor did not advance the cursor")
	}
	if scan.ProcessedCount != n {
		t.Errorf("ProcessedCount = %d, want %d", scan.ProcessedCount, n)
	}
	remaining, err := repo.CountRecordsAfterCursor(ctx, DefaultProjectUUID, scan.CursorAt, scan.CursorUUID, HostTarget{Hostname: host})
	if err != nil {
		t.Fatalf("CountRecordsAfterCursor: %v", err)
	}
	if remaining != 0 {
		t.Errorf("remaining after cursor = %d, want 0", remaining)
	}

	// A second call is a no-op: the cursor advance is not idempotent, so a
	// repeated flush must not double-count processed_count.
	before := attempts.Load()
	if err := source.FlushCursor(ctx); err != nil {
		t.Errorf("second FlushCursor(): %v", err)
	}
	if attempts.Load() != before {
		t.Error("a committed source must not attempt another write")
	}
	scan, _ = repo.GetScanByUUID(ctx, scanUUID)
	if scan.ProcessedCount != n {
		t.Errorf("ProcessedCount = %d after a repeat flush, want %d", scan.ProcessedCount, n)
	}
}

// TestFlushCursor_NoOpOnACleanRound: the steady path already committed, so the
// phase's flush has nothing to do and must not write again.
func TestFlushCursor_NoOpOnACleanRound(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "clean.example.com"
	insertTestRecordsWithHost(t, repo, host, 2)

	source := NewRiskPrioritizedDBInputSource(db, repo, scanUUID).
		WithHostScopes([]HostTarget{{Hostname: host}})
	var attempts atomic.Int64
	source.advanceCursor = func(ctx context.Context, scan string, at time.Time, id string, delta int64) error {
		attempts.Add(1)
		return repo.AdvanceScanCursorBy(ctx, scan, at, id, delta)
	}

	drainSource(t, source)
	if attempts.Load() != 1 {
		t.Fatalf("setup: expected exactly one steady commit, got %d", attempts.Load())
	}

	if err := source.FlushCursor(ctx); err != nil {
		t.Fatalf("FlushCursor(): %v", err)
	}
	if attempts.Load() != 1 {
		t.Errorf("FlushCursor wrote again on an already-committed round (%d attempts)", attempts.Load())
	}
}

// TestFlushCursor_ReportsAPersistentFailure: when the retries are exhausted the
// error must reach the caller. Silently giving up is what let a scan report a
// clean completion over a cursor that had not moved.
func TestFlushCursor_ReportsAPersistentFailure(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "broken.example.com"
	insertTestRecordsWithHost(t, repo, host, 2)

	source := NewRiskPrioritizedDBInputSource(db, repo, scanUUID).
		WithHostScopes([]HostTarget{{Hostname: host}})
	wantErr := errors.New("disk is gone")
	var attempts atomic.Int64
	source.advanceCursor = func(context.Context, string, time.Time, string, int64) error {
		attempts.Add(1)
		return wantErr
	}

	drainSource(t, source)

	err := source.FlushCursor(ctx)
	if !errors.Is(err, wantErr) {
		t.Fatalf("FlushCursor() = %v, want %v", err, wantErr)
	}
	// One steady attempt plus the bounded retry.
	if got := attempts.Load(); got != 1+cursorFlushAttempts {
		t.Errorf("attempts = %d, want %d", got, 1+cursorFlushAttempts)
	}
	scan, _ := repo.GetScanByUUID(ctx, scanUUID)
	if !scan.CursorAt.IsZero() {
		t.Errorf("cursor moved despite every write failing: %v", scan.CursorAt)
	}
}

// TestFlushCursor_DoesNotCommitUnresolvedWork is the invariant that makes
// at-least-once delivery hold: when the round ended with items a worker never
// finished, the cursor must stay BEHIND them so a later pass re-serves them. A
// flush must never invent a checkpoint to tidy up.
func TestFlushCursor_DoesNotCommitUnresolvedWork(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "unresolved.example.com"
	const n = 3
	insertTestRecordsWithHost(t, repo, host, n)

	source := NewRiskPrioritizedDBInputSource(db, repo, scanUUID).
		WithHostScopes([]HostTarget{{Hostname: host}})
	var attempts atomic.Int64
	source.advanceCursor = func(ctx context.Context, scan string, at time.Time, id string, delta int64) error {
		attempts.Add(1)
		return repo.AdvanceScanCursorBy(ctx, scan, at, id, delta)
	}

	// Serve every item but acknowledge only the first — the shape a cancelled
	// phase leaves behind, where workers dequeued items and never finished them.
	served := 0
	for {
		item, err := source.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next(): %v", err)
		}
		served++
		if served == 1 {
			item.Complete()
		}
	}
	if served != n {
		t.Fatalf("served %d records, want %d", served, n)
	}

	if unresolved := source.Unresolved(); unresolved != n-1 {
		t.Errorf("Unresolved() = %d, want %d", unresolved, n-1)
	}
	if err := source.FlushCursor(ctx); err != nil {
		t.Errorf("FlushCursor() = %v, want nil (nothing is due)", err)
	}
	if attempts.Load() != 0 {
		t.Errorf("FlushCursor wrote a checkpoint for unfinished work (%d attempts)", attempts.Load())
	}
	scan, _ := repo.GetScanByUUID(ctx, scanUUID)
	if !scan.CursorAt.IsZero() {
		t.Errorf("cursor advanced past unacknowledged records: %v", scan.CursorAt)
	}

	// And the records are still there to be re-served: the tail is re-scanned,
	// never skipped.
	remaining, err := repo.CountRecordsAfterCursor(ctx, DefaultProjectUUID, scan.CursorAt, scan.CursorUUID, HostTarget{Hostname: host})
	if err != nil {
		t.Fatalf("CountRecordsAfterCursor: %v", err)
	}
	if remaining != n {
		t.Errorf("remaining after cursor = %d, want %d (all of them)", remaining, n)
	}
}

// TestFlushCursor_EmptySnapshotIsANoOp: a round with no eligible records has no
// bound to commit to, so there is nothing to flush and nothing to report.
func TestFlushCursor_EmptySnapshotIsANoOp(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	source := NewRiskPrioritizedDBInputSource(db, repo, scanUUID).
		WithHostScopes([]HostTarget{{Hostname: "nothing.example.com"}})
	var attempts atomic.Int64
	source.advanceCursor = func(context.Context, string, time.Time, string, int64) error {
		attempts.Add(1)
		return nil
	}

	if _, err := source.Next(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("Next() = %v, want EOF", err)
	}
	if err := source.FlushCursor(ctx); err != nil {
		t.Errorf("FlushCursor() = %v, want nil", err)
	}
	if attempts.Load() != 0 {
		t.Errorf("an empty snapshot must not write a cursor (%d attempts)", attempts.Load())
	}
	if n := source.Unresolved(); n != 0 {
		t.Errorf("Unresolved() = %d, want 0", n)
	}
}

// TestFlushCursor_HonoursACancelledContext: the flush runs on its own bounded
// context, and an expired one must end the retry promptly rather than sleeping
// through its back-offs.
func TestFlushCursor_HonoursACancelledContext(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	scanUUID := createTestScan(t, repo)

	host := "cancelled.example.com"
	insertTestRecordsWithHost(t, repo, host, 2)

	source := NewRiskPrioritizedDBInputSource(db, repo, scanUUID).
		WithHostScopes([]HostTarget{{Hostname: host}})
	var attempts atomic.Int64
	source.advanceCursor = func(context.Context, string, time.Time, string, int64) error {
		attempts.Add(1)
		return errors.New("nope")
	}
	drainSource(t, source)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if err := source.FlushCursor(ctx); err == nil {
		t.Fatal("FlushCursor() = nil, want the write error")
	}
	if elapsed := time.Since(start); elapsed > cursorFlushBackoff {
		t.Errorf("FlushCursor slept through its back-offs on a dead context (%s)", elapsed)
	}
	// One steady attempt plus a single flush attempt before the cancellation is
	// observed.
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

// TestDBInputSource_CursorStaysBehindAnUnacknowledgedItem covers the polling
// source's side of the same contract: the contiguous ack-drain is what advances
// the cursor, so an item nobody finished holds it (and every later item) back.
func TestDBInputSource_CursorStaysBehindAnUnacknowledgedItem(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "oneshot-unacked.example.com"
	insertTestRecordsWithHost(t, repo, host, 2)

	source := NewOneShotDBInputSource(db, repo, scanUUID).
		WithHostScopes([]HostTarget{{Hostname: host}})

	first, err := source.Next(ctx)
	if err != nil {
		t.Fatalf("Next(): %v", err)
	}
	second, err := source.Next(ctx)
	if err != nil {
		t.Fatalf("Next(): %v", err)
	}

	// Acknowledge only the SECOND item. The head of the run is still pending, so
	// the cursor may not move past either — advancing to the second would skip
	// the first permanently.
	second.Complete()
	scan, _ := repo.GetScanByUUID(ctx, scanUUID)
	if !scan.CursorAt.IsZero() {
		t.Fatalf("cursor advanced past an unacknowledged head: %v", scan.CursorAt)
	}

	first.Complete()
	scan, _ = repo.GetScanByUUID(ctx, scanUUID)
	if scan.CursorAt.IsZero() {
		t.Fatal("cursor did not advance once the whole run was acknowledged")
	}
	if scan.ProcessedCount != 2 {
		t.Errorf("ProcessedCount = %d, want 2", scan.ProcessedCount)
	}
}
