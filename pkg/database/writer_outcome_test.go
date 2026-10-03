package database

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// --- PersistenceOutcome ------------------------------------------------------

func TestPersistenceOutcome_Clean(t *testing.T) {
	assert.True(t, PersistenceOutcome{Accepted: 5, Committed: 5}.Clean())
	assert.False(t, PersistenceOutcome{Accepted: 5, Committed: 4, Failed: 1}.Clean())
	assert.False(t, PersistenceOutcome{Accepted: 5, Committed: 4, Unknown: 1}.Clean())
	assert.True(t, PersistenceOutcome{}.Clean(), "a writer that accepted nothing is clean")
	assert.True(t, PersistenceOutcome{TimedOut: true, Accepted: 2, Committed: 2}.Clean(),
		"a drain that ran long but lost nothing is still clean")
}

func TestPersistenceOutcome_Merge(t *testing.T) {
	t.Run("adopts the first label", func(t *testing.T) {
		var o PersistenceOutcome
		o.Merge(PersistenceOutcome{Writer: PersistenceWriterFindings, Accepted: 3, Committed: 3})
		assert.Equal(t, PersistenceWriterFindings, o.Writer)
	})

	t.Run("two different writers collapse to mixed", func(t *testing.T) {
		var o PersistenceOutcome
		o.Merge(PersistenceOutcome{Writer: PersistenceWriterFindings, Accepted: 3, Committed: 2, Failed: 1})
		o.Merge(PersistenceOutcome{Writer: PersistenceWriterRecords, Accepted: 10, Committed: 8, Unknown: 2, TimedOut: true})

		assert.Equal(t, PersistenceWriterMixed, o.Writer)
		assert.Equal(t, int64(13), o.Accepted)
		assert.Equal(t, int64(10), o.Committed)
		assert.Equal(t, int64(1), o.Failed)
		assert.Equal(t, int64(2), o.Unknown)
		assert.True(t, o.TimedOut, "TimedOut is sticky: one writer timing out is the phase's problem")
		assert.False(t, o.Clean())
		assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown, "the invariant must survive a merge")
	})

	t.Run("same writer twice keeps its label", func(t *testing.T) {
		var o PersistenceOutcome
		o.Merge(PersistenceOutcome{Writer: PersistenceWriterRecords, Accepted: 1, Committed: 1})
		o.Merge(PersistenceOutcome{Writer: PersistenceWriterRecords, Accepted: 2, Committed: 2})
		assert.Equal(t, PersistenceWriterRecords, o.Writer)
		assert.Equal(t, int64(3), o.Accepted)
	})
}

func TestPersistenceOutcome_NilWritersAreCleanNoOps(t *testing.T) {
	var rw *RecordWriter
	var fw *FindingWriter

	ro := rw.Shutdown()
	fo := fw.Shutdown()

	assert.True(t, ro.Clean())
	assert.True(t, fo.Clean())
	assert.Equal(t, PersistenceWriterRecords, ro.Writer)
	assert.Equal(t, PersistenceWriterFindings, fo.Writer)
	assert.Zero(t, ro.Accepted)
	assert.Zero(t, fo.Accepted)
}

func TestWaitBounded_ExpiredTimeoutDoesNotBlock(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	t.Cleanup(wg.Done)

	start := time.Now()
	assert.False(t, waitBounded(&wg, -time.Second),
		"a deadline that already passed must report expiry, not wait forever")
	assert.False(t, waitBounded(&wg, 0),
		"a zero budget is an expired budget")
	assert.Less(t, time.Since(start), 100*time.Millisecond)

	var done sync.WaitGroup
	assert.True(t, waitBounded(&done, time.Second),
		"an already-finished group completes immediately on a live budget")
}

// --- SaveFindingsBatchResults ------------------------------------------------

// TestSaveFindingsBatchResults_Aligned: results[i] must describe writes[i],
// including the entries the method rejects itself. A compacted result slice would
// shift every later outcome onto the preceding finding, which is how a partial
// batch turns into wrong counts.
func TestSaveFindingsBatchResults_Aligned(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	recA := insertRecordP(t, repo, DefaultProjectUUID, "GET", "t.example.com", "/a", 200)

	writes := []FindingWrite{
		{Event: makeFindingEvent("m1", "/a", severity.High), HTTPRecordUUIDs: []string{recA}, ProjectUUID: DefaultProjectUUID},
		{Event: nil}, // unconvertible: no event at all
		{Event: makeFindingEvent("m2", "/b", severity.Medium), ProjectUUID: DefaultProjectUUID},
	}

	results := repo.SaveFindingsBatchResults(ctx, writes)
	require.Len(t, results, len(writes), "the result must be 1:1 with the input")

	assert.NoError(t, results[0].Err)
	assert.True(t, results[0].Inserted)
	assert.Error(t, results[1].Err, "the rejected entry carries its error at its own index")
	assert.False(t, results[1].Inserted)
	assert.NoError(t, results[2].Err)
	assert.True(t, results[2].Inserted)

	// And the single-error form still reports the one bad entry.
	assert.Error(t, repo.SaveFindingsBatch(ctx, []FindingWrite{{Event: nil}}))
}

func TestSaveFindingsBatchResults_EmptyInput(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	assert.Empty(t, repo.SaveFindingsBatchResults(context.Background(), nil))
	assert.NoError(t, repo.SaveFindingsBatch(context.Background(), nil))
}

// --- FindingWriter -----------------------------------------------------------

// blockingFindingSaver is a saveBatch seam that parks until released, ignoring
// its context entirely — a database wedged below the context layer.
type blockingFindingSaver struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func newBlockingFindingSaver() *blockingFindingSaver {
	return &blockingFindingSaver{entered: make(chan struct{}), release: make(chan struct{})}
}

func (b *blockingFindingSaver) save(_ context.Context, writes []FindingWrite) []FindingSaveResult {
	b.calls.Add(1)
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return make([]FindingSaveResult, len(writes))
}

// TestFindingWriter_StalledFlushShutdownBounded: a flush that will never return
// must not hold the phase. The findings it took are reported as Unknown — they may
// yet commit — not as Failed, and the outcome says the deadline expired.
func TestFindingWriter_StalledFlushShutdownBounded(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	saver := newBlockingFindingSaver()
	t.Cleanup(func() { close(saver.release) })

	w := NewFindingWriter(repo, FindingWriterConfig{
		BatchSize:        3,
		FlushInterval:    5 * time.Millisecond,
		FlushTimeout:     200 * time.Millisecond,
		OperationTimeout: 10 * time.Second,
		saveBatch:        saver.save,
	})

	for i := range 3 {
		require.NoError(t, w.Save(context.Background(), makeFindingEvent(fmt.Sprintf("m%d", i), "/a", severity.Low), nil, "scan", DefaultProjectUUID))
	}

	// Only measure once the flush is actually wedged.
	select {
	case <-saver.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the flush seam was never entered")
	}

	start := time.Now()
	o := w.Shutdown()
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 500*time.Millisecond, "Shutdown must honour FlushTimeout")
	assert.True(t, o.TimedOut)
	assert.Equal(t, int64(3), o.Accepted)
	assert.Equal(t, int64(3), o.Unknown, "findings inside a wedged flush are unknown, not lost")
	assert.Zero(t, o.Failed)
	assert.Zero(t, o.Committed)
	assert.False(t, o.Clean())
	assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)
}

// TestFindingWriter_OperationTimeoutBoundsSteadyFlush: a steady-state flush is
// detached from the scan's context but no longer unbounded — it fails on its own
// timeout instead of parking the writer goroutine for the rest of the process.
func TestFindingWriter_OperationTimeoutBoundsSteadyFlush(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	w := NewFindingWriter(repo, FindingWriterConfig{
		BatchSize:        2,
		FlushInterval:    5 * time.Millisecond,
		FlushTimeout:     2 * time.Second,
		OperationTimeout: 50 * time.Millisecond,
		// Honours ctx: blocks until the operation deadline, then fails every entry.
		saveBatch: func(ctx context.Context, writes []FindingWrite) []FindingSaveResult {
			<-ctx.Done()
			results := make([]FindingSaveResult, len(writes))
			for i := range results {
				results[i].Err = ctx.Err()
			}
			return results
		},
	})
	t.Cleanup(w.Close)

	for i := range 2 {
		require.NoError(t, w.Save(context.Background(), makeFindingEvent(fmt.Sprintf("m%d", i), "/a", severity.Low), nil, "scan", DefaultProjectUUID))
	}

	require.Eventually(t, func() bool { return w.Metrics().Errors == 2 }, time.Second, 5*time.Millisecond,
		"the stalled batch must fail on OperationTimeout rather than hang")
}

// TestFindingWriter_PartialBatchExactCounts: the batch save retries each finding
// individually when the transaction fails, so most "failed" batches persisted
// nearly everything. Charging the whole batch on any error reported findings as
// dropped that are in the database.
func TestFindingWriter_PartialBatchExactCounts(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	w := NewFindingWriter(repo, FindingWriterConfig{
		BatchSize:     4,
		FlushInterval: 5 * time.Millisecond,
		FlushTimeout:  2 * time.Second,
		saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
			results := make([]FindingSaveResult, len(writes))
			if len(results) > 1 {
				results[1].Err = errors.New("one bad finding")
			}
			return results
		},
	})

	for i := range 4 {
		require.NoError(t, w.Save(context.Background(), makeFindingEvent(fmt.Sprintf("m%d", i), "/a", severity.Low), nil, "scan", DefaultProjectUUID))
	}

	o := w.Shutdown()

	m := w.Metrics()
	assert.Equal(t, int64(3), m.Written)
	assert.Equal(t, int64(1), m.Errors)
	assert.Zero(t, m.Inline)

	assert.Equal(t, int64(4), o.Accepted)
	assert.Equal(t, int64(3), o.Committed)
	assert.Equal(t, int64(1), o.Failed)
	assert.Zero(t, o.Unknown)
	assert.False(t, o.TimedOut)
	assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)
}

// TestFindingWriter_ShortResultSliceCountsAsFailed: a seam (or a future repository
// change) that returns fewer results than inputs must not silently drop findings
// from the accounting.
func TestFindingWriter_ShortResultSliceCountsAsFailed(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	w := NewFindingWriter(repo, FindingWriterConfig{
		BatchSize:     3,
		FlushInterval: 5 * time.Millisecond,
		FlushTimeout:  2 * time.Second,
		saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
			return make([]FindingSaveResult, len(writes)-1) // one short
		},
	})

	for i := range 3 {
		require.NoError(t, w.Save(context.Background(), makeFindingEvent(fmt.Sprintf("m%d", i), "/a", severity.Low), nil, "scan", DefaultProjectUUID))
	}

	o := w.Shutdown()
	assert.Equal(t, int64(1), o.Failed)
	assert.Equal(t, int64(2), o.Committed)
	assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)
}

// TestFindingWriter_ShutdownIdempotentConcurrent: two phases can race to close the
// same writer; both must see the same accounting, and the invariant must hold.
func TestFindingWriter_ShutdownIdempotentConcurrent(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	w := NewFindingWriter(repo, FindingWriterConfig{
		BatchSize:     8,
		FlushInterval: 5 * time.Millisecond,
		FlushTimeout:  5 * time.Second,
	})

	const producers = 8
	const each = 5
	var wg sync.WaitGroup
	for p := range producers {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := range each {
				_ = w.Save(context.Background(),
					makeFindingEvent(fmt.Sprintf("m%d-%d", p, i), fmt.Sprintf("/p%d/%d", p, i), severity.Low),
					nil, "scan", DefaultProjectUUID)
			}
		}(p)
	}
	wg.Wait()

	outcomes := make([]PersistenceOutcome, 2)
	var shutWG sync.WaitGroup
	for i := range outcomes {
		shutWG.Add(1)
		go func(i int) {
			defer shutWG.Done()
			outcomes[i] = w.Shutdown()
		}(i)
	}
	shutWG.Wait()

	assert.Equal(t, outcomes[0], outcomes[1], "concurrent Shutdowns must report the same outcome")
	o := outcomes[0]
	assert.Equal(t, int64(producers*each), o.Accepted)
	assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)
	assert.True(t, o.Clean(), "a healthy database must drain cleanly: %+v", o)

	// A later call still returns the stored value, and Close stays a safe alias.
	assert.Equal(t, o, w.Shutdown())
	w.Close()
}

// TestFindingWriter_InlineFailuresCounted: Save's error normally goes to a caller
// that only logs it, so an inline save that failed was invisible in the shutdown
// accounting even though the finding is just as lost as a dropped flush.
func TestFindingWriter_InlineFailuresCounted(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	w := NewFindingWriter(repo, FindingWriterConfig{FlushTimeout: 2 * time.Second})
	w.Close() // after close, every Save is inline

	require.Error(t, w.Save(context.Background(), nil, nil, "scan", DefaultProjectUUID),
		"a nil event cannot be persisted")
	// A nil event is rejected before the inline path, so drive a real inline
	// failure through a closed database instead.
	require.NoError(t, db.Close())
	require.Error(t, w.Save(context.Background(),
		makeFindingEvent("m1", "/a", severity.Low), nil, "scan", DefaultProjectUUID))

	m := w.Metrics()
	assert.Equal(t, int64(1), m.Inline)
	assert.Equal(t, int64(1), m.InlineFailed)
}

// --- RecordWriter ------------------------------------------------------------

// TestRecordWriter_ShutdownSingleDeadline: the admission wait, the drain flushes
// and the wait for the flush loops used to start a FlushTimeout each, so a wedged
// database could hold Close for three times the configured budget. One deadline
// now governs all three.
func TestRecordWriter_ShutdownSingleDeadline(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unwedge := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unwedge)
	var once sync.Once

	w := NewRecordWriter(repo, RecordWriterConfig{
		BufferSize:       1,
		BatchSize:        1,
		Shards:           1,
		FlushTimeout:     200 * time.Millisecond,
		OperationTimeout: 10 * time.Second,
		DedupCacheSize:   -1, // every write must reach the flush loop
		insertBatch: func(context.Context, []*HTTPRecord) error {
			once.Do(func() { close(entered) })
			<-release // ignores ctx: wedged below the context layer
			return nil
		},
	})

	var wg sync.WaitGroup
	for i := range 5 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = w.Write(context.Background(), makeTestRequest(i), "test", DefaultProjectUUID)
		}(i)
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the insert seam was never entered")
	}

	start := time.Now()
	o := w.Shutdown()
	elapsed := time.Since(start)

	// 350ms proves ONE 200ms budget was spent, not two (400ms) or three (600ms).
	assert.Less(t, elapsed, 350*time.Millisecond, "the whole shutdown shares one deadline")
	assert.True(t, o.TimedOut)
	assert.Equal(t, PersistenceWriterRecords, o.Writer)
	assert.Positive(t, o.Unknown, "records stuck in a wedged flush are unknown")
	assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)
	assert.False(t, o.Clean())

	unwedge()
	wg.Wait()
}

// TestRecordWriter_OperationTimeoutFailsStalledBatch: a steady-state flush that
// honours its context now fails on OperationTimeout, so the waiting writer gets an
// error quickly instead of blocking until the process ends.
func TestRecordWriter_OperationTimeoutFailsStalledBatch(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	w := NewRecordWriter(repo, RecordWriterConfig{
		BatchSize:        1,
		Shards:           1,
		FlushTimeout:     2 * time.Second,
		OperationTimeout: 50 * time.Millisecond,
		DedupCacheSize:   -1,
		insertBatch: func(ctx context.Context, _ []*HTTPRecord) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})
	t.Cleanup(w.Close)

	done := make(chan error, 1)
	go func() {
		_, err := w.Write(context.Background(), makeTestRequest(1), "test", DefaultProjectUUID)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err, "a stalled batch must fail the write, not hang it")
	case <-time.After(time.Second):
		t.Fatal("Write did not return within 1s of the 50ms operation timeout")
	}

	assert.Equal(t, int64(1), w.Metrics().FlushFailed)
}

// TestRecordWriter_ShutdownCleanOutcome: the healthy path must report a clean
// outcome whose counts add up, so a caller can trust Clean() as the success gate.
func TestRecordWriter_ShutdownCleanOutcome(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	w := NewRecordWriter(repo, RecordWriterConfig{Shards: 1, DedupCacheSize: -1})

	for i := range 20 {
		_, err := w.Write(context.Background(), makeTestRequest(i), "test", DefaultProjectUUID)
		require.NoError(t, err)
	}

	o := w.Shutdown()
	assert.True(t, o.Clean(), "a healthy writer must drain cleanly: %+v", o)
	assert.False(t, o.TimedOut)
	assert.Equal(t, int64(20), o.Accepted)
	assert.Equal(t, int64(20), o.Committed)
	assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)

	assert.Equal(t, o, w.Shutdown(), "repeat Shutdown returns the stored outcome")
}

// TestRecordWriter_DedupCacheHitsAreNotAccepted documents the accounting boundary:
// a cache hit is resolved from memory without ever being enqueued, so it is not a
// write this writer accepted and must not appear in Accepted.
func TestRecordWriter_DedupCacheHitsAreNotAccepted(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	w := NewRecordWriter(repo, RecordWriterConfig{Shards: 1})

	first, err := w.Write(context.Background(), makeTestRequest(1), "test", DefaultProjectUUID)
	require.NoError(t, err)
	require.NotEmpty(t, first)

	// Same record again: resolved from the dedup cache.
	second, err := w.Write(context.Background(), makeTestRequest(1), "test", DefaultProjectUUID)
	require.NoError(t, err)
	assert.Equal(t, first, second)

	o := w.Shutdown()
	assert.Equal(t, int64(1), o.Accepted, "the cache hit was never enqueued")
	assert.True(t, o.Clean())
}
