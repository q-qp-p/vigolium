package core

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/work"
)

// TestReportCleanRun pins the healthy path: a source read to EOF leaves nothing
// to report, so a consumer that acts on a non-zero report is not told to act on
// every scan.
func TestReportCleanRun(t *testing.T) {
	t.Parallel()
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)
	e.pool.feedbackCh = make(chan *work.WorkItem, 16)
	e.scanCtx = &modules.ScanContext{}
	item, _ := makeTestItem("example.com", "/ok", "<html>x</html>")
	e.source = &sliceSource{items: []*work.WorkItem{item}}

	if _, err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	rep := e.Report()
	if !rep.Clean() {
		t.Errorf("Report() = %+v, want clean", rep)
	}
}

// blockingSource never yields an item and never EOFs: Next parks until the
// context is done. It stands in for a producer that is still working when the
// phase is cut short — a crawl mid-target, a DB poller waiting for rows.
type blockingSource struct {
	calls atomic.Int64
}

func (s *blockingSource) Next(ctx context.Context) (*work.WorkItem, error) {
	s.calls.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *blockingSource) Close() error { return nil }

// TestReportStoppedEarlyOnCancel is the fact Execute could not previously
// communicate: the input was NOT exhausted. Execute returns a nil error on this
// path, so without the report a cancelled feed and a fully consumed one are
// indistinguishable to the caller.
func TestReportStoppedEarlyOnCancel(t *testing.T) {
	t.Parallel()
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)
	e.pool.feedbackCh = make(chan *work.WorkItem, 16)
	e.scanCtx = &modules.ScanContext{}
	e.source = &blockingSource{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := e.Execute(ctx)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Execute did not return after cancellation")
	}

	rep := e.Report()
	if !rep.StoppedEarly {
		t.Errorf("Report() = %+v, want StoppedEarly", rep)
	}
	if rep.Clean() {
		t.Error("a cancelled feed must not report clean")
	}
}

// errorThenEOFSource reports a per-item error once, then EOFs — the shape a
// source with one malformed entry has. It must still count as exhausted: the
// error was about an item, not about the source.
type errorThenEOFSource struct {
	erred bool
}

func (s *errorThenEOFSource) Next(_ context.Context) (*work.WorkItem, error) {
	if !s.erred {
		s.erred = true
		return nil, errString("malformed target line")
	}
	return nil, io.EOF
}

func (s *errorThenEOFSource) Close() error { return nil }

func TestReportPerItemErrorStillExhausts(t *testing.T) {
	t.Parallel()
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)
	e.pool.feedbackCh = make(chan *work.WorkItem, 16)
	e.scanCtx = &modules.ScanContext{}
	e.source = &errorThenEOFSource{}

	if _, err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if rep := e.Report(); rep.StoppedEarly {
		t.Errorf("a source that reported an item error and then EOF'd was exhausted: %+v", rep)
	}
}

// TestReportWorkersAbandonedAndFlushSkipped covers the degraded shutdown: a
// module that ignores cancellation pins a worker past the exit grace, the worker
// is leaked, and the deferred passive flush is skipped to avoid racing it. Both
// facts reduce coverage and both were previously log-only.
func TestReportWorkersAbandonedAndFlushSkipped(t *testing.T) {
	t.Parallel()
	flusher := &flushTrackingModule{trackingPassiveModule: trackingPassiveModule{id: "flusher"}}
	blocker := &blockingPassiveModule{
		id:      "blocker",
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	t.Cleanup(func() { close(blocker.release) })

	e, _ := newTestExecutor(ExecutorConfig{
		Workers:               1,
		PassiveModuleTimeout:  time.Hour,
		FeedbackDrainMaxStall: 150 * time.Millisecond,
		WorkerExitGrace:       50 * time.Millisecond,
	}, []modules.PassiveModule{flusher, blocker})
	e.pool.feedbackCh = make(chan *work.WorkItem, 16)
	e.scanCtx = &modules.ScanContext{}
	item, _ := makeTestItem("example.com", "/stuck", "<html>x</html>")
	e.source = &sliceSource{items: []*work.WorkItem{item}}

	done := make(chan error, 1)
	go func() {
		_, err := e.Execute(context.Background())
		done <- err
	}()
	select {
	case <-blocker.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("blocking module was never entered")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Execute did not return")
	}

	rep := e.Report()
	if !rep.WorkersAbandoned {
		t.Errorf("Report() = %+v, want WorkersAbandoned", rep)
	}
	if !rep.DeferredFlushSkipped {
		t.Errorf("Report() = %+v, want DeferredFlushSkipped", rep)
	}
	if !rep.DrainStalled {
		t.Errorf("Report() = %+v, want DrainStalled", rep)
	}
}

// TestReportResetBetweenRuns: dynamic assessment builds one executor per
// feedback round, but a reused executor must not inherit a previous run's
// abandonment and report a clean round as degraded.
func TestReportResetBetweenRuns(t *testing.T) {
	t.Parallel()
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)
	e.pool.feedbackCh = make(chan *work.WorkItem, 16)
	e.scanCtx = &modules.ScanContext{}
	e.source = &blockingSource{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = e.Execute(ctx)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if !e.Report().StoppedEarly {
		t.Fatal("setup: the first run should have stopped early")
	}

	item, _ := makeTestItem("example.com", "/ok", "<html>x</html>")
	e.source = &sliceSource{items: []*work.WorkItem{item}}
	if _, err := e.Execute(context.Background()); err != nil {
		t.Fatalf("second Execute() error = %v", err)
	}
	if rep := e.Report(); !rep.Clean() {
		t.Errorf("the second run inherited the first's report: %+v", rep)
	}
}

// TestFinishItemWithholdsAckOnCancelledContext is the ack-truth fix.
//
// The worker's select can win a dequeue in the same instant the context is
// cancelled; processItem then bails out immediately, and the item used to be
// acknowledged anyway. For a DB-backed source that ack is a durable cursor
// advance past a record nothing looked at — and because a curtailed scan still
// recorded "completed", the next scan-on-receive run inherited that cursor and
// skipped the record permanently.
func TestFinishItemWithholdsAckOnCancelledContext(t *testing.T) {
	t.Parallel()
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)

	var acks atomic.Int64
	_, rr := makeTestItem("example.com", "/x", "body")
	item := work.NewWithCallback(rr, nil, func() { acks.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.finishItem(ctx, item, false)

	if got := acks.Load(); got != 0 {
		t.Errorf("callback fired %d time(s) on a cancelled context, want 0", got)
	}
	if got := e.Report().Unacked; got != 1 {
		t.Errorf("Unacked = %d, want 1", got)
	}
}

func TestFinishItemAcksOnLiveContext(t *testing.T) {
	t.Parallel()
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)

	var acks atomic.Int64
	_, rr := makeTestItem("example.com", "/x", "body")
	item := work.NewWithCallback(rr, nil, func() { acks.Add(1) })

	e.finishItem(context.Background(), item, false)

	if got := acks.Load(); got != 1 {
		t.Errorf("callback fired %d time(s), want 1", got)
	}
	if got := e.Report().Unacked; got != 0 {
		t.Errorf("Unacked = %d, want 0", got)
	}
}

// TestFinishItemAcksPoisonItemDespiteCancellation: a recovered panic forces the
// ack. Withholding it would make the poison item come back on every later run
// and freeze the cursor behind it forever — strictly worse than losing one item.
func TestFinishItemAcksPoisonItemDespiteCancellation(t *testing.T) {
	t.Parallel()
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)

	var acks atomic.Int64
	_, rr := makeTestItem("example.com", "/x", "body")
	item := work.NewWithCallback(rr, nil, func() { acks.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.finishItem(ctx, item, true)

	if got := acks.Load(); got != 1 {
		t.Errorf("a panicked item must still be acknowledged, got %d acks", got)
	}
	if got := e.Report().Unacked; got != 0 {
		t.Errorf("Unacked = %d, want 0", got)
	}
}

// TestWorkerWithholdsAckForDequeuedItemAfterCancel drives the real worker loop
// on the exact interleaving the bug needed: the item is already in the channel
// when the context is cancelled, so the worker can win the dequeue and then find
// nothing to do.
func TestWorkerWithholdsAckForDequeuedItemAfterCancel(t *testing.T) {
	t.Parallel()
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)
	e.scanCtx = &modules.ScanContext{}

	var acks atomic.Int64
	_, rr := makeTestItem("example.com", "/late", "body")
	item := work.NewWithCallback(rr, nil, func() { acks.Add(1) })

	ch := make(chan *work.WorkItem, 1)
	ch <- item
	close(ch)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// The worker's select has both ctx.Done() and a readable channel; whichever
	// it picks, the item must NOT be acknowledged, because it was not processed.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.worker(ctx, 0, ch)
	}()
	wg.Wait()

	if got := acks.Load(); got != 0 {
		t.Errorf("item acknowledged %d time(s) without being processed", got)
	}
}

// TestWorkerAcksProcessedItem is the control: on a live context the same loop
// processes and acknowledges exactly once.
func TestWorkerAcksProcessedItem(t *testing.T) {
	t.Parallel()
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)
	e.scanCtx = &modules.ScanContext{}

	var acks atomic.Int64
	_, rr := makeTestItem("example.com", "/ok", "body")
	item := work.NewWithCallback(rr, nil, func() { acks.Add(1) })

	ch := make(chan *work.WorkItem, 1)
	ch <- item
	close(ch)

	e.worker(context.Background(), 0, ch)

	if got := acks.Load(); got != 1 {
		t.Errorf("item acknowledged %d time(s), want 1", got)
	}
	if got := e.Report().Unacked; got != 0 {
		t.Errorf("Unacked = %d, want 0", got)
	}
}

// errString is a minimal error value, so a test asserting on behaviour does not
// depend on fmt.Errorf's formatting.
type errString string

func (e errString) Error() string { return string(e) }
