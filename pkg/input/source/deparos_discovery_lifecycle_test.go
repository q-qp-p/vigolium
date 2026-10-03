package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/goleak"
)

// newLifecycleSource builds a source through the real constructor (so baseCtx and
// every channel are wired the way production wires them) and installs a stub in
// place of discoverTarget. discoverFn is only read by runDiscovery, which Next
// starts, so setting it here is race-free.
func newLifecycleSource(
	t *testing.T,
	ctx context.Context,
	targets []string,
	discover func(ctx context.Context, target string) error,
) *DeparosDiscoverySource {
	t.Helper()
	d, err := NewDeparosDiscoverySource(ctx, DeparosDiscoveryConfig{
		Targets:      targets,
		DrainTimeout: 200 * time.Millisecond,
	})
	require.NoError(t, err)
	d.discoverFn = discover
	return d
}

// stubRequest builds a minimal request-only record to push through the emitter.
func stubRequest(i int) *httpmsg.HttpRequestResponse {
	svc := httpmsg.NewServiceSecure("example.com", 443, true)
	raw := fmt.Sprintf("GET /p%d HTTP/1.1\r\nHost: example.com\r\n\r\n", i)
	req := httpmsg.NewHttpRequestWithService(svc, []byte(raw))
	return httpmsg.NewHttpRequestResponse(req, nil).WithService(svc)
}

func stubRequests(n int) []*httpmsg.HttpRequestResponse {
	return stubRequestRange(0, n)
}

// stubRequestRange builds n records whose paths start at the given index, so two
// groups in the same test can carry genuinely distinct URLs.
func stubRequestRange(start, n int) []*httpmsg.HttpRequestResponse {
	out := make([]*httpmsg.HttpRequestResponse, 0, n)
	for i := start; i < start+n; i++ {
		out = append(out, stubRequest(i))
	}
	return out
}

// TestDeparosDiscovery_CancelStopsProducerAndSkipsTargets proves the source is
// owned by the context it was built with: cancelling the phase ends the running
// target at once and the remaining targets are never attempted, instead of each
// one burning its full MaxDuration on work nobody will read.
func TestDeparosDiscovery_CancelStopsProducerAndSkipsTargets(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	entered := make(chan struct{})

	d := newLifecycleSource(t, ctx, []string{"a", "b", "c"},
		func(innerCtx context.Context, _ string) error {
			if calls.Add(1) == 1 {
				close(entered)
			}
			<-innerCtx.Done()
			return innerCtx.Err()
		})

	// Next starts the producer; it will block in the stub until we cancel.
	nextDone := make(chan error, 1)
	go func() {
		_, err := d.Next(context.Background())
		nextDone <- err
	}()

	<-entered
	cancel()

	select {
	case err := <-nextDone:
		assert.ErrorIs(t, err, io.EOF, "a cancelled producer closes items, which is EOF")
	case <-time.After(time.Second):
		t.Fatal("Next did not return within 1s of cancelling the source context")
	}

	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Close did not return within 1s")
	}

	assert.Equal(t, int32(1), calls.Load(), "only the in-flight target may run")
	assert.Equal(t, 2, d.Stats().TargetsSkipped, "the two unattempted targets must be reported as skipped")
	assert.False(t, d.Stats().Abandoned)
}

// TestDeparosDiscovery_CloseJoinsBlockedEmitter proves Close joins the producer
// rather than abandoning it to a detached drain goroutine: the emitter is parked
// on a full items channel with no reader, and Close still returns promptly with
// the producer actually finished.
func TestDeparosDiscovery_CloseJoinsBlockedEmitter(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	emitting := make(chan struct{})
	d := newLifecycleSource(t, context.Background(), []string{"a"}, nil)
	// discoverFn closes over d, so it is installed after construction. Only
	// runDiscovery reads it, and Next starts that — so this is still race-free.
	d.discoverFn = func(innerCtx context.Context, _ string) error {
		close(emitting)
		// 300 records into a 100-slot channel nobody reads: this parks.
		_, err := d.saveAndEmitWithUUIDs(innerCtx, stubRequests(300), crawlRecordSource)
		if errors.Is(err, errEmitStopped) {
			return nil
		}
		return err
	}

	_, err := d.Next(context.Background())
	require.NoError(t, err, "the first item should come straight out of the buffer")
	<-emitting

	start := time.Now()
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case cerr := <-closed:
		require.NoError(t, cerr)
	case <-time.After(time.Second):
		t.Fatal("Close did not join the blocked emitter within 1s")
	}
	assert.Less(t, time.Since(start), time.Second)

	select {
	case <-d.finished:
	default:
		t.Fatal("Close returned before the producer finished")
	}
	assert.False(t, d.Stats().Abandoned, "the producer exited, so it must not be reported abandoned")
}

// TestDeparosDiscovery_PersistsAfterEmitStops is the point of splitting done from
// abort: when the consumer stops reading mid-emission the records are already paid
// for, so the remaining groups must still be written to the DB — they just stop
// becoming work items.
func TestDeparosDiscovery_PersistsAfterEmitStops(t *testing.T) {
	saver := newCaptureSaver()
	d := newTestDiscoverySource(saver)
	d.items = make(chan *work.WorkItem, 2) // smaller than group one

	groupOne := stubRequests(3)
	groupTwo := stubRequests(2)
	acc := newImportAccum(len(groupOne) + len(groupTwo))

	firstDone := make(chan error, 1)
	go func() { firstDone <- d.importGroup(context.Background(), acc, groupOne, crawlRecordSource) }()

	// Wait until the emitter has filled the buffer and is parked on record three,
	// then stop the consumer.
	require.Eventually(t, func() bool { return len(d.items) == 2 }, time.Second, 2*time.Millisecond)
	close(d.done)
	require.NoError(t, <-firstDone)

	assert.False(t, acc.emit, "emission must latch off once the consumer stops reading")

	require.NoError(t, d.importGroup(context.Background(), acc, groupTwo, jstangleRecordSource))

	assert.Equal(t, 3, saver.bySource[crawlRecordSource], "group one was saved before emission stopped")
	assert.Equal(t, 2, saver.bySource[jstangleRecordSource], "group two must still be persisted")
	assert.Len(t, d.items, 2, "group two must not be emitted")
	assert.Equal(t, 5, acc.imported)
	assert.Equal(t, 0, acc.failed)
}

// TestDeparosDiscovery_AllTargetsFailReportsOnceThenEOF locks in the latch in
// Next: both consumers (Executor.feedItems, ConcurrentMultiSource.readSource)
// treat a non-EOF error as "retry", so a sticky run error is an infinite loop.
func TestDeparosDiscovery_AllTargetsFailReportsOnceThenEOF(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	d := newLifecycleSource(t, context.Background(), []string{"a", "b"},
		func(context.Context, string) error { return errors.New("boom") })
	t.Cleanup(func() { _ = d.Close() })

	_, err := d.Next(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed for all 2 target(s)")
	assert.Contains(t, err.Error(), "boom")

	for i := range 3 {
		_, err = d.Next(context.Background())
		assert.ErrorIsf(t, err, io.EOF, "call %d after the reported error must be EOF", i+2)
	}

	stats := d.Stats()
	assert.Equal(t, 2, stats.TargetsFailed)
	assert.Len(t, stats.TargetErrors, 2)
}

// TestDeparosDiscovery_PartialFailureCounted: one failing target out of three is
// partial coverage, not a phase failure — the count and message are reportable,
// the source still ends in EOF.
func TestDeparosDiscovery_PartialFailureCounted(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	d := newLifecycleSource(t, context.Background(), []string{"a", "b", "c"},
		func(_ context.Context, target string) error {
			if target == "b" {
				return errors.New("refused")
			}
			return nil
		})
	t.Cleanup(func() { _ = d.Close() })

	_, err := d.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF, "a partial failure is not a run error")

	stats := d.Stats()
	assert.Equal(t, 1, stats.TargetsFailed)
	assert.Equal(t, 0, stats.TargetsSkipped)
	require.Len(t, stats.TargetErrors, 1)
	assert.Contains(t, stats.TargetErrors[0], "b: refused")
}

// TestDeparosDiscovery_TargetErrorsCapped keeps a sweep of thousands of hosts from
// turning the stats struct into a log dump while the count stays exact.
func TestDeparosDiscovery_TargetErrorsCapped(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	targets := make([]string, maxReportedTargetErrors+5)
	for i := range targets {
		targets[i] = fmt.Sprintf("t%d", i)
	}
	d := newLifecycleSource(t, context.Background(), targets,
		func(context.Context, string) error { return errors.New("nope") })
	t.Cleanup(func() { _ = d.Close() })

	_, err := d.Next(context.Background())
	require.Error(t, err)

	stats := d.Stats()
	assert.Equal(t, len(targets), stats.TargetsFailed, "the count stays exact")
	assert.Len(t, stats.TargetErrors, maxReportedTargetErrors)
}

// TestStats_CopiesTargetErrors: Stats hands out a snapshot, not the live slice —
// the producer keeps appending to it while the runner formats feedback.
func TestStats_CopiesTargetErrors(t *testing.T) {
	d := newTestDiscoverySource(newCaptureSaver())
	d.noteTargetError("a", errors.New("one"))

	snapshot := d.Stats()
	require.Len(t, snapshot.TargetErrors, 1)
	snapshot.TargetErrors[0] = "mutated"

	assert.Equal(t, "a: one", d.Stats().TargetErrors[0])
}

// TestImportContext covers the F10 fix in isolation: a live parent is used as-is,
// an expired one yields a detached context with its own drain budget so the local
// write of records already in hand can still land.
func TestImportContext(t *testing.T) {
	t.Run("live parent is used as-is", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		defer cancel()

		got, release := importContext(parent, time.Minute)
		defer release()

		assert.Equal(t, parent, got)
		_, hasDeadline := got.Deadline()
		assert.False(t, hasDeadline, "a live parent must not acquire a drain deadline")
	})

	t.Run("cancelled parent is detached with a drain budget", func(t *testing.T) {
		type ctxKey struct{}
		parent, cancel := context.WithCancel(context.WithValue(context.Background(), ctxKey{}, "kept"))
		cancel()

		got, release := importContext(parent, 2*time.Second)
		defer release()

		require.NoError(t, got.Err(), "the import context must be live even though the parent is not")
		assert.Equal(t, "kept", got.Value(ctxKey{}), "values must survive the detach")

		deadline, hasDeadline := got.Deadline()
		require.True(t, hasDeadline)
		assert.WithinDuration(t, time.Now().Add(2*time.Second), deadline, 500*time.Millisecond)
	})

	t.Run("non-positive drain falls back to the default", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		cancel()

		got, release := importContext(parent, 0)
		defer release()

		deadline, hasDeadline := got.Deadline()
		require.True(t, hasDeadline)
		assert.WithinDuration(t, time.Now().Add(defaultDiscoveryDrainTimeout), deadline, time.Second)
	})
}

// deadlineAwareSaver fails every save made on an expired context — exactly what
// the real repository did — and otherwise hands back deterministic UUIDs. It is
// the test double that makes the F10 regression visible.
type deadlineAwareSaver struct {
	mu       sync.Mutex
	bySource map[string]int
	expired  int
}

func newDeadlineAwareSaver() *deadlineAwareSaver {
	return &deadlineAwareSaver{bySource: map[string]int{}}
}

func (s *deadlineAwareSaver) SaveRecord(ctx context.Context, _ *httpmsg.HttpRequestResponse, source, _ string) (string, error) {
	uuids, err := s.save(ctx, 1, source)
	if err != nil {
		return "", err
	}
	return uuids[0], nil
}

func (s *deadlineAwareSaver) SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source, _ string) ([]string, error) {
	return s.save(ctx, len(records), source)
}

func (s *deadlineAwareSaver) save(ctx context.Context, n int, source string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		s.expired++
		return nil, err
	}
	base := s.bySource[source]
	s.bySource[source] += n
	uuids := make([]string, n)
	for i := range uuids {
		uuids[i] = fmt.Sprintf("%s-%d", source, base+i)
	}
	return uuids, nil
}

func (s *deadlineAwareSaver) counts() (map[string]int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.bySource))
	for k, v := range s.bySource {
		out[k] = v
	}
	return out, s.expired
}

// TestImportCollected_PersistsUnderAnExpiredPhase is the F10 regression test,
// driven at the decision rather than through a crawl.
//
// When the phase is cancelled (or a target burns its MaxDuration) the records
// already collected are paid for: the requests went out, the responses came
// back, and all that is left is a local write. Before the fix that write ran on
// the expired context, so every save failed, the executor re-saved the same
// requests under the "scanner" label, and the post-discovery cleanup — scoped to
// source='deparos' — skipped them along with the JSTangle artifacts keyed to
// them.
//
// The phase context is cancelled before the call, so there is no race: the
// condition under test is simply "ctx is dead", which is exactly what
// importContext branches on.
func TestImportCollected_PersistsUnderAnExpiredPhase(t *testing.T) {
	saver := newDeadlineAwareSaver()
	d := newTestDiscoverySource(saver)
	d.cfg.DrainTimeout = 5 * time.Second

	// Distinct URLs per group: uuidByURL is keyed by target URL, so reusing the
	// same paths across groups would collide and understate the mapping.
	crawled := stubRequestRange(0, 3)
	referenced := stubRequestRange(3, 2)
	specs := stubRequestRange(5, 1)

	phaseCtx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, phaseCtx.Err(), "the phase must already be dead for this to test anything")

	acc, err := d.importCollected(phaseCtx, nil, collectedGroups{
		sourceOrder: []string{crawlRecordSource, jstangleRecordSource},
		bySource: map[string][]*httpmsg.HttpRequestResponse{
			crawlRecordSource:    crawled,
			jstangleRecordSource: referenced,
		},
		specEndpoints: specs,
		sizeHint:      6,
	})
	require.NoError(t, err)

	counts, expired := saver.counts()
	assert.Zero(t, expired, "no save may be attempted on the expired phase context")
	assert.Equal(t, 3, counts[crawlRecordSource])
	assert.Equal(t, 2, counts[jstangleRecordSource])
	assert.Equal(t, 1, counts[specRecordSource])
	assert.NotContains(t, counts, "scanner", "discovery records must keep a discovery label")

	assert.Equal(t, 6, acc.imported, "every record in hand must be persisted and counted")
	assert.Zero(t, acc.failed)
	assert.Len(t, acc.uuidByURL, 6, "every saved record must be anchorable by URL")
}

// A live phase is used as-is: the detached drain budget is for the expired case
// only, and a running phase must not have its own deadline replaced.
func TestImportCollected_LivePhaseIsUsedAsIs(t *testing.T) {
	saver := newDeadlineAwareSaver()
	d := newTestDiscoverySource(saver)

	acc, err := d.importCollected(context.Background(), nil, collectedGroups{
		sourceOrder: []string{crawlRecordSource},
		bySource:    map[string][]*httpmsg.HttpRequestResponse{crawlRecordSource: stubRequests(2)},
		sizeHint:    2,
	})
	require.NoError(t, err)

	counts, expired := saver.counts()
	assert.Zero(t, expired)
	assert.Equal(t, 2, counts[crawlRecordSource])
	assert.Equal(t, 2, acc.imported)
}

// An aborted source stops persisting, and stops BEFORE the spec group: abort is
// "drop everything", unlike the consumer going away, which only stops emission.
func TestImportCollected_AbortStopsPersisting(t *testing.T) {
	saver := newDeadlineAwareSaver()
	d := newTestDiscoverySource(saver)
	close(d.abort)

	acc, err := d.importCollected(context.Background(), nil, collectedGroups{
		sourceOrder: []string{crawlRecordSource, jstangleRecordSource},
		bySource: map[string][]*httpmsg.HttpRequestResponse{
			crawlRecordSource:    stubRequests(2),
			jstangleRecordSource: stubRequests(2),
		},
		specEndpoints: stubRequests(1),
		sizeHint:      5,
	})
	require.NoError(t, err)
	assert.True(t, acc.aborted)

	counts, _ := saver.counts()
	assert.Equal(t, 2, counts[crawlRecordSource], "the group already in flight still lands")
	assert.NotContains(t, counts, jstangleRecordSource, "a later group must not be started")
	assert.NotContains(t, counts, specRecordSource, "the spec group must not be started")
}

// TestDiscoverTarget_PersistsUnderDiscoveryLabels covers the same guarantee on
// the real path: a live crawl against a live server, run to idle rather than cut
// off, and every record it stored carries a discovery label.
//
// Deliberately NOT time-boxed. The earlier version of this test set a phase
// deadline between "the first node is stored" (~1.0-1.5s) and "the crawl goes
// idle" (~3.1s) and asserted that records existed — a race against machine load
// that failed under a busy full-tree run with zero records collected. There is
// no budget that both reliably yields records and reliably expires, so the
// expiry half is tested deterministically above and this one waits for the crawl
// to finish on its own.
func TestDiscoverTarget_PersistsUnderDiscoveryLabels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<html><body><a href=\"/sub/\">sub</a> %s</body></html>", r.URL.Path)
	}))
	defer srv.Close()

	saver := newDeadlineAwareSaver()
	d, err := NewDeparosDiscoverySource(context.Background(), DeparosDiscoveryConfig{
		Targets:      []string{srv.URL},
		Concurrency:  4,
		MaxDuration:  time.Hour,
		DrainTimeout: 5 * time.Second,
		Repository:   saver,
		ProjectUUID:  "proj",
	})
	require.NoError(t, err)

	// Nobody consumes work items here — discoverTarget is driven directly, so
	// nothing ever closes d.items. Drain so the emitter is not what we measure.
	drainStop := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			select {
			case <-d.items:
			case <-drainStop:
				return
			}
		}
	}()

	runDone := make(chan error, 1)
	go func() { runDone <- d.discoverTarget(context.Background(), srv.URL) }()

	select {
	case derr := <-runDone:
		require.NoError(t, derr)
	case <-time.After(60 * time.Second):
		close(drainStop)
		<-drained
		t.Fatal("discoverTarget did not return")
	}
	close(drainStop)
	<-drained

	counts, expired := saver.counts()
	assert.Zero(t, expired, "a live phase must never produce a save on an expired context")

	total := 0
	for label, n := range counts {
		assert.NotEqual(t, "scanner", label, "discovery records must keep a discovery label")
		assert.Truef(t,
			label == crawlRecordSource || label == specRecordSource ||
				label == jstangleRecordSource || label == formRecordSource,
			"unexpected record source %q", label)
		total += n
	}
	require.Positive(t, total, "a crawl that ran to idle must have stored at least the start URL")

	stats := d.Stats()
	assert.Positive(t, stats.Imported, "persisted records must be counted as imported")
	assert.Zero(t, stats.ImportFailed)
	assert.Zero(t, stats.TargetsFailed)
	assert.Zero(t, stats.TargetsTimedOut, "an hour-long budget on a tiny site must not time out")
}

// TestTargetExhaustedBudget separates the two ways a target's context can end:
// its own time-box (designed, reported as timed out) from a cancelled phase
// (reported as skipped). Conflating them would show an operator's Ctrl-C as
// targets that ran long.
func TestTargetExhaustedBudget(t *testing.T) {
	live := context.Background()

	t.Run("own deadline with a live phase", func(t *testing.T) {
		targetCtx, cancel := context.WithTimeout(live, time.Nanosecond)
		defer cancel()
		<-targetCtx.Done()
		assert.True(t, targetExhaustedBudget(targetCtx, live))
	})

	t.Run("cancelled phase is not a timeout", func(t *testing.T) {
		phase, cancelPhase := context.WithCancel(live)
		targetCtx, cancel := context.WithTimeout(phase, time.Hour)
		defer cancel()
		cancelPhase()
		<-targetCtx.Done()
		assert.False(t, targetExhaustedBudget(targetCtx, phase),
			"the phase stopped it; that is skipped, not timed out")
	})

	t.Run("still running is neither", func(t *testing.T) {
		targetCtx, cancel := context.WithTimeout(live, time.Hour)
		defer cancel()
		assert.False(t, targetExhaustedBudget(targetCtx, live))
	})
}

// TestImportGroup_CountsUnsavedRecordsAsFailed: SaveRecordBatch returns "" for a
// record it could not convert or store, so counting the input over-reported every
// failure as an import.
func TestImportGroup_CountsUnsavedRecordsAsFailed(t *testing.T) {
	saver := &partialSaver{failIndexes: map[int]bool{1: true}}
	d := newTestDiscoverySource(saver)

	acc := newImportAccum(4)
	records := stubRequests(4)
	require.NoError(t, d.importGroup(context.Background(), acc, records, crawlRecordSource))

	assert.Equal(t, 3, acc.imported)
	assert.Equal(t, 1, acc.failed)
	assert.Len(t, acc.uuidByURL, 3)
	assert.NotContains(t, acc.uuidByURL, records[1].Target())
}

// TestImportGroup_NoRepositoryCountsEmitted: with nothing to persist to, a record
// that reached the scan is the only sense in which it can be "imported".
func TestImportGroup_NoRepositoryCountsEmitted(t *testing.T) {
	d := newTestDiscoverySource(nil)
	d.cfg.Repository = nil

	acc := newImportAccum(2)
	require.NoError(t, d.importGroup(context.Background(), acc, stubRequests(2), crawlRecordSource))

	assert.Equal(t, 2, acc.imported)
	assert.Equal(t, 0, acc.failed)
	assert.Empty(t, acc.uuidByURL, "no repository means no UUIDs to anchor artifacts to")
}

// partialSaver persists every record except the configured indexes, returning ""
// in their slots — the alignment contract SaveRecordBatch promises.
type partialSaver struct {
	failIndexes map[int]bool
}

func (p *partialSaver) SaveRecord(context.Context, *httpmsg.HttpRequestResponse, string, string) (string, error) {
	return "uuid", nil
}

func (p *partialSaver) SaveRecordBatch(_ context.Context, records []*httpmsg.HttpRequestResponse, source, _ string) ([]string, error) {
	out := make([]string, len(records))
	for i := range records {
		if p.failIndexes[i] {
			continue
		}
		out[i] = fmt.Sprintf("%s-%d", source, i)
	}
	return out, nil
}

// TestClose_IdempotentAndSafeBeforeStart: the runner calls Close on a source it may
// never have read from, and WP3 will call it from more than one place.
func TestClose_IdempotentAndSafeBeforeStart(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	d := newLifecycleSource(t, context.Background(), []string{"a"},
		func(context.Context, string) error { return nil })

	require.NoError(t, d.Close())
	require.NoError(t, d.Close())

	_, err := d.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF, "a closed source never starts the producer")
}

// TestClose_AbandonsUnstoppableProducer: a producer that ignores both done and
// abort must not hold the phase open forever — it is reported and left behind.
func TestClose_AbandonsUnstoppableProducer(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	d, err := NewDeparosDiscoverySource(context.Background(), DeparosDiscoveryConfig{
		Targets:      []string{"a"},
		DrainTimeout: 50 * time.Millisecond,
	})
	require.NoError(t, err)
	d.abortGrace = 50 * time.Millisecond
	entered := make(chan struct{})
	d.discoverFn = func(context.Context, string) error {
		close(entered)
		<-release // ignores ctx, done and abort alike
		return nil
	}

	go func() { _, _ = d.Next(context.Background()) }()
	<-entered

	// The bound is DrainTimeout + two abort-grace windows.
	start := time.Now()
	require.NoError(t, d.Close())
	elapsed := time.Since(start)

	assert.True(t, d.Stats().Abandoned, "giving up on the producer must be reported, not silent")
	assert.Greater(t, elapsed, 50*time.Millisecond, "Close must actually have waited")
	assert.Less(t, elapsed, 5*time.Second, "Close must not block the phase on an unstoppable producer")

	select {
	case <-d.abort:
	default:
		t.Fatal("Close must escalate to abort before abandoning the producer")
	}
}

// TestDiscoveryStats_SourceLabelsAreDistinct guards the label set the cleanup
// passes key on; a typo here silently changes which records get pruned.
func TestDiscoveryStats_SourceLabelsAreDistinct(t *testing.T) {
	labels := []string{crawlRecordSource, specRecordSource, jstangleRecordSource, formRecordSource}
	seen := map[string]bool{}
	for _, l := range labels {
		require.NotEmpty(t, l)
		require.False(t, strings.EqualFold(l, "scanner"), "a discovery label must never collide with the executor's")
		require.False(t, seen[l], "duplicate discovery source label %q", l)
		seen[l] = true
	}
}
