package core

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/output"
)

// TestSharedAdmissionSpansExecutors is the WP13 headline: the dynamic-assessment
// phase builds a fresh executor per feedback round, so an executor-local cap
// restarted every round. A cap documented as holding for the remainder of the
// phase has to survive the executor that first applied it.
func TestSharedAdmissionSpansExecutors(t *testing.T) {
	shared := NewFindingAdmission()
	first := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 2, FindingAdmission: shared}}
	second := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 2, FindingAdmission: shared}}

	_, allowed := first.admitFinding("root-1", "noisy")
	assert.True(t, allowed, "first finding is under the cap")
	_, allowed = first.admitFinding("root-2", "noisy")
	assert.True(t, allowed, "second finding is at the cap")

	// Round two. The cap is already spent.
	_, allowed = second.admitFinding("root-3", "noisy")
	assert.False(t, allowed, "the cap must not reset for the next round's executor")

	// A different module still has its own budget.
	_, allowed = second.admitFinding("root-4", "quiet")
	assert.True(t, allowed, "the cap is per module, not per phase")
}

// TestExecutorLocalAdmissionIsTheDefault pins that a phase running one Execute
// is unaffected: no shared admission means each executor keeps its own state, as
// before.
func TestExecutorLocalAdmissionIsTheDefault(t *testing.T) {
	first := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 1}}
	second := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 1}}

	_, allowed := first.admitFinding("root-1", "noisy")
	assert.True(t, allowed)
	_, allowed = first.admitFinding("root-2", "noisy")
	assert.False(t, allowed, "the executor's own cap still applies")

	_, allowed = second.admitFinding("root-3", "noisy")
	assert.True(t, allowed, "a separate executor has its own cap when none is shared")

	assert.NotSame(t, first.admission(), second.admission())
	assert.Same(t, &first.caches.admission, first.admission())
}

// TestSharedAdmissionDuplicateAcrossExecutors covers the second half of F18: a
// root cause already admitted in an earlier round must not be re-admitted, which
// is what re-fired every callback and notification for a finding already
// reported.
func TestSharedAdmissionDuplicateAcrossExecutors(t *testing.T) {
	shared := NewFindingAdmission()
	first := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 10, FindingAdmission: shared}}
	second := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 10, FindingAdmission: shared}}

	isFirst, allowed := first.admitFinding("same-root", "mod")
	assert.True(t, isFirst)
	assert.True(t, allowed)

	isFirst, allowed = second.admitFinding("same-root", "mod")
	assert.False(t, isFirst, "a later round must not own an identity an earlier round admitted")
	assert.True(t, allowed, "it is still allowed — just not dispatched again")
}

// TestSharedAdmissionNoCallbackOnRediscovery is the same property observed
// end to end, through processResults: round two re-finds the root cause round one
// reported, and the result callback does not fire a second time.
func TestSharedAdmissionNoCallbackOnRediscovery(t *testing.T) {
	shared := NewFindingAdmission()

	round1, db1 := newRepoExecutor(t)
	round1.cfg.MaxFindingsPerModule = 5
	round1.cfg.FindingAdmission = shared
	var calls1 int
	round1.cfg.OnResult = func(*output.ResultEvent) { calls1++ }

	round2, _ := newRepoExecutor(t)
	round2.cfg.MaxFindingsPerModule = 5
	round2.cfg.FindingAdmission = shared
	var calls2 int
	round2.cfg.OnResult = func(*output.ResultEvent) { calls2++ }

	mod := &trackingPassiveModule{id: "rediscovery"}
	round1.processResults(context.Background(), []*output.ResultEvent{
		{URL: "https://example.com/a", DedupKey: "root-a"},
	}, mod, nil)
	assert.Equal(t, 1, calls1)
	assert.Len(t, loadFindings(t, db1), 1)

	round2.processResults(context.Background(), []*output.ResultEvent{
		{URL: "https://example.com/a?again=1", DedupKey: "root-a"},
	}, mod, nil)
	assert.Equal(t, 0, calls2, "a root cause reported in round 1 must not re-fire in round 2")
}

// TestSharedAdmissionAdmitsExactlyCapUnderRace drives 64 goroutines across three
// executors sharing one admission and requires exactly `cap` admissions.
func TestSharedAdmissionAdmitsExactlyCapUnderRace(t *testing.T) {
	const cap = 5
	shared := NewFindingAdmission()
	executors := []*Executor{
		{cfg: ExecutorConfig{MaxFindingsPerModule: cap, FindingAdmission: shared}},
		{cfg: ExecutorConfig{MaxFindingsPerModule: cap, FindingAdmission: shared}},
		{cfg: ExecutorConfig{MaxFindingsPerModule: cap, FindingAdmission: shared}},
	}

	const workers = 64
	start := make(chan struct{})
	admitted := make(chan bool, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// Distinct identity per worker, so every call makes a real cap
			// decision rather than inheriting a duplicate's.
			_, ok := executors[i%len(executors)].admitFinding(
				"root-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "shared-mod")
			admitted <- ok
		}(i)
	}
	close(start)
	wg.Wait()
	close(admitted)

	count := 0
	for ok := range admitted {
		if ok {
			count++
		}
	}
	assert.Equal(t, cap, count, "exactly the cap must be admitted across all executors")
}

func TestNewFindingAdmissionAndZeroValue(t *testing.T) {
	assert.NotNil(t, NewFindingAdmission())

	// The zero value must be usable: a literal &Executor{cfg: …} in a test and a
	// real NewExecutor both rely on it.
	var zero FindingAdmission
	e := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 1, FindingAdmission: &zero}}
	_, allowed := e.admitFinding("root", "mod")
	assert.True(t, allowed)
}
