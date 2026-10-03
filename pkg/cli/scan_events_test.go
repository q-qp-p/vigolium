package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

func TestApplyScanCompletion(t *testing.T) {
	for _, tc := range []struct {
		name           string
		status         string
		scan           *database.Scan
		wantStatus     string
		wantStopReason string
		wantReasons    []string
	}{
		{
			name:       "complete scan is untouched",
			status:     scanevents.StatusCompleted,
			scan:       &database.Scan{Completeness: database.CompletenessComplete},
			wantStatus: scanevents.StatusCompleted,
		},
		{
			// An empty completeness is unknown — a row written by an older
			// binary, or by a caller with no outcome data — and must never be
			// read as a curtailment OR as a clean run.
			name:       "unknown completeness is untouched",
			status:     scanevents.StatusCompleted,
			scan:       &database.Scan{},
			wantStatus: scanevents.StatusCompleted,
		},
		{
			name:   "partial downgrades completed to curtailed",
			status: scanevents.StatusCompleted,
			scan: &database.Scan{
				Completeness: database.CompletenessPartial,
				StopReason:   database.ReasonScanBudget,
				PhaseOutcomes: []database.PhaseOutcome{
					{Phase: "discovery", State: database.PhasePartial, Reasons: []string{database.ReasonTargetsFailed}},
					{Phase: "known-issue-scan", State: database.PhaseSkipped, Reasons: []string{database.ReasonScanBudget}},
				},
			},
			wantStatus:     scanevents.StatusCurtailed,
			wantStopReason: database.ReasonScanBudget,
			wantReasons:    []string{database.ReasonScanBudget, database.ReasonTargetsFailed},
		},
		{
			// A scan that FAILED is not a scan that was curtailed; relabelling it
			// would lose the more serious of the two facts. The reasons still ride
			// along so a consumer can see what else went short.
			name:   "failed keeps its status",
			status: scanevents.StatusFailed,
			scan: &database.Scan{
				Completeness: database.CompletenessPartial,
				StopReason:   database.ReasonError,
				PhaseOutcomes: []database.PhaseOutcome{
					{Phase: "discovery", State: database.PhaseFailed, Reasons: []string{database.ReasonTargetsFailed}},
				},
			},
			wantStatus:     scanevents.StatusFailed,
			wantStopReason: database.ReasonError,
			wantReasons:    []string{database.ReasonTargetsFailed},
		},
		{
			name:   "interrupted keeps its status",
			status: scanevents.StatusInterrupted,
			scan: &database.Scan{
				Completeness: database.CompletenessPartial,
				StopReason:   database.ReasonCancelled,
			},
			wantStatus:     scanevents.StatusInterrupted,
			wantStopReason: database.ReasonCancelled,
		},
		{
			// Reasons are deduplicated across phases: three phases skipped by one
			// budget is one reason, not three.
			name:   "reasons are a sorted union",
			status: scanevents.StatusCompleted,
			scan: &database.Scan{
				Completeness: database.CompletenessPartial,
				PhaseOutcomes: []database.PhaseOutcome{
					{Phase: "a", Reasons: []string{database.ReasonScanBudget}},
					{Phase: "b", Reasons: []string{database.ReasonScanBudget, database.ReasonCancelled}},
					{Phase: "c", Reasons: []string{database.ReasonPhaseDeadline}},
				},
			},
			wantStatus: scanevents.StatusCurtailed,
			wantReasons: []string{
				database.ReasonCancelled, database.ReasonPhaseDeadline, database.ReasonScanBudget,
			},
		},
		{
			// Limits are not reasons: a configured bound being reached must not
			// make the terminal event report a curtailment.
			name:   "limits do not become reasons",
			status: scanevents.StatusCompleted,
			scan: &database.Scan{
				Completeness: database.CompletenessComplete,
				PhaseOutcomes: []database.PhaseOutcome{
					{Phase: "spidering", State: database.PhaseCompleted, Limits: []string{database.LimitTargetBudget}},
				},
			},
			wantStatus: scanevents.StatusCompleted,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := &scanevents.Event{Status: tc.status}
			applyScanCompletion(ev, tc.scan)

			if ev.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", ev.Status, tc.wantStatus)
			}
			if ev.StopReason != tc.wantStopReason {
				t.Errorf("StopReason = %q, want %q", ev.StopReason, tc.wantStopReason)
			}
			if !reflect.DeepEqual(ev.Reasons, tc.wantReasons) {
				t.Errorf("Reasons = %v, want %v", ev.Reasons, tc.wantReasons)
			}
		})
	}
}

func TestApplyScanCompletionNilSafe(t *testing.T) {
	// Both nils are reachable: the DB read can fail, and the helper is called
	// from a path that must not care.
	applyScanCompletion(nil, &database.Scan{Completeness: database.CompletenessPartial})

	ev := &scanevents.Event{Status: scanevents.StatusCompleted}
	applyScanCompletion(ev, nil)
	if ev.Status != scanevents.StatusCompleted {
		t.Errorf("a missing scan row changed the status to %q", ev.Status)
	}
}

func TestUnionPhaseReasons(t *testing.T) {
	if got := unionPhaseReasons(nil); got != nil {
		t.Errorf("unionPhaseReasons(nil) = %v, want nil", got)
	}
	if got := unionPhaseReasons([]database.PhaseOutcome{{Phase: "a"}}); got != nil {
		t.Errorf("a phase with no reasons must contribute nothing, got %v", got)
	}
}

func TestScanStatusCell(t *testing.T) {
	// A partial run must not read as a clean one in a listing — that is how a
	// curtailed scan gets mistaken for a usable baseline.
	if got := scanStatusCell(&database.Scan{Status: "completed", Completeness: database.CompletenessPartial}); !strings.Contains(got, "partial") {
		t.Errorf("partial cell = %q, want it to say partial", got)
	}
	if got := scanStatusCell(&database.Scan{Status: "completed", Completeness: database.CompletenessComplete}); strings.Contains(got, "partial") {
		t.Errorf("complete cell = %q, must not say partial", got)
	}
	// Unknown (older binary) renders as it always did.
	if got := scanStatusCell(&database.Scan{Status: "completed"}); strings.Contains(got, "partial") {
		t.Errorf("unknown cell = %q, must not say partial", got)
	}
	if got := scanStatusCell(&database.Scan{Status: "running"}); !strings.Contains(got, "running") {
		t.Errorf("running cell = %q", got)
	}
	if got := scanStatusCell(nil); got != "" {
		t.Errorf("nil scan = %q, want empty", got)
	}
}

// One rule, one answer: a phase skipped only for no_modules is not a gap, and
// unionPhaseReasons used to be the one of the three places that said otherwise
// — putting a reason on scan.finished that the partial banner and the phase
// line both, correctly, left out.
func TestUnionPhaseReasonsSkipsBenignSkips(t *testing.T) {
	phases := []database.PhaseOutcome{
		{Phase: "known-issue-scan", State: database.PhaseSkipped, Reasons: []string{database.ReasonNoModules}},
		{Phase: "discovery", State: database.PhasePartial, Reasons: []string{database.ReasonTargetsFailed}},
	}
	got := unionPhaseReasons(phases)
	if !reflect.DeepEqual(got, []string{database.ReasonTargetsFailed}) {
		t.Errorf("reasons = %v, want only %q", got, database.ReasonTargetsFailed)
	}

	// A phase skipped for a real reason still contributes it.
	phases[0].Reasons = []string{database.ReasonScanBudget}
	got = unionPhaseReasons(phases)
	if len(got) != 2 {
		t.Errorf("a phase skipped by the budget is a gap; reasons = %v", got)
	}

	// And a FAILED phase is never a benign skip, however few reasons it carries.
	failed := []database.PhaseOutcome{
		{Phase: "discovery", State: database.PhaseFailed, Reasons: []string{database.ReasonNoModules}},
	}
	if got := unionPhaseReasons(failed); len(got) != 1 {
		t.Errorf("a failed phase's reasons must survive; got %v", got)
	}
}

// installTestEmitter points the process stream at a buffer for one test.
func installTestEmitter(t *testing.T, uuid string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := scanevents.Default()
	scanevents.Install(scanevents.New(&buf, uuid))
	t.Cleanup(func() { scanevents.Install(prev) })
	return &buf
}

// decodeEvents parses every NDJSON line in buf.
func decodeEvents(t *testing.T, buf *bytes.Buffer) []scanevents.Event {
	t.Helper()
	var out []scanevents.Event
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var ev scanevents.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("event line is not JSON: %v (%q)", err, line)
		}
		out = append(out, ev)
	}
	return out
}

// An interrupted scan must say so on the stream, and must still report the
// totals it managed to write — the whole point of emitting the terminal event
// from the normal exit path rather than from the signal handler.
func TestEmitReportsInterruptedWithTotals(t *testing.T) {
	buf := installTestEmitter(t, "scan-int")

	prev := activeScanSignals
	t.Cleanup(func() { activeScanSignals = prev })
	activeScanSignals = &scanSignalCoordinator{ch: make(chan os.Signal, 1), done: make(chan struct{})}
	activeScanSignals.interrupted.Store(true)

	ev := scanevents.Event{Status: scanevents.StatusCompleted, RecordsWritten: scanevents.Int64(42)}
	emit := func(runErr error) {
		switch {
		case runErr != nil:
			ev.Status = scanevents.StatusFailed
		case activeScanSignals.Interrupted():
			ev.Status = scanevents.StatusInterrupted
		}
		scanevents.Finish(ev)
	}
	emit(nil)

	events := decodeEvents(t, buf)
	require.Len(t, events, 1)
	last := events[len(events)-1]
	assert.Equal(t, scanevents.TypeScanFinished, last.Type)
	assert.Equal(t, scanevents.StatusInterrupted, last.Status)
	require.NotNil(t, last.RecordsWritten)
	assert.Equal(t, int64(42), *last.RecordsWritten, "the totals prepare measured must survive")
}

// The defer order is the whole contract: prepare runs while the database is
// open, the --db-isolate merge runs after it, and emit runs after the merge so
// a merge failure is reported as a failed scan rather than a completed one.
func TestTerminalEventAfterMergeFailure(t *testing.T) {
	var order []string
	mergeErr := errors.New("merge failed")
	var status string

	run := func() (err error) {
		var emit func(error)
		// Registered first → runs last, after the merge below.
		defer func() {
			if emit != nil {
				emit(err)
			}
		}()
		// The db-isolate merge, which can turn a successful scan into a failure.
		defer func() {
			order = append(order, "merge")
			err = mergeErr
		}()

		prepared := false
		emit = func(runErr error) {
			order = append(order, "emit")
			if !prepared {
				t.Error("emit ran before prepare; the totals would be missing")
			}
			status = "completed"
			if runErr != nil {
				status = "failed"
			}
		}
		defer func() {
			order = append(order, "prepare")
			prepared = true
		}()
		return nil
	}

	if err := run(); !errors.Is(err, mergeErr) {
		t.Fatalf("run() = %v, want the merge error", err)
	}
	assert.Equal(t, []string{"prepare", "merge", "emit"}, order)
	assert.Equal(t, "failed", status,
		"a run whose results never reached the real database did not complete")
}
