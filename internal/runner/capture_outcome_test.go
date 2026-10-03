package runner

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// newCaptureTracker builds a bare phase tracker for the outcome assertions
// below. The browser phases reach theirs through r.currentPhase, which needs a
// whole Runner; nothing here does.
func newCaptureTracker() *phaseTracker {
	return &phaseTracker{phase: "spidering", start: time.Now()}
}

// TestCaptureOutcomeTranslation pins the mapping between the browser's capture
// receipt and the persistence vocabulary the scan row reports. The two types
// stay separate on purpose (Refused is known-lost, Unknown may have landed, and
// a spec-ingested row can push Persisted past Accepted), so this is the one
// place the translation is stated.
func TestCaptureOutcomeTranslation(t *testing.T) {
	for _, tc := range []struct {
		name string
		rc   spitolas.CaptureReceipt
		want database.PersistenceOutcome
	}{
		{
			name: "capture never ran",
			rc:   spitolas.CaptureReceipt{},
			want: database.PersistenceOutcome{},
		},
		{
			name: "clean drain",
			rc: spitolas.CaptureReceipt{
				Enabled: true, Accepted: 10, Persisted: 10, DrainComplete: true,
			},
			want: database.PersistenceOutcome{
				Writer: database.PersistenceWriterRecords, Accepted: 10, Committed: 10,
			},
		},
		{
			// Refused and Failed are both "captured and did not reach the
			// database", which is what Failed means on this side.
			name: "lost records",
			rc: spitolas.CaptureReceipt{
				Enabled: true, Accepted: 10, Persisted: 6, Failed: 3, Refused: 1, DrainComplete: true,
			},
			want: database.PersistenceOutcome{
				Writer: database.PersistenceWriterRecords, Accepted: 10, Committed: 6, Failed: 4,
			},
		},
		{
			name: "abandoned drain leaves entries unresolved",
			rc: spitolas.CaptureReceipt{
				Enabled: true, Accepted: 10, Persisted: 4, Failed: 1,
			},
			want: database.PersistenceOutcome{
				Writer: database.PersistenceWriterRecords, Accepted: 10, Committed: 4,
				Failed: 1, Unknown: 5, TimedOut: true,
			},
		},
		{
			// Spec ingest persists endpoints the capture never accepted, so the
			// difference can be negative without anything being wrong.
			name: "persisted exceeds accepted",
			rc: spitolas.CaptureReceipt{
				Enabled: true, Accepted: 2, Persisted: 9,
			},
			want: database.PersistenceOutcome{
				Writer: database.PersistenceWriterRecords, Accepted: 2, Committed: 9, TimedOut: true,
			},
		},
		{
			// A wedged crawl's receipt carries no counts at all.
			name: "incomplete receipt",
			rc:   spitolas.IncompleteCaptureReceipt(),
			want: database.PersistenceOutcome{
				Writer: database.PersistenceWriterRecords, TimedOut: true,
			},
		},
	} {
		if got := captureOutcome(tc.rc); got != tc.want {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.name, got, tc.want)
		}
	}
}

// A crawl that lost its whole corpus to a failing database used to write
// state: "completed" into phase_outcomes — the fact reached only a yellow
// suffix on a stderr line, because spidering closes its RecordWriter
// fire-and-forget rather than through shutdownWriters.
func TestRecordCaptureMarksLostRecordsPartial(t *testing.T) {
	tracker := newCaptureTracker()
	recordCapture(tracker, spitolas.CaptureReceipt{
		Enabled: true, Accepted: 40, Persisted: 0, Failed: 40, DrainComplete: true,
	})

	out := tracker.outcome()
	if out.State != database.PhasePartial {
		t.Errorf("state = %q, want %q", out.State, database.PhasePartial)
	}
	if len(out.Reasons) != 1 || out.Reasons[0] != database.ReasonPersistence {
		t.Errorf("reasons = %v, want [%s]", out.Reasons, database.ReasonPersistence)
	}
	if out.Persistence == nil {
		t.Fatal("the counts must reach the phase outcome, not just the banner")
	}
	if out.Persistence.Accepted != 40 || out.Persistence.Failed != 40 {
		t.Errorf("persistence = %+v, want accepted=40 failed=40", *out.Persistence)
	}
}

// A receipt abandoned before its writer drained carries NO counts, so the
// persistence outcome alone is "clean" by its own rule. The receipt is the
// authority on whether capture is accounted for, so its verdict decides.
func TestRecordCaptureMarksAbandonedDrainPartial(t *testing.T) {
	tracker := newCaptureTracker()
	recordCapture(tracker, spitolas.IncompleteCaptureReceipt())

	out := tracker.outcome()
	if out.State != database.PhasePartial {
		t.Errorf("state = %q, want %q — a wedged crawl is not a complete phase", out.State, database.PhasePartial)
	}
	if len(out.Reasons) != 1 || out.Reasons[0] != database.ReasonPersistence {
		t.Errorf("reasons = %v, want [%s]", out.Reasons, database.ReasonPersistence)
	}
}

// A clean crawl must stay clean: the whole contract is that `partial` now means
// something, which it would not if every crawl earned it.
func TestRecordCaptureLeavesACleanCrawlAlone(t *testing.T) {
	tracker := newCaptureTracker()
	recordCapture(tracker, spitolas.CaptureReceipt{
		Enabled: true, Accepted: 25, Persisted: 25, DrainComplete: true,
	})

	out := tracker.outcome()
	if out.State != database.PhaseCompleted {
		t.Errorf("state = %q, want %q", out.State, database.PhaseCompleted)
	}
	if len(out.Reasons) != 0 {
		t.Errorf("a clean crawl carries no reasons, got %v", out.Reasons)
	}
	if out.Persistence == nil || out.Persistence.Committed != 25 {
		t.Errorf("the counts are still reported for a clean crawl: %+v", out.Persistence)
	}
}

// A run with no browser capture at all must not acquire a persistence block it
// has nothing to say about.
func TestRecordCaptureIgnoresDisabledCapture(t *testing.T) {
	tracker := newCaptureTracker()
	recordCapture(tracker, spitolas.CaptureReceipt{})

	out := tracker.outcome()
	if out.State != database.PhaseCompleted {
		t.Errorf("state = %q, want %q", out.State, database.PhaseCompleted)
	}
	if out.Persistence != nil {
		t.Errorf("no capture means no persistence report, got %+v", *out.Persistence)
	}
}
