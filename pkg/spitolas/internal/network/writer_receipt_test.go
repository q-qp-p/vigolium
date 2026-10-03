package network

import (
	"errors"
	"testing"
	"time"
)

func TestWriterReceipt_CleanClose(t *testing.T) {
	saver := &fakeRecordSaver{}
	w := NewRepositoryWriter(saver, "test", "project-uuid")
	for i := range 5 {
		if err := w.Write(admissionEntry(i)); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if r := w.Receipt(); r.Closed || r.DrainComplete {
		t.Errorf("an open writer's receipt must not claim a finished drain: %+v", r)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	want := Receipt{Accepted: 5, Persisted: 5, DrainComplete: true, Closed: true}
	if got := w.Receipt(); got != want {
		t.Errorf("Receipt = %+v, want %+v", got, want)
	}
}

func TestWriterReceipt_FailingSaver(t *testing.T) {
	w := NewRepositoryWriter(&fakeRecordSaver{failAll: true}, "test", "project-uuid")
	for i := range 4 {
		_ = w.Write(admissionEntry(i))
	}
	closeErr := w.Close()
	r := w.Receipt()
	if r.Accepted != 4 || r.Persisted != 0 || r.Failed != 4 {
		t.Errorf("Receipt = %+v, want 4 accepted, 0 persisted, 4 failed", r)
	}
	if !r.DrainComplete {
		t.Error("every record got an outcome (failed), so the drain completed")
	}
	if closeErr == nil || r.Err != closeErr.Error() {
		t.Errorf("Receipt.Err = %q, want Close's error %v", r.Err, closeErr)
	}
}

func TestWriterReceipt_RefusedAfterClose(t *testing.T) {
	w := NewRepositoryWriter(&fakeRecordSaver{}, "test", "project-uuid")
	_ = w.Write(admissionEntry(0))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := w.Write(admissionEntry(i + 1)); !errors.Is(err, ErrWriterClosed) {
			t.Fatalf("Write after Close = %v", err)
		}
	}
	if r := w.Receipt(); r.Accepted != 1 || r.Refused != 3 || r.Persisted != 1 {
		t.Errorf("Receipt = %+v, want 1 accepted/persisted and 3 refused", r)
	}
	// A second Close returns the same (nil) result without re-reporting.
	if err := w.Close(); err != nil {
		t.Errorf("second Close = %v", err)
	}
}

// TestWriterReceipt_AbandonedDrain: a stalled saver plus a backlog larger than
// one batch makes the final drain run out of budget with records still queued —
// the only state in which DrainComplete is false after Close.
func TestWriterReceipt_AbandonedDrain(t *testing.T) {
	withShortWriterBudgets(t, 200*time.Millisecond, 200*time.Millisecond)
	saver := &fakeRecordSaver{block: make(chan struct{})}
	defer saver.unblock()
	w := NewRepositoryWriter(saver, "test", "project-uuid")

	const n = writerQueueSize - 12
	for i := range n {
		if err := w.Write(admissionEntry(i)); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if err := w.Close(); err == nil {
		t.Fatal("Close must report the lost records")
	}
	r := w.Receipt()
	if r.DrainComplete {
		t.Errorf("drain abandoned records but reported complete: %+v", r)
	}
	if r.Accepted != n || r.Persisted != 0 || r.Failed != n {
		t.Errorf("Receipt = %+v, want every one of %d accepted records failed", r, n)
	}
}
