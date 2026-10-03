package runner

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas"
)

// These guard the spidering watchdog — the hard guarantee that a wedged RunSpider
// (unresponsive/anti-bot browser, an unbounded rod CDP call, a stuck teardown)
// can never hang the scan forever. runWithWatchdog is the testable core;
// runSpiderWatchdog wraps it around the real (browser-driven) RunSpider.
//
// The second return value, `wedged`, is what the phases use to decide whether a
// shared browser session can still be closed. A wedge must be abandoned (closing
// an unresponsive browser hangs the phase the watchdog protects); an ordinary
// crawl failure must NOT be, because the browser is healthy and its record
// writer still holds that host's captured traffic. Conflating the two leaked a
// Chrome process per host group and discarded records earlier seeds had already
// produced — so every case below asserts `wedged`, not just the result.

// TestRunWithWatchdog_FastWorkReturnsResult: work that finishes before the
// timeout returns its own result and is not wedged; onTimeout is never called.
func TestRunWithWatchdog_FastWorkReturnsResult(t *testing.T) {
	var onTimeoutCalled bool
	got, wedged := runWithWatchdog(
		2*time.Second,
		func() string { return "work" },
		func() string { onTimeoutCalled = true; return "timeout" },
	)
	if got != "work" {
		t.Fatalf("got %q, want %q", got, "work")
	}
	if wedged {
		t.Error("work that finished in time must not be reported as wedged")
	}
	if onTimeoutCalled {
		t.Fatal("onTimeout was called even though work finished in time")
	}
}

// TestRunWithWatchdog_FailedWorkIsNotWedged is the distinction the phases turn
// on: BOTH the worker's own failure and a watchdog timeout produce a non-nil
// error, so an error-only signature would make them indistinguishable at exactly
// the point where the difference decides whether a browser gets closed.
func TestRunWithWatchdog_FailedWorkIsNotWedged(t *testing.T) {
	ordinary := errors.New("net::ERR_CONNECTION_REFUSED")

	got, wedged := runWithWatchdog(
		2*time.Second,
		func() error { return ordinary },
		func() error { return errors.New("timed out") },
	)
	if wedged {
		t.Error("a crawl that returned its own error must not be reported as wedged — " +
			"the browser is healthy and its writer still holds captured records")
	}
	if !errors.Is(got, ordinary) {
		t.Errorf("got %v, want the worker's own error", got)
	}
}

// TestRunWithWatchdog_WedgedWorkTimesOut: work that blocks past the timeout does
// NOT hang the caller — onTimeout's result is returned promptly with wedged
// true, within a small multiple of the timeout (proving the wedged worker is
// abandoned, not awaited).
func TestRunWithWatchdog_WedgedWorkTimesOut(t *testing.T) {
	release := make(chan struct{})
	defer close(release) // let the abandoned worker exit at test end

	const timeout = 100 * time.Millisecond
	start := time.Now()
	got, wedged := runWithWatchdog(
		timeout,
		func() string {
			<-release // simulate a wedged op that never returns on its own
			return "work"
		},
		func() string { return "timeout" },
	)
	elapsed := time.Since(start)

	if got != "timeout" {
		t.Fatalf("got %q, want %q (watchdog should have fired)", got, "timeout")
	}
	if !wedged {
		t.Error("a watchdog timeout must be reported as wedged, or the phase will " +
			"try to close a browser that is not answering")
	}
	// Must return ~at the timeout, not block on the wedged worker. Generous upper
	// bound to stay non-flaky on loaded CI.
	if elapsed > 2*time.Second {
		t.Fatalf("runWithWatchdog blocked %s on a wedged worker; the watchdog did not abandon it", elapsed)
	}
}

// TestRunWithWatchdog_LateWorkerDoesNotBlock: after the watchdog fires and the
// caller has moved on, the abandoned worker finishing later must not panic or
// deadlock on the (buffered) done channel.
func TestRunWithWatchdog_LateWorkerDoesNotBlock(t *testing.T) {
	finished := make(chan struct{})
	var once sync.Once

	got, wedged := runWithWatchdog(
		50*time.Millisecond,
		func() int {
			time.Sleep(300 * time.Millisecond) // finishes well after the watchdog fired
			once.Do(func() { close(finished) })
			return 1
		},
		func() int { return -1 },
	)
	if got != -1 || !wedged {
		t.Fatalf("got (%d, %v), want (-1, true) — the timeout path", got, wedged)
	}

	// The late worker must complete cleanly (buffered send, no deadlock/panic).
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("abandoned worker never finished — it likely blocked sending on the done channel")
	}
}

// TestCrawlOutcomeCarriesWedgedSeparatelyFromErr documents the struct contract
// the two watchdog wrappers return, since `wedged` is not derivable from `err`.
func TestCrawlOutcomeCarriesWedgedSeparatelyFromErr(t *testing.T) {
	ordinary := crawlOutcome{err: errors.New("navigation failed")}
	if ordinary.wedged {
		t.Error("a crawl that returned an error is not wedged by default")
	}

	timedOut := crawlOutcome{err: errors.New("timed out"), wedged: true}
	if !timedOut.wedged {
		t.Error("wedged must survive alongside err")
	}
}

// fakeRespiderSession stands in for a SpiderSession in the teardown path. Close
// blocks for closeDelay, so a test can make it outlast the watchdog.
type fakeRespiderSession struct {
	closeDelay time.Duration
	closeErr   error
	closes     atomic.Int64
	kills      atomic.Int64
}

func (f *fakeRespiderSession) Close() error {
	f.closes.Add(1)
	time.Sleep(f.closeDelay)
	return f.closeErr
}

func (f *fakeRespiderSession) Kill() { f.kills.Add(1) }

func (f *fakeRespiderSession) Receipt() spitolas.CaptureReceipt { return spitolas.CaptureReceipt{} }

// withShortTeardownGrace shortens the watchdog budget for one test. The
// production value is 90s, which no unit test can wait out.
func withShortTeardownGrace(t *testing.T, d time.Duration) {
	t.Helper()
	orig := spideringTeardownGrace
	spideringTeardownGrace = d
	t.Cleanup(func() { spideringTeardownGrace = orig })
}

// TestCloseReSpiderSessionKillsAWedgedBrowser: when the teardown watchdog fires,
// nothing will ever close the session, so its Chromium process and profile used
// to survive the rest of the scan — one per wedged host.
func TestCloseReSpiderSessionKillsAWedgedBrowser(t *testing.T) {
	withShortTeardownGrace(t, 100*time.Millisecond)
	sess := &fakeRespiderSession{closeDelay: 5 * time.Second}

	start := time.Now()
	_ = closeReSpiderSession(sess, nil)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("the teardown watchdog did not return promptly: %v", elapsed)
	}
	// Kill runs in its own goroutine (the launcher's kill waits for the process),
	// so give it a moment to land.
	deadline := time.Now().Add(2 * time.Second)
	for sess.kills.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := sess.kills.Load(); got != 1 {
		t.Fatalf("a wedged teardown killed the browser %d time(s), want 1", got)
	}
}

// TestCloseReSpiderSessionDoesNotKillOnACleanClose is the control: a teardown
// that completes must not reach for the kill, which would make every normal
// re-spider teardown pay the launcher's built-in wait.
func TestCloseReSpiderSessionDoesNotKillOnACleanClose(t *testing.T) {
	withShortTeardownGrace(t, 2*time.Second)
	sess := &fakeRespiderSession{}

	_ = closeReSpiderSession(sess, nil)

	if got := sess.closes.Load(); got != 1 {
		t.Fatalf("Close called %d time(s), want 1", got)
	}
	// Give any stray kill goroutine a chance to run before asserting none did.
	time.Sleep(50 * time.Millisecond)
	if got := sess.kills.Load(); got != 0 {
		t.Fatalf("a clean teardown killed the browser %d time(s), want 0", got)
	}
}

// TestCloseReSpiderSessionLostRecordsStillCloseCleanly: a Close that reports lost
// records completed — the browser is gone — so it must not be killed.
func TestCloseReSpiderSessionLostRecordsStillCloseCleanly(t *testing.T) {
	withShortTeardownGrace(t, 2*time.Second)
	sess := &fakeRespiderSession{closeErr: errors.New("3 records dropped")}

	_ = closeReSpiderSession(sess, nil)

	time.Sleep(50 * time.Millisecond)
	if got := sess.kills.Load(); got != 0 {
		t.Fatalf("a completed close that lost records killed the browser %d time(s), want 0", got)
	}
}
