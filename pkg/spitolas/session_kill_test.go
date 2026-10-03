package spitolas

import "testing"

// TestSpiderSessionKillIsSafeWithoutABrowser: the runner's abandonment paths call
// Kill on a session whose state is whatever a wedged crawl left behind, including
// a session that never got a browser. It must not panic there — a panic in the
// path that exists to stop a leak would take the scan with it.
func TestSpiderSessionKillIsSafeWithoutABrowser(t *testing.T) {
	var nilSession *SpiderSession
	nilSession.Kill()

	(&SpiderSession{}).Kill()

	// And after a Close, which is the ordering a racing watchdog produces.
	s := &SpiderSession{closed: true}
	s.Kill()
	s.Kill()
}
