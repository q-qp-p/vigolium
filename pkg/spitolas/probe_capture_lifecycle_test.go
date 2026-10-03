package spitolas

import (
	"os"
	"strings"
	"testing"
)

// TestProbeOwnsCaptureLifetime guards the probe's ownership of its capture.
//
// ProbeURL used to defer only writer.Close(). That flushed the records but left
// the Capture itself running: cleanupLoop exits on c.stopped, which only
// Capture.Close sets, and closing the browser ends event delivery without
// touching that flag. Every captured probe therefore stranded a polling
// goroutine plus the capture state it referenced — and ProbeURL is called
// repeatedly across a scan, so the leak scales with probe count.
//
// A source-shape guard because reproducing it needs a real browser: the
// behavioral half (that Close, and only Close, stops the loop) is covered by
// TestCleanupLoopStopsOnlyOnCaptureClose in the network package. What is checked
// here is that the probe actually calls it, that the start-failure path still
// closes the writer (whose flush goroutine starts in its constructor), and that
// the teardown order is right.
func TestProbeOwnsCaptureLifetime(t *testing.T) {
	src, err := os.ReadFile("probe.go")
	if err != nil {
		t.Fatalf("read probe.go: %v", err)
	}
	body := string(src)

	captureClose := strings.Index(body, "capture.Close()")
	if captureClose == -1 {
		t.Fatal("ProbeURL must close the capture, not just the writer — Capture.Close " +
			"is the only thing that sets c.stopped and stops cleanupLoop")
	}

	// The writer's flush goroutine is started by NewRepositoryWriter, so a failed
	// capture.Start still leaves one running.
	startFail := strings.Index(body, "capture start failed")
	if startFail == -1 {
		t.Fatal("capture start-failure branch not found; update this guard")
	}
	failBranch := body[startFail:]
	if end := strings.Index(failBranch, "\n\t}\n"); end != -1 {
		failBranch = failBranch[:end]
	}
	if !strings.Contains(failBranch, "writer.Close()") {
		t.Error("the capture start-failure path must close the writer; " +
			"NewRepositoryWriter starts its flush goroutine in the constructor")
	}

	// Deferred calls run LIFO, so the capture's defer must be registered AFTER the
	// browser's to run before it: the capture has to stop admitting records while
	// the browser is still alive, otherwise its in-flight body fetches race a
	// closing browser.
	browserClose := strings.Index(body, "br.Close()")
	switch {
	case browserClose == -1:
		t.Fatal("browser close defer not found; update this guard")
	case captureClose < browserClose:
		t.Error("the capture's deferred Close must be registered after the browser's " +
			"so LIFO tears the capture down first")
	}

	// The probe's receipt must come from the writer after the capture closed —
	// a receipt read before the drain would report records as persisted that
	// were still queued.
	receipt := strings.Index(body, "writer.Receipt()")
	switch {
	case receipt == -1:
		t.Error("ProbeURL must report the writer's receipt in ProbeResult.Capture")
	case receipt < captureClose:
		t.Error("the receipt must be read after capture.Close() has drained the writer")
	}
}
