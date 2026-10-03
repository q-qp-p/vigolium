//go:build !windows

package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/scanevents"
)

// eventPipeChildEnv switches the test binary into the child role below.
const eventPipeChildEnv = "VIGOLIUM_TEST_EVENT_PIPE_CHILD"

// TestEventsSurviveClosedPipe is the one behaviour a unit test cannot fake: Go
// raises SIGPIPE to the DEFAULT handler on a write to a closed fd 1, which kills
// the process outright. `vigolium scan --events ndjson | head -5` terminated a
// running scan mid-request, leaving no scan row and no findings, because a
// consumer had read as much as it wanted.
//
// It re-execs this binary as a child whose stdout is a pipe the parent closes.
// The child installs the production guard, writes past the closed end, and must
// exit 0 having printed the delivery warning on stderr.
func TestEventsSurviveClosedPipe(t *testing.T) {
	if os.Getenv(eventPipeChildEnv) != "" {
		runEventPipeChild()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestEventsSurviveClosedPipe", "-test.v=false")
	cmd.Env = append(os.Environ(), eventPipeChildEnv+"=1")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	// Close the read end before the child writes: every write it makes then
	// lands on a pipe with no reader.
	if err := stdout.Close(); err != nil {
		t.Fatalf("close read end: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("a closed event consumer must not kill the scan: %v\nchild stderr:\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "event stream delivery failed") {
		t.Errorf("the truncated stream must be reported on stderr, got:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "ran to completion") {
		t.Errorf("the warning must say the scan itself was unaffected, got:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "CHILD-REACHED-THE-END") {
		t.Errorf("the child must have run past every emit, got:\n%s", stderr.String())
	}
}

// runEventPipeChild is the child half: emit to a stdout nobody is reading, then
// report that it is still alive.
func runEventPipeChild() {
	stop := guardEventStreamPipe()
	scanevents.Install(scanevents.NewStdout("scan-pipe"))

	for range 64 {
		scanevents.Emit(scanevents.Event{Type: scanevents.TypePhaseProgress, Phase: "discovery"})
	}
	scanevents.Finish(scanevents.Event{Status: scanevents.StatusCompleted})
	stop()

	reportEventStreamDelivery()
	// Proof the process survived every write, not just the first.
	enc := json.NewEncoder(os.Stderr)
	_ = enc.Encode(map[string]any{"marker": "CHILD-REACHED-THE-END"})
	os.Exit(0)
}
