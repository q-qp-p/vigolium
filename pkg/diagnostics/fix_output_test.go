package diagnostics

import (
	"bytes"
	"context"
	"os"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

// captureFixOut redirects installation progress into a buffer for the duration
// of a test.
func captureFixOut(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := fixOut
	fixOut = &buf
	t.Cleanup(func() { fixOut = orig })
	return &buf
}

// TestRunFixesWritesProgressToTheWriterNotStdout is the behavioral half of the
// first-run stdout fix.
//
// The first scan on a machine installs nuclei templates and Chrome for Testing
// through this function, and that scan may be running under `--events ndjson`
// — stdout carries the event stream and nothing else — or the caller may be
// `vigolium doctor --fix --json`, which prints one JSON document. Both were
// contaminated: the "Installing …" header and its "$ <command>" line were bare
// fmt.Printf calls, so a cold-$HOME NDJSON run began with four non-JSON lines.
//
// The nuclei-templates item is used because its failure is immediate and
// offline: with git pointed at a bogus path the Fix returns at once, after the
// header has already been printed, which is exactly the output under test.
func TestRunFixesWritesProgressToTheWriterNotStdout(t *testing.T) {
	buf := captureFixOut(t)

	// A PATH with no git makes the clone fail instantly instead of reaching the
	// network. The headers are printed before Fix runs, so they land either way.
	t.Setenv("PATH", t.TempDir())

	report := &Report{
		Tools:           map[string]*ToolCheck{},
		NucleiTemplates: &CheckResult{Status: StatusError},
	}

	results := RunFixes(context.Background(), report, config.DefaultSettings(), []string{"nuclei"})
	if len(results) == 0 {
		t.Fatal("expected a result for the nuclei-templates fix")
	}

	out := buf.String()
	if !strings.Contains(out, "Installing") {
		t.Errorf("install progress did not reach the fix writer; got %q", out)
	}
}

// TestFixOutDefaultsToStderr pins the destination itself. A future refactor
// that re-points the writer at stdout would pass every other test in this file.
//
// It checks the descriptor, not pointer identity with os.Stderr: non-verbose
// `go test -json` (gotestsum) re-points os.Stderr at fd 1 after package init,
// so the *os.File fixOut captured at init no longer equals os.Stderr there.
func TestFixOutDefaultsToStderr(t *testing.T) {
	f, ok := fixOut.(*os.File)
	if !ok || f.Fd() != uintptr(syscall.Stderr) {
		t.Errorf("fixOut must default to stderr so a --events/--json run's stdout stays machine-clean; got %T", fixOut)
	}
}

// TestFixNeverWritesToStdout is the lint half: most of these paths need a
// network fetch and a package manager to reach, so a source guard covers what
// the behavioral test above cannot.
func TestFixNeverWritesToStdout(t *testing.T) {
	src, err := os.ReadFile("fix.go")
	if err != nil {
		t.Fatalf("read fix.go: %v", err)
	}

	barePrint := regexp.MustCompile(`fmt\.Print(f|ln)?\(`)

	for i, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		switch {
		case barePrint.MatchString(line):
			t.Errorf("fix.go:%d writes to stdout directly; route it through fixf so a "+
				"first-run --events ndjson scan's stdout stays machine-clean:\n\t%s", i+1, trimmed)
		case strings.Contains(line, "os.Stdout"):
			t.Errorf("fix.go:%d references os.Stdout; installer output — including a "+
				"subprocess's — belongs on fixOut (stderr):\n\t%s", i+1, trimmed)
		}
	}
}

// TestSubprocessOutputIsRouted: a git clone or an npm install writes far more
// than vigolium's own lines, and every one of those inherited os.Stdout. The
// guard above catches the assignment; this records why every cmd.Stdout in the
// file must be fixOut.
func TestSubprocessOutputIsRouted(t *testing.T) {
	src, err := os.ReadFile("fix.go")
	if err != nil {
		t.Fatalf("read fix.go: %v", err)
	}
	n := strings.Count(string(src), "cmd.Stdout = fixOut")
	if n == 0 {
		t.Fatal("expected subprocess stdout to be wired to fixOut")
	}
	if got := strings.Count(string(src), "cmd.Stdout ="); got != n {
		t.Errorf("%d cmd.Stdout assignments but only %d route to fixOut", got, n)
	}
}
