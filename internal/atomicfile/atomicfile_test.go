package atomicfile

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteBytesReplacesCleanlyAndIsReadable(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "body.json")

	if err := WriteBytes(dest, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("WriteBytes: %v", err)
	}
	if data, err := os.ReadFile(dest); err != nil {
		t.Fatal(err)
	} else if string(data) != `{"a":1}` {
		t.Errorf("contents = %q", data)
	}

	if err := WriteBytes(dest, []byte(`{"b":2}`)); err != nil {
		t.Fatalf("second write: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("temporary files survived the rename: %v", names)
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	// CreateTemp's 0600 would make every artifact the CLI writes owner-only,
	// which is not what a file the caller named should be. Compared against a
	// reference open(2) rather than the literal 0644, because the mode is now
	// applied at creation and the umask applies to it — which is the point of
	// WriteFile, and a test that pinned the literal would fail for anyone
	// running with a restrictive umask instead of reporting a real regression.
	want := referencePerm(t, filepath.Join(dir, "reference"), 0o644)
	if perm := info.Mode().Perm(); perm != want {
		t.Errorf("mode = %o, want %o", perm, want)
	}
}

// referencePerm creates a file at path with mode and returns the mode it
// actually landed at, i.e. mode minus the process umask.
func referencePerm(t *testing.T, path string, mode os.FileMode) os.FileMode {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		t.Fatalf("reference open: %v", err)
	}
	_ = f.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("reference stat: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("reference remove: %v", err)
	}
	return info.Mode().Perm()
}

// A failed write fn must leave the previous destination intact and clear its own
// staging file away, not just avoid the rename.
func TestWriteFailureKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "report.jsonl")
	if err := os.WriteFile(dest, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	boom := errors.New("read failed halfway")
	err := WriteFile(dest, 0o644, func(w *bufio.Writer) error {
		if _, werr := w.WriteString("partial line without a newline"); werr != nil {
			return werr
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Errorf("destination = %q, want the previous content", data)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("staging file survived the failure: %s", e.Name())
		}
	}
}

// Write (no mode) keeps the temp file's 0600, which is right for a path the
// caller did not name and did not ask to publish.
func TestWriteKeeps0600(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "stage.jsonl")
	if err := Write(dest, func(w *bufio.Writer) error {
		_, err := w.WriteString("{}\n")
		return err
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

// A failed write must leave any existing destination exactly as it was — the
// whole reason for temp-and-rename over a direct open.
func TestWriteBytesLeavesDestinationOnFailure(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "evidence.bin")
	if err := os.WriteFile(dest, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the directory read-only here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := WriteBytes(dest, []byte("replacement")); err == nil {
		t.Fatal("expected a failure writing into a read-only directory")
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Errorf("destination was damaged by a failed write: %q", data)
	}
}

// The staging file has to live in the destination directory for the rename to
// be atomic, so a process killed between creating one and renaming it leaves a
// ".tmp" behind. The next write to the same destination collects it.
func TestWriteSweepsAbandonedStagingFiles(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "export.jsonl")

	stale := filepath.Join(dir, ".export.jsonl.deadbeef.tmp")
	if err := os.WriteFile(stale, []byte("half an export"), 0o600); err != nil {
		t.Fatalf("seed stale staging file: %v", err)
	}
	old := time.Now().Add(-StaleAge - time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("age the stale file: %v", err)
	}

	// A staging file another process may still be filling, and an unrelated
	// dotfile for a different destination: neither is ours to remove.
	live := filepath.Join(dir, ".export.jsonl.cafebabe.tmp")
	other := filepath.Join(dir, ".somethingelse.0001.tmp")
	for _, p := range []string{live, other} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	if err := os.Chtimes(other, old, old); err != nil {
		t.Fatalf("age the unrelated file: %v", err)
	}

	if err := WriteBytes(dest, []byte("fresh\n")); err != nil {
		t.Fatalf("WriteBytes: %v", err)
	}

	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an abandoned staging file for this destination must be collected (err=%v)", err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Errorf("a recent staging file may belong to a live writer: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("a staging name for a different destination is not ours to remove: %v", err)
	}
	if got, err := os.ReadFile(dest); err != nil || string(got) != "fresh\n" {
		t.Errorf("destination = %q, %v; want \"fresh\\n\"", got, err)
	}
}

// SweepStale runs on the way in to every write, including into a directory that
// does not exist yet. It must not fail, and it must not create one.
func TestSweepStaleToleratesAMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if n := SweepStale(missing, ".x.*.tmp"); n != 0 {
		t.Errorf("swept %d entries from a directory that does not exist", n)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the sweep must not create the directory (err=%v)", err)
	}
}
