package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
)

// A requested artifact that was not written must reach the caller. Every one of
// these used to be a line on stderr and nothing else: the command exited 0, the
// --events stream said scan.finished status=completed, and the file was absent —
// three success signals for a run that produced no output.

func TestFinishStatelessExportReportsAnUnwritableDestination(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj", "a")

	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the export would succeed")
	}
	dir := filepath.Join(t.TempDir(), "readonly")
	require.NoError(t, os.Mkdir(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	out := filepath.Join(dir, "result.jsonl")
	opts := &types.Options{Stateless: true, OutputFormats: []string{"jsonl"}, Output: out}

	err := finishStatelessExport(db, opts, out, false)
	require.Error(t, err, "an export that wrote nothing reported success")
	assert.Contains(t, err.Error(), out)
	_, statErr := os.Stat(out)
	assert.True(t, os.IsNotExist(statErr), "no artifact should exist at %s", out)
}

// One bad format must not cost the operator the formats that CAN be written: a
// caller who asked for jsonl AND sqlite is better served by the one that landed
// than by neither. The run still fails — it just fails with the other file on
// disk.
func TestFinishStatelessExportWritesWhatItCanAndStillFails(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj", "a")

	base := filepath.Join(t.TempDir(), "result")
	// A non-empty directory sitting on the sqlite artifact's path makes that one
	// format fail at the final rename — staging succeeds, since it lands under its
	// own name in the same parent — while jsonl beside it succeeds.
	require.NoError(t, os.Mkdir(base+".sqlite", 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(base+".sqlite", "occupied"), []byte("x"), 0o600))

	opts := &types.Options{Stateless: true, OutputFormats: []string{"jsonl", "sqlite"}, Output: base}

	err := finishStatelessExport(db, opts, base, false)
	require.Error(t, err, "the sqlite format could not be written and the export reported success")
	assert.Contains(t, err.Error(), "sqlite")

	info, statErr := os.Stat(base + ".jsonl")
	require.NoError(t, statErr, "the format that could be written was skipped after the other one failed")
	assert.Positive(t, info.Size())
}

// The destructive failure: exportStatelessSQLite used to os.Remove the
// destination before VACUUM INTO, so a copy that could not finish left the
// operator with neither the new export nor the artifact it replaced.
func TestExportStatelessSQLiteKeepsThePreviousArtifactOnFailure(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj", "a")

	out := filepath.Join(t.TempDir(), "prior.sqlite")
	const priorContent = "the previous good export"
	require.NoError(t, os.WriteFile(out, []byte(priorContent), 0o600))

	// A cancelled context fails the VACUUM after staging has already begun —
	// standing in for the full disk, the Ctrl-C, and the killed process that all
	// reach the same point.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := exportStatelessSQLite(ctx, db, out)
	require.Error(t, err)

	got, readErr := os.ReadFile(out)
	require.NoError(t, readErr, "the previous artifact was deleted by a failed export")
	assert.Equal(t, priorContent, string(got), "the previous artifact was overwritten by a failed export")

	// The artifact is also the ONLY thing left: a staging file abandoned in the
	// operator's output directory looks like a result.
	entries, listErr := os.ReadDir(filepath.Dir(out))
	require.NoError(t, listErr)
	require.Len(t, entries, 1, "a failed export left litter beside the artifact")
	assert.Equal(t, filepath.Base(out), entries[0].Name())
}

func TestExportStatelessSQLiteReplacesAnExistingArtifact(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj", "a")

	out := filepath.Join(t.TempDir(), "result.sqlite")
	require.NoError(t, os.WriteFile(out, []byte("stale"), 0o600))
	// A stale sidecar describes the file being replaced, not the new one; left in
	// place SQLite would rather trust it than the fresh database beside it.
	require.NoError(t, os.WriteFile(out+"-wal", []byte("stale wal"), 0o600))

	got, err := exportStatelessSQLite(context.Background(), db, out)
	require.NoError(t, err)
	assert.Equal(t, out, got.path)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	assert.True(t, strings.HasPrefix(string(data), "SQLite format 3"),
		"the export did not replace the stale file with a real database")

	_, walErr := os.Stat(out + "-wal")
	assert.True(t, os.IsNotExist(walErr), "a stale -wal survived the export")
}

// recordExportFailure's precedence is a contract, not an implementation detail:
// it decides what a CI job and an agent see.
func TestRecordExportFailurePrecedence(t *testing.T) {
	exportErr := errors.New("export jsonl /tmp/out.jsonl: permission denied")

	t.Run("no error yet: the export failure becomes the result", func(t *testing.T) {
		var err error
		recordExportFailure(&err, exportErr)
		require.Error(t, err)
		assert.Equal(t, ExitError, classifyExitCode(err))
		assert.Equal(t, errCodeExportFailed, classifyErrorCode(err, ExitError))
	})

	t.Run("nothing failed: the result stays clean", func(t *testing.T) {
		var err error
		recordExportFailure(&err, nil)
		assert.NoError(t, err)
	})

	t.Run("a hard scan error wins: it is the cause", func(t *testing.T) {
		scanErr := fmt.Errorf("runner: target unreachable")
		err := scanErr
		recordExportFailure(&err, exportErr)
		assert.Equal(t, scanErr, err,
			"the export failed because the scan did; reporting the export hides the cause")
	})

	// The --fail-on gate is a COMPLETED result whose premise is that the output was
	// written before the code was chosen; when it wasn't, exit 4 would send a CI job
	// to read a file that does not exist. The gate is layered on by the CALLER
	// (withFailOnGate in runScanCmd), outside the defers that run
	// recordExportFailure — so what makes the export failure win is withFailOnGate
	// yielding to it as `prior`, not a branch inside recordExportFailure. Pin the
	// mechanism that actually runs.
	t.Run("the fail-on gate yields to a recorded export failure", func(t *testing.T) {
		var err error
		recordExportFailure(&err, exportErr)
		gated := withFailOnGate(err)
		assert.Equal(t, ExitError, classifyExitCode(gated),
			"a gate verdict whose artifact is missing must not report exit 4")
		assert.Equal(t, errCodeExportFailed, classifyErrorCode(gated, ExitError))
	})
}

// unwritableExportDir returns a path inside a directory that does not exist, so
// a write there fails the same way for every user — including root, for whom
// the permission trick above is a no-op.
func unwritableExportDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "absent")
}

// The persisted path's two artifact steps used to print and swallow: a scan
// whose html report could not be written exited 0.
func TestMaybeGenerateReportsReturnsFailure(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj-reports", "a")

	opts := types.DefaultOptions()
	opts.ProjectUUID = "proj-reports"
	opts.Output = filepath.Join(unwritableExportDir(t), "report.html")
	opts.OutputFormats = []string{"html"}
	// Stateless skips the scan-scope filter; this temp DB holds only this data.
	opts.Stateless = true

	err := maybeGenerateReports(db, opts)
	require.Error(t, err, "an unwritable report path must fail the run, not just print")
	assert.Contains(t, err.Error(), "generate", "the error must name the step")
	assert.Contains(t, err.Error(), opts.Output, "the error must name the path that failed")

	// A run that asked for no report cannot fail at this step.
	clean := types.DefaultOptions()
	assert.NoError(t, maybeGenerateReports(db, clean))
}

func TestFinishFSExportReturnsFailure(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj-fs", "b")

	// The fs export creates its own directories, so a missing parent is not a
	// failure. A regular FILE where a parent directory has to go is: mkdir
	// refuses, on every platform and for root too.
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(blocked, []byte("x"), 0o600))

	opts := types.DefaultOptions()
	opts.ProjectUUID = "proj-fs"
	opts.Output = filepath.Join(blocked, "tree")
	opts.OutputFormats = []string{"fs"}

	err := finishFSExport(db, opts)
	require.Error(t, err, "an unwritable fs destination must fail the run")
	assert.Contains(t, err.Error(), "export fs tree")

	// Stateless runs are handled by finishStatelessExport, and a run that never
	// asked for fs has nothing to do here.
	stateless := types.DefaultOptions()
	stateless.Output, stateless.OutputFormats, stateless.Stateless = opts.Output, []string{"fs"}, true
	assert.NoError(t, finishFSExport(db, stateless))

	noFS := types.DefaultOptions()
	noFS.OutputFormats = []string{"console"}
	assert.NoError(t, finishFSExport(db, noFS))
}

// isExportFailure is what keeps one failed format from cancelling the others.
func TestIsExportFailure(t *testing.T) {
	assert.False(t, isExportFailure(nil))
	assert.False(t, isExportFailure(errors.New("the scan itself broke")))

	var recorded error
	recordExportFailure(&recorded, errors.New("generate html /nope/out.html: no such directory"))
	require.Error(t, recorded)
	assert.True(t, isExportFailure(recorded),
		"recordExportFailure's own error must be recognizable as an export failure")
	assert.True(t, isExportFailure(errors.Join(errors.New("other"), recorded)),
		"it reaches the defer guards wrapped")

	// A gate trip is a completed result with its output already written.
	assert.False(t, isExportFailure(gateError{errors.New("--fail-on: tripped")}))
}

// The guard the jsonl-export defers use, stated as the rule.
func TestReportFailureDoesNotSkipJSONLExport(t *testing.T) {
	var exportErr error
	recordExportFailure(&exportErr, errors.New("generate html: unwritable"))
	scanBroke := errors.New("session init failed")

	// The REAL predicate both executeNativeScan and runRunnerScan defer on, not a
	// local restatement of it: a copy here would keep passing after the rule it
	// describes had changed underneath.
	skip := func(err error, stateless bool) bool {
		return skipDeferredJSONLExport(err, stateless, "")
	}

	assert.False(t, skip(exportErr, false),
		"a failed html report must not cancel the jsonl export — that is the format that would still have landed")
	assert.True(t, skip(scanBroke, false),
		"a failed scan still skips: a success-looking file of stale data is worse than none")
	assert.False(t, skip(nil, false), "a clean run exports")
	assert.False(t, skip(scanBroke, true),
		"stateless is exempt — its temp DB is discarded, so this is the only chance to surface anything")
	assert.True(t, skipDeferredJSONLExport(nil, true, "/tmp/out.jsonl"),
		"stateless WITH -o already materialized every format; exporting again would double the output")
}

// failingDBOpen stands in for a getDB that cannot open the configured store.
func failingDBOpen() (*database.DB, error) {
	return nil, errors.New("failed to connect to database: not a database")
}

// A pinned store that cannot be opened must fail the direct path BEFORE any
// request goes out. Scanning for minutes and then discarding every finding
// because --db pointed somewhere unusable is the silent data loss a pin exists
// to prevent.
func TestDirectScanPinnedDBFailureIsFatal(t *testing.T) {
	prevDB, prevConfig, prevSilent := globalDB, globalConfig, globalSilent
	t.Cleanup(func() { globalDB, globalConfig, globalSilent = prevDB, prevConfig, prevSilent })

	t.Run("pinned --db is fatal", func(t *testing.T) {
		globalDB, globalConfig, globalSilent = filepath.Join(t.TempDir(), "pinned.sqlite"), "", true
		repo, project, err := acquireDirectScanDB(failingDBOpen)
		require.Error(t, err, "a pinned --db that cannot be opened must fail the command")
		assert.Contains(t, err.Error(), "database unavailable")
		assert.Nil(t, repo)
		assert.Empty(t, project)
	})

	t.Run("pinned --config is fatal", func(t *testing.T) {
		globalDB, globalConfig, globalSilent = "", filepath.Join(t.TempDir(), "cfg.yaml"), true
		_, _, err := acquireDirectScanDB(failingDBOpen)
		require.Error(t, err, "--config names the store too, so it is equally a pin")
	})

	t.Run("unpinned warns and keeps scanning", func(t *testing.T) {
		globalDB, globalConfig, globalSilent = "", "", false
		var repo *database.Repository
		var err error
		out := captureStderr(t, func() { repo, _, err = acquireDirectScanDB(failingDBOpen) })
		require.NoError(t, err, "nobody asked for persistence, so the scan still runs")
		assert.Nil(t, repo, "a nil repository is what makes the result report persisted: false")
		assert.Contains(t, out, "will not be persisted",
			"the operator must be told their findings are memory-only")
	})

	t.Run("unpinned and silent says nothing", func(t *testing.T) {
		globalDB, globalConfig, globalSilent = "", "", true
		out := captureStderr(t, func() {
			_, _, err := acquireDirectScanDB(failingDBOpen)
			require.NoError(t, err)
		})
		assert.Empty(t, strings.TrimSpace(out), "--silent means silent")
	})
}

// The result document states whether the findings also reached a store, so a
// caller that reads them here and then expects `vigolium finding` to list them
// can tell which of the two runs it got.
func TestScanResultPersistedIsSerialized(t *testing.T) {
	doc, err := encodeAgentJSON(&scanResult{Target: "http://a.example/", Method: "GET"})
	require.NoError(t, err)
	assert.Contains(t, string(doc), `"persisted": false`)
	assert.NotContains(t, string(doc), "interrupted", "interrupted is omitempty on a normal run")

	doc, err = encodeAgentJSON(&scanResult{Target: "http://a.example/", Persisted: true, Interrupted: true})
	require.NoError(t, err)
	assert.Contains(t, string(doc), `"persisted": true`)
	assert.Contains(t, string(doc), `"interrupted": true`)
}
