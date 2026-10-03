package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
)

// writeGlobJSONLFixture writes a one-record JSONL export, the shape --glob-db
// most often expands to.
func writeGlobJSONLFixture(t *testing.T, path, host string) {
	t.Helper()
	rec := database.HTTPRecord{
		UUID:        "rec-" + host,
		ProjectUUID: "proj-" + host,
		Scheme:      "https",
		Hostname:    host,
		Port:        443,
		Method:      "GET",
		Path:        "/",
		URL:         "https://" + host + "/",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "rh-" + host,
		StatusCode:  200,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	line, err := json.Marshal(map[string]any{"type": "http_record", "data": json.RawMessage(data)})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := os.WriteFile(path, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// failPartway mimics an importer that dies in the middle: it commits rows (as
// the real JSONL importer does, batch by batch) and then returns an error. This
// is the whole point of the seam — no fixture file fails this way on demand.
func failPartway(t *testing.T, repo *database.Repository, tag string, records int) error {
	t.Helper()
	ctx := context.Background()
	batch := make([]*database.HTTPRecord, 0, records)
	for i := 0; i < records; i++ {
		batch = append(batch, &database.HTTPRecord{
			UUID:        fmt.Sprintf("partial-%s-%d", tag, i),
			ProjectUUID: "proj-partial",
			Scheme:      "https",
			Hostname:    "partial.example",
			Port:        443,
			Method:      "GET",
			Path:        fmt.Sprintf("/%d", i),
			URL:         fmt.Sprintf("https://partial.example/%d", i),
			HTTPVersion: "HTTP/1.1",
			RequestHash: fmt.Sprintf("rh-partial-%s-%d", tag, i),
			StatusCode:  200,
		})
	}
	if _, err := repo.SaveRecordsBatch(ctx, batch); err != nil {
		t.Fatalf("seed partial records: %v", err)
	}
	if err := repo.SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID:     "proj-partial",
		HTTPRecordUUIDs: []string{batch[0].UUID},
		ModuleID:        "mod-partial",
		Severity:        "high",
		FindingHash:     "hash-partial-" + tag,
		URL:             "https://partial.example/0",
		Hostname:        "partial.example",
	}); err != nil {
		t.Fatalf("seed partial finding: %v", err)
	}
	return fmt.Errorf("truncated after %d records", records)
}

// countRows is a small COUNT(*) helper; the scratch database has no model-free
// accessor and every assertion here is a row count.
func countRows(t *testing.T, db *database.DB, table string) int {
	t.Helper()
	var n int
	if err := db.SQLDB().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestGlobFailedSourceRollsBack is the regression this work exists for: a source
// that dies partway had already committed rows, and those rows stayed in the
// merge while the file was reported as "skipped" — so a merged read answered
// from a corpus that was neither complete nor the one it described.
func TestGlobFailedSourceRollsBack(t *testing.T) {
	dir := t.TempDir()
	writeGlobJSONLFixture(t, filepath.Join(dir, "a.jsonl"), "a.example")
	writeGlobJSONLFixture(t, filepath.Join(dir, "b.jsonl"), "b.example")
	t.Cleanup(resetDBCacheForTest)

	real := globImportPath
	globImportPath = func(ctx context.Context, repo *database.Repository, path, projectUUID string, opts dbimport.Options) (*dbimport.Result, error) {
		if filepath.Base(path) == "a.jsonl" {
			return nil, failPartway(t, repo, "a", 3)
		}
		return real(ctx, repo, path, projectUUID, opts)
	}
	t.Cleanup(func() { globImportPath = real })

	db, err := openGlobDB(filepath.Join(dir, "*.jsonl"), globDBSkipSet{})
	if err != nil {
		t.Fatalf("openGlobDB: %v", err)
	}

	if n := countRows(t, db, "http_records"); n != 1 {
		t.Errorf("http_records = %d, want 1 (only b.jsonl's row survives)", n)
	}
	if n := countRows(t, db, "findings"); n != 0 {
		t.Errorf("findings = %d, want 0 (a.jsonl's partial finding is rolled back)", n)
	}
	if n := countRows(t, db, "finding_records"); n != 0 {
		t.Errorf("finding_records = %d, want 0", n)
	}

	// The surviving row is attributed to b, not to the hole a left behind.
	if globDBMergedCount() != 1 {
		t.Fatalf("merged sources = %d, want 1", globDBMergedCount())
	}
	var rowid int64
	if err := db.SQLDB().QueryRowContext(context.Background(), "SELECT rowid FROM http_records").Scan(&rowid); err != nil {
		t.Fatalf("read rowid: %v", err)
	}
	if got := globSourceForRecordRowID(rowid); filepath.Base(got) != "b.jsonl" {
		t.Errorf("attribution = %q, want b.jsonl", got)
	}

	// The skip is reported, with the file and the reason.
	if len(globDBSkippedFiles) != 1 {
		t.Fatalf("skipped files = %+v, want one entry", globDBSkippedFiles)
	}
	if filepath.Base(globDBSkippedFiles[0].File) != "a.jsonl" {
		t.Errorf("skipped file = %q, want a.jsonl", globDBSkippedFiles[0].File)
	}
	if !strings.Contains(globDBSkippedFiles[0].Error, "truncated") {
		t.Errorf("skipped reason = %q, want the importer's message", globDBSkippedFiles[0].Error)
	}

	// …and reaches the -j envelope, which is the only account a stdout consumer
	// ever sees.
	prevGlob := globalGlobDB
	globalGlobDB = filepath.Join(dir, "*.jsonl")
	t.Cleanup(func() { globalGlobDB = prevGlob })

	env := newAgentEnvelope("finding", "findings", []any{}, 0, 0, 0)
	attachGlobSources(env)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	var decoded struct {
		GlobSources struct {
			Pattern string `json:"pattern"`
			Matched int    `json:"matched"`
			Loaded  int    `json:"loaded"`
			Skipped []struct {
				File  string `json:"file"`
				Error string `json:"error"`
			} `json:"skipped"`
		} `json:"glob_sources"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	gs := decoded.GlobSources
	if gs.Matched != 2 || gs.Loaded != 1 {
		t.Errorf("glob_sources matched/loaded = %d/%d, want 2/1", gs.Matched, gs.Loaded)
	}
	if len(gs.Skipped) != 1 || filepath.Base(gs.Skipped[0].File) != "a.jsonl" {
		t.Errorf("glob_sources.skipped = %+v, want a.jsonl", gs.Skipped)
	}
}

// A clean merge still carries glob_sources, so a consumer asserts
// matched == loaded rather than inferring completeness from an absent key.
func TestGlobSourcesPresentOnCleanMerge(t *testing.T) {
	dir := t.TempDir()
	writeGlobJSONLFixture(t, filepath.Join(dir, "a.jsonl"), "a.example")
	writeGlobJSONLFixture(t, filepath.Join(dir, "b.jsonl"), "b.example")
	t.Cleanup(resetDBCacheForTest)

	pattern := filepath.Join(dir, "*.jsonl")
	if _, err := openGlobDB(pattern, globDBSkipSet{}); err != nil {
		t.Fatalf("openGlobDB: %v", err)
	}
	prevGlob := globalGlobDB
	globalGlobDB = pattern
	t.Cleanup(func() { globalGlobDB = prevGlob })

	env := newAgentEnvelope("finding", "findings", []any{}, 0, 0, 0)
	attachGlobSources(env)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if !strings.Contains(string(raw), `"skipped":[]`) {
		t.Errorf("clean merge should carry an empty skipped array, got %s", raw)
	}
	if !strings.Contains(string(raw), `"matched":2`) || !strings.Contains(string(raw), `"loaded":2`) {
		t.Errorf("clean merge should report matched/loaded 2/2, got %s", raw)
	}
}

// Without --glob-db there is no merge to describe, and an always-present key
// would tell a single-source consumer it was reading a merged corpus.
func TestGlobSourcesAbsentWithoutPattern(t *testing.T) {
	prevGlob := globalGlobDB
	globalGlobDB = ""
	t.Cleanup(func() { globalGlobDB = prevGlob })

	env := newAgentEnvelope("finding", "findings", []any{}, 0, 0, 0)
	attachGlobSources(env)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if strings.Contains(string(raw), "glob_sources") {
		t.Errorf("glob_sources present without --glob-db: %s", raw)
	}
}

// TestGlobStrictStopsOnFirstFailure: the opt-in for a caller that would rather
// have no answer than a short one. The partial rows still go.
func TestGlobStrictStopsOnFirstFailure(t *testing.T) {
	dir := t.TempDir()
	writeGlobJSONLFixture(t, filepath.Join(dir, "a.jsonl"), "a.example")
	writeGlobJSONLFixture(t, filepath.Join(dir, "b.jsonl"), "b.example")
	t.Cleanup(resetDBCacheForTest)

	var imported []string
	real := globImportPath
	globImportPath = func(ctx context.Context, repo *database.Repository, path, projectUUID string, opts dbimport.Options) (*dbimport.Result, error) {
		imported = append(imported, filepath.Base(path))
		if filepath.Base(path) == "a.jsonl" {
			return nil, failPartway(t, repo, "a", 3)
		}
		return real(ctx, repo, path, projectUUID, opts)
	}
	t.Cleanup(func() { globImportPath = real })

	globalGlobStrict = true
	t.Cleanup(func() { globalGlobStrict = false })

	_, err := openGlobDB(filepath.Join(dir, "*.jsonl"), globDBSkipSet{})
	if err == nil {
		t.Fatal("--glob-strict should fail the read on the first bad source")
	}
	if !strings.Contains(err.Error(), "a.jsonl") || !strings.Contains(err.Error(), "--glob-db") {
		t.Errorf("error %q should name --glob-db and the failing file", err)
	}
	// b was never attempted: the point of strict is to stop, not to finish and
	// then complain.
	if len(imported) != 1 || imported[0] != "a.jsonl" {
		t.Errorf("imported = %v, want only a.jsonl", imported)
	}
}

// A source whose findings the scratch store refused is a source that did not
// fully load, even though ImportPath returns no error for it.
func TestGlobTreatsFailedFindingsAsSourceFailure(t *testing.T) {
	dir := t.TempDir()
	writeGlobJSONLFixture(t, filepath.Join(dir, "a.jsonl"), "a.example")
	writeGlobJSONLFixture(t, filepath.Join(dir, "b.jsonl"), "b.example")
	t.Cleanup(resetDBCacheForTest)

	real := globImportPath
	globImportPath = func(ctx context.Context, repo *database.Repository, path, projectUUID string, opts dbimport.Options) (*dbimport.Result, error) {
		res, err := real(ctx, repo, path, projectUUID, opts)
		if err == nil && filepath.Base(path) == "a.jsonl" {
			res.FindingsFailed = 2
		}
		return res, err
	}
	t.Cleanup(func() { globImportPath = real })

	db, err := openGlobDB(filepath.Join(dir, "*.jsonl"), globDBSkipSet{})
	if err != nil {
		t.Fatalf("openGlobDB: %v", err)
	}
	if n := countRows(t, db, "http_records"); n != 1 {
		t.Errorf("http_records = %d, want 1 (a.jsonl rolled back)", n)
	}
	if len(globDBSkippedFiles) != 1 || !strings.Contains(globDBSkippedFiles[0].Error, "could not be stored") {
		t.Errorf("skipped = %+v, want a.jsonl with a finding-storage reason", globDBSkippedFiles)
	}
}

// TestRollbackGlobMergeRemovesOnlyNewRows pins the boundary convention: marks
// are a high-water mark, so a row AT the mark predates the failed source and
// must survive. Off by one here silently empties the merge.
func TestRollbackGlobMergeRemovesOnlyNewRows(t *testing.T) {
	dir := t.TempDir()
	writeGlobJSONLFixture(t, filepath.Join(dir, "a.jsonl"), "a.example")
	t.Cleanup(resetDBCacheForTest)

	db, err := openGlobDB(filepath.Join(dir, "*.jsonl"), globDBSkipSet{})
	if err != nil {
		t.Fatalf("openGlobDB: %v", err)
	}
	ctx := context.Background()
	marks, err := globMergeMarksAt(ctx, db)
	if err != nil {
		t.Fatalf("globMergeMarksAt: %v", err)
	}
	if err := failPartway(t, database.NewRepository(db), "later", 4); err == nil {
		t.Fatal("failPartway should report an error")
	}
	if n := countRows(t, db, "http_records"); n != 5 {
		t.Fatalf("setup: http_records = %d, want 5", n)
	}
	if err := rollbackGlobMerge(ctx, db, marks); err != nil {
		t.Fatalf("rollbackGlobMerge: %v", err)
	}
	if n := countRows(t, db, "http_records"); n != 1 {
		t.Errorf("after rollback http_records = %d, want the 1 row that predated the marks", n)
	}
	if n := countRows(t, db, "findings"); n != 0 {
		t.Errorf("after rollback findings = %d, want 0", n)
	}
}
