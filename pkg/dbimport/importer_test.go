package dbimport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestMergeResults(t *testing.T) {
	results := []*Result{
		{
			RecordsImported: 10, FindingsTotal: 4, FindingsSaved: 3, FindingsSkipped: 1, ParseErrors: 1,
			SeverityCounts: map[string]int{"high": 2, "low": 1},
			SkippedTypes:   map[string]int{"note": 1},
			MergeStats:     &database.MergeStats{RecordsMerged: 10, FindingsMerged: 3, FindingsDeduped: 1, ScansMerged: 1},
		},
		nil, // nil entries are ignored
		{
			RecordsImported: 5, FindingsTotal: 2, FindingsSaved: 2,
			SeverityCounts: map[string]int{"high": 1},
			MergeStats:     &database.MergeStats{RecordsMerged: 5, FindingsMerged: 2, ScansMerged: 2, OASTMerged: 4},
		},
	}
	agg := MergeResults(results)
	if agg.RecordsImported != 15 || agg.FindingsTotal != 6 || agg.FindingsSaved != 5 || agg.FindingsSkipped != 1 || agg.ParseErrors != 1 {
		t.Fatalf("counters wrong: %+v", agg)
	}
	if agg.SeverityCounts["high"] != 3 || agg.SeverityCounts["low"] != 1 || agg.SkippedTypes["note"] != 1 {
		t.Fatalf("maps wrong: sev=%v skipped=%v", agg.SeverityCounts, agg.SkippedTypes)
	}
	if agg.MergeStats == nil {
		t.Fatal("expected summed MergeStats")
	}
	if agg.MergeStats.RecordsMerged != 15 || agg.MergeStats.FindingsMerged != 5 ||
		agg.MergeStats.FindingsDeduped != 1 || agg.MergeStats.ScansMerged != 3 || agg.MergeStats.OASTMerged != 4 {
		t.Fatalf("summed MergeStats wrong: %+v", agg.MergeStats)
	}

	// A source without MergeStats leaves the others summed; MergeResults itself
	// keeps MergeStats non-nil (the all-or-nothing display rule is the caller's).
	empty := MergeResults(nil)
	if empty.MergeStats != nil || empty.RecordsImported != 0 {
		t.Fatalf("empty aggregate should be zero-valued: %+v", empty)
	}
}

// newTestRepo spins up a throwaway in-memory SQLite repository, mirroring how
// the stateless JSONL loader bootstraps its scratch DB.
func newTestRepo(t *testing.T) *database.Repository {
	t.Helper()
	ctx := context.Background()

	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = ":memory:"

	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	return database.NewRepository(db)
}

// jsonlEnvelope serializes a single {"type":...,"data":...} JSONL line.
func jsonlEnvelope(t *testing.T, typ string, data any) string {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal data: %v", err)
	}
	line, err := json.Marshal(struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}{Type: typ, Data: raw})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(line)
}

// TestImportJSONLOversizedLine guards the regression that produced
// "bufio.Scanner: token too long": an http_record whose raw_response body is
// larger than the old 10MB scanner cap must still load. The reader-based loop
// grows to any line length.
func TestImportJSONLOversizedLine(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// 12MB body → ~16MB once base64-encoded onto a single JSONL line, well past
	// the 10MB cap that used to fail.
	big := database.HTTPRecord{
		UUID:        "rec-big",
		Scheme:      "https",
		Hostname:    "example.com",
		Port:        443,
		Method:      "GET",
		Path:        "/big",
		URL:         "https://example.com/big",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "h-big",
		StatusCode:  200,
		HasResponse: true,
		RawResponse: bytes.Repeat([]byte("A"), 12*1024*1024),
	}
	small := database.HTTPRecord{
		UUID:        "rec-small",
		Scheme:      "https",
		Hostname:    "example.com",
		Port:        443,
		Method:      "GET",
		Path:        "/small",
		URL:         "https://example.com/small",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "h-small",
		StatusCode:  200,
	}

	// No trailing newline on the final line: exercises the EOF-without-delimiter path.
	stream := jsonlEnvelope(t, "http_record", big) + "\n" +
		jsonlEnvelope(t, "http_record", small)

	res, err := ImportJSONL(ctx, repo, strings.NewReader(stream), "", Options{})
	if err != nil {
		t.Fatalf("ImportJSONL on oversized line: %v", err)
	}
	if res.RecordsImported != 2 {
		t.Errorf("RecordsImported = %d, want 2", res.RecordsImported)
	}
	if res.ParseErrors != 0 {
		t.Errorf("ParseErrors = %d, want 0", res.ParseErrors)
	}
}

// newFileDBForTest creates a schema-ready, file-backed SQLite database at path.
// SQLite merges ATTACH a real source file, so an on-disk (not :memory:) database
// is required on both sides of the merge.
func newFileDBForTest(t *testing.T, path string) *database.DB {
	t.Helper()
	ctx := context.Background()
	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB(%s): %v", path, err)
	}
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema(%s): %v", path, err)
	}
	if err := db.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults(%s): %v", path, err)
	}
	return db
}

// TestImportPathSQLiteMerge exercises the SQLite dispatch: a vigolium .sqlite
// result database passed to ImportPath must be detected by its magic header and
// merged (records + findings) into the destination, and a re-import must be a
// no-op (idempotent dedup on natural keys).
func TestImportPathSQLiteMerge(t *testing.T) {
	ctx := context.Background()

	// Source: a file-backed vigolium DB with one record + one finding, closed
	// before the merge so its WAL is flushed (mirrors the real scan→import flow).
	srcPath := filepath.Join(t.TempDir(), "external-scan.sqlite")
	srcDB := newFileDBForTest(t, srcPath)
	if _, err := srcDB.ExecContext(ctx, `INSERT INTO http_records
		(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash)
		VALUES ('rec-1', ?, 'https', 'example.com', 443, 'GET', '/', 'https://example.com/', 'HTTP/1.1', 'rh-1')`,
		database.DefaultProjectUUID); err != nil {
		t.Fatalf("seed source record: %v", err)
	}
	if _, err := srcDB.ExecContext(ctx, `INSERT INTO findings
		(project_uuid, http_record_uuids, module_id, module_name, severity, finding_hash)
		VALUES (?, '["rec-1"]', 'xss', 'XSS', 'high', 'fh-1')`,
		database.DefaultProjectUUID); err != nil {
		t.Fatalf("seed source finding: %v", err)
	}
	if err := srcDB.Close(); err != nil {
		t.Fatalf("close source: %v", err)
	}

	// Destination: a separate file-backed vigolium DB (the current/primary one).
	destDB := newFileDBForTest(t, filepath.Join(t.TempDir(), "dest.sqlite"))
	t.Cleanup(func() { _ = destDB.Close() })
	destRepo := database.NewRepository(destDB)

	res, err := ImportPath(ctx, destRepo, srcPath, database.DefaultProjectUUID, Options{})
	if err != nil {
		t.Fatalf("ImportPath(sqlite): %v", err)
	}
	if res.MergeStats == nil {
		t.Fatal("expected MergeStats to be set for a SQLite import")
	}
	if res.RecordsImported != 1 {
		t.Errorf("RecordsImported = %d, want 1", res.RecordsImported)
	}
	if res.FindingsSaved != 1 {
		t.Errorf("FindingsSaved = %d, want 1", res.FindingsSaved)
	}

	// Re-importing the same database merges nothing new.
	res2, err := ImportPath(ctx, destRepo, srcPath, database.DefaultProjectUUID, Options{})
	if err != nil {
		t.Fatalf("ImportPath(sqlite) re-import: %v", err)
	}
	if res2.RecordsImported != 0 || res2.FindingsSaved != 0 {
		t.Errorf("re-import merged new rows: records=%d findings=%d, want 0/0",
			res2.RecordsImported, res2.FindingsSaved)
	}
	if res2.MergeStats == nil || res2.MergeStats.FindingsDeduped != 1 {
		t.Errorf("re-import should dedup the 1 existing finding, got %+v", res2.MergeStats)
	}
}

// jsonlRecordLine builds one http_record envelope line for the given uuid.
func jsonlRecordLine(t *testing.T, uuid string) string {
	t.Helper()
	return jsonlEnvelope(t, "http_record", database.HTTPRecord{
		UUID:        uuid,
		Scheme:      "https",
		Hostname:    "example.com",
		Port:        443,
		Method:      "GET",
		Path:        "/" + uuid,
		URL:         "https://example.com/" + uuid,
		HTTPVersion: "HTTP/1.1",
		RequestHash: "h-" + uuid,
		StatusCode:  200,
	})
}

// TestImportJSONLDuplicateUUIDIsIdempotent covers the two ways a record uuid
// repeats in practice: twice inside one file, and across two runs over the same
// file. Both used to abort the import with a UNIQUE constraint error AFTER an
// arbitrary number of earlier batches had already committed.
func TestImportJSONLDuplicateUUIDIsIdempotent(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// 501 lines, one of which repeats an earlier uuid, so the duplicate lands in
	// the second flush batch rather than the first.
	var b strings.Builder
	for i := 0; i < 500; i++ {
		b.WriteString(jsonlRecordLine(t, fmt.Sprintf("rec-%03d", i)))
		b.WriteByte('\n')
	}
	b.WriteString(jsonlRecordLine(t, "rec-000"))
	b.WriteByte('\n')
	stream := b.String()

	res, err := ImportJSONL(ctx, repo, strings.NewReader(stream), "", Options{})
	if err != nil {
		t.Fatalf("ImportJSONL with a duplicate uuid: %v", err)
	}
	if res.RecordsImported != 500 {
		t.Errorf("RecordsImported = %d, want 500", res.RecordsImported)
	}
	if res.RecordsSkippedDuplicate != 1 {
		t.Errorf("RecordsSkippedDuplicate = %d, want 1", res.RecordsSkippedDuplicate)
	}

	var stored int
	if err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).
		ColumnExpr("COUNT(*)").Scan(ctx, &stored); err != nil {
		t.Fatalf("count records: %v", err)
	}
	if stored != 500 {
		t.Errorf("stored rows = %d, want 500", stored)
	}

	// Re-importing the identical bytes inserts nothing and skips everything.
	res2, err := ImportJSONL(ctx, repo, strings.NewReader(stream), "", Options{})
	if err != nil {
		t.Fatalf("ImportJSONL re-import: %v", err)
	}
	if res2.RecordsImported != 0 || res2.RecordsSkippedDuplicate != 501 {
		t.Errorf("re-import: imported=%d skipped=%d, want 0/501",
			res2.RecordsImported, res2.RecordsSkippedDuplicate)
	}
}

// TestImportJSONLLineCap checks the ceiling on a single line and, as importantly,
// that the error says how much of the file already reached the database — the
// operator's next question after "this import failed" is "what is in there now".
func TestImportJSONLLineCap(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// One good line (flushed only at the end — under the batch size), then a line
	// well past the cap. The cap is below the reader's 1 MiB buffer, so this also
	// exercises the non-ErrBufferFull branch of the check.
	stream := jsonlRecordLine(t, "rec-ok") + "\n" +
		`{"type":"http_record","data":{"uuid":"` + strings.Repeat("x", 8*1024) + `"}}` + "\n"

	_, err := ImportJSONL(ctx, repo, strings.NewReader(stream), "", Options{MaxLineBytes: 4096})
	if err == nil {
		t.Fatal("expected an error for a line over MaxLineBytes")
	}
	for _, want := range []string{"line 2", "4096 bytes", "already committed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}

	// The same stream is fine with the cap raised, which proves the cap is what
	// rejected it rather than the content.
	res, err := ImportJSONL(ctx, repo, strings.NewReader(stream), "", Options{MaxLineBytes: 1 << 20})
	if err != nil {
		t.Fatalf("ImportJSONL with a raised cap: %v", err)
	}
	if res.RecordsImported != 2 {
		t.Errorf("RecordsImported = %d, want 2", res.RecordsImported)
	}
}

// TestImportJSONLLineCapAcrossBufferRefills drives the accumulate branch: a line
// longer than the reader's own buffer, so the cap has to be enforced during the
// refill loop rather than once on a finished line.
func TestImportJSONLLineCapAcrossBufferRefills(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// 3 MiB on one line against a 1 MiB reader buffer and a 2 MiB cap.
	stream := `{"type":"http_record","data":{"uuid":"` + strings.Repeat("x", 3<<20) + `"}}` + "\n"
	_, err := ImportJSONL(ctx, repo, strings.NewReader(stream), "", Options{MaxLineBytes: 2 << 20})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want an 'exceeds' error", err)
	}
}

// TestImportJSONLFlushesWhileParsing asserts records reach the database before
// the stream ends. Buffering the whole file first is what made a large export an
// out-of-memory failure instead of a slow import.
func TestImportJSONLFlushesWhileParsing(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// recordFlushBatch good lines, then an over-long one. The first batch must
	// already be committed when the failure is reported.
	var b strings.Builder
	for i := 0; i < recordFlushBatch; i++ {
		b.WriteString(jsonlRecordLine(t, fmt.Sprintf("flush-%03d", i)))
		b.WriteByte('\n')
	}
	b.WriteString(`{"type":"http_record","data":{"uuid":"` + strings.Repeat("y", 8*1024) + `"}}` + "\n")

	_, err := ImportJSONL(ctx, repo, strings.NewReader(b.String()), "", Options{MaxLineBytes: 4096})
	if err == nil {
		t.Fatal("expected the over-long line to fail the import")
	}
	if want := fmt.Sprintf("(%d records already committed)", recordFlushBatch); !strings.Contains(err.Error(), want) {
		t.Errorf("error %q should report %q", err, want)
	}

	var stored int
	if err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).
		ColumnExpr("COUNT(*)").Scan(ctx, &stored); err != nil {
		t.Fatalf("count records: %v", err)
	}
	if stored != recordFlushBatch {
		t.Errorf("stored rows = %d, want %d (the flushed batch)", stored, recordFlushBatch)
	}
}

// TestTallyFindingSavesSeparatesFailures pins the three-way split. A deduped
// finding is already in the destination; a failed one is nowhere, and reporting
// both as "skipped" described a lossy import as a clean one.
func TestTallyFindingSavesSeparatesFailures(t *testing.T) {
	findings := []*database.Finding{
		{Severity: "high"},
		{Severity: "low"},
		{Severity: "critical"},
		{Severity: "medium"},
	}
	results := []database.FindingSaveResult{
		{Inserted: true},
		{Inserted: false},
		{Err: errors.New("constraint failed")},
		{Inserted: true},
	}
	sev := map[string]int{}
	saved, deduped, failed := tallyFindingSaves(findings, results, sev)
	if saved != 2 || deduped != 1 || failed != 1 {
		t.Fatalf("saved=%d deduped=%d failed=%d, want 2/1/1", saved, deduped, failed)
	}
	// A failed finding contributes no severity: it is not in the database, and
	// counting it would make the severity breakdown sum past what was stored.
	if sev["critical"] != 0 {
		t.Errorf("failed finding tallied into severity: %v", sev)
	}
	if sev["high"] != 1 || sev["low"] != 1 || sev["medium"] != 1 {
		t.Errorf("severity tally wrong: %v", sev)
	}

	// A short results slice is a caller bug; it must not panic mid-import.
	if s, d, f := tallyFindingSaves(findings, results[:1], map[string]int{}); s != 1 || d != 0 || f != 0 {
		t.Errorf("short results: %d/%d/%d, want 1/0/0", s, d, f)
	}
}
