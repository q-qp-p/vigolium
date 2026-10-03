package database

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeduplicateDeparosRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID

	// Helper to insert a deparos record with specific fields.
	insertRecord := func(hostname, method, path, responseHash string, statusCode int, contentLength int64) string {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:                  id,
			ProjectUUID:           projectUUID,
			Scheme:                "https",
			Hostname:              hostname,
			Port:                  443,
			Method:                method,
			Path:                  path,
			URL:                   "https://" + hostname + path,
			HTTPVersion:           "HTTP/1.1",
			RequestHash:           id, // unique
			StatusCode:            statusCode,
			ResponseContentLength: contentLength,
			ResponseHash:          responseHash,
			HasResponse:           true,
			Source:                "deparos",
			SentAt:                time.Now(),
			CreatedAt:             time.Now(),
		}
		_, err := db.NewInsert().Model(rec).Exec(ctx)
		if err != nil {
			t.Fatalf("insert record: %v", err)
		}
		return id
	}

	// Group 1: 3 records with same response hash on host1 — shortest path "/a" should survive
	g1a := insertRecord("host1.com", "GET", "/a", "hash-aaa", 405, 0)
	_ = insertRecord("host1.com", "GET", "/a/b/c", "hash-aaa", 405, 0)
	_ = insertRecord("host1.com", "GET", "/a/b", "hash-aaa", 405, 0)

	// Group 2: 2 records with same hash on host1, different status — no dedup (different group key)
	g2a := insertRecord("host1.com", "GET", "/x", "hash-bbb", 200, 100)
	g2b := insertRecord("host1.com", "GET", "/x/y", "hash-bbb", 404, 100)

	// Group 3: 2 records, same hash on host2
	g3a := insertRecord("host2.com", "POST", "/short", "hash-ccc", 200, 50)
	_ = insertRecord("host2.com", "POST", "/much/longer/path", "hash-ccc", 200, 50)

	// Non-deparos record — should NOT be touched
	nonDeparos := uuid.NewString()
	_, err := db.NewInsert().Model(&HTTPRecord{
		UUID:                  nonDeparos,
		ProjectUUID:           projectUUID,
		Scheme:                "https",
		Hostname:              "host1.com",
		Port:                  443,
		Method:                "GET",
		Path:                  "/z",
		URL:                   "https://host1.com/z",
		HTTPVersion:           "HTTP/1.1",
		RequestHash:           nonDeparos,
		StatusCode:            405,
		ResponseContentLength: 0,
		ResponseHash:          "hash-aaa",
		HasResponse:           true,
		Source:                "scanner",
		SentAt:                time.Now(),
		CreatedAt:             time.Now(),
	}).Exec(ctx)
	if err != nil {
		t.Fatalf("insert non-deparos record: %v", err)
	}

	// Record without response — should NOT be touched
	noResp := insertRecordNoResponse(t, db, ctx, projectUUID)

	// Insert a finding_records junction row for one of the duplicates to verify cleanup
	_, err = db.ExecContext(ctx,
		"INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name, finding_hash, severity, confidence, http_record_uuids) VALUES (?, 'scan1', 'mod1', 'mod1', 'fh1', 'info', 'tentative', '[]')",
		projectUUID)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	// Link finding (id=1) to a record that will be deleted
	_, err = db.ExecContext(ctx, "INSERT INTO finding_records (finding_id, record_uuid) VALUES (1, ?)", g1a)
	if err != nil {
		// g1a survives, so let's link to a duplicate that will be deleted
		t.Logf("finding_records insert note: %v (may be fine)", err)
	}

	// Run dedup
	deleted, err := repo.DeduplicateDeparosRecords(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateDeparosRecords: %v", err)
	}

	// Group 1: 3 records, 1 kept → 2 deleted
	// Group 2: different status codes, so they're separate groups of 1 each → 0 deleted
	// Group 3: 2 records, 1 kept → 1 deleted
	// Total: 3 deleted
	if deleted != 3 {
		t.Errorf("expected 3 deleted, got %d", deleted)
	}

	// Verify survivors
	survivors := map[string]bool{g1a: true, g2a: true, g2b: true, g3a: true, nonDeparos: true, noResp: true}
	var remaining []*HTTPRecord
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if len(remaining) != len(survivors) {
		t.Errorf("expected %d remaining records, got %d", len(survivors), len(remaining))
	}
	for _, rec := range remaining {
		if !survivors[rec.UUID] {
			t.Errorf("unexpected survivor: %s (path=%s, source=%s)", rec.UUID, rec.Path, rec.Source)
		}
	}
}

func TestDeduplicateDeparosRecords_NoRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	deleted, err := repo.DeduplicateDeparosRecords(ctx, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", deleted)
	}
}

func TestDeduplicateFindings(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID

	// Helper to insert a finding with specific fields.
	insertFinding := func(moduleID, severity, matchedAtURL string) int64 {
		matchedAt := "[]"
		if matchedAtURL != "" {
			matchedAt = `["` + matchedAtURL + `"]`
		}
		res, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name,
				finding_hash, severity, confidence, http_record_uuids, matched_at)
			VALUES (?, 'scan1', ?, ?, ?, ?, 'firm', '[]', ?)`,
			projectUUID, moduleID, moduleID, uuid.NewString(), severity, matchedAt)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}

	// Group 1: same module, severity, URL — 5 findings (like input-behavior-probe with different payloads)
	g1First := insertFinding("input-behavior-probe", "info", "http://localhost:3000/ftp/eastere.gg")
	_ = insertFinding("input-behavior-probe", "info", "http://localhost:3000/ftp/eastere.gg")
	_ = insertFinding("input-behavior-probe", "info", "http://localhost:3000/ftp/eastere.gg")
	_ = insertFinding("input-behavior-probe", "info", "http://localhost:3000/ftp/eastere.gg")
	_ = insertFinding("input-behavior-probe", "info", "http://localhost:3000/ftp/eastere.gg")

	// Group 2: same module, different URL — separate group, kept
	g2 := insertFinding("input-behavior-probe", "info", "http://localhost:3000/api/users")

	// Group 3: different module, same URL — separate group, kept
	g3 := insertFinding("xss-scanner", "medium", "http://localhost:3000/ftp/eastere.gg")

	// Group 4: same module, same URL, different severity — separate group
	g4 := insertFinding("input-behavior-probe", "medium", "http://localhost:3000/ftp/eastere.gg")

	// Group 5: no matched_at — should NOT be touched
	g5 := insertFinding("input-behavior-probe", "info", "")

	// Insert a junction row for one of the duplicates
	_, _ = db.ExecContext(ctx, "INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)", g1First+1, uuid.NewString())

	deleted, grouped, err := repo.DeduplicateFindings(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateFindings: %v", err)
	}

	// Group 1: 5 → 1 = 4 deleted, 1 group merged
	// Groups 2-5: 1 each = 0 deleted
	// Total: 4 deleted, 1 grouped
	if deleted != 4 {
		t.Errorf("expected 4 deleted, got %d", deleted)
	}
	if grouped != 1 {
		t.Errorf("expected 1 grouped, got %d", grouped)
	}

	// Verify survivors
	var remaining []*Finding
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if len(remaining) != 5 {
		t.Errorf("expected 5 remaining findings, got %d", len(remaining))
	}

	survivors := map[int64]bool{g1First: true, g2: true, g3: true, g4: true, g5: true}
	for _, f := range remaining {
		if !survivors[f.ID] {
			t.Errorf("unexpected survivor: id=%d module=%s severity=%s", f.ID, f.ModuleID, f.Severity)
		}
	}

	// Verify junction rows for deleted findings are cleaned up
	var junctionCount int
	err = db.NewRaw("SELECT COUNT(*) FROM finding_records WHERE finding_id = ?", g1First+1).Scan(ctx, &junctionCount)
	if err != nil {
		t.Fatalf("junction count query: %v", err)
	}
	if junctionCount != 0 {
		t.Errorf("expected junction rows cleaned up, got %d", junctionCount)
	}
}

// TestDeduplicateFindings_SecretDetectExcluded verifies that the URL-keyed dedup
// does NOT collapse distinct secrets the secret detector reports on one URL. A
// client_id, client_secret, and access_token leaked in the same response share
// (module, severity, URL) but are three separate secrets — they must all survive,
// not get merged into one with the others buried as Additional Evidence.
func TestDeduplicateFindings_SecretDetectExcluded(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID

	const url = "http://example.com/leak.html"
	insertSecret := func(extracted string) int64 {
		res, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name,
				finding_hash, severity, confidence, http_record_uuids, matched_at, extracted_results)
			VALUES (?, 'scan1', 'secret-detect', 'secret-detect', ?, 'high', 'firm', '[]', ?, ?)`,
			projectUUID, uuid.NewString(), `["`+url+`"]`, `["`+extracted+`"]`)
		if err != nil {
			t.Fatalf("insert secret finding: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}

	// Three distinct secrets on the same URL (same module + severity).
	insertSecret("12345-abc.apps.googleusercontent.com")
	insertSecret("VfJASjhImoB6IErdcHR0DLt9")
	insertSecret("ya29.GlskBNk6_nqhfOcJHvyoIAQoAkw95ulaGbENUB")

	// A different module on the same URL with duplicates still collapses, proving
	// the exclusion is scoped to secret-detect, not a blanket no-op.
	for i := 0; i < 3; i++ {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name,
				finding_hash, severity, confidence, http_record_uuids, matched_at)
			VALUES (?, 'scan1', 'input-behavior-probe', 'input-behavior-probe', ?, 'info', 'firm', '[]', ?)`,
			projectUUID, uuid.NewString(), `["`+url+`"]`); err != nil {
			t.Fatalf("insert probe finding: %v", err)
		}
	}

	deleted, grouped, err := repo.DeduplicateFindings(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateFindings: %v", err)
	}
	// Only the input-behavior-probe group collapses (3 → 1 = 2 deleted, 1 group).
	if deleted != 2 || grouped != 1 {
		t.Fatalf("expected 2 deleted / 1 grouped (probe only), got %d / %d", deleted, grouped)
	}

	var secretCount int
	if err := db.NewRaw("SELECT COUNT(*) FROM findings WHERE module_id = 'secret-detect'").Scan(ctx, &secretCount); err != nil {
		t.Fatalf("count secrets: %v", err)
	}
	if secretCount != 3 {
		t.Fatalf("all 3 distinct secrets on one URL must survive the URL-keyed dedup, got %d", secretCount)
	}
}

func TestDeduplicateFindings_HostScoped(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID

	insert := func(host, matchedAtURL string) int64 {
		res, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, hostname, module_id, module_name,
				finding_hash, severity, confidence, http_record_uuids, matched_at)
			VALUES (?, 'scan1', ?, 'input-behavior-probe', 'input-behavior-probe', ?, 'info', 'firm', '[]', ?)`,
			projectUUID, host, uuid.NewString(), `["`+matchedAtURL+`"]`)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}

	// 3 duplicates on host A and 3 on host B (same module/severity/URL within each host).
	insert("a.example.com", "http://a.example.com/x")
	insert("a.example.com", "http://a.example.com/x")
	insert("a.example.com", "http://a.example.com/x")
	insert("b.example.com", "http://b.example.com/y")
	insert("b.example.com", "http://b.example.com/y")
	insert("b.example.com", "http://b.example.com/y")

	// Scoped to host A: only A's 2 redundant findings collapse; B is untouched.
	deleted, grouped, err := repo.DeduplicateFindings(ctx, projectUUID, "a.example.com")
	if err != nil {
		t.Fatalf("DeduplicateFindings (scoped): %v", err)
	}
	if deleted != 2 || grouped != 1 {
		t.Fatalf("scoped pass: expected 2 deleted / 1 grouped, got %d / %d", deleted, grouped)
	}
	var bCount int
	if err := db.NewRaw("SELECT COUNT(*) FROM findings WHERE hostname = ?", "b.example.com").Scan(ctx, &bCount); err != nil {
		t.Fatalf("count B: %v", err)
	}
	if bCount != 3 {
		t.Fatalf("host B should be untouched by an A-scoped pass, got %d findings", bCount)
	}

	// Unscoped pass now collapses host B's duplicates too.
	deleted, grouped, err = repo.DeduplicateFindings(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateFindings (unscoped): %v", err)
	}
	if deleted != 2 || grouped != 1 {
		t.Fatalf("unscoped pass: expected 2 deleted / 1 grouped, got %d / %d", deleted, grouped)
	}
}

func TestDeduplicateFindings_EvidenceCollected(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	matchedAt := `["http://example.com/api"]`

	// Insert 3 findings with the same group key but different request/response data.
	insertWithReqRes := func(request, response string) int64 {
		res, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name,
				finding_hash, severity, confidence, http_record_uuids, matched_at, request, response)
			VALUES (?, 'scan1', 'sqli', 'sqli', ?, 'high', 'firm', '[]', ?, ?, ?)`,
			projectUUID, uuid.NewString(), matchedAt, request, response)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}

	survivorID := insertWithReqRes("GET /api?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nok")
	_ = insertWithReqRes("GET /api?id=1'+OR+1=1 HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 500\r\n\r\nerror")
	_ = insertWithReqRes("GET /api?id=1'+UNION+SELECT HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 500\r\n\r\nSQL error")

	deleted, grouped, err := repo.DeduplicateFindings(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateFindings: %v", err)
	}
	if deleted != 2 {
		t.Errorf("expected 2 deleted, got %d", deleted)
	}
	if grouped != 1 {
		t.Errorf("expected 1 grouped, got %d", grouped)
	}

	// Verify survivor has evidence from the 2 deleted duplicates.
	survivor := &Finding{}
	err = db.NewSelect().Model(survivor).Where("id = ?", survivorID).Scan(ctx)
	if err != nil {
		t.Fatalf("select survivor: %v", err)
	}
	if len(survivor.AdditionalEvidence) != 2 {
		t.Fatalf("expected 2 additional evidence entries, got %d", len(survivor.AdditionalEvidence))
	}
	// Each evidence entry should contain the separator.
	for i, ev := range survivor.AdditionalEvidence {
		if !strings.Contains(ev, EvidenceSeparator) {
			t.Errorf("evidence[%d] missing separator: %q", i, ev)
		}
	}
}

func TestDeduplicateFindings_EvidenceCapped(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	matchedAt := `["http://example.com/api"]`

	// Insert 1 survivor + 15 duplicates (16 total) with the same group key.
	insertWithReqRes := func(request, response string) int64 {
		res, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name,
				finding_hash, severity, confidence, http_record_uuids, matched_at, request, response)
			VALUES (?, 'scan1', 'sqli', 'sqli', ?, 'high', 'firm', '[]', ?, ?, ?)`,
			projectUUID, uuid.NewString(), matchedAt, request, response)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}

	survivorID := insertWithReqRes("GET /api?id=0 HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nok")
	for i := 1; i <= 15; i++ {
		insertWithReqRes(
			"GET /api?id="+strings.Repeat("x", i)+" HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 500\r\n\r\nerror",
		)
	}

	deleted, grouped, err := repo.DeduplicateFindings(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateFindings: %v", err)
	}
	if deleted != 15 {
		t.Errorf("expected 15 deleted, got %d", deleted)
	}
	if grouped != 1 {
		t.Errorf("expected 1 grouped, got %d", grouped)
	}

	// Verify survivor's AdditionalEvidence is capped at maxAdditionalEvidence.
	survivor := &Finding{}
	err = db.NewSelect().Model(survivor).Where("id = ?", survivorID).Scan(ctx)
	if err != nil {
		t.Fatalf("select survivor: %v", err)
	}
	if len(survivor.AdditionalEvidence) != maxAdditionalEvidence {
		t.Fatalf("expected %d additional evidence entries (capped), got %d", maxAdditionalEvidence, len(survivor.AdditionalEvidence))
	}
}

// TestDeduplicateFindings_MigratesEvidenceLinks is the Claim-3 regression: when a
// duplicate finding is folded into the survivor, its finding_records (evidence)
// links must move to the survivor rather than being deleted, so the survivor can
// still reach the exact record that proved the folded variant.
func TestDeduplicateFindings_MigratesEvidenceLinks(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	matchedAt := `["http://example.com/api"]`

	insertFinding := func() int64 {
		res, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name,
				finding_hash, severity, confidence, http_record_uuids, matched_at, request, response)
			VALUES (?, 'scan1', 'sqli', 'sqli', ?, 'high', 'firm', '[]', ?, 'req', 'resp')`,
			projectUUID, uuid.NewString(), matchedAt)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	linkRecord := func(fid int64, recUUID string) {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)`, fid, recUUID); err != nil {
			t.Fatalf("insert finding_records: %v", err)
		}
	}

	survivorID := insertFinding() // lower id → survivor (created_at/id ASC)
	dupID := insertFinding()
	linkRecord(survivorID, "rec-survivor")
	linkRecord(dupID, "rec-dup")
	// A record BOTH already link to must not create a duplicate junction row.
	linkRecord(survivorID, "rec-shared")
	linkRecord(dupID, "rec-shared")

	deleted, grouped, err := repo.DeduplicateFindings(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateFindings: %v", err)
	}
	if deleted != 1 || grouped != 1 {
		t.Fatalf("expected 1 deleted / 1 grouped, got %d / %d", deleted, grouped)
	}

	var survivorRecords []string
	if err := db.NewSelect().TableExpr("finding_records").Column("record_uuid").
		Where("finding_id = ?", survivorID).OrderExpr("record_uuid").Scan(ctx, &survivorRecords); err != nil {
		t.Fatalf("select survivor records: %v", err)
	}
	if got := strings.Join(survivorRecords, ","); got != "rec-dup,rec-shared,rec-survivor" {
		t.Fatalf("survivor records = %q, want the migrated union without duplication", got)
	}

	var dupCount int
	if err := db.NewSelect().TableExpr("finding_records").ColumnExpr("COUNT(*)").
		Where("finding_id = ?", dupID).Scan(ctx, &dupCount); err != nil {
		t.Fatalf("count dup records: %v", err)
	}
	if dupCount != 0 {
		t.Fatalf("expected the duplicate's junction rows removed, got %d", dupCount)
	}
}

func TestDeduplicateFindings_NoFindings(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	deleted, grouped, err := repo.DeduplicateFindings(ctx, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", deleted)
	}
	if grouped != 0 {
		t.Errorf("expected 0 grouped, got %d", grouped)
	}
}

func TestDeduplicateSoftDeparosRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	now := time.Now()

	// Helper to insert a deparos record with response characteristics.
	insertRec := func(hostname, method, path string, statusCode int, contentLength, words int64, contentType string) string {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:                  id,
			ProjectUUID:           projectUUID,
			Scheme:                "https",
			Hostname:              hostname,
			Port:                  443,
			Method:                method,
			Path:                  path,
			URL:                   "https://" + hostname + path,
			HTTPVersion:           "HTTP/1.1",
			RequestHash:           id,
			ResponseHash:          id, // unique hash per record
			StatusCode:            statusCode,
			ResponseContentLength: contentLength,
			ResponseWords:         words,
			ResponseContentType:   contentType,
			HasResponse:           true,
			Source:                "deparos",
			SentAt:                now,
			CreatedAt:             now,
		}
		_, err := db.NewInsert().Model(rec).Exec(ctx)
		if err != nil {
			t.Fatalf("insert record: %v", err)
		}
		return id
	}

	// Group 1: 5 records under /ftp/quarantine/... (status 405, size 0, words 28)
	// Shortest path "/ftp/quarantine/" should survive.
	g1Short := insertRec("host1.com", "GET", "/ftp/quarantine/", 405, 0, 28, "text/html")
	g1Dup1 := insertRec("host1.com", "GET", "/ftp/quarantine/abc.zip", 405, 0, 28, "text/html")
	_ = insertRec("host1.com", "GET", "/ftp/quarantine/def.tar.gz", 405, 0, 28, "text/html")
	_ = insertRec("host1.com", "GET", "/ftp/quarantine/ghi/nested", 405, 0, 28, "text/html")
	_ = insertRec("host1.com", "GET", "/ftp/quarantine/jkl.pdf", 405, 0, 28, "text/html")

	// Group 2: 3 records under /api/v1/... (status 200, size 100, words 50)
	g2Short := insertRec("host1.com", "GET", "/api/v1/a", 200, 100, 50, "application/json")
	_ = insertRec("host1.com", "GET", "/api/v1/b/c", 200, 100, 50, "application/json")
	_ = insertRec("host1.com", "GET", "/api/v1/d/e/f", 200, 100, 50, "application/json")

	// Group 3: only 2 records under /static/... — below threshold, NOT deduplicated
	g3a := insertRec("host1.com", "GET", "/static/css/main.css", 200, 500, 10, "text/css")
	g3b := insertRec("host1.com", "GET", "/static/css/reset.css", 200, 500, 10, "text/css")

	// Non-deparos record matching group 1 characteristics — should NOT be touched
	nonDeparos := uuid.NewString()
	_, err := db.NewInsert().Model(&HTTPRecord{
		UUID:                  nonDeparos,
		ProjectUUID:           projectUUID,
		Scheme:                "https",
		Hostname:              "host1.com",
		Port:                  443,
		Method:                "GET",
		Path:                  "/ftp/quarantine/scanner",
		URL:                   "https://host1.com/ftp/quarantine/scanner",
		HTTPVersion:           "HTTP/1.1",
		RequestHash:           nonDeparos,
		ResponseHash:          nonDeparos,
		StatusCode:            405,
		ResponseContentLength: 0,
		ResponseWords:         28,
		ResponseContentType:   "text/html",
		HasResponse:           true,
		Source:                "scanner",
		SentAt:                now,
		CreatedAt:             now,
	}).Exec(ctx)
	if err != nil {
		t.Fatalf("insert non-deparos record: %v", err)
	}

	// Insert a finding_records junction row for one of the duplicates
	_, err = db.ExecContext(ctx,
		"INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name, finding_hash, severity, confidence, http_record_uuids) VALUES (?, 'scan1', 'mod1', 'mod1', 'fh-soft', 'info', 'tentative', '[]')",
		projectUUID)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	_, err = db.ExecContext(ctx, "INSERT INTO finding_records (finding_id, record_uuid) VALUES (1, ?)", g1Dup1)
	if err != nil {
		t.Fatalf("insert finding_records: %v", err)
	}

	cleanup, err := repo.DeduplicateSoftDeparosRecords(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateSoftDeparosRecords: %v", err)
	}

	// Group 1: 5 → 1 = 4 selected, but g1Dup1 is cited by a finding and is kept
	//          = 3 deleted, 1 kept
	// Group 2: 3 → 1 = 2 deleted
	// Group 3: 2 members, below threshold = 0 deleted
	// Total: 5 deleted, 1 kept.
	if cleanup.Deleted != 5 {
		t.Errorf("expected 5 deleted, got %d", cleanup.Deleted)
	}
	if cleanup.KeptReferenced != 1 {
		t.Errorf("expected 1 record kept for its finding link, got %d", cleanup.KeptReferenced)
	}
	if cleanup.ByStatus == nil {
		t.Error("expected non-nil ByStatus map")
	}
	// The breakdown counts only what was deleted, so the spared 405 is absent from it.
	if cleanup.ByStatus[405] != 3 {
		t.Errorf("expected 3 deleted 405s in the breakdown, got %d", cleanup.ByStatus[405])
	}

	// Verify survivors — g1Dup1 survives purely because a finding references it.
	survivors := map[string]bool{g1Short: true, g1Dup1: true, g2Short: true, g3a: true, g3b: true, nonDeparos: true}
	var remaining []*HTTPRecord
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if len(remaining) != len(survivors) {
		t.Errorf("expected %d remaining records, got %d", len(survivors), len(remaining))
	}
	for _, rec := range remaining {
		if !survivors[rec.UUID] {
			t.Errorf("unexpected survivor: %s (path=%s, source=%s)", rec.UUID, rec.Path, rec.Source)
		}
	}

	// The evidence link survives intact: the finding can still reach its record.
	var junctionCount int
	err = db.NewRaw("SELECT COUNT(*) FROM finding_records WHERE record_uuid = ?", g1Dup1).Scan(ctx, &junctionCount)
	if err != nil {
		t.Fatalf("junction count query: %v", err)
	}
	if junctionCount != 1 {
		t.Errorf("expected the finding's evidence link preserved, got %d junction rows", junctionCount)
	}

	// Idempotent: a second pass finds the same survivor set and deletes nothing.
	again, err := repo.DeduplicateSoftDeparosRecords(ctx, projectUUID)
	if err != nil {
		t.Fatalf("second DeduplicateSoftDeparosRecords: %v", err)
	}
	if again.Deleted != 0 {
		t.Errorf("expected second pass to delete 0, got %d", again.Deleted)
	}
}

func TestDeduplicateSoftDeparosRecords_NoRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	cleanup, err := repo.DeduplicateSoftDeparosRecords(ctx, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cleanup.Deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", cleanup.Deleted)
	}
}

func TestDeduplicateSoftDeparosRecords_DifferentCharacteristics(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	now := time.Now()

	insertRec := func(path string, statusCode int, words int64) string {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:                  id,
			ProjectUUID:           projectUUID,
			Scheme:                "https",
			Hostname:              "host1.com",
			Port:                  443,
			Method:                "GET",
			Path:                  path,
			URL:                   "https://host1.com" + path,
			HTTPVersion:           "HTTP/1.1",
			RequestHash:           id,
			ResponseHash:          id,
			StatusCode:            statusCode,
			ResponseContentLength: 100,
			ResponseWords:         words,
			ResponseContentType:   "text/html",
			HasResponse:           true,
			Source:                "deparos",
			SentAt:                now,
			CreatedAt:             now,
		}
		_, err := db.NewInsert().Model(rec).Exec(ctx)
		if err != nil {
			t.Fatalf("insert record: %v", err)
		}
		return id
	}

	// Same prefix /api/v1/ but different status codes — should NOT be grouped
	insertRec("/api/v1/a", 200, 50)
	insertRec("/api/v1/b", 404, 50)
	insertRec("/api/v1/c", 500, 50)

	// Same prefix /api/v1/ but different word counts — should NOT be grouped
	insertRec("/api/v1/d", 200, 10)
	insertRec("/api/v1/e", 200, 20)
	insertRec("/api/v1/f", 200, 30)

	cleanup, err := repo.DeduplicateSoftDeparosRecords(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateSoftDeparosRecords: %v", err)
	}
	if cleanup.Deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", cleanup.Deleted)
	}
}

// TestDeduplicateSoftDeparosRecords_ReflectedURLLength is the regression for the
// reflected-URL case: a family of probes against an error page that echoes the
// requested URI share status/words/content-type/prefix but differ in
// response_content_length (the echoed URI's length varies per probe). Now that
// exact length is no longer part of the soft-dedup key, the family collapses.
func TestDeduplicateSoftDeparosRecords_ReflectedURLLength(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	now := time.Now()

	insertRec := func(path string, contentLength int64) {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:                  id,
			ProjectUUID:           projectUUID,
			Scheme:                "https",
			Hostname:              "host1.com",
			Port:                  443,
			Method:                "GET",
			Path:                  path,
			URL:                   "https://host1.com" + path,
			HTTPVersion:           "HTTP/1.1",
			RequestHash:           id,
			ResponseHash:          id, // unique hash → exact dedup can't help
			StatusCode:            400,
			ResponseContentLength: contentLength, // varies with the echoed URI
			ResponseWords:         42,
			ResponseContentType:   "text/html",
			HasResponse:           true,
			Source:                "deparos",
			SentAt:                now,
			CreatedAt:             now,
		}
		if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
			t.Fatalf("insert record: %v", err)
		}
	}

	// 4 probes under /jboss-net/, identical shape but each a different length.
	insertRec("/jboss-net//happyaxis.jsp", 430)
	insertRec("/jboss-net//happyaxis.jsp.OLD", 434)
	insertRec("/jboss-net//happyaxis.jsp.orig", 435)
	insertRec("/jboss-net//happyaxis.jsp.csproj", 437)

	cleanup, err := repo.DeduplicateSoftDeparosRecords(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateSoftDeparosRecords: %v", err)
	}
	// 4 → 1 survivor = 3 deleted, despite the differing content lengths.
	if cleanup.Deleted != 3 {
		t.Errorf("expected 3 deleted (reflected-URL family collapses regardless of length), got %d", cleanup.Deleted)
	}
}

func TestApplyDeparosStatusPolicy(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	now := time.Now()

	insertRec := func(hostname, path string, statusCode int, source string) string {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:         id,
			ProjectUUID:  projectUUID,
			Scheme:       "https",
			Hostname:     hostname,
			Port:         443,
			Method:       "GET",
			Path:         path,
			URL:          "https://" + hostname + path,
			HTTPVersion:  "HTTP/1.1",
			RequestHash:  id,
			ResponseHash: id,
			StatusCode:   statusCode,
			HasResponse:  true,
			Source:       source,
			SentAt:       now,
			CreatedAt:    now,
		}
		if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
			t.Fatalf("insert record: %v", err)
		}
		return id
	}

	// 4xx that must be dropped.
	insertRec("h1.com", "/bad-400", 400, "deparos")
	insertRec("h1.com", "/forbidden-403", 403, "deparos")
	insertRec("h1.com", "/gone-410", 410, "deparos")
	// 401s on h1: collapse to one representative (shortest path survives).
	a1 := insertRec("h1.com", "/a", 401, "deparos")
	insertRec("h1.com", "/admin/secret", 401, "deparos")
	insertRec("h1.com", "/another/longer/path", 401, "deparos")
	// 401 on a second host keeps its own representative.
	b1 := insertRec("h2.com", "/login", 401, "deparos")
	// Kept statuses (not 4xx).
	ok200 := insertRec("h1.com", "/index", 200, "deparos")
	redir := insertRec("h1.com", "/old", 301, "deparos")
	serr := insertRec("h1.com", "/boom", 500, "deparos")
	// A 403 from a non-deparos source must be untouched.
	nonDeparos := insertRec("h1.com", "/scanner-403", 403, "scanner")

	cleanup, err := repo.ApplyDeparosStatusPolicy(ctx, projectUUID, DeparosStatusPolicy{KeepOnePerHost: []int{401}})
	if err != nil {
		t.Fatalf("ApplyDeparosStatusPolicy: %v", err)
	}
	// Dropped: 400, 403, 410 (3) + two extra 401s on h1 (2) = 5.
	if cleanup.Deleted != 5 {
		t.Errorf("expected 5 deleted, got %d", cleanup.Deleted)
	}
	if cleanup.ByStatus[401] != 2 {
		t.Errorf("expected 2 collapsed 401 records in breakdown, got %d", cleanup.ByStatus[401])
	}

	survivors := map[string]bool{a1: true, b1: true, ok200: true, redir: true, serr: true, nonDeparos: true}
	var remaining []*HTTPRecord
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if len(remaining) != len(survivors) {
		t.Errorf("expected %d remaining, got %d", len(survivors), len(remaining))
	}
	for _, rec := range remaining {
		if !survivors[rec.UUID] {
			t.Errorf("unexpected survivor: %s (path=%s status=%d source=%s)", rec.UUID, rec.Path, rec.StatusCode, rec.Source)
		}
	}
}

func TestApplyDeparosStatusPolicy_NoKeepDropsAll4xx(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID
	now := time.Now()

	insert := func(path string, status int) {
		id := uuid.NewString()
		_, err := db.NewInsert().Model(&HTTPRecord{
			UUID: id, ProjectUUID: projectUUID, Scheme: "https", Hostname: "h.com", Port: 443,
			Method: "GET", Path: path, URL: "https://h.com" + path, HTTPVersion: "HTTP/1.1",
			RequestHash: id, ResponseHash: id, StatusCode: status, HasResponse: true,
			Source: "deparos", SentAt: now, CreatedAt: now,
		}).Exec(ctx)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	insert("/a", 401)
	insert("/b", 403)
	insert("/c", 200)

	// Empty policy ⇒ every 4xx (including 401) is dropped.
	cleanup, err := repo.ApplyDeparosStatusPolicy(ctx, projectUUID, DeparosStatusPolicy{})
	if err != nil {
		t.Fatalf("ApplyDeparosStatusPolicy: %v", err)
	}
	if cleanup.Deleted != 2 {
		t.Errorf("expected 2 deleted (401+403), got %d", cleanup.Deleted)
	}
}

// TestApplyDeparosStatusPolicy_Tiers proves the tiered retention policy:
//   - KeepOnePerHost (401/403): collapse to one representative per (host,status).
//   - KeepPerPath (405): preserve EVERY distinct path (route identity), collapse
//     only exact-duplicate paths, and cap distinct paths per (host,status).
//   - Noise (404): dropped entirely.
func TestApplyDeparosStatusPolicy_Tiers(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID
	now := time.Now()

	insert := func(host, path string, status int) string {
		id := uuid.NewString()
		_, err := db.NewInsert().Model(&HTTPRecord{
			UUID: id, ProjectUUID: projectUUID, Scheme: "https", Hostname: host, Port: 443,
			Method: "GET", Path: path, URL: "https://" + host + path, HTTPVersion: "HTTP/1.1",
			RequestHash: id, ResponseHash: id, StatusCode: status, HasResponse: true,
			Source: "deparos", SentAt: now, CreatedAt: now,
		}).Exec(ctx)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
		return id
	}

	// Authz tier: three 403s on one host collapse to the shortest path.
	f1 := insert("h.com", "/x", 403)
	insert("h.com", "/admin/panel", 403)
	insert("h.com", "/very/long/forbidden/path", 403)
	// Endpoint-exists tier: two DISTINCT 405 paths must BOTH survive (route
	// identity), plus an exact-duplicate of one that must collapse.
	m1 := insert("h.com", "/api/users", 405)
	m2 := insert("h.com", "/api/orders", 405)
	insert("h.com", "/api/users", 405) // exact-dup path → dropped
	// Noise tier: 404 dropped entirely.
	insert("h.com", "/nope", 404)
	// Untouched: 200.
	ok := insert("h.com", "/", 200)

	cleanup, err := repo.ApplyDeparosStatusPolicy(ctx, projectUUID, DeparosStatusPolicy{
		KeepOnePerHost: []int{401, 403, 429},
		KeepPerPath:    []int{405, 415, 422},
		PerPathCap:     100,
	})
	if err != nil {
		t.Fatalf("ApplyDeparosStatusPolicy: %v", err)
	}
	// Dropped: two extra 403s (2) + one dup 405 path (1) + one 404 (1) = 4.
	if cleanup.Deleted != 4 {
		t.Errorf("expected 4 deleted, got %d", cleanup.Deleted)
	}

	survivors := map[string]bool{f1: true, m1: true, m2: true, ok: true}
	var remaining []*HTTPRecord
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if len(remaining) != len(survivors) {
		t.Errorf("expected %d remaining, got %d", len(survivors), len(remaining))
	}
	for _, rec := range remaining {
		if !survivors[rec.UUID] {
			t.Errorf("unexpected survivor: path=%s status=%d", rec.Path, rec.StatusCode)
		}
	}
}

// TestApplyDeparosStatusPolicy_PerPathCap proves distinct KeepPerPath paths are
// bounded per (host,status) so a pathological host can't flood the store.
func TestApplyDeparosStatusPolicy_PerPathCap(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID
	now := time.Now()

	for i := 0; i < 10; i++ {
		id := uuid.NewString()
		_, err := db.NewInsert().Model(&HTTPRecord{
			UUID: id, ProjectUUID: projectUUID, Scheme: "https", Hostname: "flood.com", Port: 443,
			Method: "GET", Path: fmt.Sprintf("/p%02d", i), URL: fmt.Sprintf("https://flood.com/p%02d", i),
			HTTPVersion: "HTTP/1.1", RequestHash: id, ResponseHash: id, StatusCode: 422, HasResponse: true,
			Source: "deparos", SentAt: now, CreatedAt: now,
		}).Exec(ctx)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	cleanup, err := repo.ApplyDeparosStatusPolicy(ctx, projectUUID, DeparosStatusPolicy{
		KeepPerPath: []int{422},
		PerPathCap:  3,
	})
	if err != nil {
		t.Fatalf("ApplyDeparosStatusPolicy: %v", err)
	}
	if cleanup.Deleted != 7 {
		t.Errorf("expected 7 deleted (10 distinct paths capped to 3), got %d", cleanup.Deleted)
	}
}

func TestDeduplicateDeparosByNormHash(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	now := time.Now()

	insertRec := func(hostname, path string, status int, normHash, source string) string {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:                id,
			ProjectUUID:         projectUUID,
			Scheme:              "https",
			Hostname:            hostname,
			Port:                443,
			Method:              "GET",
			Path:                path,
			URL:                 "https://" + hostname + path,
			HTTPVersion:         "HTTP/1.1",
			RequestHash:         id,
			ResponseHash:        id, // unique — exact dedup never fires
			ResponseNormHash:    normHash,
			StatusCode:          status,
			ResponseContentType: "text/html",
			HasResponse:         true,
			Source:              source,
			SentAt:              now,
			CreatedAt:           now,
		}
		if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
			t.Fatalf("insert record: %v", err)
		}
		return id
	}

	// Same normalized body across 3 echoing paths — shortest path survives.
	keep := insertRec("h1.com", "/x", 200, "NORM-AAA", "deparos")
	insertRec("h1.com", "/x/longer", 200, "NORM-AAA", "deparos")
	insertRec("h1.com", "/x/longest/path", 200, "NORM-AAA", "deparos")
	// Different normalized body — kept.
	other := insertRec("h1.com", "/y", 200, "NORM-BBB", "deparos")
	// Same norm hash but different status — not collapsed together.
	diffStatus := insertRec("h1.com", "/z", 500, "NORM-AAA", "deparos")
	// Empty norm hash (e.g. empty body) — left to exact dedup, untouched.
	emptyNorm1 := insertRec("h1.com", "/e1", 204, "", "deparos")
	emptyNorm2 := insertRec("h1.com", "/e2", 204, "", "deparos")
	// Matching norm hash but non-deparos source — untouched.
	nonDeparos := insertRec("h1.com", "/n", 200, "NORM-AAA", "scanner")

	cleanup, err := repo.DeduplicateDeparosByNormHash(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateDeparosByNormHash: %v", err)
	}
	if cleanup.Deleted != 2 {
		t.Errorf("expected 2 deleted, got %d", cleanup.Deleted)
	}

	survivors := map[string]bool{keep: true, other: true, diffStatus: true, emptyNorm1: true, emptyNorm2: true, nonDeparos: true}
	var remaining []*HTTPRecord
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if len(remaining) != len(survivors) {
		t.Errorf("expected %d remaining, got %d", len(survivors), len(remaining))
	}
	for _, rec := range remaining {
		if !survivors[rec.UUID] {
			t.Errorf("unexpected survivor: %s (path=%s norm=%s)", rec.UUID, rec.Path, rec.ResponseNormHash)
		}
	}
}

// insertRecordNoResponse inserts a deparos record without a response.
func insertRecordNoResponse(t *testing.T, db *DB, ctx context.Context, projectUUID string) string {
	t.Helper()
	id := uuid.NewString()
	rec := &HTTPRecord{
		UUID:         id,
		ProjectUUID:  projectUUID,
		Scheme:       "https",
		Hostname:     "host1.com",
		Port:         443,
		Method:       "GET",
		Path:         "/no-response",
		URL:          "https://host1.com/no-response",
		HTTPVersion:  "HTTP/1.1",
		RequestHash:  id,
		HasResponse:  false,
		Source:       "deparos",
		ResponseHash: "hash-aaa",
		SentAt:       time.Now(),
		CreatedAt:    time.Now(),
	}
	_, err := db.NewInsert().Model(rec).Exec(ctx)
	if err != nil {
		t.Fatalf("insert no-response record: %v", err)
	}
	return id
}

// --- WP5: discovery cleanup never deletes finding evidence ---------------------

// dedupEvidenceFixture builds the shared setup for the evidence-protection tests:
// a repository, a record inserter, and helpers to attach a finding or an analysis
// artifact to a record.
type dedupEvidenceFixture struct {
	db          *DB
	repo        *Repository
	ctx         context.Context
	projectUUID string
	now         time.Time
	t           *testing.T
}

func newDedupEvidenceFixture(t *testing.T) *dedupEvidenceFixture {
	t.Helper()
	db := newTestDB(t)
	return &dedupEvidenceFixture{
		db:          db,
		repo:        NewRepository(db),
		ctx:         context.Background(),
		projectUUID: DefaultProjectUUID,
		now:         time.Now(),
		t:           t,
	}
}

// insert writes one deparos record. scheme/port make the origin explicit so the
// origin-partition tests can place byte-identical responses on different origins.
func (f *dedupEvidenceFixture) insert(scheme, hostname string, port int, path string, status int, opts ...func(*HTTPRecord)) string {
	f.t.Helper()
	id := uuid.NewString()
	rec := &HTTPRecord{
		UUID: id, ProjectUUID: f.projectUUID,
		Scheme: scheme, Hostname: hostname, Port: port,
		Method: "GET", Path: path,
		URL:         fmt.Sprintf("%s://%s:%d%s", scheme, hostname, port, path),
		HTTPVersion: "HTTP/1.1",
		RequestHash: id, ResponseHash: id,
		StatusCode: status, HasResponse: true,
		Source: "deparos", SentAt: f.now, CreatedAt: f.now,
	}
	for _, o := range opts {
		o(rec)
	}
	if _, err := f.db.NewInsert().Model(rec).Exec(f.ctx); err != nil {
		f.t.Fatalf("insert record %s: %v", path, err)
	}
	return id
}

// citeByFinding links recUUID to a new finding, making it protected evidence.
func (f *dedupEvidenceFixture) citeByFinding(recUUID string) {
	f.t.Helper()
	res, err := f.db.ExecContext(f.ctx,
		`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name,
			finding_hash, severity, confidence, http_record_uuids)
		VALUES (?, 'scan1', 'mod1', 'mod1', ?, 'info', 'tentative', '[]')`,
		f.projectUUID, uuid.NewString())
	if err != nil {
		f.t.Fatalf("insert finding: %v", err)
	}
	fid, _ := res.LastInsertId()
	if _, err := f.db.ExecContext(f.ctx,
		`INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)`, fid, recUUID); err != nil {
		f.t.Fatalf("insert finding_records: %v", err)
	}
}

// citeByArtifact attaches an analysis artifact (the JSTangle/derived-evidence
// path), the second reference kind cleanup must respect.
func (f *dedupEvidenceFixture) citeByArtifact(recUUID string) {
	f.t.Helper()
	if _, err := f.db.NewInsert().Model(&AnalysisArtifact{
		ProjectUUID: f.projectUUID, HTTPRecordUUID: recUUID,
		Kind: "sourcemap", SHA256: uuid.NewString(), ByteLength: 3,
		Content: []byte("js"), CreatedAt: f.now,
	}).Exec(f.ctx); err != nil {
		f.t.Fatalf("insert analysis_artifact: %v", err)
	}
}

func (f *dedupEvidenceFixture) alive(recUUID string) bool {
	f.t.Helper()
	n, err := f.db.NewSelect().Model((*HTTPRecord)(nil)).Where("uuid = ?", recUUID).Count(f.ctx)
	if err != nil {
		f.t.Fatalf("count record: %v", err)
	}
	return n == 1
}

// TestApplyDeparosStatusPolicy_KeepsReferencedRecords is the WP5 regression for
// the project-wide evidence loss: the 4xx drop tier ran after every discovery
// phase and deleted an earlier scan's records along with the finding_records rows
// that pointed at them, so a finding from scan 1 silently lost its evidence when
// scan 2 ran in the same project.
func TestApplyDeparosStatusPolicy_KeepsReferencedRecords(t *testing.T) {
	f := newDedupEvidenceFixture(t)

	cited := f.insert("https", "h.com", 443, "/cited", 404)
	artifact := f.insert("https", "h.com", 443, "/artifact", 404)
	noise := f.insert("https", "h.com", 443, "/noise", 404)
	f.citeByFinding(cited)
	f.citeByArtifact(artifact)

	// Empty policy ⇒ every 4xx is noise and selected for deletion.
	cleanup, err := f.repo.ApplyDeparosStatusPolicy(f.ctx, f.projectUUID, DeparosStatusPolicy{})
	if err != nil {
		t.Fatalf("ApplyDeparosStatusPolicy: %v", err)
	}
	if cleanup.Deleted != 1 {
		t.Errorf("expected 1 deleted (only the unreferenced 404), got %d", cleanup.Deleted)
	}
	if cleanup.KeptReferenced != 2 {
		t.Errorf("expected 2 kept (finding + artifact), got %d", cleanup.KeptReferenced)
	}
	if cleanup.ByStatus[404] != 1 {
		t.Errorf("breakdown must count only deletions; got %d for 404", cleanup.ByStatus[404])
	}
	if !f.alive(cited) {
		t.Error("record cited by a finding was deleted")
	}
	if !f.alive(artifact) {
		t.Error("record carrying an analysis artifact was deleted")
	}
	if f.alive(noise) {
		t.Error("unreferenced noise record survived")
	}

	// The evidence link is intact, not merely the record.
	var links int
	if err := f.db.NewRaw("SELECT COUNT(*) FROM finding_records WHERE record_uuid = ?", cited).Scan(f.ctx, &links); err != nil {
		t.Fatalf("junction count: %v", err)
	}
	if links != 1 {
		t.Errorf("expected the evidence link preserved, got %d", links)
	}

	// Idempotent: the protected records are re-selected every pass and must keep
	// being spared rather than accumulating deletions.
	again, err := f.repo.ApplyDeparosStatusPolicy(f.ctx, f.projectUUID, DeparosStatusPolicy{})
	if err != nil {
		t.Fatalf("second ApplyDeparosStatusPolicy: %v", err)
	}
	if again.Deleted != 0 || again.KeptReferenced != 2 {
		t.Errorf("second pass: deleted %d / kept %d, want 0 / 2", again.Deleted, again.KeptReferenced)
	}
}

// TestDeduplicateDeparosByNormHash_KeepsReferencedRecords covers the norm-hash
// pass: the referenced record is not the group survivor, so without the guard it
// would be collapsed away.
func TestDeduplicateDeparosByNormHash_KeepsReferencedRecords(t *testing.T) {
	f := newDedupEvidenceFixture(t)
	norm := func(r *HTTPRecord) { r.ResponseNormHash = "NORM-AAA"; r.ResponseContentType = "text/html" }

	survivor := f.insert("https", "h.com", 443, "/a", 200, norm)
	cited := f.insert("https", "h.com", 443, "/bbbb", 200, norm)
	noise := f.insert("https", "h.com", 443, "/cccc", 200, norm)
	f.citeByFinding(cited)

	cleanup, err := f.repo.DeduplicateDeparosByNormHash(f.ctx, f.projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateDeparosByNormHash: %v", err)
	}
	if cleanup.Deleted != 1 || cleanup.KeptReferenced != 1 {
		t.Errorf("deleted %d / kept %d, want 1 / 1", cleanup.Deleted, cleanup.KeptReferenced)
	}
	if !f.alive(survivor) || !f.alive(cited) {
		t.Error("expected both the shortest-path survivor and the cited record to remain")
	}
	if f.alive(noise) {
		t.Error("unreferenced duplicate survived")
	}
}

// TestDeduplicateRecordsBySource_KeepsReferencedRecords covers the source-scoped
// pass, which the agent knowledge-base traffic cleanup also runs (A.6 #7).
func TestDeduplicateRecordsBySource_KeepsReferencedRecords(t *testing.T) {
	f := newDedupEvidenceFixture(t)
	same := func(r *HTTPRecord) { r.ResponseHash = "SAME"; r.ResponseContentLength = 10 }

	survivor := f.insert("https", "h.com", 443, "/a", 200, same)
	cited := f.insert("https", "h.com", 443, "/bbbb", 200, same)
	noise := f.insert("https", "h.com", 443, "/cccc", 200, same)
	f.citeByFinding(cited)

	deleted, err := f.repo.DeduplicateRecordsBySource(f.ctx, f.projectUUID, "deparos")
	if err != nil {
		t.Fatalf("DeduplicateRecordsBySource: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}
	if !f.alive(survivor) || !f.alive(cited) {
		t.Error("expected the survivor and the cited record to remain")
	}
	if f.alive(noise) {
		t.Error("unreferenced duplicate survived")
	}
}

// TestDedupPartitionsByOrigin proves the passes key on (hostname, scheme, port),
// not hostname alone: byte-identical responses served by three different origins
// on one hostname are three services' evidence, and collapsing them to a single
// survivor threw two of them away.
func TestDedupPartitionsByOrigin(t *testing.T) {
	f := newDedupEvidenceFixture(t)

	plain := f.insert("http", "h.com", 80, "/x", 401)
	tls := f.insert("https", "h.com", 443, "/x", 401)
	altPort := f.insert("https", "h.com", 8443, "/x", 401)
	// A second 401 on one origin is a genuine duplicate and must still collapse.
	dupOnTLS := f.insert("https", "h.com", 443, "/x-longer", 401)

	cleanup, err := f.repo.ApplyDeparosStatusPolicy(f.ctx, f.projectUUID,
		DeparosStatusPolicy{KeepOnePerHost: []int{401}})
	if err != nil {
		t.Fatalf("ApplyDeparosStatusPolicy: %v", err)
	}
	if cleanup.Deleted != 1 {
		t.Errorf("expected 1 deleted (the same-origin duplicate), got %d", cleanup.Deleted)
	}
	for name, id := range map[string]string{"http:80": plain, "https:443": tls, "https:8443": altPort} {
		if !f.alive(id) {
			t.Errorf("origin %s lost its representative 401", name)
		}
	}
	if f.alive(dupOnTLS) {
		t.Error("same-origin duplicate 401 survived")
	}
}
