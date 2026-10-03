package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
)

// writeFindingGlobFixture writes a standalone .sqlite result file holding one
// finding and the HTTP record it links to, with real request/response bytes.
func writeFindingGlobFixture(t *testing.T, dir, host string) string {
	t.Helper()
	path := filepath.Join(dir, "scan-"+host+".sqlite")

	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB(%s): %v", path, err)
	}
	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	if _, err := db.NewInsert().Model(&database.HTTPRecord{
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
		HasResponse: true,
		RawRequest:  []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
		RawResponse: []byte("HTTP/1.1 200 OK\r\n\r\nbody-of-" + host),
	}).Exec(ctx); err != nil {
		t.Fatalf("insert record: %v", err)
	}
	if err := database.NewRepository(db).SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID:     "proj-" + host,
		HTTPRecordUUIDs: []string{"rec-" + host},
		ModuleID:        "mod-" + host,
		ModuleName:      "Module " + host,
		Severity:        "high",
		Confidence:      "firm",
		FindingHash:     "hash-" + host,
		URL:             "https://" + host + "/",
		Hostname:        host,
	}); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	return path
}

// mergedFindings runs the glob merge the way runFinding does and returns the
// merged database alongside the findings in it.
func mergedFindings(t *testing.T, pattern string, skip globDBSkipSet) (*database.DB, []*database.Finding) {
	t.Helper()
	db, err := openGlobDB(pattern, skip)
	if err != nil {
		t.Fatalf("openGlobDB: %v", err)
	}
	var findings []*database.Finding
	if err := db.NewSelect().Model(&findings).Order("id ASC").Scan(context.Background()); err != nil {
		t.Fatalf("scan findings: %v", err)
	}
	return db, findings
}

// The point of the whole path: the merge carries no records at all, yet the
// evidence still resolves — from each finding's own source file.
func TestLoadGlobFindingRecordsResolvesFromSourceFiles(t *testing.T) {
	dir := t.TempDir()
	writeFindingGlobFixture(t, dir, "a.example")
	writeFindingGlobFixture(t, dir, "b.example")
	t.Cleanup(resetDBCacheForTest)

	_, findings := mergedFindings(t, filepath.Join(dir, "scan-*.sqlite"),
		globDBSkipSet{Records: true, RecordFileMap: true})
	if len(findings) != 2 {
		t.Fatalf("expected 2 merged findings, got %d", len(findings))
	}

	byUUID := loadGlobFindingRecords(context.Background(), findings,
		[]string{"rec-a.example", "rec-b.example"})
	if len(byUUID) != 2 {
		t.Fatalf("expected both records resolved, got %d: %v", len(byUUID), byUUID)
	}
	for _, host := range []string{"a.example", "b.example"} {
		record := byUUID["rec-"+host]
		if record == nil {
			t.Fatalf("record for %s not resolved", host)
		}
		want := "HTTP/1.1 200 OK\r\n\r\nbody-of-" + host
		if string(record.RawResponse) != want {
			t.Fatalf("%s: raw response = %q, want %q", host, record.RawResponse, want)
		}
		if len(record.RawRequest) == 0 {
			t.Fatalf("%s: raw request came back empty", host)
		}
	}
}

// The per-finding attribution is a hint, not a guarantee. A uuid its own file
// does not hold must still be found by the fallback sweep rather than rendered
// as empty evidence.
func TestLoadGlobFindingRecordsSweepsWhenAttributionMisses(t *testing.T) {
	dir := t.TempDir()
	writeFindingGlobFixture(t, dir, "a.example")
	writeFindingGlobFixture(t, dir, "b.example")
	t.Cleanup(resetDBCacheForTest)

	_, findings := mergedFindings(t, filepath.Join(dir, "scan-*.sqlite"),
		globDBSkipSet{Records: true, RecordFileMap: true})

	// Point the first finding at the OTHER file's record: its attributed file
	// cannot satisfy it, so only the sweep can.
	findings[0].HTTPRecordUUIDs = []string{"rec-b.example"}

	byUUID := loadGlobFindingRecords(context.Background(),
		findings[:1], []string{"rec-b.example"})
	if byUUID["rec-b.example"] == nil {
		t.Fatalf("sweep failed to resolve a record outside its finding's file: %v", byUUID)
	}
}

// A uuid no file holds must simply be absent — not a hang, not a panic.
func TestLoadGlobFindingRecordsToleratesUnresolvableUUID(t *testing.T) {
	dir := t.TempDir()
	writeFindingGlobFixture(t, dir, "a.example")
	t.Cleanup(resetDBCacheForTest)

	_, findings := mergedFindings(t, filepath.Join(dir, "scan-*.sqlite"),
		globDBSkipSet{Records: true, RecordFileMap: true})
	findings[0].HTTPRecordUUIDs = []string{"rec-gone"}

	byUUID := loadGlobFindingRecords(context.Background(), findings, []string{"rec-gone"})
	if len(byUUID) != 0 {
		t.Fatalf("expected nothing resolved, got %v", byUUID)
	}
}

func TestGlobFindingRecordPlanGroupsByAttributedFile(t *testing.T) {
	dir := t.TempDir()
	writeFindingGlobFixture(t, dir, "a.example")
	writeFindingGlobFixture(t, dir, "b.example")
	t.Cleanup(resetDBCacheForTest)

	_, findings := mergedFindings(t, filepath.Join(dir, "scan-*.sqlite"),
		globDBSkipSet{Records: true, RecordFileMap: true})

	wanted := map[string]struct{}{"rec-a.example": {}, "rec-b.example": {}}
	order, byFile := globFindingRecordPlan(findings, wanted)
	if len(order) != 2 {
		t.Fatalf("expected 2 files in the plan, got %d: %v", len(order), order)
	}
	for _, file := range order {
		if len(byFile[file]) != 1 {
			t.Fatalf("%s: expected 1 uuid, got %v", file, byFile[file])
		}
	}
}

// A uuid nobody asked for must not drag its file into the plan.
func TestGlobFindingRecordPlanIgnoresUnwantedUUIDs(t *testing.T) {
	findings := []*database.Finding{{ID: 1, HTTPRecordUUIDs: []string{"rec-x"}}}
	order, byFile := globFindingRecordPlan(findings, map[string]struct{}{"rec-y": {}})
	if len(order) != 0 || len(byFile) != 0 {
		t.Fatalf("plan = %v / %v, want empty", order, byFile)
	}
}

// The core contract: an output mode may never pull records into the merge, but a
// filter always must — a filter runs in SQL and cannot be applied after the fact.
//
// wantOmitted is what the merge left out, which is what decides whether evidence
// has to be hydrated from the source files. Note it is true for a plain listing
// too: nothing is wrong with that, because a run that renders no evidence never
// reaches batchLoadFindingRecords to ask.
func TestFindingGlobSkipSetOutputModeNeverForcesTheMerge(t *testing.T) {
	restoreGlob := globalGlobDB
	globalGlobDB = "scans/*.sqlite"
	t.Cleanup(func() { globalGlobDB = restoreGlob })

	cases := []struct {
		name             string
		setFlag          func()
		filters          database.QueryFilters
		wantRecords      bool // merge omits http_records entirely
		wantRecordBodies bool // merge omits raw_request/raw_response
		wantOmitted      bool
	}{
		{
			name:             "plain listing merges no records at all",
			setFlag:          func() {},
			filters:          database.QueryFilters{},
			wantRecords:      true,
			wantRecordBodies: true,
			wantOmitted:      true,
		},
		{
			name:             "--with-records hydrates lazily instead of merging bodies",
			setFlag:          func() { findingWithRecords = true },
			filters:          database.QueryFilters{},
			wantRecords:      true,
			wantRecordBodies: true,
			wantOmitted:      true,
		},
		{
			name:             "--push-to-burp hydrates lazily too",
			setFlag:          func() { findingPushToBurp = true },
			filters:          database.QueryFilters{},
			wantRecords:      true,
			wantRecordBodies: true,
			wantOmitted:      true,
		},
		{
			name:             "--host needs record rows, not bodies",
			setFlag:          func() {},
			filters:          database.QueryFilters{HostPattern: "api.example"},
			wantRecords:      false,
			wantRecordBodies: true,
			wantOmitted:      true,
		},
		{
			name:             "--search needs the raw corpus in SQL",
			setFlag:          func() {},
			filters:          database.QueryFilters{SearchTerms: []string{"jwt"}},
			wantRecords:      false,
			wantRecordBodies: false,
			wantOmitted:      false,
		},
		{
			name:             "--search with --raw keeps the corpus and needs no lazy pass",
			setFlag:          func() { findingRaw = true },
			filters:          database.QueryFilters{SearchTerms: []string{"jwt"}},
			wantRecords:      false,
			wantRecordBodies: false,
			wantOmitted:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetFindingOutputFlags(t)
			tc.setFlag()
			skip := findingGlobSkipSet(tc.filters)
			if skip.Records != tc.wantRecords {
				t.Errorf("Records = %v, want %v", skip.Records, tc.wantRecords)
			}
			if skip.RecordBodies != tc.wantRecordBodies {
				t.Errorf("RecordBodies = %v, want %v", skip.RecordBodies, tc.wantRecordBodies)
			}
			// The merge is what decides whether evidence must be fetched from the
			// source files, so assert through the predicate the read site uses.
			globDBSources = []globDBSource{{file: "a.sqlite"}}
			globDBSkipped = skip
			t.Cleanup(func() { globDBSources = nil; globDBSkipped = globDBSkipSet{} })
			if got := globMergeOmittedRecords(); got != tc.wantOmitted {
				t.Errorf("globMergeOmittedRecords() = %v, want %v", got, tc.wantOmitted)
			}
		})
	}
}

// Without a --glob-db merge there is nothing to hydrate from: a single --db
// source is queried in place with nothing omitted, so the lazy path must stay off
// however aggressive the skip set would have been.
func TestGlobMergeOmittedRecordsFalseWithoutAMerge(t *testing.T) {
	globDBSources = nil
	globDBSkipped = globDBSkipSet{Records: true, RecordBodies: true}
	t.Cleanup(func() { globDBSkipped = globDBSkipSet{} })

	if globMergeOmittedRecords() {
		t.Fatal("lazy hydration must not engage when no glob merge ran")
	}
}

func resetFindingOutputFlags(t *testing.T) {
	t.Helper()
	saved := [...]bool{findingRaw, findingBurp, findingMarkdown, findingWithRecords, findingPushToBurp, findingToRepeater}
	t.Cleanup(func() {
		findingRaw, findingBurp, findingMarkdown = saved[0], saved[1], saved[2]
		findingWithRecords, findingPushToBurp, findingToRepeater = saved[3], saved[4], saved[5]
	})
	findingRaw, findingBurp, findingMarkdown = false, false, false
	findingWithRecords, findingPushToBurp, findingToRepeater = false, false, false
}

// resetDBCacheForTest clears the process-wide connection openGlobDB installs, so
// a merge in one test cannot answer a query in the next. It also removes the
// scratch file behind it: a test calls openGlobDB directly rather than through a
// command, so nothing else runs the closeDatabaseOnExit that normally disposes of
// it, and the suite would strand one temp database per test.
func resetDBCacheForTest() {
	clicommon.ResetDBCache()
	removeScratchDB()
	globDBSources = nil
	globRecordFile = nil
	globDBSkipped = globDBSkipSet{}
	globDBSkippedFiles = nil
	globDBMatchedCount = 0
	globDBParseErrors = 0
	globalGlobStrict = false
	globImportPath = dbimport.ImportPath
}
