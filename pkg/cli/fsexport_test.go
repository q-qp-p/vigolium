package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/fsexport"
)

// gzipBytes returns s gzip-compressed, for seeding a wire-encoded response body.
func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write([]byte(s))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// TestWriteFSExport drives the full fs writer over a seeded DB and asserts the
// on-disk tree shape, the @target line, the gzip-decoded body, the index.json
// schema, and the finding→traffic cross-link.
func TestWriteFSExport(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)

	// alpha: https record with a gzip-encoded body + a linked High finding.
	gzBody := gzipBytes(t, "<html>HELLO-DECODED</html>")
	_, err := db.NewInsert().Model(&database.HTTPRecord{
		UUID:                "rec-alpha",
		Scheme:              "https",
		Hostname:            "alpha.example",
		Port:                443,
		Method:              "GET",
		Path:                "/alpha",
		URL:                 "https://alpha.example/alpha",
		HTTPVersion:         "HTTP/1.1",
		RequestHash:         "rhash-alpha",
		StatusCode:          200,
		ResponseContentType: "text/html; charset=utf-8",
		HasResponse:         true,
		RawRequest:          []byte("GET /alpha HTTP/1.1\r\nHost: alpha.example\r\n\r\n"),
		RawResponse: append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n"),
			gzBody...),
	}).Exec(ctx)
	require.NoError(t, err)

	require.NoError(t, database.NewRepository(db).SaveFindingDirect(ctx, &database.Finding{
		HTTPRecordUUIDs: []string{"rec-alpha"},
		ModuleID:        "broken-auth",
		ModuleName:      "Broken Authentication",
		ModuleType:      "active",
		Severity:        "high",
		Confidence:      "firm",
		FindingHash:     "hash-alpha",
		URL:             "https://alpha.example/alpha",
		Hostname:        "alpha.example",
		Description:     "Auth bypass.",
		MatchedAt:       []string{"https://alpha.example/alpha"},
	}))

	// bravo: a second host with no finding, to assert finding:null + host count.
	_, err = db.NewInsert().Model(&database.HTTPRecord{
		UUID:        "rec-bravo",
		Scheme:      "http",
		Hostname:    "bravo.example",
		Port:        80,
		Method:      "POST",
		Path:        "/login",
		URL:         "http://bravo.example/login",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "rhash-bravo",
		StatusCode:  403,
		HasResponse: true,
		RawRequest:  []byte("POST /login HTTP/1.1\r\nHost: bravo.example\r\n\r\n"),
		RawResponse: []byte("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{}"),
	}).Exec(ctx)
	require.NoError(t, err)

	base := filepath.Join(t.TempDir(), "out")
	stats, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)
	assert.Equal(t, 2, stats.Traffic)
	assert.Equal(t, 1, stats.Findings)
	assert.Equal(t, 2, stats.Hosts)

	trafficRoot := base + "-traffic"
	findingsRoot := base + "-findings"

	// .req carries the @target authority line then the raw request verbatim.
	reqData, err := os.ReadFile(filepath.Join(trafficRoot, "alpha.example", "0001.req"))
	require.NoError(t, err)
	req := string(reqData)
	assert.True(t, strings.HasPrefix(req, "@target https://alpha.example\nGET /alpha HTTP/1.1\r\n"),
		"req must lead with @target then the raw request: %q", req)

	// .resp.headers keeps the status line + headers, no body.
	hdrData, err := os.ReadFile(filepath.Join(trafficRoot, "alpha.example", "0001.resp.headers"))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(hdrData), "HTTP/1.1 200 OK\r\n"))

	// .resp.body is gzip-decoded so it greps as plaintext.
	bodyData, err := os.ReadFile(filepath.Join(trafficRoot, "alpha.example", "0001.resp.body"))
	require.NoError(t, err)
	assert.Equal(t, "<html>HELLO-DECODED</html>", string(bodyData))

	// traffic index.json schema + per-record finding severity backfill.
	var traffic []map[string]any
	readJSON(t, filepath.Join(trafficRoot, "index.json"), &traffic)
	require.Len(t, traffic, 2)
	byHost := map[string]map[string]any{}
	for _, e := range traffic {
		byHost[e["host"].(string)] = e
	}
	alpha := byHost["alpha.example"]
	assert.Equal(t, "0001", alpha["id"])
	assert.Equal(t, "alpha.example/0001", alpha["path"])
	assert.Equal(t, "GET", alpha["method"])
	assert.Equal(t, "/alpha", alpha["url"])
	assert.EqualValues(t, 200, alpha["status"])
	assert.Equal(t, "text/html", alpha["content_type"])
	assert.Equal(t, "high", alpha["finding"], "linked record must carry its finding's severity")
	assert.Nil(t, byHost["bravo.example"]["finding"], "unlinked record must have finding:null")

	// finding markdown cross-links back to the exact .req file AND embeds the
	// linked record's request/response inline (gzip body decoded) so the finding
	// is self-contained and shareable on its own.
	mdData, err := os.ReadFile(filepath.Join(findingsRoot, "alpha.example", "0001.md"))
	require.NoError(t, err)
	md := string(mdData)
	assert.Contains(t, md, "# HIGH — Broken Authentication")
	assert.Contains(t, md, "../../out-traffic/alpha.example/0001.req")
	assert.Contains(t, md, "## Request")
	assert.Contains(t, md, "GET /alpha HTTP/1.1", "raw request must be embedded inline")
	assert.NotContains(t, md, "@target", "the synthetic @target marker line must be stripped from the inline request")
	assert.Contains(t, md, "## Response")
	assert.Contains(t, md, "<html>HELLO-DECODED</html>", "decoded response body must be embedded inline")

	// findings index.json links to the traffic path.
	var findings []map[string]any
	readJSON(t, filepath.Join(findingsRoot, "index.json"), &findings)
	require.Len(t, findings, 1)
	assert.Equal(t, "alpha.example/0001.md", findings[0]["path"])
	assert.Equal(t, "high", findings[0]["severity"])
	assert.Equal(t, "broken-auth", findings[0]["module"])
	tr, _ := findings[0]["traffic"].([]any)
	require.Len(t, tr, 1)
	assert.Equal(t, "alpha.example/0001", tr[0])
}

// An identity selector has to narrow both halves of the tree. `db export --uuid
// <rec> --format fs` used to write the one selected .req beside EVERY finding in
// the store, producing a directory that reads as "the findings for this request"
// and is not.
func TestWriteFSExportUUIDBoundsFindings(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	repo := database.NewRepository(db)

	for _, host := range []string{"alpha", "bravo"} {
		_, err := db.NewInsert().Model(&database.HTTPRecord{
			UUID:        "rec-" + host,
			Scheme:      "https",
			Hostname:    host + ".example",
			Port:        443,
			Method:      "GET",
			Path:        "/" + host,
			URL:         "https://" + host + ".example/" + host,
			HTTPVersion: "HTTP/1.1",
			RequestHash: "rhash-" + host,
			StatusCode:  200,
			HasResponse: true,
			RawRequest:  []byte("GET /" + host + " HTTP/1.1\r\nHost: " + host + ".example\r\n\r\n"),
			RawResponse: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"),
		}).Exec(ctx)
		require.NoError(t, err)

		require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
			HTTPRecordUUIDs: []string{"rec-" + host},
			ModuleID:        "mod-" + host,
			ModuleName:      "Module " + host,
			ModuleType:      "active",
			Severity:        "high",
			Confidence:      "firm",
			FindingHash:     "hash-" + host,
			URL:             "https://" + host + ".example/" + host,
			Hostname:        host + ".example",
			Description:     "Finding on " + host,
			MatchedAt:       []string{"https://" + host + ".example/" + host},
		}))
	}

	base := filepath.Join(t.TempDir(), "out")
	stats, err := writeFSExport(ctx, db,
		database.QueryFilters{RecordUUIDs: []string{"rec-alpha"}}, base, fsExportOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, stats.Traffic, "only the selected record")
	assert.Equal(t, 1, stats.Findings, "only the findings linked to the selected record")

	var findings []map[string]any
	readJSON(t, filepath.Join(base+"-findings", "index.json"), &findings)
	require.Len(t, findings, 1)
	assert.Equal(t, "mod-alpha", findings[0]["module"])

	// bravo's finding must not have been written anywhere in the tree.
	_, err = os.Stat(filepath.Join(base+"-findings", "bravo.example"))
	assert.True(t, os.IsNotExist(err), "an unlinked finding's host dir must not be created")
}

// TestWriteFSExportOmitResponse drops the .resp.* files but keeps .req + index.
func TestWriteFSExportOmitResponse(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	seedRecordWithBodies(t, db, "alpha")

	base := filepath.Join(t.TempDir(), "out")
	_, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{omitResponse: true})
	require.NoError(t, err)

	dir := filepath.Join(base+"-traffic", "alpha.example")
	_, err = os.Stat(filepath.Join(dir, "0001.req"))
	require.NoError(t, err, ".req must still be written")
	_, err = os.Stat(filepath.Join(dir, "0001.resp.body"))
	assert.True(t, os.IsNotExist(err), ".resp.body must be omitted")
	_, err = os.Stat(filepath.Join(dir, "0001.resp.headers"))
	assert.True(t, os.IsNotExist(err), ".resp.headers must be omitted")
}

func TestFSTargetLine(t *testing.T) {
	cases := []struct {
		scheme string
		host   string
		port   int
		want   string
	}{
		{"https", "a.example", 443, "@target https://a.example"},
		{"http", "a.example", 80, "@target http://a.example"},
		{"https", "a.example", 8443, "@target https://a.example:8443"},
		{"http", "a.example", 8080, "@target http://a.example:8080"},
		{"", "a.example", 0, "@target http://a.example"},
	}
	for _, c := range cases {
		got := fsexport.TargetLine(&database.HTTPRecord{Scheme: c.scheme, Hostname: c.host, Port: c.port})
		assert.Equal(t, c.want, got)
	}
}

// readJSON decodes a JSON file into v, failing the test on any error.
func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, v))
}

// fsSeedRecord inserts one minimal record, optionally with a response body.
func fsSeedRecord(t *testing.T, db *database.DB, uuid, host, path, body string) {
	t.Helper()
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + body)
	_, err := db.NewInsert().Model(&database.HTTPRecord{
		UUID:        uuid,
		Scheme:      "https",
		Hostname:    host,
		Port:        443,
		Method:      "GET",
		Path:        path,
		URL:         "https://" + host + path,
		HTTPVersion: "HTTP/1.1",
		RequestHash: "rhash-" + uuid,
		StatusCode:  200,
		HasResponse: true,
		RawRequest:  []byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
		RawResponse: resp,
	}).Exec(context.Background())
	require.NoError(t, err)
}

// fsStagingLeftovers lists the staging and retired directories beside base.
func fsStagingLeftovers(t *testing.T, base string) []string {
	t.Helper()
	var out []string
	for _, pattern := range []string{".*.staging-*", "*.old-*"} {
		matches, err := filepath.Glob(filepath.Join(filepath.Dir(base), pattern))
		require.NoError(t, err)
		out = append(out, matches...)
	}
	return out
}

// A re-export used to write into the live tree, so a smaller result set left the
// previous run's files behind: 0002.req from a three-record run survived a
// one-record re-export, while index.json (which IS rewritten) described a tree
// that disagreed with its own contents.
func TestFSExportReexportRemovesStaleFiles(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	for i, name := range []string{"a", "b", "c"} {
		fsSeedRecord(t, db, "rec-"+name, "alpha.example", fmt.Sprintf("/%d", i), "body-"+name)
	}

	base := filepath.Join(t.TempDir(), "out")
	stats, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)
	require.Equal(t, 3, stats.Traffic)
	require.FileExists(t, filepath.Join(base+"-traffic", "alpha.example", "0002.req"))

	// Re-export a single record.
	stats, err = writeFSExport(ctx, db,
		database.QueryFilters{RecordUUIDs: []string{"rec-a"}}, base, fsExportOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, stats.Traffic)

	assert.NoFileExists(t, filepath.Join(base+"-traffic", "alpha.example", "0002.req"),
		"a re-export publishes a whole generation; last run's files must be gone")
	var index []map[string]any
	readJSON(t, filepath.Join(base+"-traffic", "index.json"), &index)
	assert.Len(t, index, 1, "the index and the tree must agree")
	assert.Empty(t, fsStagingLeftovers(t, base), "no staging or retired tree may survive a publish")
}

// A re-export that now matches nothing must replace the stale generation with
// an empty index, not leave last run's results under a name that claims to
// describe this one.
func TestFSExportEmptyReplacesStaleTrees(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	fsSeedRecord(t, db, "rec-a", "alpha.example", "/a", "body-a")

	base := filepath.Join(t.TempDir(), "out")
	_, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(base+"-traffic", "alpha.example", "0001.req"))

	stats, err := writeFSExport(ctx, db,
		database.QueryFilters{RecordUUIDs: []string{"rec-nonexistent"}}, base, fsExportOptions{})
	require.NoError(t, err)
	assert.Equal(t, 0, stats.Traffic)
	assert.Equal(t, base+"-traffic", stats.TrafficDir, "the stale tree was corrected, so it is reported")

	assert.NoDirExists(t, filepath.Join(base+"-traffic", "alpha.example"))
	var index []map[string]any
	readJSON(t, filepath.Join(base+"-traffic", "index.json"), &index)
	assert.Empty(t, index)
	assert.Empty(t, fsStagingLeftovers(t, base))
}

// Nothing to export and nothing already there: create nothing at all, so the
// summary's "Nothing to export" is literally true.
func TestFSExportFreshEmptyCreatesNothing(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)

	dir := t.TempDir()
	base := filepath.Join(dir, "out")
	stats, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)
	assert.Empty(t, stats.TrafficDir)
	assert.Empty(t, stats.FindingsDir)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "an empty first export must not create a tree")
}

// A base path that collides with an unrelated directory is an operator mistake
// worth an error. Deleting their files is not a reasonable way to report it.
func TestFSExportRefusesForeignDir(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	fsSeedRecord(t, db, "rec-a", "alpha.example", "/a", "body-a")

	dir := t.TempDir()
	base := filepath.Join(dir, "out")
	foreign := base + "-traffic"
	require.NoError(t, os.MkdirAll(foreign, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(foreign, "thesis.txt"), []byte("important"), 0o644))

	_, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a vigolium fs export")

	data, readErr := os.ReadFile(filepath.Join(foreign, "thesis.txt"))
	require.NoError(t, readErr, "the foreign directory must be untouched")
	assert.Equal(t, "important", string(data))
	assert.Empty(t, fsStagingLeftovers(t, base), "a refused publish must clean up after itself")
}

// Traffic publishes before findings, so a findings failure leaves the previous
// findings tree in place and says that traffic was already updated.
func TestFSExportFailureKeepsPrevious(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	fsSeedRecord(t, db, "rec-a", "alpha.example", "/a", "body-a")
	require.NoError(t, database.NewRepository(db).SaveFindingDirect(ctx, &database.Finding{
		HTTPRecordUUIDs: []string{"rec-a"},
		ModuleID:        "mod-a",
		ModuleName:      "Module A",
		ModuleType:      "active",
		Severity:        "high",
		Confidence:      "firm",
		FindingHash:     "hash-a",
		URL:             "https://alpha.example/a",
		Hostname:        "alpha.example",
		Description:     "finding a",
	}))

	base := filepath.Join(t.TempDir(), "out")
	_, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(base+"-findings", "alpha.example", "0001.md"))

	// Make the findings pass fail: drop the table the second query reads.
	_, err = db.NewRaw("DROP TABLE findings").Exec(ctx)
	require.NoError(t, err)

	_, err = writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.Error(t, err)

	assert.FileExists(t, filepath.Join(base+"-findings", "alpha.example", "0001.md"),
		"a failed findings pass must leave the previous findings tree intact")
	assert.Empty(t, fsStagingLeftovers(t, base), "no staging tree may survive a failure")
}

// The finding markdown embeds the .req/.resp files of its linked traffic by
// READING them back. Read from the live root, a record whose body is now empty
// re-inherited the previous generation's body at the same host/id.
func TestFSExportNoStaleBodyInFinding(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	fsSeedRecord(t, db, "rec-a", "alpha.example", "/a", "SECRET-FROM-RUN-ONE")

	base := filepath.Join(t.TempDir(), "out")
	_, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(base+"-traffic", "alpha.example", "0001.resp.body"))

	// Record B takes the same host/id in the next generation, with no body, and
	// carries the finding.
	_, err = db.NewRaw("DELETE FROM http_records").Exec(ctx)
	require.NoError(t, err)
	fsSeedRecord(t, db, "rec-b", "alpha.example", "/b", "")
	require.NoError(t, database.NewRepository(db).SaveFindingDirect(ctx, &database.Finding{
		HTTPRecordUUIDs: []string{"rec-b"},
		ModuleID:        "mod-b",
		ModuleName:      "Module B",
		ModuleType:      "active",
		Severity:        "high",
		Confidence:      "firm",
		FindingHash:     "hash-b",
		URL:             "https://alpha.example/b",
		Hostname:        "alpha.example",
		Description:     "finding b",
	}))

	_, err = writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)

	md, err := os.ReadFile(filepath.Join(base+"-findings", "alpha.example", "0001.md"))
	require.NoError(t, err)
	assert.NotContains(t, string(md), "SECRET-FROM-RUN-ONE",
		"a finding must not embed the previous generation's response body")
	assert.NoFileExists(t, filepath.Join(base+"-traffic", "alpha.example", "0001.resp.body"))
}

// An empty directory is one of ours by construction (a published generation
// always has an index.json, and a half-made one has nothing worth keeping).
func TestFSExportPublishesOverAnEmptyDir(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	fsSeedRecord(t, db, "rec-a", "alpha.example", "/a", "body-a")

	base := filepath.Join(t.TempDir(), "out")
	require.NoError(t, os.MkdirAll(base+"-traffic", 0o755))

	_, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(base+"-traffic", "alpha.example", "0001.req"))
}

// A kill -9 between creating a staging tree and publishing it leaves one
// behind. Nothing else sweeps it, so the next export to the same destination
// does — but only once it is old enough not to be a live concurrent export.
func TestFSExportSweepsAbandonedStagingTrees(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	fsSeedRecord(t, db, "rec-a", "alpha.example", "/a", "body-a")

	dir := t.TempDir()
	base := filepath.Join(dir, "out")

	stale := filepath.Join(dir, ".out-traffic.staging-deadbeef")
	require.NoError(t, os.MkdirAll(stale, 0o755))
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(stale, old, old))

	fresh := filepath.Join(dir, ".out-traffic.staging-cafe")
	require.NoError(t, os.MkdirAll(fresh, 0o755))

	_, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)

	assert.NoDirExists(t, stale, "an abandoned staging tree must be collected")
	assert.DirExists(t, fresh, "a recent staging tree may belong to a live export")
}

// The staging directory IS the published root after the rename, so its mode is
// the tree's mode. os.MkdirTemp would have made it 0700 while the host
// directories inside stayed 0755.
func TestFSExportRootKeepsDirectoryMode(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	fsSeedRecord(t, db, "rec-a", "alpha.example", "/a", "body-a")

	base := filepath.Join(t.TempDir(), "out")
	_, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)

	root, err := os.Stat(base + "-traffic")
	require.NoError(t, err)
	host, err := os.Stat(filepath.Join(base+"-traffic", "alpha.example"))
	require.NoError(t, err)
	assert.Equal(t, host.Mode().Perm(), root.Mode().Perm(),
		"the published root and the host directories inside it must agree")
}
