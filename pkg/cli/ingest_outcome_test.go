package cli

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/work"
)

// capturedRecord builds a request/response pair the way a HAR or Burp export
// hands one over: the response is already attached, so nothing needs fetching.
func capturedRecord(t *testing.T, path string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.ParseRawRequest(
		"GET " + path + " HTTP/1.1\r\nHost: capture.example\r\n\r\n")
	require.NoError(t, err)
	resp := httpmsg.NewHttpResponse([]byte(
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n{\"ok\":1}\n"))
	require.NotNil(t, resp)
	return rr.WithResponse(resp)
}

// requestOnlyRecord is what a URL list or a spec yields: no response, so the
// executor has to go and get one.
func requestOnlyRecord(t *testing.T, path string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.ParseRawRequest(
		"GET " + path + " HTTP/1.1\r\nHost: capture.example\r\n\r\n")
	require.NoError(t, err)
	return rr
}

func newIngestSaver(t *testing.T) (*ingestSaver, *database.DB) {
	t.Helper()
	db := newDBAtPath(t, filepath.Join(t.TempDir(), "ingest.sqlite"))
	settings := config.DefaultSettings()
	return &ingestSaver{
		repo:          database.NewRepository(db),
		projectUUID:   "",
		staticMatcher: config.NewScopeMatcher(settings.Scope),
	}, db
}

func TestIngestSaverCountsWhatItStored(t *testing.T) {
	saver, _ := newIngestSaver(t)
	ctx := context.Background()

	saver.save(ctx, capturedRecord(t, "/api/a"))
	saver.save(ctx, capturedRecord(t, "/api/b"))

	got := saver.result()
	assert.Equal(t, int64(2), got.Stored)
	assert.Zero(t, got.Failed)
	assert.Zero(t, got.Skipped)
}

// A write the database refuses is a FAILURE, not a silent skip. This is the
// half of the defect a row count alone cannot show: the count has to be able to
// come back lower than the input and say why.
func TestIngestSaverCountsARefusedWriteAsFailed(t *testing.T) {
	saver, db := newIngestSaver(t)
	ctx := context.Background()

	saver.save(ctx, capturedRecord(t, "/api/ok"))
	require.NoError(t, db.Close()) // every later write is refused

	saver.save(ctx, capturedRecord(t, "/api/gone"))

	got := saver.result()
	assert.Equal(t, int64(1), got.Stored)
	assert.Equal(t, int64(1), got.Failed)
	assert.Zero(t, got.Skipped)
}

// A static asset the storage carve-out does not keep was dropped on purpose.
// Counting it as a failure would make every ordinary ingest exit non-zero.
func TestIngestSaverCountsAFilteredRecordAsSkipped(t *testing.T) {
	saver, _ := newIngestSaver(t)
	saver.save(context.Background(), capturedRecord(t, "/assets/logo.png"))

	got := saver.result()
	assert.Zero(t, got.Stored)
	assert.Zero(t, got.Failed)
	assert.Equal(t, int64(1), got.Skipped, "a filtered static asset must not read as a failure")
}

// The classification fix: a record that arrives with its response never reaches
// the executor, so ingesting a capture does not require its origins to resolve.
func TestPreloadedResponseSourcePeelsRecordsThatCarryAResponse(t *testing.T) {
	items := []*httpmsg.HttpRequestResponse{
		capturedRecord(t, "/1"),
		requestOnlyRecord(t, "/2"),
		capturedRecord(t, "/3"),
		requestOnlyRecord(t, "/4"),
	}
	var saved []string
	src := &preloadedResponseSource{
		inner: source.NewSliceSource(items, nil),
		save: func(_ context.Context, rr *httpmsg.HttpRequestResponse) {
			saved = append(saved, rr.Request().Path())
		},
	}

	var reachedExecutor []string
	for {
		item, err := src.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		reachedExecutor = append(reachedExecutor, item.Request.Request().Path())
	}

	assert.Equal(t, []string{"/1", "/3"}, saved, "captured records must be written, not re-fetched")
	assert.Equal(t, []string{"/2", "/4"}, reachedExecutor, "only records needing a response reach the executor")
}

func TestPreloadedResponseSourceReportsTheInputTotal(t *testing.T) {
	src := &preloadedResponseSource{
		inner: source.NewSliceSource([]*httpmsg.HttpRequestResponse{
			capturedRecord(t, "/1"), requestOnlyRecord(t, "/2"),
		}, nil),
		save: func(context.Context, *httpmsg.HttpRequestResponse) {},
	}
	assert.Equal(t, int64(2), source.GetTotal(src))
}

// The peeled item is acknowledged. A DB-backed source advances its cursor on
// Complete, and a record written here is a record that must not be re-served.
func TestPreloadedResponseSourceCompletesPeeledItems(t *testing.T) {
	completed := 0
	inner := &oneShotSource{item: work.NewWithCallback(
		capturedRecord(t, "/done"), nil, func() { completed++ })}

	src := &preloadedResponseSource{
		inner: inner,
		save:  func(context.Context, *httpmsg.HttpRequestResponse) {},
	}
	_, err := src.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 1, completed)
}

// oneShotSource yields a single pre-built WorkItem, then EOF.
type oneShotSource struct {
	item *work.WorkItem
	done bool
}

func (s *oneShotSource) Next(context.Context) (*work.WorkItem, error) {
	if s.done {
		return nil, io.EOF
	}
	s.done = true
	return s.item, nil
}
func (s *oneShotSource) Close() error { return nil }

func TestIngestOutcomeAddAccumulates(t *testing.T) {
	var total ingestOutcome
	total.add(ingestOutcome{Stored: 3, Failed: 1, Skipped: 2, Formats: []string{"har"}})
	total.add(ingestOutcome{Stored: 5, Skipped: 1, Formats: []string{"har", "urls"}})

	assert.Equal(t, int64(8), total.Stored)
	assert.Equal(t, int64(1), total.Failed)
	assert.Equal(t, int64(3), total.Skipped)
	assert.Equal(t, []string{"har", "urls"}, total.Formats, "formats are deduplicated in first-seen order")
}

func TestExecutorIngestOutcomeNeverGoesNegative(t *testing.T) {
	assert.Zero(t, nonNegative(-5))
	assert.Equal(t, int64(7), nonNegative(7))
}

func TestIngestSummaryLineLeadsWithTheShortfall(t *testing.T) {
	origSilent, origNoFetch := globalSilent, globalDisableFetchResponse
	t.Cleanup(func() { globalSilent, globalDisableFetchResponse = origSilent, origNoFetch })
	globalDisableFetchResponse = false

	ok := ingestSummaryLine(ingestOutcome{Stored: 30}, 0)
	assert.Contains(t, ok, "Ingestion completed: 30 records ingested")
	assert.NotContains(t, ok, "failed")

	bad := ingestSummaryLine(ingestOutcome{Stored: 6, Failed: 4}, 0)
	assert.Contains(t, bad, "Ingestion incomplete: 6 of 10 records stored, 4 failed")

	skipped := ingestSummaryLine(ingestOutcome{Stored: 2, Skipped: 5}, 0)
	assert.Contains(t, skipped, "5 skipped")
}

// A run that stored nothing of what it read must exit non-zero. Reporting a
// full count over an empty table, and exiting 0, is the defect this replaces.
func TestReportIngestExitsNonZeroWhenRecordsCouldNotBeStored(t *testing.T) {
	origSilent, origJSON := globalSilent, globalJSON
	t.Cleanup(func() { globalSilent, globalJSON = origSilent, origJSON })
	globalSilent, globalJSON = true, false

	err := reportIngest(ingestOutcome{Stored: 0, Failed: 30}, false, 0, 1, 0)
	require.Error(t, err)
	assert.Equal(t, errCodeIngestIncomplete, classifyErrorCode(err, 1))
	assert.Contains(t, err.Error(), "stored 0 of 30 record(s)")

	assert.NoError(t, reportIngest(ingestOutcome{Stored: 30}, false, 0, 1, 0))
}

// Records a filter dropped are not a failure: an ingest that skips every static
// asset in a capture still succeeded.
func TestReportIngestSucceedsWhenRecordsWereOnlySkipped(t *testing.T) {
	origSilent, origJSON := globalSilent, globalJSON
	t.Cleanup(func() { globalSilent, globalJSON = origSilent, origJSON })
	globalSilent, globalJSON = true, false

	assert.NoError(t, reportIngest(ingestOutcome{Stored: 4, Skipped: 26}, false, 0, 1, 0))
}
