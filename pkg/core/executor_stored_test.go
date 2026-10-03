package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

// storedTestItem builds the request/response pair saveToDatabase is handed.
func storedTestItem(t *testing.T, path string) (*work.WorkItem, *httpmsg.HttpRequestResponse) {
	t.Helper()
	rr, err := httpmsg.ParseRawRequest(
		"GET " + path + " HTTP/1.1\r\nHost: stored.example\r\n\r\n")
	require.NoError(t, err)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
	require.NotNil(t, resp)
	withResp := rr.WithResponse(resp)
	return work.NewWithModules(withResp, nil), withResp
}

// Stored() counts rows, where Processed() counts attempts. `vigolium ingest`
// reported Processed() as "records ingested", so a run whose every fetch failed
// announced a full count over an empty table.
func TestExecutorStoredCountsWrittenRecords(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()

	for _, p := range []string{"/a", "/b", "/c"} {
		item, rr := storedTestItem(t, p)
		e.saveToDatabase(ctx, item, rr, nil)
	}

	assert.Equal(t, int64(3), e.Stored())
	assert.Zero(t, e.StoreFailed())
	assert.Equal(t, 3, countRecords(t, db))
}

func TestExecutorStoreFailedCountsRefusedWrites(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()

	item, rr := storedTestItem(t, "/ok")
	e.saveToDatabase(ctx, item, rr, nil)
	require.NoError(t, db.Close()) // every later write is refused

	for _, p := range []string{"/gone-1", "/gone-2"} {
		failItem, failRR := storedTestItem(t, p)
		e.saveToDatabase(ctx, failItem, failRR, nil)
	}

	assert.Equal(t, int64(1), e.Stored())
	assert.Equal(t, int64(2), e.StoreFailed())
}

// An item that already maps to a stored row counts as stored: the question
// Stored() answers is "is this input in the store", and for a record that CAME
// from the store the answer is yes.
func TestExecutorStoredCountsAnExistingRecord(t *testing.T) {
	e, _ := newRepoExecutor(t)
	item, rr := storedTestItem(t, "/existing")
	item.RecordUUID = "already-there"

	e.saveToDatabase(context.Background(), item, rr, nil)

	assert.Equal(t, int64(1), e.Stored())
	assert.Zero(t, e.StoreFailed())
}

// A nil repository stores nothing and must not claim otherwise.
func TestExecutorStoredIsZeroWithoutARepository(t *testing.T) {
	e := &Executor{caches: scanCaches{requestUUIDs: newShardedMap(1)}}
	item, rr := storedTestItem(t, "/nowhere")
	e.saveToDatabase(context.Background(), item, rr, nil)

	assert.Zero(t, e.Stored())
	assert.Zero(t, e.StoreFailed())
}
