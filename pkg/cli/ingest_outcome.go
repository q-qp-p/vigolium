package cli

import (
	"context"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/storagesig"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// ingestOutcome is what one ingest source actually did to the database.
//
// It exists because `ingest` used to print `executor.Processed() + directSaved`
// as "N records ingested". Processed() counts items the executor ATTEMPTED, so
// a HAR replayed against a host that no longer resolves printed "30 records
// ingested" over a table with zero rows in it. Stored is the only number that
// may be reported as ingested; Failed is what the caller has to be told about
// instead of discovering with a row count.
type ingestOutcome struct {
	// Stored counts records that are in the database because of this run.
	Stored int64
	// Failed counts records that should have been stored and were not: a write
	// the database refused, or a request that never got a response to store.
	Failed int64
	// Skipped counts records a filter deliberately dropped — a static asset, or
	// a request outside the configured scope. Not a failure: nothing was lost
	// that the configuration asked to keep. Records dropped by the executor's
	// pre-fetch filters are not visible here and are not counted.
	Skipped int64

	// Submitted and Errors are remote mode's (-s/--server) own counters, which
	// are about HTTP submissions rather than rows: the server owns the store.
	Submitted int64
	Errors    int64

	// Formats names the input formats this outcome covers, in first-seen order.
	Formats []string
}

// add folds another source's outcome into this one.
func (o *ingestOutcome) add(other ingestOutcome) {
	o.Stored += other.Stored
	o.Failed += other.Failed
	o.Skipped += other.Skipped
	o.Submitted += other.Submitted
	o.Errors += other.Errors
	for _, f := range other.Formats {
		o.noteFormat(f)
	}
}

// noteFormat records an input format once, preserving the order they were seen
// in so a batch reports "har,urls" rather than whichever one finished last.
func (o *ingestOutcome) noteFormat(format string) {
	if format == "" {
		return
	}
	for _, existing := range o.Formats {
		if existing == format {
			return
		}
	}
	o.Formats = append(o.Formats, format)
}

// ingestSaver writes records that already carry their response straight to the
// database, applying the same static-file and scope filters the executor would,
// and counting exactly what it did with each one.
//
// Safe for concurrent use: InputSource.Next may be called from more than one
// goroutine, and preloadedResponseSource saves from inside it.
type ingestSaver struct {
	repo          *database.Repository
	projectUUID   string
	staticMatcher *config.ScopeMatcher
	// scopeMatcher is nil unless scope.applied_on_ingest is set.
	scopeMatcher *config.ScopeMatcher

	mu      sync.Mutex
	outcome ingestOutcome
}

// save stores one record that already has its response, or counts why it did
// not. It never re-fetches: the response the caller supplied is the one that
// lands in the database.
func (s *ingestSaver) save(ctx context.Context, rr *httpmsg.HttpRequestResponse) {
	if rr == nil || rr.Request() == nil {
		return
	}

	if s.staticMatcher != nil && s.staticMatcher.IsStaticFile(rr.Request().Path()) {
		var hg storagesig.HeaderGetter
		if rr.HasResponse() && rr.Response() != nil {
			hg = rr.Response()
		}
		if !storagesig.KeepStaticAsMeta(rr.Request().Path(), hg) {
			s.count(func(o *ingestOutcome) { o.Skipped++ })
			return
		}
		if rr.Response() != nil {
			rr.Response().TruncateBody(0) // metadata-only: keep headers, drop body
		}
	}

	if s.scopeMatcher != nil {
		if !s.scopeMatcher.InScopeRequest(
			rr.Service().Host(),
			rr.Request().Path(),
			rr.Request().Header("Content-Type"),
			string(rr.Request().Raw()),
		) {
			s.count(func(o *ingestOutcome) { o.Skipped++ })
			return
		}
	}

	if _, err := s.repo.SaveRecord(ctx, rr, database.RecordSourceIngestCLI, s.projectUUID); err != nil {
		zap.L().Warn("ingest: failed to store record",
			zap.String("url", rr.Target()), zap.Error(err))
		s.count(func(o *ingestOutcome) { o.Failed++ })
		return
	}
	s.count(func(o *ingestOutcome) { o.Stored++ })
}

func (s *ingestSaver) count(fn func(*ingestOutcome)) {
	s.mu.Lock()
	fn(&s.outcome)
	s.mu.Unlock()
}

// result returns a snapshot of what this saver has done so far.
func (s *ingestSaver) result() ingestOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.outcome
}

// preloadedResponseSource peels records that ALREADY carry a response off the
// stream and writes them directly, so the executor only ever sees records that
// still need a live fetch.
//
// Without it, "no live refetch" was a property of the stdin auto-detect path
// alone: anything that arrived through a FORMAT parser — a HAR, a Burp XML
// export, a Postman collection — reached the executor with its captured
// response attached and had it thrown away and re-fetched. Ingesting a capture
// then required every origin in it to still resolve, which is the opposite of
// what a capture is for.
type preloadedResponseSource struct {
	inner source.InputSource
	save  func(context.Context, *httpmsg.HttpRequestResponse)
}

// Next returns the next record that still needs a response, having written any
// record it passed over on the way.
func (s *preloadedResponseSource) Next(ctx context.Context) (*work.WorkItem, error) {
	for {
		item, err := s.inner.Next(ctx)
		if err != nil {
			return nil, err
		}
		if item == nil || item.Request == nil || !item.Request.HasResponse() {
			return item, nil
		}
		s.save(ctx, item.Request)
		item.Complete()
	}
}

func (s *preloadedResponseSource) Close() error { return s.inner.Close() }

// Count reports the inner source's total. It is the size of the INPUT, which is
// what the executor uses it for (sizing the insertion-point cache and the
// progress denominator); the peeled records are part of that input even though
// no worker will see them.
func (s *preloadedResponseSource) Count() int64 { return source.GetTotal(s.inner) }
