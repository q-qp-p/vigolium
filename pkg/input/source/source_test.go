package source

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

// fakeSource is an in-test InputSource that yields a fixed list of work items
// (carrying a marker label as their first enabled-module entry) and then io.EOF.
// It records whether Close was called. No real I/O involved.
type fakeSource struct {
	labels   []string
	idx      int
	mu       sync.Mutex
	closed   bool
	failNext error // when set, Next returns this error instead of an item
}

func newFakeSource(labels ...string) *fakeSource {
	return &fakeSource{labels: labels}
}

func (f *fakeSource) Next(ctx context.Context) (*work.WorkItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return nil, err
	}
	if f.idx >= len(f.labels) {
		return nil, io.EOF
	}
	label := f.labels[f.idx]
	f.idx++
	return work.NewWithModules(nil, []string{label}), nil
}

func (f *fakeSource) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *fakeSource) Count() int64 { return int64(len(f.labels)) }

// label extracts the marker label from a fakeSource-produced WorkItem.
func label(item *work.WorkItem) string {
	if item == nil || len(item.EnableModules) == 0 {
		return ""
	}
	return item.EnableModules[0]
}

// drain pulls all items from a source until io.EOF, returning the labels.
func drain(t *testing.T, src InputSource) []string {
	t.Helper()
	var got []string
	for {
		item, err := src.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		got = append(got, label(item))
	}
	return got
}

func TestIsEOF(t *testing.T) {
	assert.True(t, IsEOF(io.EOF))
	assert.False(t, IsEOF(errors.New("other")))
	assert.False(t, IsEOF(nil))
}

func TestGetTotal(t *testing.T) {
	// Countable source reports its count; non-countable reports 0.
	assert.Equal(t, int64(3), GetTotal(newFakeSource("a", "b", "c")))
	assert.Equal(t, int64(0), GetTotal(&nonCountable{}))
}

// nonCountable is an InputSource that does not implement Countable.
type nonCountable struct{}

func (n *nonCountable) Next(ctx context.Context) (*work.WorkItem, error) { return nil, io.EOF }
func (n *nonCountable) Close() error                                     { return nil }

func TestSingleSource(t *testing.T) {
	rr, err := httpmsg.GetRawRequestFromURL("http://example.com/")
	require.NoError(t, err)

	s := NewSingleSource(rr, []string{"mod"})
	assert.Equal(t, int64(1), s.Count())

	item, err := s.Next(context.Background())
	require.NoError(t, err)
	require.NotNil(t, item)
	assert.Equal(t, rr, item.Request)

	// Second call is EOF.
	_, err = s.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
	assert.NoError(t, s.Close())
}

func TestSingleSource_ContextCancelled(t *testing.T) {
	rr, err := httpmsg.GetRawRequestFromURL("http://example.com/")
	require.NoError(t, err)
	s := NewSingleSource(rr, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Next(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestSliceSource(t *testing.T) {
	rr1, _ := httpmsg.GetRawRequestFromURL("http://example.com/1")
	rr2, _ := httpmsg.GetRawRequestFromURL("http://example.com/2")

	s := NewSliceSource([]*httpmsg.HttpRequestResponse{rr1, rr2}, nil)
	assert.Equal(t, int64(2), s.Count())

	i1, err := s.Next(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rr1, i1.Request)
	i2, err := s.Next(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rr2, i2.Request)

	_, err = s.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
	assert.NoError(t, s.Close())
}

func TestSliceSource_ContextCancelled(t *testing.T) {
	s := NewSliceSource(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Next(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestTargetSource(t *testing.T) {
	s := NewTargetSource([]string{"http://example.com/a", "http://example.com/b"}, []string{"mod"})
	assert.Equal(t, int64(2), s.Count())

	i1, err := s.Next(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "example.com", i1.Request.Service().Host())
	assert.Equal(t, []string{"mod"}, i1.EnableModules)

	_, err = s.Next(context.Background())
	require.NoError(t, err)

	_, err = s.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
}

// TestTargetSource_SkipsUnparseableTargets keeps one junk entry from ending the
// whole source. A -T/--target-file list is promoted into Targets, so a single
// malformed line in a recon export used to abort the scan at that point instead
// of scanning the remaining hosts — the urls format parser logs and continues,
// and this path must behave the same.
func TestTargetSource_SkipsUnparseableTargets(t *testing.T) {
	s := NewTargetSource([]string{
		"not a url",
		"http://example.com/a",
		"http://exa mple.com",
		"http://example.com/b",
		"://",
	}, nil)

	var hosts []string
	for {
		item, err := s.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		hosts = append(hosts, item.Request.Service().Host())
	}
	assert.Equal(t, []string{"example.com", "example.com"}, hosts)
}

func TestTargetSource_ClosedReturnsEOF(t *testing.T) {
	s := NewTargetSource([]string{"http://example.com/a"}, nil)
	require.NoError(t, s.Close())
	_, err := s.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
}

func TestTargetSource_ContextCancelled(t *testing.T) {
	s := NewTargetSource([]string{"http://example.com/a"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Next(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestMultiSource_SequentialOrdering(t *testing.T) {
	// MultiSource drains sources in order: first fully, then second.
	a := newFakeSource("a1", "a2")
	b := newFakeSource("b1")
	m := NewMultiSource(a, b)

	got := drain(t, m)
	assert.Equal(t, []string{"a1", "a2", "b1"}, got)
	assert.Equal(t, int64(3), m.Count())

	require.NoError(t, m.Close())
	assert.True(t, a.closed)
	assert.True(t, b.closed)

	// After Close, Next returns EOF.
	_, err := m.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
}

func TestMultiSource_PropagatesError(t *testing.T) {
	a := newFakeSource("a1")
	a.failNext = errors.New("boom")
	m := NewMultiSource(a)

	_, err := m.Next(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestConcurrentMultiSource_ForwardsAllItems(t *testing.T) {
	// Reads from all sources concurrently; every item must be forwarded
	// exactly once (order across sources is not guaranteed).
	a := newFakeSource("a1", "a2")
	b := newFakeSource("b1", "b2", "b3")
	cs := NewConcurrentMultiSource(context.Background(), a, b)

	got := drain(t, cs)
	sort.Strings(got)
	assert.Equal(t, []string{"a1", "a2", "b1", "b2", "b3"}, got)

	require.NoError(t, cs.Close())
	assert.True(t, a.closed)
	assert.True(t, b.closed)
}

func TestConcurrentMultiSource_PropagatesError(t *testing.T) {
	a := newFakeSource()
	a.failNext = errors.New("kaboom")
	cs := NewConcurrentMultiSource(context.Background(), a)
	defer func() { _ = cs.Close() }()

	// The error item should surface from Next.
	var sawErr error
	for {
		_, err := cs.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			sawErr = err
			break
		}
	}
	require.Error(t, sawErr)
	assert.Contains(t, sawErr.Error(), "kaboom")
}

func TestConcurrentMultiSource_ContextCancelStopsStreaming(t *testing.T) {
	// A source that never yields: with nothing ready on the items channel, Next's
	// select must take the cancelled context. Using a source WITH items made this
	// a coin flip — both select arms were ready — so the test passed or failed at
	// random rather than proving anything about cancellation.
	a := newBlockingSource()
	cs := NewConcurrentMultiSource(context.Background(), a)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := cs.Next(ctx)
	assert.ErrorIs(t, err, context.Canceled)

	require.NoError(t, cs.Close())
}

func TestNewInputSource_NoSource(t *testing.T) {
	_, err := NewInputSource(SourceConfig{})
	assert.Error(t, err)
}

func TestNewInputSource_SingleTarget(t *testing.T) {
	// One source configured -> returned directly (not wrapped in MultiSource).
	src, err := NewInputSource(SourceConfig{Targets: []string{"http://example.com/"}})
	require.NoError(t, err)
	_, ok := src.(*TargetSource)
	assert.True(t, ok)
}

func TestNewInputSource_MultipleSources(t *testing.T) {
	// Targets + stdin -> combined MultiSource.
	src, err := NewInputSource(SourceConfig{
		Targets:  []string{"http://example.com/"},
		UseStdin: true,
	})
	require.NoError(t, err)
	_, ok := src.(*MultiSource)
	assert.True(t, ok)
	_ = src.Close()
}

// TestNewInputSource_MultipleFilePaths verifies that repeated -T/--target-file
// inputs (carried as FilePaths) are all read and their URLs merged into one
// stream, alongside any single FilePath and direct Targets.
func TestNewInputSource_MultipleFilePaths(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "t1.txt")
	f2 := filepath.Join(dir, "t2.txt")
	require.NoError(t, os.WriteFile(f1, []byte("http://example.com/a\nhttp://example.com/b\n"), 0o644))
	require.NoError(t, os.WriteFile(f2, []byte("http://example.com/c\n# comment\nhttp://example.com/d\n"), 0o644))

	src, err := NewInputSource(SourceConfig{
		Targets:   []string{"http://example.com/cli"},
		FilePaths: []string{f1, f2},
		Format:    "urls",
	})
	require.NoError(t, err)
	defer func() { _ = src.Close() }()

	var got []string
	for {
		item, nextErr := src.Next(context.Background())
		if errors.Is(nextErr, io.EOF) {
			break
		}
		require.NoError(t, nextErr)
		u, urlErr := item.Request.URL()
		require.NoError(t, urlErr)
		got = append(got, u.String())
	}
	sort.Strings(got)

	want := []string{
		"http://example.com/a",
		"http://example.com/b",
		"http://example.com/c",
		"http://example.com/cli",
		"http://example.com/d",
	}
	assert.Equal(t, want, got, "URLs from the CLI target plus both -T files must all stream through")
}

func TestSupportedFormats(t *testing.T) {
	// SupportedFormats must advertise every canonical format the resolver accepts
	// (it previously listed only 5 of the 9). Assert completeness so the public
	// list can't silently drift from formatRegistry again.
	got := SupportedFormats()
	for _, name := range SupportedFormatNames() {
		assert.Contains(t, got, name, "SupportedFormats must list %q", name)
		parser, err := resolveFormat(name)
		require.NoError(t, err, "canonical format %q must resolve", name)
		require.NotNil(t, parser)
	}
	assert.Contains(t, got, "postman", "regression: postman was missing from the advertised list")
	assert.Contains(t, got, "har")
	assert.Contains(t, got, "burpxml")
}

// TestResolveFormatUnknownErrors guards the fix for the silent Nuclei fallback:
// an unknown explicit format must return an error, not a Nuclei parser, so a
// typo fails fast instead of misparsing the input.
func TestResolveFormatUnknownErrors(t *testing.T) {
	for _, bad := range []string{"postamn", "nuclie", "swaggr", "totally-made-up"} {
		parser, err := resolveFormat(bad)
		require.Error(t, err, "unknown format %q must error", bad)
		assert.Nil(t, parser)
		assert.Contains(t, err.Error(), bad, "error should name the offending value")
	}
}

// TestResolveFormatAliasesAndDefault verifies documented aliases resolve and an
// empty format falls back to the "urls" default (matching the -I flag default).
func TestResolveFormatAliasesAndDefault(t *testing.T) {
	for _, alias := range []string{"swagger", "burp", "burp-xml", "burpstate", "nuclei-output", "list", " HAR ", ""} {
		parser, err := resolveFormat(alias)
		require.NoError(t, err, "alias %q must resolve", alias)
		require.NotNil(t, parser)
	}
}

// TestFileSourceParseErrorSurfacedOnceThenEOF guards the fix for the feedItems
// busy-loop: a FileSource whose parser failed must surface its parse error
// exactly once and then report io.EOF, NOT return the same non-EOF error on
// every call. Returning the sticky error forever would spin any consumer that
// retries non-EOF errors (core.Executor.feedItems) and never terminate the scan.
func TestFileSourceParseErrorSurfacedOnceThenEOF(t *testing.T) {
	sentinel := errors.New("boom: parse failed")

	// Simulate "parse finished/failed": started, items channel closed, parseErr set.
	items := make(chan *work.WorkItem)
	close(items)
	f := &FileSource{
		items:    items,
		done:     make(chan struct{}),
		started:  true,
		parseErr: sentinel,
	}

	ctx := context.Background()

	// First call surfaces the parse error.
	_, err := f.Next(ctx)
	require.ErrorIs(t, err, sentinel, "first Next should surface the parse error")

	// Every subsequent call must be io.EOF, never the sticky error again.
	for i := 0; i < 3; i++ {
		_, err = f.Next(ctx)
		require.ErrorIs(t, err, io.EOF, "Next call %d after the error should be io.EOF", i+1)
	}
}

// TestNewFileSourceDetectsBurpScope guards the -T/--target-file path for Burp
// scope exports: the file arrives with the default "urls" format, and reading
// its JSON line by line would feed the scanner brace and regex fragments as
// targets. Content sniffing must swap in the burpscope parser instead.
func TestNewFileSourceDetectsBurpScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.json")
	content := `{"target":{"scope":{"advanced_mode":true,"include":[
	  {"enabled":true,"file":"^/.*","host":"^www\\.example\\.com$","port":"^443$","protocol":"https"}
	]}}}`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	fs, err := NewFileSource(FileSourceConfig{FilePath: path, Format: "urls"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fs.Close() })
	assert.Equal(t, "burpscope", fs.Format().Name())

	item, err := fs.Next(context.Background())
	require.NoError(t, err)
	require.NotNil(t, item)
}

// TestNewFileSourceDetectsHAR guards the same slot for an HTTP Archive. A HAR
// passed without -I har used to be read line by line as a URL list, which
// turned a 30-entry capture into 91 "targets" made of JSON punctuation — and,
// because every one of them failed, into an ingest that stored nothing.
func TestNewFileSourceDetectsHAR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.har")
	content := `{"log":{"version":"1.2","creator":{"name":"fixture","version":"1"},"entries":[
	  {"request":{"method":"GET","url":"https://example.com/a","httpVersion":"HTTP/1.1",
	    "headers":[{"name":"Host","value":"example.com"}],"queryString":[],"cookies":[]},
	   "response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1",
	    "headers":[],"cookies":[],"content":{"size":2,"mimeType":"text/plain","text":"ok"}}}
	]}}`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	fs, err := NewFileSource(FileSourceConfig{FilePath: path, Format: "urls"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fs.Close() })
	assert.Equal(t, "har", fs.Format().Name())

	item, err := fs.Next(context.Background())
	require.NoError(t, err)
	require.NotNil(t, item)
	assert.True(t, item.Request.HasResponse(),
		"the captured response must survive the parse, or the executor will re-fetch it")
}

// TestNewFileSourceExplicitFormatWinsOverSniff verifies the sniff only ever
// displaces the URL-list default, so an explicit -I is never second-guessed.
func TestNewFileSourceExplicitFormatWinsOverSniff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.json")
	content := `{"target":{"scope":{"include":[{"enabled":true,"host":"^www\\.example\\.com$"}]}}}`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	fs, err := NewFileSource(FileSourceConfig{FilePath: path, Format: "har"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fs.Close() })
	assert.Equal(t, "har", fs.Format().Name())
}

// TestNewFileSourceURLListUnaffected keeps a plain target list on the URL parser
// — the sniff must not fire on ordinary input.
func TestNewFileSourceURLListUnaffected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	require.NoError(t, os.WriteFile(path, []byte("https://example.com/\n"), 0o644))

	fs, err := NewFileSource(FileSourceConfig{FilePath: path, Format: "urls"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fs.Close() })
	assert.Equal(t, "urls", fs.Format().Name())
}

// TestIsTargetListFormat covers the predicate that decides whether a file's
// contents can be promoted into Options.Targets. It answers from formatRegistry,
// so an alias added there is covered without a second edit — a hand-copied alias
// list that missed one would parse the file fine and then leave every
// target-seeded phase with nothing to crawl.
func TestIsTargetListFormat(t *testing.T) {
	// Empty resolves to the "urls" default, matching resolveFormat.
	for _, name := range []string{"", "urls", "url", "list", " URLs ", "LIST", "burpscope", "burp-scope", "burp-config", "burp-project-config"} {
		assert.True(t, IsTargetListFormat(name), "expected %q to be a target list", name)
	}
	for _, name := range []string{"har", "http-archive", "openapi", "swagger", "wsdl", "soap", "burpxml", "burp", "burpraw", "raw", "curl", "postman", "nuclei", "deparos"} {
		assert.False(t, IsTargetListFormat(name), "expected %q not to be a target list", name)
	}
	// An unknown name is not a target list; resolveFormat rejects it separately.
	assert.False(t, IsTargetListFormat("postamn"))
}

// TestIsTargetListFormatCoversEveryRegistryName keeps the predicate total: every
// canonical name and alias resolveFormat accepts must get an answer from the same
// table, so the two can never disagree about which formats exist.
func TestIsTargetListFormatCoversEveryRegistryName(t *testing.T) {
	for _, e := range formatRegistry {
		for _, name := range append([]string{e.canonical}, e.aliases...) {
			_, err := resolveFormat(name)
			require.NoError(t, err, "registry name %q must resolve", name)
			assert.Equal(t, e.targetList, IsTargetListFormat(name),
				"%q must give the same answer as its registry row", name)
		}
	}
}
