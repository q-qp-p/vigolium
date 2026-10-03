package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
)

// pathLoggingServer answers 404 (what fingerprint learning expects) and records
// every path it was asked for.
func pathLoggingServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// TestEngineRequestFilterBlocksEgress is the point of the whole seam: an excluded
// path must never be requested, not merely discarded after the response comes
// back. It drives the engine's own client, which is the single pipe every
// discovery request goes through.
func TestEngineRequestFilterBlocksEgress(t *testing.T) {
	srv, paths := pathLoggingServer(t)

	cfg := testConfig(srv.URL)
	cfg.Engine.RequestFilter = func(u *url.URL) bool { return !strings.HasPrefix(u.Path, "/admin") }

	engine, err := testEngineWithConfig(cfg)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	defer engine.Stop()

	for _, path := range []string{"/public", "/admin", "/admin/users"} {
		req, reqErr := http.NewRequestWithContext(context.Background(), "GET", srv.URL+path, nil)
		if reqErr != nil {
			t.Fatalf("build request: %v", reqErr)
		}
		rc, sendErr := engine.httpClient.Send(context.Background(), req)
		if rc != nil {
			rc.Close()
		}
		if path == "/public" {
			if sendErr != nil {
				t.Fatalf("GET %s should have been sent: %v", path, sendErr)
			}
			continue
		}
		if sendErr == nil {
			t.Fatalf("GET %s should have been refused", path)
		}
		if !strings.Contains(sendErr.Error(), pkghttp.ErrRequestFiltered.Error()) {
			t.Fatalf("GET %s refused with the wrong error: %v", path, sendErr)
		}
	}

	for _, got := range paths() {
		if strings.HasPrefix(got, "/admin") {
			t.Fatalf("the server was contacted for an excluded path %q; saw %v", got, paths())
		}
	}
	if len(paths()) == 0 {
		t.Fatal("the allowed request never reached the server — the filter is too wide")
	}
}

// TestEngineRequestFilterAlsoGatesTheSpiderQueue pins the other half of item 4:
// the same predicate becomes the spider scope's exclusion, so an excluded link is
// never queued either — and that holds in the default "any" scope mode, where the
// checker used to return before any exclude check.
func TestEngineRequestFilterAlsoGatesTheSpiderQueue(t *testing.T) {
	srv, _ := pathLoggingServer(t)

	cfg := testConfig(srv.URL)
	cfg.Target.ScopeMode = "any"
	cfg.Engine.RequestFilter = func(u *url.URL) bool { return !strings.HasPrefix(u.Path, "/admin") }

	engine, err := testEngineWithConfig(cfg)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	defer engine.Stop()

	excluded, _ := url.Parse(srv.URL + "/admin/users")
	if engine.spiderScope.IsInScope(excluded) {
		t.Fatal("an excluded URL must not be in the spider's scope, even in scope mode \"any\"")
	}
	allowed, _ := url.Parse(srv.URL + "/public")
	if !engine.spiderScope.IsInScope(allowed) {
		t.Fatal("a non-excluded URL must stay in the spider's scope")
	}
}

func TestEngineRequestCounterCountsAttempts(t *testing.T) {
	srv, _ := pathLoggingServer(t)

	var sent atomic.Int64
	cfg := testConfig(srv.URL)
	cfg.Engine.RequestCounter = &sent

	engine, err := testEngineWithConfig(cfg)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	defer engine.Stop()

	const n = 3
	for i := 0; i < n; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL+"/x", nil)
		rc, sendErr := engine.httpClient.Send(context.Background(), req)
		if sendErr != nil {
			t.Fatalf("send: %v", sendErr)
		}
		rc.Close()
	}
	if got := sent.Load(); got != n {
		t.Fatalf("counter reports %d attempts, want %d", got, n)
	}
}

// TestEngineWithoutEgressHooksIsUnchanged guards the default path: no filter and
// no counter means the chain is exactly the retry middleware it has always been.
func TestEngineWithoutEgressHooksIsUnchanged(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	mw := engineMiddleware(&cfg.Engine)
	if len(mw) != 1 {
		t.Fatalf("default middleware chain has %d rungs, want 1 (retry only)", len(mw))
	}
	if excludeFromRequestFilter(nil) != nil {
		t.Fatal("a nil filter must produce a nil exclude predicate")
	}
}

func TestEngineMiddlewareOrder(t *testing.T) {
	var n atomic.Int64
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Engine.RequestFilter = func(*url.URL) bool { return true }
	cfg.Engine.RequestCounter = &n
	if got := len(engineMiddleware(&cfg.Engine)); got != 3 {
		t.Fatalf("chain has %d rungs, want 3 (filter, retry, counting)", got)
	}
}

func TestExcludeFromRequestFilterInverts(t *testing.T) {
	exclude := excludeFromRequestFilter(func(u *url.URL) bool { return u.Path == "/ok" })
	ok, _ := url.Parse("https://example.com/ok")
	bad, _ := url.Parse("https://example.com/no")
	if exclude(ok) {
		t.Fatal("an allowed URL must not be excluded")
	}
	if !exclude(bad) {
		t.Fatal("a refused URL must be excluded")
	}
}

// TestEngineRateLimitIsOptIn guards the throughput contract: an engine with no
// configured rate must have no bucket at all. Adding one with the token bucket's
// own 10 rps fallback would crawl ~100x slower than the thread count implies.
func TestEngineRateLimitIsOptIn(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	if got := len(engineMiddleware(&cfg.Engine)); got != 1 {
		t.Fatalf("unpaced chain has %d rungs, want 1 (retry only)", got)
	}
	cfg.Engine.RequestsPerSecond = 5
	if got := len(engineMiddleware(&cfg.Engine)); got != 2 {
		t.Fatalf("paced chain has %d rungs, want 2 (rate limit + retry)", got)
	}
}

// TestEngineRateLimitPacesRequests drives the real chain: five requests at 2 rps
// with a burst of 2 cannot all go out instantly.
func TestEngineRateLimitPacesRequests(t *testing.T) {
	srv, _ := pathLoggingServer(t)

	cfg := testConfig(srv.URL)
	cfg.Engine.RequestsPerSecond = 2

	engine, err := testEngineWithConfig(cfg)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	defer engine.Stop()

	start := time.Now()
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL+"/x", nil)
		rc, sendErr := engine.httpClient.Send(context.Background(), req)
		if sendErr != nil {
			t.Fatalf("send %d: %v", i, sendErr)
		}
		rc.Close()
	}
	// Burst 2 covers the first two; the remaining three wait ~500ms each.
	if elapsed := time.Since(start); elapsed < 1200*time.Millisecond {
		t.Fatalf("5 requests at 2/s took %v, want at least ~1.2s — the bucket is not in the chain", elapsed)
	}
}
