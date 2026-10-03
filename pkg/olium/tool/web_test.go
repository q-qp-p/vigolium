package tool

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// stubCaptureSink is a no-op CaptureSink so the capture-enabled web_fetch
// variant can be constructed in tests without a database.
type stubCaptureSink struct{}

func (stubCaptureSink) SaveRecord(context.Context, *httpmsg.HttpRequestResponse, string, string) (string, error) {
	return "rec-uuid", nil
}
func (stubCaptureSink) SaveRecordBatch(context.Context, []*httpmsg.HttpRequestResponse, string, string) ([]string, error) {
	return nil, nil
}

// TestWebFetchIsReadOnly locks in the side-effect contract: IsReadOnly means
// "no observable side effects", and the general tool accepts mutating methods
// and browser mode whether or not a database is wired, so neither wiring may
// claim it. Only the restricted variant is read-only.
func TestWebFetchIsReadOnly(t *testing.T) {
	if NewWebFetch().IsReadOnly() {
		t.Error("no-capture web_fetch accepts POST and browser mode; it must NOT be read-only")
	}
	if NewWebFetchWithCapture(stubCaptureSink{}, "proj").IsReadOnly() {
		t.Error("capture-enabled web_fetch must NOT be read-only (it writes records concurrently)")
	}
	if !NewWebFetchReadOnly().IsReadOnly() {
		t.Error("read-only web_fetch should be read-only")
	}
}

// TestWebFetchReadOnlyRefusesSideEffects: the read-only variant refuses
// mutating methods and browser mode before any request leaves, and still
// serves GET/HEAD.
func TestWebFetchReadOnlyRefusesSideEffects(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	fetch := NewWebFetchReadOnly()
	ctx := context.Background()
	refused := []struct {
		name string
		args map[string]any
		want string
	}{
		{"post", map[string]any{"url": srv.URL, "method": "POST", "body": "a=1"}, "only GET and HEAD"},
		{"delete lowercase", map[string]any{"url": srv.URL, "method": "delete"}, "only GET and HEAD"},
		{"browser", map[string]any{"url": srv.URL, "mode": "browser"}, "mode='browser' is not available"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			res, err := fetch.Execute(ctx, tc.args, nil)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if !res.IsError || !strings.Contains(res.Content, tc.want) {
				t.Fatalf("want IsError naming %q, got IsError=%v %q", tc.want, res.IsError, res.Content)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("refused calls reached the server %d time(s)", n)
	}

	for _, method := range []string{"", "GET", "head"} {
		res, err := fetch.Execute(ctx, map[string]any{"url": srv.URL, "method": method}, nil)
		if err != nil || res.IsError {
			t.Fatalf("method %q: err=%v result=%q", method, err, res.Content)
		}
	}
	if n := hits.Load(); n != 3 {
		t.Fatalf("allowed calls reached the server %d time(s), want 3", n)
	}
}

// TestRegisterBuiltinsWebFetchVariant: the read-only registry carries the
// restricted web_fetch; the full registry carries the general one.
func TestRegisterBuiltinsWebFetchVariant(t *testing.T) {
	ro := NewRegistry()
	RegisterReadOnlyBuiltins(ro)
	wf, err := ro.Get("web_fetch")
	if err != nil {
		t.Fatal(err)
	}
	if !wf.IsReadOnly() {
		t.Error("RegisterReadOnlyBuiltins must register the read-only web_fetch")
	}

	full := NewRegistry()
	RegisterBuiltins(full, nil)
	wf, err = full.Get("web_fetch")
	if err != nil {
		t.Fatal(err)
	}
	if wf.IsReadOnly() {
		t.Error("RegisterBuiltins must register the general (not read-only) web_fetch")
	}
}

// TestWebFetchTruncationBoundary locks in the off-by-one fix: a body landing
// exactly on max_bytes is complete, not truncated; a body one byte over is
// truncated and trimmed back to the cap.
func TestWebFetchTruncationBoundary(t *testing.T) {
	const n = 100
	body := strings.Repeat("x", n)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	fetch := NewWebFetch()
	ctx := context.Background()

	cases := []struct {
		name          string
		maxBytes      float64
		wantTruncated bool
		wantBytes     int
	}{
		{"exactly at limit", float64(n), false, n},
		{"one under limit", float64(n - 1), true, n - 1},
		{"well over limit", float64(n + 50), false, n},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := fetch.Execute(ctx, map[string]any{
				"url":       srv.URL,
				"max_bytes": tc.maxBytes,
			}, nil)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if res.IsError {
				t.Fatalf("unexpected error result: %s", res.Content)
			}
			gotTrunc, _ := res.Details["truncated"].(bool)
			if gotTrunc != tc.wantTruncated {
				t.Errorf("truncated = %v, want %v", gotTrunc, tc.wantTruncated)
			}
			gotBytes, _ := res.Details["bytes"].(int)
			if gotBytes != tc.wantBytes {
				t.Errorf("bytes = %d, want %d", gotBytes, tc.wantBytes)
			}
			if tc.wantTruncated && !strings.Contains(res.Content, "[truncated at") {
				t.Error("expected truncation marker in content")
			}
		})
	}
}
