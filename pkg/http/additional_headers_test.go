package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestWithAdditionalHeaders_SharesTransportAddsCreds mirrors
// TestCloneWithoutCredentials_SharesTransportIsolatesCreds for the view that
// goes the other way: the primary session's headers are ADDED while everything
// expensive or scan-wide is shared.
func TestWithAdditionalHeaders_SharesTransportAddsCreds(t *testing.T) {
	opts := types.DefaultOptions()
	opts.Headers = []string{"X-Trace: keep"}
	r := newTestRequesterWithOpts(t, opts)

	view, err := r.WithAdditionalHeaders([]string{"Authorization: Bearer session-token"})
	if err != nil {
		t.Fatalf("WithAdditionalHeaders: %v", err)
	}
	if view == r {
		t.Fatal("expected a distinct view, got the parent")
	}

	// Shared: pool, observation state, request counter, carried sessions.
	if view.client.HTTPClient.Transport != r.client.HTTPClient.Transport {
		t.Error("view must share the parent transport (connection pool)")
	}
	if view.clientNoRedir.HTTPClient.Transport != r.clientNoRedir.HTTPClient.Transport {
		t.Error("view must share the no-redirect transport too")
	}
	if view.respObserver != r.respObserver {
		t.Error("view must share the response observer")
	}
	if view.blockNotifier != r.blockNotifier {
		t.Error("view must share the block notifier")
	}
	if view.edgePacer != r.edgePacer {
		t.Error("view must share the edge-pacing dedup")
	}
	if view.sent != r.sent {
		t.Error("view must share the request counter: phase.progress counts both")
	}
	if view.carried != r.carried {
		t.Error("view must share the carried-session store")
	}

	// Isolated: cookie jar.
	if view.client.HTTPClient.Jar == r.client.HTTPClient.Jar {
		t.Error("view must have its own cookie jar")
	}

	// Credential surface.
	if view.customHeaders["Authorization"] != "Bearer session-token" {
		t.Errorf("view Authorization = %q, want the session token", view.customHeaders["Authorization"])
	}
	if view.customHeaders["X-Trace"] != "keep" {
		t.Error("view must keep the operator's own headers")
	}
	if _, ok := r.customHeaders["Authorization"]; ok {
		t.Error("the parent must stay anonymous: use_in_discovery:false means the credentials never reach discovery")
	}
}

// An added header replaces a parent header of the same name whatever its case,
// so the two cannot both sit in the map and race on iteration order when
// doRequest Sets them.
func TestWithAdditionalHeaders_AddedWinsCaseInsensitively(t *testing.T) {
	opts := types.DefaultOptions()
	opts.Headers = []string{"authorization: Bearer stale", "X-Keep: 1"}
	r := newTestRequesterWithOpts(t, opts)

	view, err := r.WithAdditionalHeaders([]string{"Authorization: Bearer fresh"})
	if err != nil {
		t.Fatalf("WithAdditionalHeaders: %v", err)
	}
	var authEntries int
	for name, value := range view.customHeaders {
		if name == "X-Keep" {
			continue
		}
		authEntries++
		if value != "Bearer fresh" {
			t.Errorf("header %q = %q, want the added value to win", name, value)
		}
	}
	if authEntries != 1 {
		t.Errorf("want exactly one Authorization entry, got %d: %v", authEntries, view.customHeaders)
	}
}

// An empty list is a no-op: the caller gets the parent back rather than a view
// with its own cookie jar and cache partition for no reason.
func TestWithAdditionalHeaders_EmptyReturnsParent(t *testing.T) {
	r := newTestRequester(t)
	for _, headers := range [][]string{nil, {}, {"not-a-header"}} {
		view, err := r.WithAdditionalHeaders(headers)
		if err != nil {
			t.Fatalf("WithAdditionalHeaders(%v): %v", headers, err)
		}
		if view != r {
			t.Errorf("WithAdditionalHeaders(%v) built a view; want the parent unchanged", headers)
		}
	}
}

// TestWithAdditionalHeaders_ViewSendsHeaderParentDoesNot is the end-to-end
// statement of the WP: one host, two requesters over one pool, and only the
// assessment view authenticates.
func TestWithAdditionalHeaders_ViewSendsHeaderParentDoesNot(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		seen = append(seen, req.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestRequester(t)
	view, err := r.WithAdditionalHeaders([]string{"Authorization: Bearer session-token"})
	if err != nil {
		t.Fatalf("WithAdditionalHeaders: %v", err)
	}

	before := r.RequestsSent()
	for _, req := range []*Requester{view, r} {
		rr, err := httpmsg.GetRawRequestFromURL(srv.URL)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		if _, _, err := req.Execute(rr, Options{NoClustering: true}); err != nil {
			t.Fatalf("Execute: %v", err)
		}
	}

	if len(seen) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(seen))
	}
	if seen[0] != "Bearer session-token" {
		t.Errorf("view Authorization = %q, want the session token", seen[0])
	}
	if seen[1] != "" {
		t.Errorf("parent Authorization = %q, want none", seen[1])
	}
	// One counter: a consumer watching phase.progress must see the view's
	// traffic, not a slope that stalls the moment assessment starts.
	if got := r.RequestsSent() - before; got != 2 {
		t.Errorf("RequestsSent delta = %d, want 2 (the counter is shared)", got)
	}
	if r.RequestsSent() != view.RequestsSent() {
		t.Errorf("counters diverged: parent %d vs view %d", r.RequestsSent(), view.RequestsSent())
	}
}

// TestWithAdditionalHeaders_DoesNotShareResponseCache is the authenticated
// mirror of TestAnonymousViewDoesNotShareResponseCache: the credentials arrive
// via the header map, AFTER the cluster key is computed from the raw bytes, so
// without a partition of its own the authenticated request and the anonymous
// one would be served each other's response.
func TestWithAdditionalHeaders_DoesNotShareResponseCache(t *testing.T) {
	r := newTestRequester(t)
	view, err := r.WithAdditionalHeaders([]string{"Authorization: Bearer session-token"})
	if err != nil {
		t.Fatalf("WithAdditionalHeaders: %v", err)
	}

	svc := httpmsg.NewServiceSecure("target.test", 443, true)
	raw := []byte("GET /admin HTTP/1.1\r\nHost: target.test\r\n\r\n")
	input := httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(svc, raw), nil)

	parentOpts := Options{}
	parentOpts.clusterScope = r.clusterScope
	viewOpts := Options{}
	viewOpts.clusterScope = view.clusterScope

	if computeClusterKey(input, parentOpts) == computeClusterKey(input, viewOpts) {
		t.Error("the authenticated view shares a cache key with the anonymous parent")
	}

	// And two views must still coalesce with each other, for the same reason
	// anonymous views do: a per-view partition would switch clustering off for
	// the whole assessment phase.
	other, err := r.WithAdditionalHeaders([]string{"Authorization: Bearer session-token"})
	if err != nil {
		t.Fatalf("second view: %v", err)
	}
	if other.clusterScope != view.clusterScope {
		t.Errorf("views must share one partition: %q vs %q", other.clusterScope, view.clusterScope)
	}
	// Also distinct from the credential-stripped partition, which is a third
	// credential surface.
	anon, err := r.CloneWithoutCredentials()
	if err != nil {
		t.Fatalf("CloneWithoutCredentials: %v", err)
	}
	if anon.clusterScope == view.clusterScope {
		t.Error("the authenticated and credential-stripped partitions must differ")
	}
}

// TestWithAdditionalHeaders_CarriedSessionInstalledLater reaches the view. The
// spidering phase installs carried sessions on the shared requester at the END
// of its phase — after assessment has already derived its view — so a view that
// copied the map instead of sharing the store would send the session headers
// without the browser-cleared cookies.
func TestWithAdditionalHeaders_CarriedSessionInstalledLater(t *testing.T) {
	var gotCookie, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotCookie = req.Header.Get("Cookie")
		gotAuth = req.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestRequester(t)
	view, err := r.WithAdditionalHeaders([]string{"Authorization: Bearer session-token"})
	if err != nil {
		t.Fatalf("WithAdditionalHeaders: %v", err)
	}

	// Installed on the PARENT, after the view exists.
	host := httpmsg.NormalizeHost(mustHost(t, srv.URL))
	r.SetCarriedSessions(map[string]httpmsg.CarriedSession{
		host: {CookieHeader: "cf_clearance=abc"},
	})

	rr, err := httpmsg.GetRawRequestFromURL(srv.URL)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, _, err := view.Execute(rr, Options{NoClustering: true}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if gotCookie != "cf_clearance=abc" {
		t.Errorf("Cookie = %q, want the carried browser session", gotCookie)
	}
	if gotAuth != "Bearer session-token" {
		t.Errorf("Authorization = %q, want the session header too", gotAuth)
	}
}
