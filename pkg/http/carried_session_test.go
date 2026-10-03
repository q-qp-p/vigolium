package http

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// newTestRequesterWithOpts builds a Requester from explicit options (the shared
// newTestRequester in raw_target_test.go uses DefaultOptions only).
func newTestRequesterWithOpts(t *testing.T, opts *types.Options) *Requester {
	t.Helper()
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	r, err := NewRequester(opts, &services.Services{Options: opts})
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	return r
}

// TestCarriedSession_InjectsCookieAndUA proves a harvested per-host session is
// merged into outgoing requests: the carried cookies and pinned User-Agent
// reach the server for the matching host.
func TestCarriedSession_InjectsCookieAndUA(t *testing.T) {
	var gotCookie, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotCookie = req.Header.Get("Cookie")
		gotUA = req.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestRequester(t)

	host := httpmsg.NormalizeHost(mustHost(t, srv.URL))
	r.SetCarriedSessions(map[string]httpmsg.CarriedSession{
		host: {CookieHeader: "cf_clearance=abc; sess=1", UserAgent: "PinnedBrowser/1.0"},
	})

	rr, err := httpmsg.GetRawRequestFromURL(srv.URL)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, _, err := r.Execute(rr, Options{NoClustering: true}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if gotCookie != "cf_clearance=abc; sess=1" {
		t.Errorf("Cookie = %q, want carried cookies", gotCookie)
	}
	if gotUA != "PinnedBrowser/1.0" {
		t.Errorf("User-Agent = %q, want pinned browser UA", gotUA)
	}
}

// TestCarriedSession_InjectsAuthorization proves a harvested token-session
// credential (JWT/Bearer) is applied to a request that has no Authorization of its
// own — the token-based-SPA analogue of the cookie carry.
func TestCarriedSession_InjectsAuthorization(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestRequester(t)

	host := httpmsg.NormalizeHost(mustHost(t, srv.URL))
	r.SetCarriedSessions(map[string]httpmsg.CarriedSession{
		host: {AuthorizationHeader: "Bearer eyJ.jwt.token"},
	})

	rr, err := httpmsg.GetRawRequestFromURL(srv.URL)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, _, err := r.Execute(rr, Options{NoClustering: true}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotAuth != "Bearer eyJ.jwt.token" {
		t.Errorf("Authorization = %q, want carried bearer token", gotAuth)
	}
}

// TestCarriedSession_CustomHeaderWins proves an explicit -H Cookie/User-Agent
// overrides the carried session — the session never clobbers operator headers.
func TestCarriedSession_CustomHeaderWins(t *testing.T) {
	var gotCookie, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotCookie = req.Header.Get("Cookie")
		gotUA = req.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := types.DefaultOptions()
	opts.Headers = []string{"Cookie: operator=1", "User-Agent: OperatorUA/9"}
	r := newTestRequesterWithOpts(t, opts)

	host := httpmsg.NormalizeHost(mustHost(t, srv.URL))
	r.SetCarriedSessions(map[string]httpmsg.CarriedSession{
		host: {CookieHeader: "cf_clearance=abc", UserAgent: "PinnedBrowser/1.0"},
	})

	rr, err := httpmsg.GetRawRequestFromURL(srv.URL)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, _, err := r.Execute(rr, Options{NoClustering: true}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if gotCookie != "operator=1" {
		t.Errorf("Cookie = %q, want operator -H header to win", gotCookie)
	}
	if gotUA != "OperatorUA/9" {
		t.Errorf("User-Agent = %q, want operator -H header to win", gotUA)
	}
}

// TestCarriedSession_WrongHostNotInjected proves a session harvested for one
// host is never sent to another host.
func TestCarriedSession_WrongHostNotInjected(t *testing.T) {
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotCookie = req.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestRequester(t)
	// Session keyed to an unrelated host.
	r.SetCarriedSessions(map[string]httpmsg.CarriedSession{
		"other.example": {CookieHeader: "cf_clearance=abc"},
	})

	rr, err := httpmsg.GetRawRequestFromURL(srv.URL)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, _, err := r.Execute(rr, Options{NoClustering: true}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if gotCookie != "" {
		t.Errorf("Cookie = %q, want no carried cookie for a non-matching host", gotCookie)
	}
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Host
}

// TestCarriedSession_SecureCookieNotSentOverHTTP is the WP9 statement on the
// HTTP path: the flat Cookie header the session used to carry had no attributes,
// so a Secure cookie and a /admin cookie rode on every request to the host,
// including plain-http ones. With the harvested jar carried, the requester
// evaluates it per request the way a browser does.
func TestCarriedSession_SecureCookieNotSentOverHTTP(t *testing.T) {
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotCookie = req.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestRequester(t)
	host := httpmsg.NormalizeHost(mustHost(t, srv.URL))
	r.SetCarriedSessions(map[string]httpmsg.CarriedSession{
		host: {
			// The flat header is deliberately everything, to prove the
			// per-request evaluation — not the fallback — is what runs.
			CookieHeader: "sid=s; tracker=t; admin_csrf=c",
			Cookies: []httpmsg.CarriedCookie{
				{Name: "sid", Value: "s", Domain: host, Path: "/", HostOnly: true},
				{Name: "tracker", Value: "t", Domain: host, Path: "/", Secure: true},
				{Name: "admin_csrf", Value: "c", Domain: host, Path: "/admin"},
			},
		},
	})

	// httptest.NewServer is http, and the request path is /.
	rr, err := httpmsg.GetRawRequestFromURL(srv.URL)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, _, err := r.Execute(rr, Options{NoClustering: true}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotCookie != "sid=s" {
		t.Errorf("Cookie = %q, want only the site-wide non-Secure cookie", gotCookie)
	}

	// The same session on /admin does send the path-scoped cookie.
	rr, err = httpmsg.GetRawRequestFromURL(srv.URL + "/admin")
	if err != nil {
		t.Fatalf("build /admin request: %v", err)
	}
	if _, _, err := r.Execute(rr, Options{NoClustering: true}); err != nil {
		t.Fatalf("Execute /admin: %v", err)
	}
	if gotCookie != "admin_csrf=c; sid=s" {
		t.Errorf("/admin Cookie = %q, want the path-scoped cookie too", gotCookie)
	}
}

// A session harvested before attributes were recorded still sends its flat
// header, unchanged.
func TestCarriedSession_FlatHarvestUnchanged(t *testing.T) {
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotCookie = req.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestRequester(t)
	host := httpmsg.NormalizeHost(mustHost(t, srv.URL))
	r.SetCarriedSessions(map[string]httpmsg.CarriedSession{
		host: {CookieHeader: "cf_clearance=abc; sess=1"},
	})

	rr, err := httpmsg.GetRawRequestFromURL(srv.URL)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, _, err := r.Execute(rr, Options{NoClustering: true}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotCookie != "cf_clearance=abc; sess=1" {
		t.Errorf("Cookie = %q, want the flat harvest unchanged", gotCookie)
	}
}
