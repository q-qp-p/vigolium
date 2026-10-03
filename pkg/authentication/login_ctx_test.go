package authentication

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// bearerSession is a one-shot JSON login flow: POST /login, take $.token.
func bearerSession(name, loginURL string) *Session {
	return &Session{
		Name: name,
		Role: RolePrimary,
		Login: &LoginFlow{
			URL:         loginURL,
			Method:      "POST",
			ContentType: "application/json",
			Body:        `{"u":"a","p":"b"}`,
			Extract: []ExtractRule{
				{Source: ExtractJSON, Path: "$.token", ApplyAs: "Authorization: Bearer {value}"},
			},
		},
	}
}

// tokenHandler answers a login with a token after an optional delay.
func tokenHandler(delay time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"token":"tok-123"}`)
	}
}

// stalledServer serves a login that never answers until the test is over.
//
// It does NOT rely on the request context to release the handler: the server
// notices a client that walked away only when the connection is reaped, which
// in practice is far too late — a 5s handler made Close() wait the full 5s. A
// release channel closed before the server is shut down keeps the test's cost
// to the client-side timing it is actually measuring. Cleanups run LIFO, so the
// release is registered after the shutdown and therefore runs first.
func stalledServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv
}

// TestHydrateSessionsContext_CancelledContextStopsImmediately: a login used to
// run on its own 30s client timeout with no context at all, so a Ctrl-C during
// setup left the scan waiting on a request nobody wanted the answer to.
func TestHydrateSessionsContext_CancelledContextStopsImmediately(t *testing.T) {
	srv := stalledServer(t)

	mgr, err := NewManager([]*Session{bearerSession("admin", srv.URL)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err = mgr.HydrateSessionsContext(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to wrap context.Canceled", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("took %v to notice a cancelled context", elapsed)
	}
}

// A cancel that arrives while the request is in flight aborts the request
// itself, not just the loop around it.
func TestHydrateSessionsContext_CancelDuringRequest(t *testing.T) {
	srv := stalledServer(t)

	mgr, err := NewManager([]*Session{bearerSession("admin", srv.URL)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	err = mgr.HydrateSessionsContext(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the context is cancelled mid-request")
	}
	if elapsed > time.Second {
		t.Errorf("took %v; the in-flight request was not aborted", elapsed)
	}
}

// TestHydrateSessionsContext_BudgetExpires: the budget is a TOTAL, so a login
// that never answers costs the scan the budget rather than the per-request
// timeout.
func TestHydrateSessionsContext_BudgetExpires(t *testing.T) {
	srv := stalledServer(t)

	mgr, err := NewManager([]*Session{bearerSession("admin", srv.URL)},
		WithLoginBudget(150*time.Millisecond))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	start := time.Now()
	err = mgr.HydrateSessionsContext(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the login budget expires")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("took %v, want the 150ms budget to govern", elapsed)
	}
}

// TestHydrateSessionsContext_BudgetSpansSessions: one budget for ALL sessions.
// Three sessions must not get three budgets — that is the "nine minutes of
// silent setup" this bound exists to prevent.
func TestHydrateSessionsContext_BudgetSpansSessions(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		tokenHandler(300*time.Millisecond)(w, r)
	}))
	defer srv.Close()

	sessions := []*Session{
		bearerSession("one", srv.URL),
		bearerSession("two", srv.URL),
		bearerSession("three", srv.URL),
	}
	sessions[1].Role = RoleCompare
	sessions[2].Role = RoleCompare

	mgr, err := NewManager(sessions, WithLoginBudget(400*time.Millisecond))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	start := time.Now()
	err = mgr.HydrateSessionsContext(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the shared budget to run out before the third login")
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("took %v; the budget is per session, not total", elapsed)
	}
	if got := hits.Load(); got > 2 {
		t.Errorf("%d login requests sent; the budget should have stopped the loop earlier", got)
	}
}

// TestHydrateSessionsContext_MultiStepFailsAtTheStepTheBudgetRanOut: a
// three-step flow of 100ms steps under a 150ms budget must fail naming step 1
// (the second step), not run to completion or report the first.
func TestHydrateSessionsContext_MultiStepFailsMidFlow(t *testing.T) {
	var steps atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		steps.Add(1)
		tokenHandler(100*time.Millisecond)(w, r)
	}))
	defer srv.Close()

	step := func(path string) LoginStep {
		return LoginStep{
			URL:         srv.URL + path,
			Method:      "POST",
			ContentType: "application/json",
			Body:        `{}`,
			Extract: []ExtractRule{
				{Source: ExtractJSON, Path: "$.token", ApplyAs: "Authorization: Bearer {value}"},
			},
		}
	}
	sess := &Session{
		Name: "multi",
		Role: RolePrimary,
		Login: &LoginFlow{
			Steps: []LoginStep{step("/a"), step("/b"), step("/c")},
		},
	}

	mgr, err := NewManager([]*Session{sess}, WithLoginBudget(150*time.Millisecond))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	err = mgr.HydrateSessionsContext(context.Background())
	if err == nil {
		t.Fatal("expected the budget to cut the flow short")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want it to wrap context.DeadlineExceeded", err)
	}
	// Named by step so an operator can see where the flow stopped.
	if !strings.Contains(err.Error(), "step[1]") && !strings.Contains(err.Error(), "step[2]") {
		t.Errorf("error %q does not name the step it died on", err)
	}
	if got := steps.Load(); got >= 3 {
		t.Errorf("%d steps sent; the flow should not have completed", got)
	}
	// The flow's own completion flag, not IsHydrated(): a flow cut short after
	// its first step has already written one header, and IsHydrated() counts any
	// header as hydrated. The caller learns the flow failed from the returned
	// error, which is what initSessions acts on.
	if sess.hydrated {
		t.Error("a flow that did not finish must not set the hydrated flag")
	}
}

// TestLoginGoesThroughTheTransport: with --proxy set, every scan request goes
// through the proxy EXCEPT, previously, the login — so the proxy log showed an
// authenticated scan with no login in it, and a proxy-only route to the target
// failed the login outright.
func TestLoginGoesThroughTheTransport(t *testing.T) {
	target := httptest.NewServer(tokenHandler(0))
	defer target.Close()

	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A real forward proxy sees an absolute-form request URI.
		if r.URL.IsAbs() {
			proxied.Add(1)
		}
		tokenHandler(0)(w, r)
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	sess := bearerSession("admin", target.URL)
	mgr, err := NewManager([]*Session{sess},
		WithLoginTransport(&http.Transport{Proxy: http.ProxyURL(proxyURL)}))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.HydrateSessionsContext(context.Background()); err != nil {
		t.Fatalf("HydrateSessionsContext: %v", err)
	}

	if proxied.Load() != 1 {
		t.Errorf("the proxy saw %d login requests, want 1", proxied.Load())
	}
	if sess.Headers["Authorization"] != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want the extracted token", sess.Headers["Authorization"])
	}
}

// A nil transport keeps Go's default, so an existing caller that installs
// nothing behaves exactly as it did.
func TestLoginNilTransportStillWorks(t *testing.T) {
	srv := httptest.NewServer(tokenHandler(0))
	defer srv.Close()

	sess := bearerSession("admin", srv.URL)
	mgr, err := NewManager([]*Session{sess}, WithLoginTransport(nil), WithLoginBudget(0))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if mgr.loginBudget != DefaultLoginBudget {
		t.Errorf("loginBudget = %v, want the default to survive a zero override", mgr.loginBudget)
	}
	if err := mgr.HydrateSessionsContext(context.Background()); err != nil {
		t.Fatalf("HydrateSessionsContext: %v", err)
	}
	if !sess.IsHydrated() {
		t.Error("session should be hydrated")
	}
}

// HydrateSessions() — the context-free API the agent swarm still calls — must
// keep working, on a background context under the default budget.
func TestHydrateSessionsBackgroundWrapper(t *testing.T) {
	srv := httptest.NewServer(tokenHandler(0))
	defer srv.Close()

	sess := bearerSession("admin", srv.URL)
	mgr, err := NewManager([]*Session{sess})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.HydrateSessions(); err != nil {
		t.Fatalf("HydrateSessions: %v", err)
	}
	if sess.Headers["Authorization"] != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want the extracted token", sess.Headers["Authorization"])
	}
}

// A per-flow cookie jar: the client the manager shares must not accumulate one
// session's cookies and hand them to the next, or one session's login could
// satisfy another's cookie extract rule.
func TestLoginJarIsPerFlow(t *testing.T) {
	var sawCookie atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			sawCookie.Store(true)
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "s1", Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"token":"tok-123"}`)
	}))
	defer srv.Close()

	cookieSession := func(name string) *Session {
		return &Session{
			Name:  name,
			Login: &LoginFlow{URL: srv.URL, Method: "POST", Extract: []ExtractRule{{Source: ExtractCookie, Name: "sid"}}},
		}
	}
	first := cookieSession("one")
	second := cookieSession("two")
	second.Role = RoleCompare

	mgr, err := NewManager([]*Session{first, second})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.HydrateSessionsContext(context.Background()); err != nil {
		t.Fatalf("HydrateSessionsContext: %v", err)
	}
	if sawCookie.Load() {
		t.Error("the second login carried the first login's cookie; the jar is shared")
	}
	if first.Headers["Cookie"] == "" || second.Headers["Cookie"] == "" {
		t.Errorf("both sessions should have extracted their own cookie: %v / %v", first.Headers, second.Headers)
	}
}

// ProbeLoginContext honours its context too, so an interactive probe is
// interruptible.
func TestProbeLoginContext_Cancelled(t *testing.T) {
	srv := stalledServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if _, err := ProbeLoginContext(ctx, bearerSession("admin", srv.URL), nil); err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("took %v to notice a cancelled context", elapsed)
	}
}

// ProbeLogin (no context) keeps its old shape: status back, no error.
func TestProbeLoginStillReturnsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	status, err := ProbeLogin(bearerSession("admin", srv.URL))
	if err != nil {
		t.Fatalf("ProbeLogin: %v", err)
	}
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}
}
