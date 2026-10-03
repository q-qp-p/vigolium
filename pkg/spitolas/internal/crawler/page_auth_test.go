package crawler

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// authRecorder stands in for the page calls that install credentials.
type authRecorder struct {
	headers   []map[string]string // every setHeaders call, in order
	cookies   int
	headerErr error
	cookieErr error
}

func (r *authRecorder) ops() pageAuthOps {
	return pageAuthOps{
		setCookies: func(_ *browser.Page, c []*http.Cookie) error {
			r.cookies += len(c)
			return r.cookieErr
		},
		setHeaders: func(_ *browser.Page, h map[string]string) error {
			r.headers = append(r.headers, h)
			return r.headerErr
		},
	}
}

func newAuthCrawler(t *testing.T, target string, scope func(string) bool, rec *authRecorder) *Crawler {
	t.Helper()
	cfg, err := config.New(target)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ExtraHeaders = map[string]string{"Authorization": "Bearer secret-token"}
	cfg.InitialCookies = []*http.Cookie{{Name: "sid", Value: "abc"}}
	cfg.CrawlScope = scope
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.authOps = rec.ops()
	return c
}

// TestPageAuthOriginBinding: a scope that admits only the target host gets the
// headers on the target; an off-scope landing (adopted relocation or login
// wall) clears them, records the host, and later pages do not get them back.
func TestPageAuthOriginBinding(t *testing.T) {
	onlyTarget := func(u string) bool { return strings.HasPrefix(u, "https://app.example.com/") }
	rec := &authRecorder{}
	c := newAuthCrawler(t, "https://app.example.com/", onlyTarget, rec)
	if got := c.GetStats().AuthState; got != AuthConfigured {
		t.Fatalf("initial AuthState = %q, want %q", got, AuthConfigured)
	}

	if err := c.applyPageAuth(nil); err != nil {
		t.Fatalf("applyPageAuth: %v", err)
	}
	if len(rec.headers) != 1 || rec.headers[0]["Authorization"] == "" || rec.cookies != 1 {
		t.Fatalf("target page: headers=%v cookies=%d, want the configured headers and cookie", rec.headers, rec.cookies)
	}
	if got := c.GetStats().AuthState; got != AuthApplied {
		t.Fatalf("AuthState = %q, want %q", got, AuthApplied)
	}

	// The start URL bounced to another host the operator scope does not admit.
	c.evaluateStartRedirect(nil, "https://relocated.example.net/home")
	if len(rec.headers) != 2 || len(rec.headers[1]) != 0 {
		t.Fatalf("off-scope landing did not clear the headers: %v", rec.headers)
	}
	st := c.GetStats()
	if st.CredentialOriginsDenied != 1 || !slices.Equal(st.CredentialHostsDenied, []string{"relocated.example.net"}) {
		t.Fatalf("denied = %d %v, want the landing host", st.CredentialOriginsDenied, st.CredentialHostsDenied)
	}

	// A fresh page (reset) after the withdrawal gets cookies but no headers.
	if err := c.applyPageAuth(nil); err != nil {
		t.Fatalf("applyPageAuth after withdrawal: %v", err)
	}
	if len(rec.headers) != 2 {
		t.Fatalf("headers re-installed after withdrawal: %v", rec.headers)
	}

	// Recorded hosts carry no header values.
	for _, h := range c.GetStats().CredentialHostsDenied {
		if strings.Contains(h, "secret-token") {
			t.Fatal("a header value leaked into the denied-host list")
		}
	}
}

// TestPageAuthScopeAdmitsLanding: an operator scope that admits the landing
// host keeps the headers.
func TestPageAuthScopeAdmitsLanding(t *testing.T) {
	rec := &authRecorder{}
	c := newAuthCrawler(t, "https://app.example.com/", func(string) bool { return true }, rec)
	_ = c.applyPageAuth(nil)
	c.evaluateStartRedirect(nil, "https://relocated.example.net/home")
	if len(rec.headers) != 1 || c.GetStats().CredentialOriginsDenied != 0 {
		t.Fatalf("in-scope landing withdrew the headers: %v denied=%d", rec.headers, c.GetStats().CredentialOriginsDenied)
	}
}

// TestPageAuthDefaultScopeAdoption: under the default host scope an adopted
// relocation host is not the host the credentials were given for.
func TestPageAuthDefaultScopeAdoption(t *testing.T) {
	rec := &authRecorder{}
	c := newAuthCrawler(t, "https://app.example.com/", nil, rec)
	_ = c.applyPageAuth(nil)
	c.evaluateStartRedirect(nil, "https://relocated.example.net/home")
	st := c.GetStats()
	if !st.HostAdopted {
		t.Fatal("expected the relocation host to be adopted")
	}
	if st.CredentialOriginsDenied != 1 || len(rec.headers) != 2 {
		t.Fatalf("adopted host kept the headers: denied=%d headers=%v", st.CredentialOriginsDenied, rec.headers)
	}

	// A subdomain landing is the target's own scope: nothing withdrawn.
	rec2 := &authRecorder{}
	c2 := newAuthCrawler(t, "https://example.com/", nil, rec2)
	_ = c2.applyPageAuth(nil)
	c2.evaluateStartRedirect(nil, "https://www.example.com/")
	if c2.GetStats().CredentialOriginsDenied != 0 || len(rec2.headers) != 1 {
		t.Fatal("same-site landing withdrew the headers")
	}
}

// TestPageAuthTargetOutOfScope: headers are never installed on a target the
// operator scope does not admit, and that counts as a failed application.
func TestPageAuthTargetOutOfScope(t *testing.T) {
	rec := &authRecorder{}
	c := newAuthCrawler(t, "https://app.example.com/", func(string) bool { return false }, rec)
	if err := c.applyPageAuth(nil); err == nil {
		t.Fatal("want an error for withheld headers")
	}
	if len(rec.headers) != 0 {
		t.Fatalf("headers installed on an out-of-scope target: %v", rec.headers)
	}
	st := c.GetStats()
	if st.AuthState != AuthFailed || !slices.Equal(st.CredentialHostsDenied, []string{"app.example.com"}) {
		t.Fatalf("AuthState=%q denied=%v", st.AuthState, st.CredentialHostsDenied)
	}
}

// TestSeedPageAuthRequireAuth: a failing install fails the seed only with
// RequireAuth; without it the state says "failed" and the crawl proceeds.
// The state stays failed even if a later page succeeds.
func TestSeedPageAuthRequireAuth(t *testing.T) {
	rec := &authRecorder{headerErr: errors.New("cdp: target closed")}
	c := newAuthCrawler(t, "https://app.example.com/", nil, rec)
	if err := c.seedPageAuth(nil); err != nil {
		t.Fatalf("without RequireAuth the crawl must proceed, got %v", err)
	}
	if got := c.GetStats().AuthState; got != AuthFailed {
		t.Fatalf("AuthState = %q, want %q", got, AuthFailed)
	}
	rec.headerErr = nil
	_ = c.applyPageAuth(nil)
	if got := c.GetStats().AuthState; got != AuthFailed {
		t.Fatalf("a later success flipped AuthState to %q; a failed start must stay reported", got)
	}

	rec2 := &authRecorder{cookieErr: errors.New("cdp: invalid cookie")}
	c2 := newAuthCrawler(t, "https://app.example.com/", nil, rec2)
	c2.config.RequireAuth = true
	err := c2.seedPageAuth(nil)
	if err == nil || !strings.Contains(err.Error(), "authentication required") {
		t.Fatalf("RequireAuth with a failing install: err = %v", err)
	}
}

// TestPageAuthNotRequested: no configured auth is a state, not a failure.
func TestPageAuthNotRequested(t *testing.T) {
	cfg, err := config.New("https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	cfg.RequireAuth = true
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec := &authRecorder{}
	c.authOps = rec.ops()
	if err := c.seedPageAuth(nil); err != nil {
		t.Fatalf("nothing configured: %v", err)
	}
	if got := c.GetStats().AuthState; got != AuthNotRequested || len(rec.headers) != 0 || rec.cookies != 0 {
		t.Fatalf("AuthState=%q headers=%v cookies=%d", got, rec.headers, rec.cookies)
	}
}
