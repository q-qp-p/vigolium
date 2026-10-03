package crawler

import (
	"slices"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestAdmissibleFetchURLs: the shared tail of every in-page primer refuses
// destructive paths and anything the operator scope does not admit, and counts
// the scope denials.
func TestAdmissibleFetchURLs(t *testing.T) {
	cfg, err := config.New("https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	cfg.CrawlScope = func(u string) bool {
		return strings.HasPrefix(u, "https://app.example.com/") && !strings.HasPrefix(u, "https://app.example.com/admin")
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	in := []string{
		"https://app.example.com/products?id=1",
		"https://app.example.com/admin/users",    // denied by scope
		"https://app.example.com/admin",          // denied by scope
		"https://app.example.com/account/logout", // destructive (not a scope denial)
		"https://other.example.net/widget",       // denied by scope
		"https://app.example.com/search?q=x",
		"https://app.example.com/items/delete?id=3", // destructive
	}
	orig := slices.Clone(in)
	got, denied := c.admissibleFetchURLs(in)
	want := []string{"https://app.example.com/products?id=1", "https://app.example.com/search?q=x"}
	if !slices.Equal(got, want) {
		t.Fatalf("admitted = %v, want %v", got, want)
	}
	if denied != 3 || c.GetStats().AuxFetchesDenied != 3 {
		t.Fatalf("denied = %d (stats %d), want 3", denied, c.GetStats().AuxFetchesDenied)
	}
	if !slices.Equal(in, orig) {
		t.Fatal("the caller's slice was modified")
	}
}

// TestAdmissibleFetchURLsDefaultScope: without a custom scope nothing changes
// except that a denied login-wall host is refused.
func TestAdmissibleFetchURLsDefaultScope(t *testing.T) {
	cfg, err := config.New("https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	in := []string{"https://app.example.com/a", "https://cdn.example.org/b", "https://login.idp.test/authorize"}
	got, denied := c.admissibleFetchURLs(in)
	if !slices.Equal(got, in) || denied != 0 {
		t.Fatalf("default scope changed the set: %v denied=%d", got, denied)
	}

	c.denyWallHost("login.idp.test")
	got, denied = c.admissibleFetchURLs(in)
	if slices.Contains(got, "https://login.idp.test/authorize") || denied != 1 {
		t.Fatalf("wall host fetched: %v denied=%d", got, denied)
	}
}

// TestServiceWorkerPrimingScopeGate: the primer that fetches inside its own
// script is off under a custom scope.
func TestServiceWorkerPrimingScopeGate(t *testing.T) {
	if !serviceWorkerPrimingAllowed(false) {
		t.Error("service-worker priming should run without a custom scope")
	}
	if serviceWorkerPrimingAllowed(true) {
		t.Error("service-worker priming must be off under a custom scope")
	}
}
