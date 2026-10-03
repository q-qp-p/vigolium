package action

import (
	"net/url"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestShouldSkipHrefHonoursCrawlScope covers the anchor pre-filter: an operator's
// scope boundary is applied to an anchor's href BEFORE the element is offered as
// a click candidate, so the browser never navigates to an excluded URL and then
// discards the page.
func TestShouldSkipHrefHonoursCrawlScope(t *testing.T) {
	base, err := url.Parse("https://app.example.com/dashboard/")
	if err != nil {
		t.Fatal(err)
	}
	// A scope that rejects /logout anywhere, and anything on other.example.
	scope := config.CrawlScope(func(raw string) bool {
		u, perr := url.Parse(raw)
		if perr != nil {
			return true
		}
		if u.Hostname() == "other.example" {
			return false
		}
		return !strings.HasPrefix(u.Path, "/logout")
	})

	cfg := &config.Config{URL: base, CrawlScope: scope}
	e := NewCandidateElementExtractor(cfg)
	e.SetFollowExternalLinks(true) // isolate the scope check from the host check

	tests := []struct {
		name string
		href string
		skip bool
	}{
		{"absolute excluded path", "https://app.example.com/logout", true},
		{"root-relative excluded path", "/logout", true},
		{"root-relative excluded subpath", "/logout/confirm", true},
		{"absolute excluded host", "https://other.example/anything", true},
		{"scheme-relative excluded host", "//other.example/anything", true},
		{"absolute allowed path", "https://app.example.com/orders", false},
		{"root-relative allowed path", "/orders", false},
		// Path-relative hrefs are deliberately not judged: resolving them needs
		// the live document base, which a <base> tag or a pushState can have moved.
		{"path-relative is left to the crawler", "settings", false},
		{"fragment is left alone", "#section", false},
		{"javascript href is left alone", "javascript:doThing()", false},
		{"unparseable href is left alone", "/%zz", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.shouldSkipHref(tt.href); got != tt.skip {
				t.Errorf("shouldSkipHref(%q) = %v, want %v", tt.href, got, tt.skip)
			}
		})
	}
}

// TestShouldSkipHrefWithoutCrawlScope pins that a crawl with no operator scope
// behaves exactly as before: only the mailto/tel/download/external rules apply.
func TestShouldSkipHrefWithoutCrawlScope(t *testing.T) {
	base, _ := url.Parse("https://app.example.com/")
	e := NewCandidateElementExtractor(&config.Config{URL: base})

	for _, href := range []string{"/logout", "https://app.example.com/logout", "#x", "javascript:x()"} {
		if e.shouldSkipHref(href) {
			t.Errorf("shouldSkipHref(%q) = true with no CrawlScope, want false", href)
		}
	}
	// The pre-existing rules still apply.
	for _, href := range []string{"mailto:a@b.c", "tel:+1", "/report.pdf"} {
		if !e.shouldSkipHref(href) {
			t.Errorf("shouldSkipHref(%q) = false, want true", href)
		}
	}
}

func TestOutOfCrawlScopeWithoutBaseURL(t *testing.T) {
	// No config URL: a root-relative href has no host to resolve against, so it
	// cannot be judged and must be allowed through to the crawler's own check.
	e := NewCandidateElementExtractor(&config.Config{
		CrawlScope: func(string) bool { return false },
	})
	if e.outOfCrawlScope("/logout") {
		t.Fatal("a root-relative href with no base URL must not be judged")
	}
	// An absolute href carries its own host and is judged.
	if !e.outOfCrawlScope("https://example.com/logout") {
		t.Fatal("an absolute href must be judged even with no base URL")
	}
}

// TestDefaultExtractorHasNoCrawlScope guards the non-config constructor: it must
// not acquire a scope it was never given.
func TestDefaultExtractorHasNoCrawlScope(t *testing.T) {
	e := NewCandidateElementExtractorDefault()
	if e.crawlScope != nil || e.baseURL != nil {
		t.Fatal("the default extractor must carry no scope boundary")
	}
	if e.outOfCrawlScope("/logout") {
		t.Fatal("no scope boundary means nothing is out of scope")
	}
}
