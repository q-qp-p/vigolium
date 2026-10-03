package source

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestBuildDiscoveryHeaders_InjectsSessionForMatchingHost(t *testing.T) {
	d := &DeparosDiscoverySource{cfg: DeparosDiscoveryConfig{
		BrowserSessions: map[string]httpmsg.CarriedSession{
			"example.com": {CookieHeader: "cf_clearance=abc", UserAgent: "PinnedUA/1.0"},
		},
	}}

	headers := d.buildDiscoveryHeaders("https://example.com/app")
	if headers["Cookie"] != "cf_clearance=abc" {
		t.Errorf("Cookie = %q, want carried cookie", headers["Cookie"])
	}
	if headers["User-Agent"] != "PinnedUA/1.0" {
		t.Errorf("User-Agent = %q, want carried UA", headers["User-Agent"])
	}
}

func TestBuildDiscoveryHeaders_NonMatchingHostGetsNothing(t *testing.T) {
	d := &DeparosDiscoverySource{cfg: DeparosDiscoveryConfig{
		BrowserSessions: map[string]httpmsg.CarriedSession{
			"example.com": {CookieHeader: "cf_clearance=abc"},
		},
	}}

	// A different host must not inherit example.com's session.
	if headers := d.buildDiscoveryHeaders("https://other.test/"); headers != nil {
		t.Errorf("expected nil headers for non-matching host, got %v", headers)
	}
}

func TestBuildDiscoveryHeaders_ConfiguredHeaderWins(t *testing.T) {
	d := &DeparosDiscoverySource{cfg: DeparosDiscoveryConfig{
		CustomHeaders: map[string]string{"cookie": "operator=1"}, // lowercase on purpose
		BrowserSessions: map[string]httpmsg.CarriedSession{
			"example.com": {CookieHeader: "cf_clearance=abc", UserAgent: "PinnedUA/1.0"},
		},
	}}

	headers := d.buildDiscoveryHeaders("https://example.com/")
	// A configured Cookie (any case) wins; the session's Cookie is not added.
	if headers["cookie"] != "operator=1" {
		t.Errorf("configured cookie = %q, want operator=1", headers["cookie"])
	}
	if _, ok := headers["Cookie"]; ok {
		t.Error("session Cookie must not be added when a Cookie header is already configured")
	}
	// User-Agent was not configured, so the session's UA is still injected.
	if headers["User-Agent"] != "PinnedUA/1.0" {
		t.Errorf("User-Agent = %q, want carried UA", headers["User-Agent"])
	}
}

func TestBuildDiscoveryHeaders_NoSessionNoCustomIsNil(t *testing.T) {
	d := &DeparosDiscoverySource{cfg: DeparosDiscoveryConfig{}}
	if headers := d.buildDiscoveryHeaders("https://example.com/"); headers != nil {
		t.Errorf("expected nil headers with no session and no custom headers, got %v", headers)
	}
}

// TestBuildDiscoveryHeaders_HTTPTargetDropsSecureCookie: the engine takes one
// static Cookie header per target, and it used to be the whole flattened jar —
// so a Secure cookie the browser only ever sent over https rode a plain-http
// crawl of the same host. With the harvested attributes carried, the header is
// evaluated for the target's origin.
func TestBuildDiscoveryHeaders_HTTPTargetDropsSecureCookie(t *testing.T) {
	sess := httpmsg.CarriedSession{
		// Deliberately everything, to prove the evaluation runs rather than the
		// flat fallback.
		CookieHeader: "sid=s; tracker=t",
		Cookies: []httpmsg.CarriedCookie{
			{Name: "sid", Value: "s", Domain: "example.com", Path: "/", HostOnly: true},
			{Name: "tracker", Value: "t", Domain: "example.com", Path: "/", Secure: true},
		},
	}
	d := &DeparosDiscoverySource{cfg: DeparosDiscoveryConfig{
		BrowserSessions: map[string]httpmsg.CarriedSession{"example.com": sess},
	}}

	if got := d.buildDiscoveryHeaders("http://example.com/")["Cookie"]; got != "sid=s" {
		t.Errorf("http target Cookie = %q, want the Secure cookie dropped", got)
	}
	if got := d.buildDiscoveryHeaders("https://example.com/")["Cookie"]; got != "sid=s; tracker=t" {
		t.Errorf("https target Cookie = %q, want both cookies", got)
	}
	// Path is ignored for an origin-wide header, so a path-scoped cookie is
	// still offered: the engine crawls the whole origin from one header.
	withPath := httpmsg.CarriedSession{Cookies: []httpmsg.CarriedCookie{
		{Name: "admin_csrf", Value: "c", Domain: "example.com", Path: "/admin"},
	}}
	d.cfg.BrowserSessions = map[string]httpmsg.CarriedSession{"example.com": withPath}
	if got := d.buildDiscoveryHeaders("https://example.com/")["Cookie"]; got != "admin_csrf=c" {
		t.Errorf("path-scoped cookie = %q, want it offered for the whole origin", got)
	}
}

// A host-only cookie harvested from the apex must not be handed to a subdomain
// target.
func TestBuildDiscoveryHeaders_HostOnlyCookieStaysOnItsHost(t *testing.T) {
	sess := httpmsg.CarriedSession{Cookies: []httpmsg.CarriedCookie{
		{Name: "ho", Value: "1", Domain: "example.com", Path: "/", HostOnly: true},
		{Name: "dw", Value: "2", Domain: "example.com", Path: "/"},
	}}
	// Keyed by the subdomain, as a harvest from that subdomain's crawl would be.
	d := &DeparosDiscoverySource{cfg: DeparosDiscoveryConfig{
		BrowserSessions: map[string]httpmsg.CarriedSession{"api.example.com": sess},
	}}
	if got := d.buildDiscoveryHeaders("https://api.example.com/")["Cookie"]; got != "dw=2" {
		t.Errorf("Cookie = %q, want only the domain-wide cookie", got)
	}
}

// An unparseable target matches nothing rather than panicking or sending the
// whole jar.
func TestBuildDiscoveryHeaders_UnparseableTarget(t *testing.T) {
	sess := httpmsg.CarriedSession{Cookies: []httpmsg.CarriedCookie{
		{Name: "sid", Value: "s", Domain: "example.com", Path: "/"},
	}}
	d := &DeparosDiscoverySource{cfg: DeparosDiscoveryConfig{
		BrowserSessions: map[string]httpmsg.CarriedSession{"example.com": sess},
	}}
	if headers := d.buildDiscoveryHeaders("::not a url::"); headers != nil {
		t.Errorf("expected nil headers for an unparseable target, got %v", headers)
	}
}
